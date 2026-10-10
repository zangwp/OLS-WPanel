package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func accessChangeFixture(t *testing.T, exists bool) firewallAccessChangeRecord {
	t.Helper()
	oldPath, oldCompleted, oldPending := firewallAccessChangePath, completedFirewallAccessChangeID, pendingAccess
	firewallAccessChangePath = filepath.Join(t.TempDir(), "access-change.json")
	completedFirewallAccessChangeID = ""
	t.Cleanup(func() {
		firewallAccessChangePath, completedFirewallAccessChangeID, pendingAccess = oldPath, oldCompleted, oldPending
	})
	record := firewallAccessChangeRecord{Version: 1, ID: firewallAccessChangeID("fixture-token"), State: "pending", PreviousExists: exists}
	if exists {
		record.Previous = "table inet " + accessTable + " { old fixture policy }"
	}
	if err := saveFirewallAccessChange(record); err != nil {
		t.Fatal(err)
	}
	pendingAccess.token = "fixture-token"
	return record
}

func TestAccessRollbackStatusRequiresObservedOldPolicyAndInactiveJobs(t *testing.T) {
	for _, tc := range []struct {
		name, timer, service, tables, current string
		previousExists, failSystemd, failNft  bool
		want                                  string
	}{
		{name: "timer still waiting", timer: "LoadState=loaded\nActiveState=active", want: "pending"},
		{name: "rollback still running", service: "LoadState=loaded\nActiveState=activating\nResult=success", want: "pending"},
		{name: "systemd command error", failSystemd: true, want: "error"},
		{name: "incomplete timer output", timer: "ActiveState=inactive", want: "error"},
		{name: "incomplete service output", service: "LoadState=loaded\nActiveState=inactive", want: "error"},
		{name: "failed rollback service", service: "LoadState=loaded\nActiveState=failed\nResult=exit-code", want: "error"},
		{name: "nft read failure", failNft: true, want: "error"},
		{name: "new table remains", tables: "table inet " + accessTable, current: "new policy", want: "error"},
		{name: "old table missing", previousExists: true, want: "error"},
		{name: "old table not exact", previousExists: true, tables: "table inet " + accessTable, current: "changed old policy", want: "error"},
		{name: "original table absent restored", want: "rolled_back"},
		{name: "exact old table restored", previousExists: true, tables: "table inet " + accessTable, want: "rolled_back"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := accessChangeFixture(t, tc.previousExists)
			old := portCommand
			t.Cleanup(func() { portCommand = old })
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				if name == "systemctl" {
					if len(args) < 2 || args[0] != "show" {
						t.Fatalf("mutation in status check: %s %v", name, args)
					}
					if tc.failSystemd {
						return "LoadState=loaded\nActiveState=inactive\nResult=success", errors.New("partial permission failure")
					}
					if strings.HasSuffix(args[1], ".timer") && tc.timer != "" {
						return tc.timer, nil
					}
					if strings.HasSuffix(args[1], ".service") && tc.service != "" {
						return tc.service, nil
					}
					return "LoadState=loaded\nActiveState=inactive\nResult=success", nil
				}
				if name == "nft" {
					if tc.failNft {
						return "", errors.New("permission denied")
					}
					switch strings.Join(args, " ") {
					case "--json --stateless list tables":
						entries := []map[string]any{}
						if tc.tables != "" {
							entries = append(entries, map[string]any{"table": map[string]string{"family": "inet", "name": accessTable}})
						}
						data, _ := json.Marshal(map[string]any{"nftables": entries})
						return string(data), nil
					case "--stateless list table inet " + accessTable:
						if tc.current != "" {
							return tc.current, nil
						}
						return record.Previous, nil
					}
				}
				t.Fatalf("unexpected status command: %s %v", name, args)
				return "", errors.New("unexpected command")
			}
			got := inspectFirewallAccessChange(context.Background())
			if got.ID != record.ID || got.State != tc.want {
				t.Fatalf("status %+v, want %s", got, tc.want)
			}
			if tc.want == "error" && got.Error == "" {
				t.Fatal("unsafe state had no retryable error")
			}
			if tc.want != "rolled_back" && pendingAccess.token == "" {
				t.Fatal("uncertain result unlocked confirmation state")
			}
			if tc.want == "rolled_back" && pendingAccess.token != "" {
				t.Fatal("verified rollback did not retire matching token")
			}
			stored, err := readFirewallAccessChange()
			if err != nil {
				t.Fatal(err)
			}
			wantStored := "pending"
			if tc.want == "rolled_back" {
				wantStored = "rolled_back"
			}
			if stored.State != wantStored {
				t.Fatalf("unverified completion persisted: %+v", stored)
			}
		})
	}
}

func TestAccessRollbackReceiptSurvivesPanelRestartAndDoesNotAuthorizeConfirmation(t *testing.T) {
	record := accessChangeFixture(t, false)
	pendingAccess.token = "" // A newly started panel has no authorization token.
	old := portCommand
	t.Cleanup(func() { portCommand = old })
	portCommand = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" {
			return "LoadState=not-found\nActiveState=inactive", nil
		}
		if name == "nft" && strings.Join(args, " ") == "--json --stateless list tables" {
			return `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"filter","handle":1}}]}`, nil
		}
		t.Fatalf("unexpected command: %s %v", name, args)
		return "", errors.New("unexpected")
	}
	if got := inspectFirewallAccessChange(context.Background()); got.ID != record.ID || got.State != "rolled_back" {
		t.Fatalf("restart lost observed rollback: %+v", got)
	}
	portCommand = func(context.Context, string, ...string) (string, error) {
		t.Fatal("receipt recheck ran a mutation/inspection")
		return "", nil
	}
	if got := inspectFirewallAccessChange(context.Background()); got.State != "rolled_back" {
		t.Fatalf("terminal state not retained: %+v", got)
	}
	if err := ConfirmFirewallAccess(record.ID); err == nil {
		t.Fatal("public change ID authorized confirmation")
	}
	data, err := os.ReadFile(firewallAccessChangePath)
	if err != nil || strings.Contains(string(data), "fixture-token") {
		t.Fatalf("receipt contained authorization token: %s, %v", data, err)
	}
}

func TestAccessRollbackStatusDoesNotClearDifferentChangeAndAllowsRetry(t *testing.T) {
	record := accessChangeFixture(t, false)
	pendingAccess.token = "different-active-token"
	old := portCommand
	t.Cleanup(func() { portCommand = old })
	failed := true
	portCommand = func(_ context.Context, name string, args ...string) (string, error) {
		if failed {
			return "", errors.New("temporary inspection failure")
		}
		if name == "systemctl" {
			return "LoadState=not-found\nActiveState=inactive", nil
		}
		if name == "nft" {
			return `{"nftables":[]}`, nil
		}
		t.Fatalf("unexpected command: %s %v", name, args)
		return "", errors.New("unexpected")
	}
	if got := inspectFirewallAccessChange(context.Background()); got.State != "error" {
		t.Fatalf("inspection failure was completion: %+v", got)
	}
	failed = false
	if got := inspectFirewallAccessChange(context.Background()); got.ID != record.ID || got.State != "rolled_back" {
		t.Fatalf("retry did not prove recovery: %+v", got)
	}
	if pendingAccess.token != "different-active-token" {
		t.Fatal("old receipt retired a different active change")
	}
}

func TestAccessRollbackRejectsIncompleteSuccessfulTableResponses(t *testing.T) {
	for _, output := range []string{"", "table inet ols_wpanel_acce", `{}`, `{"nftables":null}`, `{"nftables":[`, `{"nftables":[{"table":{"family":"inet"}}]}`, `{"nftables":[{"chain":{"family":"inet","name":"input"}}]}`, `{"nftables":[{}]}`, `{"nftables":[{"table":{"family":"inet","name":"ols_wpanel_access"}},{"table":{"family":"inet","name":"ols_wpanel_access"}}]}`} {
		t.Run(output, func(t *testing.T) {
			accessChangeFixture(t, false)
			old := portCommand
			t.Cleanup(func() { portCommand = old })
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				if name == "systemctl" {
					return "LoadState=not-found\nActiveState=inactive", nil
				}
				if name == "nft" && strings.Join(args, " ") == "--json --stateless list tables" {
					return output, nil
				}
				t.Fatalf("unexpected command: %s %v", name, args)
				return "", errors.New("unexpected")
			}
			if got := inspectFirewallAccessChange(context.Background()); got.State != "error" || got.Error == "" || pendingAccess.token == "" {
				t.Fatalf("incomplete response became proof of absence: %+v", got)
			}
		})
	}
}

func TestAccessChangeReceiptUnknownInvalidAndFinalWriteFailureStayConservative(t *testing.T) {
	record := accessChangeFixture(t, false)
	if err := os.Remove(firewallAccessChangePath); err != nil {
		t.Fatal(err)
	}
	if got := inspectFirewallAccessChange(context.Background()); got.State != "unknown" {
		t.Fatalf("missing receipt reported completion: %+v", got)
	}
	if err := os.WriteFile(firewallAccessChangePath, []byte(`{"version":1,"change_id":"bad","state":"rolled_back"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := inspectFirewallAccessChange(context.Background()); got.State != "error" {
		t.Fatalf("corrupt receipt reported completion: %+v", got)
	}
	if err := os.Remove(firewallAccessChangePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(firewallAccessChangePath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveFirewallAccessChange(record); err == nil {
		t.Fatal("non-regular receipt was overwritten")
	}
	completeFirewallAccessChange("fixture-token")
	if got := inspectFirewallAccessChange(context.Background()); got.State != "error" {
		t.Fatalf("unreadable durable record claimed completion: %+v", got)
	}
}

func TestAccessApplyRecordsRecoveryBeforeWatchdogAndRefusesUnwritableReceipt(t *testing.T) {
	for _, failRecord := range []bool{false, true} {
		t.Run(map[bool]string{false: "recorded-before-apply", true: "receipt-failure-no-mutation"}[failRecord], func(t *testing.T) {
			record := accessChangeFixture(t, true)
			oldCmd, oldAvailable, oldLookup, oldDir, oldConfig := portCommand, accessSystemdAvailable, accessNftLookPath, accessRunDirectory, config.AppConfig
			t.Cleanup(func() {
				portCommand, accessSystemdAvailable, accessNftLookPath, accessRunDirectory, config.AppConfig = oldCmd, oldAvailable, oldLookup, oldDir, oldConfig
			})
			accessRunDirectory = t.TempDir()
			accessSystemdAvailable = func() bool { return true }
			accessNftLookPath = func(string) (string, error) { return "/fixture/nft", nil }
			config.AppConfig = &config.Config{Panel: config.PanelConfig{Port: 8443}}
			if failRecord {
				firewallAccessChangePath = filepath.Join(t.TempDir(), "missing-parent", "receipt.json")
			}
			applied, watchdog := false, false
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				command := name + " " + strings.Join(args, " ")
				switch command {
				case "nft --version":
					return "nftables v1.1.1", nil
				case "nft -a list chain inet filter input":
					return "type filter hook input priority filter; policy accept;", nil
				case "systemctl show nftables --property=ExecStart --value":
					return "/usr/sbin/nft -f /etc/nftables.conf", nil
				case "ss -H -lntup":
					return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*", nil
				case "sshd -T":
					return "port 22", nil
				case "nft --stateless list tables":
					return "table inet " + accessTable, nil
				case "nft --stateless list ruleset":
					return "fixture complete ruleset", nil
				case "nft --stateless list table inet " + accessTable:
					if applied {
						return "fixture new table", nil
					}
					return record.Previous, nil
				case "systemctl reset-failed " + accessRollbackUnit + ".service":
					return "", nil
				}
				if name == "systemctl" && args[0] == "is-active" {
					return "inactive", errors.New("inactive")
				}
				if name == "ufw" {
					return "", errors.New("unavailable")
				}
				if name == "nft" && len(args) == 3 && args[0] == "--check" {
					return "", nil
				}
				if name == "systemd-run" {
					stored, err := readFirewallAccessChange()
					if err != nil || stored.Previous != record.Previous || stored.State != "pending" || applied {
						t.Fatalf("watchdog lacked original snapshot: %+v %v", stored, err)
					}
					if !strings.Contains(command, "--on-active=90s") {
						t.Fatal("rollback interval changed")
					}
					watchdog = true
					return "", nil
				}
				if name == "nft" && len(args) == 2 && args[0] == "--file" {
					if !watchdog {
						t.Fatal("policy applied before watchdog")
					}
					applied = true
					return "", nil
				}
				t.Fatalf("unexpected apply command: %s", command)
				return "", errors.New("unexpected")
			}
			req := FirewallAccessRequest{Rules: []FirewallAccessRule{{Protocol: "tcp", Port: 22, Source: "203.0.113.5"}, {Protocol: "tcp", Port: 8443, Source: "203.0.113.5"}}}
			preview, err := PreviewFirewallAccess(req, "203.0.113.5")
			if err != nil {
				t.Fatal(err)
			}
			req.Fingerprint = preview.Fingerprint
			result, err := ApplyFirewallAccess(req, "203.0.113.5")
			if failRecord {
				if err == nil || watchdog || applied {
					t.Fatalf("receipt failure mutated policy: err=%v watchdog=%v applied=%v", err, watchdog, applied)
				}
				return
			}
			if err != nil || !applied || !watchdog || result.ChangeID != firewallAccessChangeID(result.ConfirmationToken) {
				t.Fatalf("incorrect tracked application: %+v %v", result, err)
			}
			stored, err := readFirewallAccessChange()
			if err != nil || stored.ID != result.ChangeID {
				t.Fatalf("receipt ID not correlated: %+v %v", stored, err)
			}
			data, _ := os.ReadFile(firewallAccessChangePath)
			if strings.Contains(string(data), result.ConfirmationToken) {
				t.Fatal("receipt leaked confirmation token")
			}
		})
	}
}

func TestAccessConfirmedReceiptRetainsSuccessfulSameChangeAfterRestart(t *testing.T) {
	record := accessChangeFixture(t, false)
	oldCmd, oldPersist, oldConfig := portCommand, persistAccessRules, config.AppConfig
	t.Cleanup(func() { portCommand, persistAccessRules, config.AppConfig = oldCmd, oldPersist, oldConfig })
	config.AppConfig = &config.Config{Panel: config.PanelConfig{Port: 8443}}
	pendingAccess.expected, pendingAccess.sshPort, pendingAccess.panelPort = "new table", 22, 8443
	pendingAccess.deadline = time.Now().Add(time.Minute)
	stopped, saved := false, false
	portCommand = func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "ss -H -lntup":
			return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*", nil
		case "sshd -T":
			return "port 22", nil
		case "nft --stateless list table inet " + accessTable:
			return "new table", nil
		case "systemctl is-enabled nftables":
			return "enabled", nil
		case "systemctl enable nftables":
			return "", nil
		case "systemctl stop " + accessRollbackUnit + ".timer " + accessRollbackUnit + ".service":
			stopped = true
			return "", nil
		}
		if name == "systemctl" && args[0] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		t.Fatalf("unexpected confirmation command: %s", command)
		return "", errors.New("unexpected")
	}
	persistAccessRules = func(context.Context) error {
		if !stopped {
			t.Fatal("policy persisted before stopping both rollback jobs")
		}
		saved = true
		return nil
	}
	if err := ConfirmFirewallAccess("fixture-token"); err != nil || !saved {
		t.Fatalf("confirmation failed: %v saved=%v", err, saved)
	}
	completedFirewallAccessChangeID = "" // Forget process memory as on restart.
	portCommand = func(context.Context, string, ...string) (string, error) {
		t.Fatal("completed receipt inspected or mutated services")
		return "", nil
	}
	if got := inspectFirewallAccessChange(context.Background()); got.ID != record.ID || got.State != "confirmed" {
		t.Fatalf("confirmed result lost correlation: %+v", got)
	}
}
