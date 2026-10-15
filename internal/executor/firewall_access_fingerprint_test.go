package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

type accessFingerprintState struct {
	owned, external string
	ssh, panel      int
	writes, timers  int
	saved           bool
}

func newAccessFingerprintFixture(t *testing.T, exists bool) *accessFingerprintState {
	t.Helper()
	oldCommand, oldAvailable, oldLookup, oldRun, oldPersist := portCommand, accessSystemdAvailable, accessNftLookPath, accessRunDirectory, persistAccessRules
	oldConfig, oldPath, oldPending := config.AppConfig, firewallAccessChangePath, pendingAccess
	oldProtection, oldDeadline := pendingProtectionToken, pendingProtectionDeadline
	t.Cleanup(func() {
		portCommand, accessSystemdAvailable, accessNftLookPath, accessRunDirectory, persistAccessRules = oldCommand, oldAvailable, oldLookup, oldRun, oldPersist
		config.AppConfig, firewallAccessChangePath, pendingAccess = oldConfig, oldPath, oldPending
		pendingProtectionToken, pendingProtectionDeadline = oldProtection, oldDeadline
	})
	state := &accessFingerprintState{ssh: 22, panel: 8443, external: "table ip olswpanel_persist { set ssh_limit { type ipv4_addr; flags dynamic,timeout; timeout 1m; elements = { 198.51.100.1 } } }"}
	if exists {
		state.owned = accessRulesScript([]FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}}, false)
	}
	config.AppConfig = &config.Config{Panel: config.PanelConfig{Port: 8443}}
	accessSystemdAvailable = func() bool { return true }
	accessNftLookPath = func(string) (string, error) { return "/fixture/nft", nil }
	accessRunDirectory = t.TempDir()
	firewallAccessChangePath = filepath.Join(t.TempDir(), "access-change.json")
	pendingAccess.token, pendingProtectionToken = "", ""
	portCommand = func(_ context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch command {
		case "nft --version":
			return "nftables v1.1.3", nil
		case "nft -a list chain inet filter input":
			return "type filter hook input priority filter; policy drop;", nil
		case "systemctl show nftables --property=ExecStart --value":
			return "/usr/sbin/nft -f " + nftablesConfigPath, nil
		case "ss -H -lntup":
			return fmt.Sprintf("tcp LISTEN 0 128 0.0.0.0:%d 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:%d 0.0.0.0:*", state.ssh, state.panel), nil
		case "sshd -T":
			return fmt.Sprintf("port %d", state.ssh), nil
		case "nft --stateless list tables":
			if state.owned == "" {
				return "table inet filter", nil
			}
			return "table inet filter\ntable inet " + accessTable, nil
		case "nft --stateless list table inet " + accessTable:
			return state.owned, nil
		case "nft --stateless list ruleset":
			return state.owned + "\n" + state.external, nil
		case "systemctl is-enabled nftables":
			return "enabled", nil
		case "systemctl enable nftables", "systemctl reset-failed " + accessRollbackUnit + ".service":
			return "", nil
		}
		if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		if name == "ufw" {
			return "inactive", nil
		}
		if name == "nft" && len(args) == 3 && args[0] == "--check" {
			return "", nil
		}
		if name == "systemd-run" {
			record, err := readFirewallAccessChange()
			if err != nil || record.State != "pending" || state.writes != 0 || !strings.Contains(command, "--on-active=90s") {
				t.Fatalf("first-use protection was not staged before mutation: %+v %v", record, err)
			}
			state.timers++
			return "", nil
		}
		if name == "nft" && len(args) == 2 && args[0] == "--file" {
			data, err := os.ReadFile(args[1])
			state.owned = string(data)
			state.writes++
			return "", err
		}
		t.Fatalf("unexpected access command: %s", command)
		return "", errors.New("unexpected")
	}
	persistAccessRules = func(context.Context) error { state.saved = true; return nil }
	return state
}

func accessPreviewRoundTrip(t *testing.T, rules []FirewallAccessRule) (FirewallAccessPreview, FirewallAccessRequest) {
	t.Helper()
	preview, err := PreviewFirewallAccess(FirewallAccessRequest{Rules: rules}, "203.0.113.5")
	if err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(map[string]any{"success": true, "data": preview})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct{ Data FirewallAccessPreview }
	if err := json.Unmarshal(response, &decoded); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"rules": rules, "fingerprint": decoded.Data.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	var request FirewallAccessRequest
	if err := json.Unmarshal(body, &request); err != nil || request.Fingerprint == "" {
		t.Fatalf("preview fingerprint was lost through the API JSON contract: %v", err)
	}
	return preview, request
}

func TestAccessPreviewIgnoresIndependentBanAndRateLimitUpdates(t *testing.T) {
	for _, external := range []struct{ name, table string }{
		{"ban added", "table inet f2b-table { set addr-set-sshd { type ipv4_addr; elements = { 198.51.100.1, 198.51.100.2 } } }"},
		{"ban removed", "table inet f2b-table { set addr-set-sshd { type ipv4_addr; } }"},
		{"rate limit timeout changed", "table ip olswpanel_persist { set ssh_limit { type ipv4_addr; flags dynamic,timeout; timeout 1m; elements = { 198.51.100.1 expires 43s } } }"},
	} {
		for _, exists := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", external.name, exists), func(t *testing.T) {
				state := newAccessFingerprintFixture(t, exists)
				rules := []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 2212}}
				preview, request := accessPreviewRoundTrip(t, rules)
				if !strings.Contains(preview.ExistingRules, "ssh_limit") {
					t.Fatal("complete ruleset was omitted from the informational preview")
				}
				state.external = external.table
				result, err := ApplyFirewallAccess(request, "203.0.113.5")
				if err != nil || state.writes != 1 {
					t.Fatalf("unrelated live set update rejected the unchanged selection: %+v %v", result, err)
				}
				if exists {
					if !result.Saved || !state.saved || result.RequiresConfirmation || state.timers != 0 {
						t.Fatalf("ordinary port save did not finish immediately: %+v %+v", result, state)
					}
				} else if result.Saved || state.saved || !result.RequiresConfirmation || result.ConfirmationToken == "" || state.timers != 1 {
					t.Fatalf("first-use confirmation or rollback was bypassed: %+v %+v", result, state)
				}
			})
		}
	}
}

func TestAccessPreviewStillRejectsChangesBeforeAnyMutation(t *testing.T) {
	for _, name := range []string{"owned policy", "owned table removed", "owned table created", "selection", "SSH endpoint", "panel endpoint", "missing fingerprint"} {
		t.Run(name, func(t *testing.T) {
			state := newAccessFingerprintFixture(t, name != "owned table created")
			rules := []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 2212}, {Protocol: "tcp", Port: 2222}, {Protocol: "tcp", Port: 9443}}
			_, request := accessPreviewRoundTrip(t, rules)
			switch name {
			case "owned policy":
				state.owned = strings.Replace(state.owned, "ct state established", "tcp dport 80 drop\nct state established", 1)
			case "owned table removed":
				state.owned = ""
			case "owned table created":
				state.owned = accessRulesScript(rules, false)
			case "selection":
				request.Rules[2].Port = 2213
			case "SSH endpoint":
				state.ssh = 2222
			case "panel endpoint":
				state.panel, config.AppConfig.Panel.Port = 9443, 9443
			case "missing fingerprint":
				request.Fingerprint = ""
			}
			_, err := ApplyFirewallAccess(request, "203.0.113.5")
			if !errors.Is(err, ErrFirewallAccessPreviewChanged) || state.writes != 0 || state.timers != 0 || state.saved {
				t.Fatalf("changed preview was not rejected before mutation: %v %+v", err, state)
			}
			if _, err := os.Stat(firewallAccessChangePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("stale preview created a rollback receipt: %v", err)
			}
		})
	}
}

func TestAccessPreviewNormalizesEquivalentDraftSelections(t *testing.T) {
	state := newAccessFingerprintFixture(t, true)
	rules := []FirewallAccessRule{{Protocol: "TCP", Port: 2212, Source: "203.0.113.5"}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 22}}
	_, request := accessPreviewRoundTrip(t, rules)
	request.Rules = []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 2212, Source: "203.0.113.5/32"}, {Protocol: "tcp", Port: 2212, Source: "203.0.113.5/32"}}
	result, err := ApplyFirewallAccess(request, "203.0.113.5")
	if err != nil || !result.Saved || !state.saved || state.writes != 1 {
		t.Fatalf("equivalent order, protocol case or duplicate selection changed the fingerprint: %+v %v", result, err)
	}
}
