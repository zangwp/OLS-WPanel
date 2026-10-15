package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the public confirmation caller, including the systemd missing-unit
// behavior which a successful generic command fixture previously concealed.
func TestSSHConfirmationAcceptsCollectedRollbackService(t *testing.T) {
	oldMove, oldConfig, oldJail := sshMove, sshConfigPath, sshJailPath
	oldCommand, oldPersist := portCommand, persistAccessRules
	t.Cleanup(func() {
		sshMove, sshConfigPath, sshJailPath = oldMove, oldConfig, oldJail
		portCommand, persistAccessRules = oldCommand, oldPersist
	})
	dir := t.TempDir()
	sshConfigPath, sshJailPath = filepath.Join(dir, "sshd_config"), filepath.Join(dir, "jail")
	dual, final := "Port 22\nPort 2111\n", "Port 2111\n"
	for path, data := range map[string]string{
		sshConfigPath: dual, filepath.Join(dir, "final"): final,
		filepath.Join(dir, "verified"): "verified-token", filepath.Join(dir, "pending"): "verified-token",
	} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	sshMove.SSHPortChange = SSHPortChange{Token: "verified-token", OldPort: 22, NewPort: 2111, Deadline: time.Now().Add(time.Minute)}
	sshMove.dir, sshMove.service, sshMove.expectedConfig, sshMove.expectedTable = dir, "ssh.service", dual, "dual policy"
	table, stopped, persisted, rolledBack := "dual policy", map[string]bool{}, false, false
	portCommand = func(_ context.Context, name string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch name {
		case "nft":
			if len(args) == 2 && args[0] == "--file" {
				table = "final policy"
				return "", nil
			}
			return table, nil
		case "/usr/sbin/sshd":
			return "port 2111\nlistenaddress 0.0.0.0:2111\n", nil
		case "ss":
			return "tcp LISTEN 0 128 0.0.0.0:2111 0.0.0.0:* users:((\"sshd\",pid=10,fd=3))", nil
		case "/bin/sh":
			rolledBack = true
			return "", nil
		case "systemctl":
			if len(args) > 0 && args[0] == "stop" {
				for _, unit := range args[1:] {
					stopped[unit] = true
				}
				if strings.Contains(joined, sshMoveUnit+".service") {
					return "Unit not loaded", errors.New("exit status 5")
				}
				return "", nil
			}
			if len(args) > 0 && args[0] == "show" {
				return "LoadState=not-found\nActiveState=inactive\nResult=success\nJob=", nil
			}
			if len(args) > 0 && args[0] == "is-active" {
				return "inactive", errors.New("inactive")
			}
			return "", nil
		default:
			return "", fmt.Errorf("unexpected command: %s %v", name, args)
		}
	}
	persistAccessRules = func(context.Context) error {
		if !stopped[sshMoveUnit+".timer"] || !stopped[sshMoveUnit+".service"] {
			t.Fatal("persisted before cancelling both rollback units")
		}
		persisted = true
		return nil
	}
	if err := ConfirmSSHPortChange("verified-token"); err != nil || !persisted || rolledBack || sshMove.Token != "" {
		t.Fatalf("collected service falsely aborted a verified SSH migration: error=%v persisted=%t rolledBack=%t", err, persisted, rolledBack)
	}
}

func TestSSHConfirmationNeverPersistsUnsettledRollbackOrChangedState(t *testing.T) {
	for _, sample := range []string{"active", "queued", "unreadable", "missing_job", "failed_result", "config_changed_during_stop", "policy_changed_during_stop", "listener_changed_during_stop", "rollback_failure"} {
		t.Run(sample, func(t *testing.T) {
			oldMove, oldConfig, oldJail := sshMove, sshConfigPath, sshJailPath
			oldCommand, oldPersist := portCommand, persistAccessRules
			t.Cleanup(func() {
				sshMove, sshConfigPath, sshJailPath = oldMove, oldConfig, oldJail
				portCommand, persistAccessRules = oldCommand, oldPersist
			})
			dir := t.TempDir()
			sshConfigPath, sshJailPath = filepath.Join(dir, "sshd_config"), filepath.Join(dir, "jail")
			original, dual, final := "Port 22\n", "Port 22\nPort 2111\n", "Port 2111\n"
			for path, data := range map[string]string{
				sshConfigPath: dual, filepath.Join(dir, "original"): original, filepath.Join(dir, "final"): final,
				filepath.Join(dir, "verified"): "verified-token", filepath.Join(dir, "pending"): "verified-token",
			} {
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			sshMove.SSHPortChange = SSHPortChange{Token: "verified-token", OldPort: 22, NewPort: 2111, Deadline: time.Now().Add(time.Minute)}
			sshMove.dir, sshMove.service, sshMove.expectedConfig, sshMove.expectedTable = dir, "ssh.service", dual, "dual policy"
			table, stopped, rollbackCount, persistCount := "dual policy", false, 0, 0
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				switch name {
				case "nft":
					if len(args) == 2 && args[0] == "--file" {
						table = "final policy"
						return "", nil
					}
					return table, nil
				case "/usr/sbin/sshd":
					return "port 2111\nlistenaddress 0.0.0.0:2111\n", nil
				case "ss":
					port := 2111
					if stopped && sample == "listener_changed_during_stop" {
						port = 22
					}
					return fmt.Sprintf("tcp LISTEN 0 128 0.0.0.0:%d 0.0.0.0:* users:((\"sshd\",pid=10,fd=3))", port), nil
				case "/bin/sh":
					rollbackCount++
					if sample == "rollback_failure" {
						return "fixture restore failed", errors.New("failed")
					}
					table = "original policy"
					if err := os.WriteFile(sshConfigPath, []byte(original), 0600); err != nil {
						t.Fatal(err)
					}
					return "", os.Remove(filepath.Join(dir, "pending"))
				case "systemctl":
					if args[0] == "is-active" {
						return "inactive", errors.New("inactive")
					}
					if args[0] == "stop" {
						stopped = true
						if sample == "config_changed_during_stop" {
							if err := os.WriteFile(sshConfigPath, []byte(original), 0600); err != nil {
								t.Fatal(err)
							}
						}
						if sample == "policy_changed_during_stop" {
							table = "original policy"
						}
						return "Unit not loaded", errors.New("exit status 5")
					}
					if args[0] == "show" {
						switch sample {
						case "active":
							return "LoadState=loaded\nActiveState=active\nResult=success\nJob=", nil
						case "queued":
							return "LoadState=loaded\nActiveState=inactive\nResult=success\nJob=123", nil
						case "unreadable":
							return "", errors.New("D-Bus unavailable")
						case "missing_job":
							return "LoadState=not-found\nActiveState=inactive\nResult=success", nil
						case "failed_result":
							return "LoadState=loaded\nActiveState=failed\nResult=exit-code\nJob=", nil
						}
						return "LoadState=not-found\nActiveState=inactive\nResult=success\nJob=0", nil
					}
					return "", nil
				default:
					t.Fatalf("unexpected command %s %v", name, args)
					return "", nil
				}
			}
			persistAccessRules = func(context.Context) error {
				persistCount++
				if sample != "rollback_failure" {
					t.Fatal("unsafe final state reached persistence")
				}
				return errors.New("fixture persistence failed")
			}
			err := ConfirmSSHPortChange("verified-token")
			if err == nil || rollbackCount != 1 || sshMove.Token != "" || sshMove.ChangeID == "" || sshMove.changeState != "error" {
				t.Fatalf("abort lost its observation identity or retained a usable token: %v rollback=%d token=%q", err, rollbackCount, sshMove.Token)
			}
			if sample != "rollback_failure" && persistCount != 0 {
				t.Fatal("unverified state was persisted")
			}
			if sample == "rollback_failure" {
				if _, err := os.Stat(filepath.Join(dir, "pending")); err != nil {
					t.Fatal("failed recovery lost pending evidence", err)
				}
			}
			if err := ConfirmSSHPortChange("verified-token"); err == nil {
				t.Fatal("aborted token was accepted for retry")
			}
		})
	}
}

func TestSSHStatusOnlyReportsProvenMatchingTerminalOutcome(t *testing.T) {
	for _, sample := range []string{"rolled_back", "rolled_back_without_table", "confirmed", "auto_rollback", "pending", "pending_without_watchdog", "unknown_after_restart", "unreadable_task", "queued_task", "missing_marker_but_wrong_config", "wrong_policy", "wrong_listener", "two_listeners", "unreadable_snapshot", "previously_rolled_back_external_change"} {
		t.Run(sample, func(t *testing.T) {
			oldMove, oldConfig, oldCommand := sshMove, sshConfigPath, portCommand
			t.Cleanup(func() { sshMove, sshConfigPath, portCommand = oldMove, oldConfig, oldCommand })
			dir := t.TempDir()
			sshConfigPath = filepath.Join(dir, "sshd_config")
			original, final := "Port 22\n", "Port 2111\n"
			for path, data := range map[string]string{
				sshConfigPath: original, filepath.Join(dir, "original"): original, filepath.Join(dir, "final"): final,
				filepath.Join(dir, "restore.nft"): "add table inet " + accessTable + "\ndelete table inet " + accessTable + "\noriginal policy\n",
			} {
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			sshMove.SSHPortChange = SSHPortChange{OldPort: 22, NewPort: 2111, ChangeID: sshPortChangeID("retired-token")}
			sshMove.dir, sshMove.changeState = dir, "error"
			table, port := "original policy", 22
			if sample == "confirmed" {
				sshMove.changeState, sshMove.confirmedTable, table, port = "confirmed", "final policy", "final policy", 2111
				if err := os.WriteFile(sshConfigPath, []byte(final), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if sample == "auto_rollback" {
				sshMove.changeState, sshMove.Token = "pending", "retired-token"
			}
			if sample == "rolled_back_without_table" {
				table = ""
				if err := os.WriteFile(filepath.Join(dir, "restore.nft"), []byte("add table inet "+accessTable+"\ndelete table inet "+accessTable+"\n\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if sample == "previously_rolled_back_external_change" {
				sshMove.changeState, table, port = "rolled_back", "later administrative policy", 2111
				if err := os.WriteFile(sshConfigPath, []byte(final), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if sample == "pending" || sample == "pending_without_watchdog" {
				sshMove.changeState, sshMove.Token = "pending", "retired-token"
				if err := os.WriteFile(filepath.Join(dir, "pending"), []byte("retired-token"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if sample == "unknown_after_restart" {
				sshMove.ChangeID = ""
			}
			if sample == "missing_marker_but_wrong_config" {
				if err := os.WriteFile(sshConfigPath, []byte(final), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if sample == "wrong_policy" {
				table = "external policy"
			}
			if sample == "wrong_listener" {
				port = 2111
			}
			if sample == "unreadable_snapshot" {
				if err := os.Remove(filepath.Join(dir, "original")); err != nil {
					t.Fatal(err)
				}
			}
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				if name == "systemctl" && args[0] == "show" {
					if sample == "unreadable_task" {
						return "", errors.New("D-Bus unavailable")
					}
					if sample == "pending" {
						return "LoadState=loaded\nActiveState=active\nResult=success\nJob=", nil
					}
					if sample == "queued_task" {
						return "LoadState=loaded\nActiveState=inactive\nResult=success\nJob=51", nil
					}
					return "LoadState=not-found\nActiveState=inactive\nResult=success\nJob=", nil
				}
				if name == "nft" && strings.Join(args, " ") == "--json --stateless list tables" {
					if table == "" {
						return `{"nftables":[]}`, nil
					}
					return fmt.Sprintf(`{"nftables":[{"table":{"family":"inet","name":%q}}]}`, accessTable), nil
				}
				if name == "nft" && strings.Join(args, " ") == "--stateless list table inet "+accessTable {
					return table, nil
				}
				t.Fatalf("status attempted a mutation or unexpected command: %s %v", name, args)
				return "", nil
			}
			listeners := []FirewallListener{{Protocol: "tcp", Port: port, Process: "sshd"}}
			if sample == "two_listeners" {
				listeners = append(listeners, FirewallListener{Protocol: "tcp", Port: 2111, Process: "sshd"})
			}
			status := SSHPortStatus{Port: 22, ChangeID: sshMove.ChangeID, ChangeState: "unknown"}
			err := observeSSHPortChange(context.Background(), listeners, &status)
			switch sample {
			case "rolled_back", "rolled_back_without_table", "auto_rollback", "confirmed":
				want := "rolled_back"
				if sample == "confirmed" {
					want = "confirmed"
				}
				if err != nil || status.Pending || status.ChangeState != want || status.ChangeID == "" || status.Port != port {
					t.Fatalf("proven terminal outcome lost: %+v %v", status, err)
				}
			case "pending":
				if err != nil || !status.Pending || status.ChangeState != "pending" {
					t.Fatalf("retryable pending transaction lost: %+v %v", status, err)
				}
			case "unknown_after_restart":
				if status.ChangeID != "" || status.ChangeState != "unknown" {
					t.Fatalf("restart fabricated another process's receipt: %+v", status)
				}
			case "previously_rolled_back_external_change":
				if err != nil || status.Pending || status.ChangeState != "unknown" {
					t.Fatalf("a proven old receipt froze a later administrative change: %+v %v", status, err)
				}
			default:
				if !status.Pending || status.ChangeState == "confirmed" || status.ChangeState == "rolled_back" {
					t.Fatalf("unproven outcome reported terminal: %+v %v", status, err)
				}
			}
		})
	}
}

func TestSSHStatusDoesNotMistakeUnreadableTaskForNoMigration(t *testing.T) {
	oldMove, oldCommand := sshMove, portCommand
	t.Cleanup(func() { sshMove, portCommand = oldMove, oldCommand })
	sshMove.SSHPortChange = SSHPortChange{}
	portCommand = func(_ context.Context, name string, args ...string) (string, error) {
		switch name {
		case "ss":
			return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=10,fd=3))", nil
		case "sshd":
			return "port 22\n", nil
		case "systemctl":
			if args[0] == "show" {
				return "", errors.New("D-Bus unavailable")
			}
		}
		t.Fatalf("status inspected beyond unproven rollback state: %s %v", name, args)
		return "", nil
	}
	status := GetSSHPortStatus()
	if status.Available || !status.Pending || status.ChangeState != "unknown" || !strings.Contains(status.Reason, "SSH") {
		t.Fatalf("unreadable task became an available port migration: %+v", status)
	}
}
