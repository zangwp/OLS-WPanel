package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestSSHMigrationBootstrapsStrictPolicyAndRollsBackAbsentTable(t *testing.T) {
	for _, sample := range []struct {
		name                                     string
		existing, reverse, failReload, failCheck bool
		pendingUnit                              string
		queued, unreadable                       bool
	}{{name: "new_table"}, {name: "existing_table", existing: true}, {name: "restore_port_22", existing: true, reverse: true}, {name: "reload_failure", failReload: true}, {name: "final_preflight_failure", failCheck: true},
		{name: "active access rollback service", pendingUnit: accessRollbackUnit + ".service"},
		{name: "active legacy rollback service", pendingUnit: firewallRollbackUnit + ".service"},
		{name: "queued legacy rollback", pendingUnit: firewallRollbackUnit + ".service", queued: true},
		{name: "unreadable access rollback", pendingUnit: accessRollbackUnit + ".service", unreadable: true}} {
		t.Run(sample.name, func(t *testing.T) {
			oldConfig, oldJail, oldRun, oldDefaults := sshConfigPath, sshJailPath, sshMoveRunDirectory, sshDefaultsPath
			oldCommand, oldAvailable, oldPersist, oldMove := portCommand, sshSystemdAvailable, persistAccessRules, sshMove
			oldPanelConfig := config.AppConfig
			t.Cleanup(func() {
				sshConfigPath, sshJailPath, sshMoveRunDirectory, sshDefaultsPath = oldConfig, oldJail, oldRun, oldDefaults
				portCommand, sshSystemdAvailable, persistAccessRules, sshMove = oldCommand, oldAvailable, oldPersist, oldMove
				config.AppConfig = oldPanelConfig
			})
			dir := t.TempDir()
			sshConfigPath, sshJailPath = filepath.Join(dir, "sshd_config"), filepath.Join(dir, "jail.local")
			sshMoveRunDirectory, sshDefaultsPath = dir, filepath.Join(dir, "defaults")
			config.AppConfig = &config.Config{Panel: config.PanelConfig{Port: 8443}}
			oldPort, newPort := 22, 2222
			if sample.reverse {
				oldPort, newPort = newPort, oldPort
			}
			original := fmt.Sprintf("Port %d\nPasswordAuthentication no\n", oldPort)
			baseChain := strings.Replace(sshBootstrapTestChain(), "tcp dport 22 counter", fmt.Sprintf("tcp dport %d counter", oldPort), 1)
			if err := os.WriteFile(sshConfigPath, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			sshSystemdAvailable = func() bool { return true }
			present, armed, saved, restored := sample.existing, false, false, false
			initial := ""
			if sample.existing {
				rules, err := sshBootstrapAccessRules(baseChain, oldPort, 8443)
				if err != nil {
					t.Fatal(err)
				}
				initial = accessRulesScript(rules, false)
			}
			table := initial
			checked := map[string]bool{}
			ports := func(path string) []int {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				result := []int{}
				for _, line := range strings.Split(string(data), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 2 && fields[0] == "Port" {
						port, _ := strconv.Atoi(fields[1])
						result = append(result, port)
					}
				}
				return result
			}
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				switch name {
				case "ss":
					var output strings.Builder
					for _, port := range ports(sshConfigPath) {
						fmt.Fprintf(&output, "tcp LISTEN 0 128 0.0.0.0:%d 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n", port)
					}
					output.WriteString("tcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:((\"ols-wpanel\",pid=2,fd=4))\n")
					return output.String(), nil
				case "sshd", "/usr/sbin/sshd":
					path := sshConfigPath
					for i, argument := range args {
						if argument == "-f" {
							path = args[i+1]
						}
					}
					var output strings.Builder
					for _, port := range ports(path) {
						fmt.Fprintf(&output, "port %d\nlistenaddress 0.0.0.0:%d\n", port, port)
					}
					return output.String(), nil
				case "getenforce":
					return "Disabled", nil
				case "ufw":
					return "inactive", nil
				case "systemctl":
					if strings.HasPrefix(joined, "show") && strings.Contains(joined, "--property=LoadState") {
						if len(args) > 1 && args[1] == sample.pendingUnit {
							if sample.unreadable {
								return "", errors.New("fixture unit read failed")
							}
							if sample.queued {
								return "LoadState=loaded\nActiveState=inactive\nResult=success\nJob=123", nil
							}
							return "LoadState=loaded\nActiveState=active\nResult=success\nJob=", nil
						}
						return "LoadState=not-found\nActiveState=inactive\nResult=success\nJob=", nil
					}
					if strings.HasPrefix(joined, "is-active") {
						if strings.HasSuffix(joined, "ssh.service") || (armed && strings.HasSuffix(joined, sshMoveUnit+".timer")) {
							return "active", nil
						}
						return "inactive", errors.New("inactive")
					}
					if joined == "is-enabled nftables" {
						return "enabled", nil
					}
					if strings.HasPrefix(joined, "is-enabled") {
						return "disabled", errors.New("disabled")
					}
					if strings.Contains(joined, "--property=ExecStart") {
						if strings.Contains(joined, "nftables") {
							return "/usr/sbin/nft -f " + nftablesConfigPath, nil
						}
						return "/usr/sbin/sshd -D", nil
					}
					if strings.HasPrefix(joined, "reload") && sample.failReload {
						return "fixture reload failure", errors.New("reload failed")
					}
					if strings.HasPrefix(joined, "stop") {
						armed = false
					}
					return "", nil
				case "nft":
					if joined == "--stateless list tables" {
						if present {
							return "table inet filter\ntable inet " + accessTable, nil
						}
						return "table inet filter", nil
					}
					if joined == "--stateless list chain inet filter input" {
						return baseChain, nil
					}
					if joined == "--stateless list table inet "+accessTable {
						if !present {
							t.Fatal("migration read an absent access table")
						}
						return table, nil
					}
					if strings.Contains(joined, "list chain") {
						return "type filter hook input priority filter; policy drop;", nil
					}
					if len(args) == 3 && args[0] == "--check" && args[1] == "--file" {
						data, err := os.ReadFile(args[2])
						if err != nil {
							t.Fatal(err)
						}
						name := filepath.Base(args[2])
						checked[name] = true
						// A checked transaction can see its own newly created table,
						// but must leave the host state unchanged for the next check.
						next := present
						for _, line := range strings.Split(string(data), "\n") {
							if line == "delete table inet "+accessTable {
								if !next {
									return "No such file or directory: access table does not exist", errors.New("missing table")
								}
								next = false
							}
							if line == "table inet "+accessTable+" {" {
								next = true
							}
						}
						if name == "final-check.nft" {
							dual, _ := os.ReadFile(filepath.Join(filepath.Dir(args[2]), "dual.nft"))
							final, _ := os.ReadFile(filepath.Join(filepath.Dir(args[2]), "final.nft"))
							if string(data) != string(dual)+string(final) || !next {
								t.Fatal("final preflight did not validate the staged policy followed by its replacement")
							}
							if sample.failCheck {
								return "fixture final policy failure", errors.New("invalid final policy")
							}
						}
						return "", nil
					}
					if len(args) == 2 && args[0] == "--file" {
						data, err := os.ReadFile(args[1])
						if err != nil {
							t.Fatal(err)
						}
						if strings.HasSuffix(args[1], "dual.nft") || strings.HasSuffix(args[1], "final.nft") {
							if !armed {
								t.Fatal("policy changed without an independent rollback")
							}
							if !present && strings.Contains(string(data), "delete table") {
								t.Fatal("first migration tried to replace an absent policy table")
							}
							table, present = string(data), true
						}
					}
					return "", nil
				case "systemd-run":
					if present != sample.existing || !checked["dual.nft"] || !checked["final-check.nft"] || !checked["allow.nft"] || !strings.Contains(joined, "--on-active=300s") {
						t.Fatal("rollback was not armed before creating the policy")
					}
					armed = true
					return "", nil
				case "/bin/sh":
					if len(args) != 1 || !strings.HasSuffix(args[0], "rollback.sh") {
						t.Fatal("unexpected script", args)
					}
					restoreFile, err := os.ReadFile(filepath.Join(filepath.Dir(args[0]), "restore.nft"))
					if err != nil || string(restoreFile) != "add table inet "+accessTable+"\ndelete table inet "+accessTable+"\n\n" {
						t.Fatalf("rollback did not restore absence: %q %v", restoreFile, err)
					}
					present, restored, table = false, true, ""
					return "", os.WriteFile(sshConfigPath, []byte(original), 0600)
				}
				t.Fatalf("unexpected host command: %s %s", name, joined)
				return "", errors.New("unexpected")
			}
			persistAccessRules = func(context.Context) error {
				if armed || !present {
					t.Fatal("persisted without a confirmed policy or before stopping rollback")
				}
				saved = true
				return nil
			}
			if status := GetSSHPortStatus(); !status.Available {
				t.Fatalf("normal installer policy still requires a separate policy toggle: %+v", status)
			}
			change, err := BeginSSHPortChange(newPort, "203.0.113.5")
			if sample.pendingUnit != "" {
				current, readErr := os.ReadFile(sshConfigPath)
				if err == nil || !strings.Contains(err.Error(), "请先完成其他防火墙变更") || readErr != nil || string(current) != original || armed || saved || restored || present != sample.existing || table != initial {
					t.Fatalf("SSH migration ignored a running, queued or unreadable rollback: %+v %v", change, err)
				}
				return
			}
			if sample.failCheck {
				current, readErr := os.ReadFile(sshConfigPath)
				if err == nil || !strings.Contains(err.Error(), "fixture final policy failure") || readErr != nil || string(current) != original || armed || saved || restored || present {
					t.Fatalf("failed preflight changed the original state: %+v %v", change, err)
				}
				entries, readErr := os.ReadDir(dir)
				if readErr != nil || len(entries) != 1 || entries[0].Name() != "sshd_config" {
					t.Fatalf("failed preflight left transaction files: %v %v", entries, readErr)
				}
				return
			}
			if sample.failReload {
				if err == nil || !restored || present || saved || armed {
					t.Fatalf("failed bootstrap did not restore original state: %+v %v", change, err)
				}
				return
			}
			if err != nil || !armed || !present || change.OldPort != oldPort || change.NewPort != newPort || !strings.Contains(table, fmt.Sprintf("ip saddr 203.0.113.0/24 tcp dport %d ", newPort)) {
				t.Fatalf("migration did not preserve SSH sources: %+v %v", change, err)
			}
			if err := ConfirmSSHPortChange(change.Token); err == nil {
				t.Fatal("bootstrap bypassed new-connection verification")
			}
			if err := os.WriteFile(filepath.Join(sshMove.dir, "verified"), []byte(change.Token), 0600); err != nil {
				t.Fatal(err)
			}
			if err := ConfirmSSHPortChange(change.Token); err != nil || !saved || armed || !present || restored {
				t.Fatalf("verified bootstrap did not save: %v", err)
			}
			if strings.Contains(table, fmt.Sprintf("tcp dport %d counter", oldPort)) {
				t.Fatal("confirmed policy retained the old SSH allow entry")
			}
			finalPorts := ports(sshConfigPath)
			jail, readErr := os.ReadFile(sshJailPath)
			if len(finalPorts) != 1 || finalPorts[0] != newPort || readErr != nil || string(jail) != sshJailConfig(strconv.Itoa(newPort)) {
				t.Fatalf("confirmed migration retained the old SSH listener or Fail2ban port: %v %q %v", finalPorts, jail, readErr)
			}
		})
	}
}
