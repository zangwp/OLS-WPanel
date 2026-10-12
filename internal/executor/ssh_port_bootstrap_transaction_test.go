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
	for _, failReload := range []bool{false, true} {
		t.Run(strconv.FormatBool(failReload), func(t *testing.T) {
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
			original := "Port 22\nPasswordAuthentication no\n"
			if err := os.WriteFile(sshConfigPath, []byte(original), 0600); err != nil {
				t.Fatal(err)
			}
			sshSystemdAvailable = func() bool { return true }
			present, armed, saved, restored := false, false, false, false
			table := ""
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
					if strings.HasPrefix(joined, "reload") && failReload {
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
						return sshBootstrapTestChain(), nil
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
					if len(args) == 2 && args[0] == "--file" {
						data, err := os.ReadFile(args[1])
						if err != nil {
							t.Fatal(err)
						}
						if strings.HasSuffix(args[1], "dual.nft") || strings.HasSuffix(args[1], "final.nft") {
							if !armed {
								t.Fatal("policy changed without an independent rollback")
							}
							if strings.HasSuffix(args[1], "dual.nft") && strings.Contains(string(data), "delete table") {
								t.Fatal("first migration tried to replace an absent policy table")
							}
							table, present = string(data), true
						}
					}
					return "", nil
				case "systemd-run":
					if present || !strings.Contains(joined, "--on-active=300s") {
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
			change, err := BeginSSHPortChange(2222, "203.0.113.5")
			if failReload {
				if err == nil || !restored || present || saved || armed {
					t.Fatalf("failed bootstrap did not restore original state: %+v %v", change, err)
				}
				return
			}
			if err != nil || !armed || !present || !strings.Contains(table, "ip saddr 203.0.113.0/24 tcp dport 2222") {
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
			if strings.Contains(table, "tcp dport 22 counter") {
				t.Fatal("confirmed policy retained the old SSH allow entry")
			}
		})
	}
}
