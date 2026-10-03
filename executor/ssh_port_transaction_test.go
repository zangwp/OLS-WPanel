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
)

func TestSSHPortTransaction(t *testing.T) {
	for _, failReload := range []bool{false, true} {
		t.Run(fmt.Sprintf("reload_failure_%v", failReload), func(t *testing.T) {
			oldConfig, oldJail, oldRun, oldDefaults := sshConfigPath, sshJailPath, sshMoveRunDirectory, sshDefaultsPath
			oldCmd, oldAvailable, oldPersist, oldMove := portCommand, sshSystemdAvailable, persistAccessRules, sshMove
			defer func() {
				sshConfigPath = oldConfig
				sshJailPath = oldJail
				sshMoveRunDirectory = oldRun
				sshDefaultsPath = oldDefaults
				portCommand = oldCmd
				sshSystemdAvailable = oldAvailable
				persistAccessRules = oldPersist
				sshMove = oldMove
			}()
			dir := t.TempDir()
			sshConfigPath = filepath.Join(dir, "sshd_config")
			sshJailPath = filepath.Join(dir, "jail.local")
			sshMoveRunDirectory = dir
			sshDefaultsPath = filepath.Join(dir, "defaults")
			original := "Port 22\nPasswordAuthentication no\n"
			if e := os.WriteFile(sshConfigPath, []byte(original), 0600); e != nil {
				t.Fatal(e)
			}
			initial := accessRulesScript([]FirewallAccessRule{{"tcp", 22, ""}, {"tcp", 8443, ""}, {"tcp", 443, ""}}, false)
			table := initial
			armed, saved, restored := false, false, false
			sshSystemdAvailable = func() bool { return true }
			ports := func(path string) []int {
				data, _ := os.ReadFile(path)
				var out []int
				for _, l := range strings.Split(string(data), "\n") {
					f := strings.Fields(l)
					if len(f) == 2 && f[0] == "Port" {
						n, _ := strconv.Atoi(f[1])
						out = append(out, n)
					}
				}
				return out
			}
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				switch name {
				case "ss":
					var b strings.Builder
					for _, p := range ports(sshConfigPath) {
						fmt.Fprintf(&b, "tcp LISTEN 0 128 0.0.0.0:%d 0.0.0.0:* users:((\"sshd\",pid=10,fd=3))\n", p)
					}
					return b.String(), nil
				case "sshd", "/usr/sbin/sshd":
					path := sshConfigPath
					for i, a := range args {
						if a == "-f" {
							path = args[i+1]
						}
					}
					var b strings.Builder
					for _, p := range ports(path) {
						fmt.Fprintf(&b, "port %d\nlistenaddress 0.0.0.0:%d\n", p, p)
					}
					return b.String(), nil
				case "getenforce":
					return "Disabled", nil
				case "ufw":
					return "inactive", nil
				case "systemctl":
					if strings.HasPrefix(joined, "is-active") {
						if strings.HasSuffix(joined, "ssh.service") {
							return "active", nil
						}
						if strings.HasSuffix(joined, sshMoveUnit+".timer") && armed {
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
						return "reload failed", errors.New("failed")
					}
					if strings.HasPrefix(joined, "stop") {
						armed = false
					}
					return "", nil
				case "nft":
					if joined == "--stateless list tables" {
						return "table inet " + accessTable, nil
					}
					if joined == "--stateless list table inet "+accessTable {
						return table, nil
					}
					if strings.Contains(joined, "list chain") {
						return "chain input { policy accept; }", nil
					}
					if len(args) == 2 && args[0] == "--file" && (strings.HasSuffix(args[1], "dual.nft") || strings.HasSuffix(args[1], "final.nft")) {
						data, e := os.ReadFile(args[1])
						table = string(data)
						return "", e
					}
					return "", nil
				case "systemd-run":
					data, _ := os.ReadFile(sshConfigPath)
					if string(data) != original {
						t.Fatal("configuration changed before rollback scheduled")
					}
					if !strings.Contains(joined, "--on-active=300s") {
						t.Fatal("missing rollback deadline")
					}
					armed = true
					return "", nil
				case "/bin/sh":
					if !strings.HasSuffix(joined, "rollback.sh") {
						t.Fatal("unexpected script")
					}
					if e := os.WriteFile(sshConfigPath, []byte(original), 0600); e != nil {
						t.Fatal(e)
					}
					table = initial
					restored = true
					return "", nil
				}
				t.Fatalf("unexpected command: %s %s", name, joined)
				return "", nil
			}
			persistAccessRules = func(context.Context) error {
				if armed {
					t.Fatal("persist before stopping rollback")
				}
				saved = true
				return nil
			}
			change, e := BeginSSHPortChange(2222, "203.0.113.9")
			if failReload {
				if e == nil || !restored || table != initial || saved {
					t.Fatalf("failed transaction not restored: %v", e)
				}
				data, _ := os.ReadFile(sshConfigPath)
				if string(data) != original {
					t.Fatal("original config lost")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if !armed || len(ports(sshConfigPath)) != 2 {
				t.Fatal("dual-port staging missing")
			}
			if e = ConfirmSSHPortChange(change.Token); e == nil {
				t.Fatal("confirmation bypassed proof")
			}
			if e = os.WriteFile(filepath.Join(sshMove.dir, "verified"), []byte(change.Token), 0600); e != nil {
				t.Fatal(e)
			}
			if e = ConfirmSSHPortChange(change.Token); e != nil {
				t.Fatal(e)
			}
			p := ports(sshConfigPath)
			if !saved || restored || len(p) != 1 || p[0] != 2222 || strings.Contains(table, "tcp dport 22 ") {
				t.Fatal("migration not finalized")
			}
		})
	}
}
