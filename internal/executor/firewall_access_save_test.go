package executor

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestAccessOrdinaryPortDeletionSavesImmediatelyAndRestoresOnFailure(t *testing.T) {
	for _, failSave := range []bool{false, true} {
		t.Run(strconv.FormatBool(failSave), func(t *testing.T) {
			oldCmd, oldPersist, oldAvailable, oldRun := portCommand, persistAccessRules, accessSystemdAvailable, accessRunDirectory
			oldConfig, oldPending := config.AppConfig, pendingAccess
			t.Cleanup(func() {
				portCommand, persistAccessRules, accessSystemdAvailable, accessRunDirectory = oldCmd, oldPersist, oldAvailable, oldRun
				config.AppConfig, pendingAccess = oldConfig, oldPending
			})
			config.AppConfig = &config.Config{Panel: config.PanelConfig{Port: 8443}}
			accessRunDirectory = t.TempDir()
			accessSystemdAvailable = func() bool { return true }
			pendingAccess.token = ""
			previous := []FirewallAccessRule{{"tcp", 22, "203.0.113.0/24"}, {"tcp", 8443, ""}, {"tcp", 8080, ""}}
			original := accessRulesScript(previous, false)
			current := original
			applied, restored, saved, disabled := false, false, false, false
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				command := name + " " + strings.Join(args, " ")
				switch command {
				case "nft --version":
					return "nftables v1.1.1", nil
				case "nft -a list chain inet filter input":
					return "type filter hook input priority filter; policy drop;", nil
				case "systemctl show nftables --property=ExecStart --value":
					return "/usr/sbin/nft -f " + nftablesConfigPath, nil
				case "ss -H -lntup":
					return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*", nil
				case "sshd -T":
					return "port 22", nil
				case "nft --stateless list tables":
					return "table inet " + accessTable, nil
				case "nft --stateless list table inet " + accessTable:
					return current, nil
				case "nft --stateless list ruleset":
					return current, nil
				case "systemctl is-enabled nftables":
					return "disabled", errors.New("disabled")
				case "systemctl enable nftables":
					return "", nil
				case "systemctl disable nftables":
					disabled = true
					return "", nil
				}
				if name == "systemctl" && len(args) > 1 && args[0] == "show" && strings.Contains(command, "--property=LoadState") {
					return "LoadState=not-found\nActiveState=inactive\nResult=success\nJob=", nil
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
				if name == "nft" && len(args) == 2 && args[0] == "--file" {
					data, err := os.ReadFile(args[1])
					if strings.HasSuffix(args[1], "rollback.nft") {
						if !strings.Contains(string(data), original) {
							t.Fatal("rollback did not preserve the original table")
						}
						current, restored = original, true
					} else {
						current, applied = string(data), true
					}
					return "", err
				}
				t.Fatalf("ordinary-port save unexpectedly used a watchdog or confirmation operation: %s", command)
				return "", errors.New("unexpected")
			}
			persistAccessRules = func(context.Context) error {
				if !applied {
					t.Fatal("persisted before applying the selected policy")
				}
				if failSave {
					return errors.New("disk full")
				}
				saved = true
				return nil
			}
			req := FirewallAccessRequest{Rules: previous[:2]}
			preview, err := PreviewFirewallAccess(req, "203.0.113.5")
			if err != nil || preview.RequiresConfirmation || preview.RequiresSSHValidation {
				t.Fatalf("ordinary port deletion needs a management verification: %+v %v", preview, err)
			}
			req.Fingerprint = preview.Fingerprint
			result, err := ApplyFirewallAccess(req, "203.0.113.5")
			if failSave {
				if err == nil || saved || !restored || !disabled || current != original || result.Saved {
					t.Fatalf("failed persistence was not restored: %+v %v", result, err)
				}
			} else if err != nil || !saved || !result.Saved || result.RequiresConfirmation || result.ConfirmationToken != "" || restored {
				t.Fatalf("ordinary port deletion did not complete immediately: %+v %v", result, err)
			}
		})
	}
}
