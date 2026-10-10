package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSSHConfirmationRequiresProofBeforeMutation(t *testing.T) {
	oldMove, oldCommand := sshMove, portCommand
	defer func() { sshMove = oldMove; portCommand = oldCommand }()
	sshMove.Token = "test"
	sshMove.Deadline = time.Now().Add(time.Minute)
	sshMove.dir = t.TempDir()
	portCommand = func(context.Context, string, ...string) (string, error) {
		t.Fatal("mutation before new-session proof")
		return "", nil
	}
	if e := ConfirmSSHPortChange("test"); e == nil || !strings.Contains(e.Error(), "验证命令") {
		t.Fatalf("proof bypassed: %v", e)
	}
	if e := os.WriteFile(filepath.Join(sshMove.dir, "verified"), []byte("wrong-token"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := ConfirmSSHPortChange("test"); e == nil {
		t.Fatal("wrong proof accepted")
	}
	sshMove.Deadline = time.Now().Add(-time.Second)
	if e := ConfirmSSHPortChange("test"); e == nil {
		t.Fatal("expired confirmation accepted")
	}
}

func TestSSHConfirmationRejectsConcurrentConfigEdit(t *testing.T) {
	oldMove, oldPath, oldCommand := sshMove, sshConfigPath, portCommand
	defer func() { sshMove = oldMove; sshConfigPath = oldPath; portCommand = oldCommand }()
	sshMove.Token = "test"
	sshMove.Deadline = time.Now().Add(time.Minute)
	sshMove.dir = t.TempDir()
	sshMove.expectedConfig = "expected"
	sshConfigPath = filepath.Join(sshMove.dir, "config")
	if e := os.WriteFile(sshConfigPath, []byte("edited externally"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(sshMove.dir, "verified"), []byte("test"), 0600); e != nil {
		t.Fatal(e)
	}
	portCommand = func(context.Context, string, ...string) (string, error) {
		t.Fatal("mutation after concurrent configuration edit")
		return "", nil
	}
	if e := ConfirmSSHPortChange("test"); e == nil || !strings.Contains(e.Error(), "其他操作") {
		t.Fatalf("edit ignored: %v", e)
	}
}

func TestSSHListenerVerificationRejectsIncompleteInspection(t *testing.T) {
	oldCommand := portCommand
	defer func() { portCommand = oldCommand }()
	valid := "tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=10,fd=3))"
	for _, sample := range []struct {
		name, output string
		commandError error
	}{
		{"command-failure", "", errors.New("permission denied")},
		{"partial-output-on-failure", valid, errors.New("inspection failed")},
		{"truncated-row", "tcp LISTEN 0", nil},
		{"unknown-protocol", "unknown LISTEN 0 128 0.0.0.0:22 0.0.0.0:*", nil},
		{"unreadable-address", "tcp LISTEN 0 128 unknown 0.0.0.0:*", nil},
		{"unreadable-port", "tcp LISTEN 0 128 0.0.0.0:unknown 0.0.0.0:*", nil},
		{"unreadable-owner", "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:*", nil},
	} {
		t.Run(sample.name, func(t *testing.T) {
			portCommand = func(context.Context, string, ...string) (string, error) {
				return sample.output, sample.commandError
			}
			if err := waitSSHRetired(context.Background(), 22); err == nil {
				t.Fatal("unreadable inspection proved old SSH port was retired")
			}
			if err := waitSSHListener(context.Background(), 2222); err == nil {
				t.Fatal("incomplete inspection proved new SSH listener")
			}
		})
	}
	portCommand = func(context.Context, string, ...string) (string, error) { return valid, nil }
	if err := waitSSHListener(context.Background(), 2222); err != nil {
		t.Fatal(err)
	}
	if err := waitSSHRetired(context.Background(), 22); err != nil {
		t.Fatal(err)
	}
	portCommand = func(context.Context, string, ...string) (string, error) { return "", nil }
	if err := waitSSHRetired(context.Background(), 22); err != nil {
		t.Fatal("successful empty inspection must distinguish absence from failure", err)
	}
}

func TestSSHConfirmationRollsBackWhenOldPortInspectionFails(t *testing.T) {
	for _, name := range []string{"command-failure", "truncated-output", "owner-unavailable"} {
		t.Run(name, func(t *testing.T) {
			oldMove, oldConfig, oldJail := sshMove, sshConfigPath, sshJailPath
			oldCommand, oldPersist := portCommand, persistAccessRules
			defer func() {
				sshMove, sshConfigPath, sshJailPath = oldMove, oldConfig, oldJail
				portCommand, persistAccessRules = oldCommand, oldPersist
			}()
			dir := t.TempDir()
			sshConfigPath, sshJailPath = filepath.Join(dir, "sshd_config"), filepath.Join(dir, "jail.local")
			original := "Port 22\nPasswordAuthentication no\n"
			dual := "Port 22\nPort 2222\nPasswordAuthentication no\n"
			for path, data := range map[string]string{
				sshConfigPath:                  dual,
				filepath.Join(dir, "final"):    "Port 2222\nPasswordAuthentication no\n",
				filepath.Join(dir, "verified"): "inspection-token",
			} {
				if err := os.WriteFile(path, []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			sshMove.SSHPortChange = SSHPortChange{Token: "inspection-token", OldPort: 22, NewPort: 2222, Deadline: time.Now().Add(time.Minute)}
			sshMove.dir, sshMove.service = dir, "ssh.service"
			sshMove.expectedConfig, sshMove.expectedTable = dual, "expected table"
			inspections, restored := 0, false
			portCommand = func(_ context.Context, binary string, args ...string) (string, error) {
				switch binary {
				case "nft":
					return "expected table", nil
				case "/usr/sbin/sshd":
					return "port 2222\nlistenaddress 0.0.0.0:2222\n", nil
				case "ss":
					inspections++
					if inspections == 1 {
						return "tcp LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=10,fd=3))", nil
					}
					if name == "truncated-output" {
						return "tcp LISTEN 0", nil
					}
					if name == "owner-unavailable" {
						return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*", nil
					}
					return "", errors.New("inspection failed")
				case "/bin/sh":
					if len(args) != 1 || args[0] != filepath.Join(dir, "rollback.sh") {
						t.Fatal("unexpected script invocation", args)
					}
					restored = true
					return "", os.WriteFile(sshConfigPath, []byte(original), 0600)
				case "systemctl":
					if len(args) > 0 && args[0] == "stop" && !restored {
						t.Fatal("watchdog cancelled before failed inspection was restored")
					}
					return "", nil
				default:
					t.Fatal("unexpected external command", binary, args)
					return "", errors.New("unexpected command")
				}
			}
			persistAccessRules = func(context.Context) error {
				t.Fatal("failed old-port inspection persisted a permanent policy")
				return nil
			}
			if err := ConfirmSSHPortChange("inspection-token"); err == nil || !strings.Contains(err.Error(), "已恢复原 SSH 配置") {
				t.Fatalf("migration falsely confirmed: %v", err)
			}
			current, err := os.ReadFile(sshConfigPath)
			if err != nil || string(current) != original || !restored || sshMove.Token != "" || inspections != 2 {
				t.Fatalf("failed inspection did not restore original transaction: %q %v", current, err)
			}
		})
	}
}
