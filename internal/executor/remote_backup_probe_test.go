package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestRemoteBackupProbeProcessHelper(t *testing.T) {
	if os.Getenv("OLS_REMOTE_PROBE_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "connect":
		fmt.Fprintln(os.Stderr, "Warning: Permanently added 'backup.example.com' (ED25519) to the list of known hosts.")
		fmt.Println("Synthetic login banner")
		fmt.Println("OLS_WPANEL_OK")
	case "changed":
		fmt.Fprintln(os.Stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED")
		os.Exit(23)
	case "stall":
		time.Sleep(10 * time.Second)
	case "keys":
		fmt.Println("backup.example.com ssh-ed25519 saved-key")
	case "fingerprint":
		data, _ := io.ReadAll(os.Stdin)
		if !strings.Contains(string(data), "saved-key") {
			os.Exit(24)
		}
		fmt.Println("256 SHA256:saved-key backup.example.com (ED25519)")
	}
	os.Exit(0)
}

func remoteBackupProbeFixture(t *testing.T, connectMode string) (models.RemoteBackupSettings, string, string, *[]string) {
	t.Helper()
	t.Setenv("OLS_REMOTE_PROBE_HELPER", "1")
	dir := t.TempDir()
	knownHosts := filepath.Join(dir, "known_hosts")
	key := filepath.Join(dir, "key")
	for name, value := range map[string]string{knownHosts: "backup.example.com ssh-ed25519 saved-key\nother.example.org ssh-ed25519 other-key\n", key: "synthetic"} {
		if err := os.WriteFile(name, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	calls := []string{}
	oldCommand := remoteBackupProbeCommand
	t.Cleanup(func() { remoteBackupProbeCommand = oldCommand })
	remoteBackupProbeCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 45*time.Second {
			t.Fatal("remote probe command has no bounded shared deadline")
		}
		calls = append(calls, name+" "+strings.Join(args, " "))
		mode := "transfer"
		if name == "ssh" || (name == "sshpass" && len(args) > 1 && args[1] == "ssh") {
			mode = connectMode
			if !slices.Contains(args, "StrictHostKeyChecking=accept-new") || !slices.Contains(args, "UserKnownHostsFile="+knownHosts) {
				t.Fatal("test connection no longer checks the saved host identity")
			}
		} else if name == "ssh-keygen" {
			if slices.Contains(args, "-F") {
				mode = "keys"
				if !slices.Contains(args, "[backup.example.com]:2222") {
					t.Fatal("fingerprint lookup is not scoped to this host and port")
				}
			} else {
				mode = "fingerprint"
			}
		} else if name == "ssh-keyscan" {
			t.Fatal("unauthenticated key scan must never replace saved identities")
		} else if !strings.Contains(strings.Join(args, " "), "UserKnownHostsFile="+knownHosts) || !strings.Contains(strings.Join(args, " "), "StrictHostKeyChecking=accept-new") {
			t.Fatal("rsync test does not use the same saved identities")
		}
		return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRemoteBackupProbeProcessHelper$", "--", mode)
	}
	return models.RemoteBackupSettings{Host: "backup.example.com", Port: 2222, Username: "backup", AuthType: "key", RemotePath: "/backup"}, knownHosts, key, &calls
}

func TestRemoteBackupProbePreservesAllSavedHostKeys(t *testing.T) {
	for _, auth := range []string{"key", "password"} {
		t.Run(auth, func(t *testing.T) {
			settings, knownHosts, key, calls := remoteBackupProbeFixture(t, "connect")
			settings.AuthType = auth
			settings.Password = "test-secret"
			before, _ := os.ReadFile(knownHosts)
			fingerprint, err := probeSSHBackupConnection(context.Background(), settings, knownHosts, key)
			if err != nil || !strings.Contains(fingerprint, "SHA256:saved-key") {
				t.Fatalf("probe fingerprint=%q error=%v", fingerprint, err)
			}
			after, _ := os.ReadFile(knownHosts)
			if string(after) != string(before) || len(*calls) != 4 {
				t.Fatalf("saved host keys changed or probe incomplete: %q calls=%v", after, *calls)
			}
			if strings.Contains(strings.Join(*calls, "\n"), settings.Password) {
				t.Fatal("password leaked into process arguments")
			}
		})
	}
}

func TestRemoteBackupProbeChangedHostDoesNotTransferOrReplaceKeys(t *testing.T) {
	settings, knownHosts, key, calls := remoteBackupProbeFixture(t, "changed")
	before, _ := os.ReadFile(knownHosts)
	fingerprint, err := probeSSHBackupConnection(context.Background(), settings, knownHosts, key)
	if err == nil || !strings.Contains(err.Error(), "IDENTIFICATION HAS CHANGED") || fingerprint != "" || len(*calls) != 1 {
		t.Fatalf("changed identity accepted: fingerprint=%q error=%v calls=%v", fingerprint, err, *calls)
	}
	after, _ := os.ReadFile(knownHosts)
	if string(before) != string(after) {
		t.Fatal("changed identity overwrote the saved host keys")
	}
}

func TestRemoteBackupProbeCancelsStalledCommand(t *testing.T) {
	settings, knownHosts, key, calls := remoteBackupProbeFixture(t, "stall")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := probeSSHBackupConnection(ctx, settings, knownHosts, key)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second || len(*calls) != 1 {
		t.Fatalf("stalled connection did not stop: elapsed=%v error=%v calls=%v", time.Since(started), err, *calls)
	}
}

func TestRemoteBackupProbeCancelledRequestDoesNotStartCommand(t *testing.T) {
	settings, knownHosts, key, calls := remoteBackupProbeFixture(t, "connect")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := probeSSHBackupConnection(ctx, settings, knownHosts, key)
	if !errors.Is(err, context.Canceled) || len(*calls) != 0 {
		t.Fatalf("cancelled request started a probe: %v calls=%v", err, *calls)
	}
}
