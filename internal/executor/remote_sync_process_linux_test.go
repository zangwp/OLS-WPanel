//go:build linux

package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRsyncCancellationKillsSpawnedProcessGroup(t *testing.T) {
	openTestDB(t)
	binDir := t.TempDir()
	childPIDPath := filepath.Join(t.TempDir(), "child.pid")
	sshpassPath := filepath.Join(binDir, "sshpass")
	script := "#!/bin/sh\n" +
		"sleep 30 </dev/null >/dev/null 2>&1 &\n" +
		"child=$!\n" +
		"printf '%s' \"$child\" > \"$OLS_WPANEL_RSYNC_CHILD_PID\"\n" +
		"wait \"$child\"\n"
	if err := os.WriteFile(sshpassPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OLS_WPANEL_RSYNC_CHILD_PID", childPIDPath)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	ok := syncBackupToRsyncContext(ctx,
		backupsRoot+"/example.com/files/file_full_test.tar.gz",
		BackupSourceFile, 0, "", "backup.example.com", 22, "root", "password", "secret", "/backups", 1)
	if ok {
		t.Fatal("cancelled rsync unexpectedly succeeded")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("cancelled rsync returned too slowly: %s", elapsed)
	}

	rawPID, err := os.ReadFile(childPIDPath)
	if err != nil {
		t.Fatalf("fake sshpass did not record its child PID: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(rawPID)))
	if err != nil {
		t.Fatalf("invalid child PID %q: %v", rawPID, err)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	deadline := time.Now().Add(2 * time.Second)
	for {
		if !processIsRunning(pid) {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("rsync child process %d survived context cancellation", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func processIsRunning(pid int) bool {
	return processIsRunningWithProbe(
		func() error { return syscall.Kill(pid, 0) },
		func() ([]byte, error) { return os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat")) },
	)
}

func processIsRunningWithProbe(probe func() error, readStat func() ([]byte, error)) bool {
	err := probe()
	if errors.Is(err, syscall.ESRCH) {
		return false
	}
	stat, readErr := readStat()
	// The process can be reaped after kill(pid, 0) succeeds but before the
	// procfs read. Missing stat is proof of termination, not a live child.
	if errors.Is(readErr, os.ErrNotExist) {
		return false
	}
	// A zombie or dead task cannot execute more work. Parse after comm's final
	// ')' because a process name can contain spaces and closing parentheses.
	if readErr == nil {
		if close := strings.LastIndexByte(string(stat), ')'); close >= 0 {
			fields := strings.Fields(string(stat[close+1:]))
			if len(fields) > 0 && (fields[0] == "Z" || fields[0] == "X") {
				return false
			}
		}
	}
	// Unknown probe/read failures must not make a real survivor pass.
	return true
}

func TestRsyncChildTerminationProbeHandlesReapingRace(t *testing.T) {
	for _, sample := range []struct {
		name    string
		probe   error
		stat    string
		readErr error
		running bool
	}{
		{"reaped_after_successful_signal_probe", nil, "", os.ErrNotExist, false},
		{"already_reaped", syscall.ESRCH, "", nil, false},
		{"zombie_with_spaced_name", nil, "42 (worker ) name) Z 1 2 3", nil, false},
		{"dead_before_final_reaping", nil, "42 (sleep) X 1 2 3", nil, false},
		{"live_sleep", nil, "42 (sleep) S 1 2 3", nil, true},
		{"read_denied_is_not_termination", nil, "", os.ErrPermission, true},
		{"signal_denied_is_not_termination", syscall.EPERM, "", os.ErrPermission, true},
		{"malformed_stat_is_not_termination", nil, "invalid", nil, true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			got := processIsRunningWithProbe(func() error { return sample.probe }, func() ([]byte, error) { return []byte(sample.stat), sample.readErr })
			if got != sample.running {
				t.Fatalf("running=%v want=%v", got, sample.running)
			}
		})
	}
}
