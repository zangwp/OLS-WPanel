package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shrinkSafeApplyTimeouts shortens polling for failure-path tests and restores
// the original values during cleanup.
func shrinkSafeApplyTimeouts(t *testing.T) {
	t.Helper()
	oldRestart, oldPollTimeout, oldPollInterval := safeApplyRestartTimeout, safeApplyReadinessPollTimeout, safeApplyReadinessPollInterval
	safeApplyRestartTimeout = 200 * time.Millisecond
	safeApplyReadinessPollTimeout = 50 * time.Millisecond
	safeApplyReadinessPollInterval = 10 * time.Millisecond
	t.Cleanup(func() {
		safeApplyRestartTimeout, safeApplyReadinessPollTimeout, safeApplyReadinessPollInterval = oldRestart, oldPollTimeout, oldPollInterval
	})
}

func withFakeRestart(t *testing.T, fn func(serviceName string) error) {
	t.Helper()
	old := restartServiceFunc
	restartServiceFunc = fn
	t.Cleanup(func() { restartServiceFunc = old })
}

func alwaysReady(context.Context) error { return nil }

func TestSafeApplyRestartConfigSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	restartCalls := 0
	withFakeRestart(t, func(string) error { restartCalls++; return nil })

	result := SafeApplyRestartConfig(path, "new", "old", "fake-service", alwaysReady)
	if !result.Applied || result.Err != nil {
		t.Fatalf("expected success, got %+v", result)
	}
	if restartCalls != 1 {
		t.Fatalf("expected exactly 1 restart call, got %d", restartCalls)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "new" {
		t.Fatalf("expected file to contain new content, got %q", string(data))
	}
}

func TestSafeApplyRestartConfigRollsBackWhenRestartFails(t *testing.T) {
	shrinkSafeApplyTimeouts(t)
	path := filepath.Join(t.TempDir(), "config.conf")
	os.WriteFile(path, []byte("old"), 0644)

	calls := 0
	withFakeRestart(t, func(string) error {
		calls++
		if calls == 1 {
			return errors.New("boom")
		}
		return nil // rollback restart succeeds
	})

	result := SafeApplyRestartConfig(path, "new", "old", "fake-service", alwaysReady)
	if result.Applied {
		t.Fatal("expected Applied=false")
	}
	if !result.RolledBack || !result.RollbackSucceeded {
		t.Fatalf("expected successful rollback, got %+v", result)
	}
	if result.Err == nil {
		t.Fatal("expected a non-nil error explaining the failure")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "old" {
		t.Fatalf("expected file to be restored to old content, got %q", string(data))
	}
}

func TestSafeApplyRestartConfigRollsBackWhenReadinessFails(t *testing.T) {
	shrinkSafeApplyTimeouts(t)
	path := filepath.Join(t.TempDir(), "config.conf")
	os.WriteFile(path, []byte("old"), 0644)

	restartCalls := 0
	withFakeRestart(t, func(string) error { restartCalls++; return nil })

	// The service becomes ready only after the rollback restart. Track restarts
	// rather than elapsed time or poll count to avoid timing-dependent failures.
	ready := func(context.Context) error {
		if restartCalls >= 2 {
			return nil
		}
		return errors.New("not ready")
	}

	result := SafeApplyRestartConfig(path, "new", "old", "fake-service", ready)
	if result.Applied {
		t.Fatal("expected Applied=false since new config never became ready in time")
	}
	if !result.RolledBack || !result.RollbackSucceeded {
		t.Fatalf("expected successful rollback, got %+v", result)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "old" {
		t.Fatalf("expected file to be restored to old content, got %q", string(data))
	}
	if restartCalls < 2 {
		t.Fatalf("expected at least 2 restarts (apply + rollback), got %d", restartCalls)
	}
}

func TestSafeApplyRestartConfigReportsCriticalFailureWhenRollbackRestartAlsoFails(t *testing.T) {
	shrinkSafeApplyTimeouts(t)
	path := filepath.Join(t.TempDir(), "config.conf")
	os.WriteFile(path, []byte("old"), 0644)

	withFakeRestart(t, func(string) error { return errors.New("service refuses to start") })

	result := SafeApplyRestartConfig(path, "new", "old", "fake-service", alwaysReady)
	if result.Applied {
		t.Fatal("expected Applied=false")
	}
	if !result.RolledBack {
		t.Fatal("expected RolledBack=true (rollback was attempted)")
	}
	if result.RollbackSucceeded {
		t.Fatal("expected RollbackSucceeded=false since the rollback restart also failed")
	}
	if result.Err == nil {
		t.Fatal("expected a non-nil error describing the critical failure")
	}
	// Even if the rollback restart fails, the old config must be restored on disk.
	data, _ := os.ReadFile(path)
	if string(data) != "old" {
		t.Fatalf("expected file to still be restored to old content even if restart failed, got %q", string(data))
	}
}

// TestSafeApplyRestartConfigReportsCriticalFailureWhenRollbackWriteFails ensures
// a failed restore is reported as a rollback failure: the bad config remains
// on disk, so claiming that nothing changed would conceal a critical failure.
func TestSafeApplyRestartConfigReportsCriticalFailureWhenRollbackWriteFails(t *testing.T) {
	shrinkSafeApplyTimeouts(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	os.WriteFile(path, []byte("old"), 0644)

	withFakeRestart(t, func(string) error {
		// Fail the first restart and remove the directory before rollback writes
		// the old config, forcing atomicWriteConfigFile to fail.
		os.RemoveAll(dir)
		return errors.New("boom")
	})

	result := SafeApplyRestartConfig(path, "new", "old", "fake-service", alwaysReady)
	if result.Applied {
		t.Fatal("expected Applied=false")
	}
	if !result.RolledBack {
		t.Fatal("expected RolledBack=true even though the rollback's own write failed — regression test for the reported bug")
	}
	if result.RollbackSucceeded {
		t.Fatal("expected RollbackSucceeded=false since the rollback write itself failed")
	}
	if result.Err == nil {
		t.Fatal("expected a non-nil error")
	}
}

// TestSafeApplyRestartConfigSerializesConcurrentCalls detects overlapping
// restarts that could overwrite the shared temporary file. Without locking,
// maxInFlight would exceed one.
func TestSafeApplyRestartConfigSerializesConcurrentCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	os.WriteFile(path, []byte("old"), 0644)

	var inFlight, maxInFlight int32
	withFakeRestart(t, func(string) error {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			cur := atomic.LoadInt32(&maxInFlight)
			if n <= cur {
				break
			}
			if atomic.CompareAndSwapInt32(&maxInFlight, cur, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		return nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			SafeApplyRestartConfig(path, "new", "old", "fake-service", alwaysReady)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxInFlight); got > 1 {
		t.Fatalf("expected concurrent calls to be serialized by the mutex, but saw %d overlapping restarts", got)
	}
}

// TestSafeApplyRestartConfigPreservesFilePermissions ensures a save preserves
// hardened modes such as 0600 for Redis configs containing requirepass.
func TestSafeApplyRestartConfigPreservesFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	withFakeRestart(t, func(string) error { return nil })

	result := SafeApplyRestartConfig(path, "new", "old", "fake-service", alwaysReady)
	if !result.Applied {
		t.Fatalf("expected success, got %+v", result)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected file permissions to stay 0600, got %o", perm)
	}
}

func TestSafeApplyRestartConfigDoesNotTouchServiceWhenInitialWriteFails(t *testing.T) {
	// A missing directory forces a write failure without relying on permissions.
	path := filepath.Join(t.TempDir(), "no-such-dir", "config.conf")

	restartCalls := 0
	withFakeRestart(t, func(string) error { restartCalls++; return nil })

	result := SafeApplyRestartConfig(path, "new", "old", "fake-service", alwaysReady)
	if result.Applied || result.RolledBack {
		t.Fatalf("expected a plain write failure with no restart/rollback attempted, got %+v", result)
	}
	if result.Err == nil {
		t.Fatal("expected a non-nil error")
	}
	if restartCalls != 0 {
		t.Fatalf("expected restart to never be called when the write itself failed, got %d calls", restartCalls)
	}
}
