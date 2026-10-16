package executor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Variables let tests shorten timeouts without waiting 30-60 seconds.
var (
	safeApplyRestartTimeout        = 60 * time.Second
	safeApplyReadinessPollTimeout  = 30 * time.Second
	safeApplyReadinessPollInterval = 1 * time.Second
)

// safeApplyMu serializes SafeApplyRestartConfig calls.
var safeApplyMu sync.Mutex

// restartServiceFunc is replaceable so tests can run without systemd.
var restartServiceFunc = func(serviceName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), safeApplyRestartTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "restart", serviceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// SafeApplyResult lets callers report whether applying or restoring the config succeeded.
type SafeApplyResult struct {
	Applied           bool  // New config is active.
	RolledBack        bool  // Restoring the old config was attempted.
	RollbackSucceeded bool  // Service restored; meaningful only when RolledBack is true.
	Err               error // Apply error; nil with Applied=true means success.
}

// SafeApplyRestartConfig atomically writes a config, restarts the service, and
// polls readiness. On failure it restores the old config, restarts once, and
// checks readiness again. MariaDB and Redis lack reliable standalone syntax
// checks, so each step has a timeout; failure after rollback is reported without
// further retries. ready must connect to the service, not just check systemd.
// A global lock serializes these infrequent admin actions to prevent concurrent
// saves from overwriting each other's config or temporary file.
func SafeApplyRestartConfig(configPath, newContent, oldContent, serviceName string, ready func(context.Context) error) SafeApplyResult {
	safeApplyMu.Lock()
	defer safeApplyMu.Unlock()

	if err := atomicWriteConfigFile(configPath, newContent); err != nil {
		return SafeApplyResult{Err: fmt.Errorf("写入配置失败，配置未改动: %w", err)}
	}

	if err := restartServiceFunc(serviceName); err != nil {
		return rollbackConfigAndRestart(configPath, oldContent, serviceName, ready, fmt.Errorf("重启服务失败: %w", err))
	}
	if err := pollServiceReady(ready); err != nil {
		return rollbackConfigAndRestart(configPath, oldContent, serviceName, ready, fmt.Errorf("重启后健康检查失败: %w", err))
	}
	return SafeApplyResult{Applied: true}
}

func atomicWriteConfigFile(path, content string) error {
	// Preserve existing permissions, including hardened Redis configs containing
	// requirepass. Use 0644 only for a new file.
	mode := os.FileMode(0644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}

	tmpPath := path + ".olswpanel.tmp"
	if err := os.WriteFile(tmpPath, []byte(content), mode); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// pollServiceReady retries ready until it succeeds or the total timeout expires.
func pollServiceReady(ready func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), safeApplyReadinessPollTimeout)
	defer cancel()

	ticker := time.NewTicker(safeApplyReadinessPollInterval)
	defer ticker.Stop()

	var lastErr error
	for {
		if err := ready(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return lastErr
		case <-ticker.C:
		}
	}
}

func rollbackConfigAndRestart(configPath, oldContent, serviceName string, ready func(context.Context) error, applyErr error) SafeApplyResult {
	if err := atomicWriteConfigFile(configPath, oldContent); err != nil {
		// Set RolledBack even when restoring the file fails: the bad config remains
		// on disk and requires admin intervention. Callers must report rollback
		// failure rather than claiming that no changes were made.
		return SafeApplyResult{RolledBack: true, RollbackSucceeded: false, Err: fmt.Errorf("%v；回滚写入配置也失败: %w", applyErr, err)}
	}
	if err := restartServiceFunc(serviceName); err != nil {
		return SafeApplyResult{RolledBack: true, RollbackSucceeded: false, Err: fmt.Errorf("%v；回滚重启也失败: %w", applyErr, err)}
	}
	if err := pollServiceReady(ready); err != nil {
		return SafeApplyResult{RolledBack: true, RollbackSucceeded: false, Err: fmt.Errorf("%v；回滚重启成功但服务仍未就绪: %w", applyErr, err)}
	}
	return SafeApplyResult{RolledBack: true, RollbackSucceeded: true, Err: applyErr}
}
