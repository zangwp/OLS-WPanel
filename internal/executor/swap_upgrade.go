package executor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

const (
	swapFilePath     = "/swapfile"
	swapFstabPath    = "/etc/fstab"
	swapSysctlPath   = "/etc/sysctl.d/99-ols-wpanel-swap.conf"
	swapMinFreeBytes = int64(8 * 1024 * 1024 * 1024)
)

var swapCommand = runBoundedSwapCommand

var swapProcessRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = 5 * time.Second
	return command.CombinedOutput()
}

func swapCommandBudget(name string) time.Duration {
	switch name {
	case "dd":
		return 10 * time.Minute
	case "swapoff":
		return 3 * time.Minute
	default:
		return time.Minute
	}
}

func runBoundedSwapCommand(name string, args ...string) error {
	return runSwapCommandWithTimeout(name, args, swapCommandBudget(name), swapProcessRunner)
}

func runSwapCommandWithTimeout(name string, args []string, budget time.Duration, run func(context.Context, string, ...string) ([]byte, error)) error {
	// Each command, including rollback, receives an independent budget. A failed
	// or expired forward command cannot cancel the subsequent recovery command.
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	output, err := run(ctx, name, args...)
	if ctx.Err() != nil {
		return fmt.Errorf("%s 执行超时（上限 %s）: %w: %s", name, budget, errors.Join(ctx.Err(), err), strings.TrimSpace(string(output)))
	}
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}

var swapStatfs = syscall.Statfs

func init() {
	database.RegisterUpgrade("1.0.38", ensureSwapUpgrade)
}

// ensureSwapUpgrade is best-effort: the panel must not fail to start merely
// because this optional safety buffer could not be created.
func ensureSwapUpgrade() error {
	created, reason, err := ensureAutomaticSwap(
		"/proc/meminfo",
		"/proc/swaps",
		swapFilePath,
		swapFstabPath,
		swapSysctlPath,
	)
	if err != nil {
		log.Printf("[升级] 自动创建 Swap 失败，已跳过且不会自动重试: %v", err)
		return nil
	}
	if created {
		log.Printf("[升级] 已按物理内存自动创建推荐的 Swap")
	} else {
		log.Printf("[升级] 跳过自动创建 Swap: %s", reason)
	}
	return nil
}

func ensureAutomaticSwap(meminfoPath, swapsPath, swapPath, fstabPath, sysctlPath string) (bool, string, error) {
	swapManagerMu.Lock()
	defer swapManagerMu.Unlock()
	// This legacy upgrade runs outside RunSwapCLI; it does not already hold the
	// terminal lock. Coordinate the production path with concurrent SSH changes.
	if swapPath == swapFilePath {
		lock, err := acquireSwapCLILock(canonicalSwapCLILockPath)
		if err != nil {
			return false, "", err
		}
		defer lock.Close()
	}
	totalMemory, err := readMeminfoValue(meminfoPath, "MemTotal:")
	if err != nil {
		return false, "", err
	}
	swapSizeBytes := RecommendedSwapBytes(totalMemory)
	swapSizeMB := swapSizeBytes / (1024 * 1024)

	hasSwap, err := swapsConfigured(swapsPath)
	if err != nil {
		return false, "", err
	}
	if hasSwap {
		return false, "系统已有启用的 Swap", nil
	}
	if _, err := os.Stat(swapPath); err == nil {
		return false, swapPath + " 已存在", nil
	} else if !os.IsNotExist(err) {
		return false, "", fmt.Errorf("检查 %s: %w", swapPath, err)
	}

	var fs syscall.Statfs_t
	if err := swapStatfs("/", &fs); err != nil {
		return false, "", fmt.Errorf("检查根分区空间: %w", err)
	}
	freeBytes := int64(fs.Bavail) * int64(fs.Bsize)
	totalBytes := int64(fs.Blocks) * int64(fs.Bsize)
	usedBytes := totalBytes - int64(fs.Bfree)*int64(fs.Bsize)
	if freeBytes < swapMinFreeBytes {
		return false, "根分区可用空间不足 8GB", nil
	}
	if totalBytes <= 0 || (usedBytes+swapSizeBytes)*100/totalBytes > 85 {
		return false, "创建后根分区使用率将超过 85%", nil
	}

	log.Printf("[升级] 正在创建 %dMB Swap，可能需要几十秒", swapSizeMB)
	status, err := applyManagedSwapLocked(swapSizeMB, systemDefaultSwappiness, swapManagerPaths{meminfo: meminfoPath, swaps: swapsPath, swap: swapPath, fstab: fstabPath, sysctl: sysctlPath})
	recordSwapOperation("swap_upgrade_create", status, err)
	if err != nil {
		return false, "", err
	}
	return true, "", nil
}

func rollbackFstabAppend(path string, size int64) {
	if err := os.Truncate(path, size); err != nil {
		log.Printf("[升级] 回滚 %s 失败，请手动删除 Swap 配置行: %v", path, err)
	}
}

func readMeminfoValue(path, key string) (int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == key {
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				return 0, err
			}
			return kb * 1024, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("%s not found in %s", key, path)
}

func swapsConfigured(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		if strings.TrimSpace(scanner.Text()) != "" {
			return true, nil
		}
	}
	return false, scanner.Err()
}
