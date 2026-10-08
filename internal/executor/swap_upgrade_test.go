package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEnsureAutomaticSwapCreatesEligibleServerSwap(t *testing.T) {
	f := newEmptySwapUpgradeFixture(t)
	created, reason, err := ensureAutomaticSwap(f.paths.meminfo, f.paths.swaps, f.paths.swap, f.paths.fstab, f.paths.sysctl)
	if err != nil || !created || reason != "" {
		t.Fatalf("ensureAutomaticSwap() = created %v, reason %q, err %v", created, reason, err)
	}
	if got := strings.Join(f.commands, "\n"); !strings.Contains(got, "mkswap "+filepath.Dir(f.paths.swap)) ||
		!strings.Contains(got, "swapon "+f.paths.swap) ||
		!strings.Contains(got, "count=1024") ||
		!strings.Contains(got, ".ols-wpanel-swap-new-") ||
		!strings.Contains(got, "sysctl -p "+f.paths.sysctl) {
		t.Fatalf("commands = %q", got)
	}
	fstabData, err := os.ReadFile(f.paths.fstab)
	if err != nil || !strings.Contains(string(fstabData), f.paths.swap+" none swap sw 0 0") {
		t.Fatalf("fstab = %q, err %v", fstabData, err)
	}
	sysctlData, err := os.ReadFile(f.paths.sysctl)
	if err != nil || !strings.Contains(string(sysctlData), "vm.swappiness = 60") {
		t.Fatalf("sysctl = %q, err %v", sysctlData, err)
	}
}

func TestEnsureAutomaticSwapSkipsExistingSwap(t *testing.T) {
	root := t.TempDir()
	meminfo := filepath.Join(root, "meminfo")
	swaps := filepath.Join(root, "swaps")
	mustWriteSwapTestFile(t, meminfo, "MemTotal:        4194304 kB\n")
	mustWriteSwapTestFile(t, swaps, "Filename Type Size Used Priority\n/dev/vda2 partition 1 0 -2\n")

	created, reason, err := ensureAutomaticSwap(
		meminfo, swaps, filepath.Join(root, "swapfile"), filepath.Join(root, "fstab"), filepath.Join(root, "swap.conf"),
	)
	if err != nil || created || reason != "系统已有启用的 Swap" {
		t.Fatalf("ensureAutomaticSwap() = created %v, reason %q, err %v", created, reason, err)
	}
}

func TestRecommendedSwapBytes(t *testing.T) {
	tests := []struct {
		name     string
		memoryGB float64
		wantGB   int64
	}{
		{"512MB", 0.5, 2},
		{"1GB", 1, 2},
		{"2GB", 2, 1},
		{"4GB", 4, 1},
		{"8GB", 8, 1},
		{"16GB", 16, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			memory := int64(test.memoryGB * 1024 * 1024 * 1024)
			want := test.wantGB * 1024 * 1024 * 1024
			if got := RecommendedSwapBytes(memory); got != want {
				t.Fatalf("RecommendedSwapBytes(%d) = %d, want %d", memory, got, want)
			}
		})
	}
}

func TestEnsureAutomaticSwapSkipsLowDiskSpace(t *testing.T) {
	root := t.TempDir()
	meminfo := filepath.Join(root, "meminfo")
	swaps := filepath.Join(root, "swaps")
	mustWriteSwapTestFile(t, meminfo, "MemTotal:        4194304 kB\n")
	mustWriteSwapTestFile(t, swaps, "Filename Type Size Used Priority\n")

	oldStatfs := swapStatfs
	swapStatfs = func(_ string, stat *syscall.Statfs_t) error {
		stat.Bsize = 4096
		stat.Blocks = 2 * 1024 * 1024
		stat.Bfree = 1024
		stat.Bavail = 1024
		return nil
	}
	t.Cleanup(func() { swapStatfs = oldStatfs })

	created, reason, err := ensureAutomaticSwap(
		meminfo, swaps, filepath.Join(root, "swapfile"), filepath.Join(root, "fstab"), filepath.Join(root, "swap.conf"),
	)
	if err != nil || created || reason != "根分区可用空间不足 8GB" {
		t.Fatalf("ensureAutomaticSwap() = created %v, reason %q, err %v", created, reason, err)
	}
}

func TestEnsureAutomaticSwapCleansFailedAllocation(t *testing.T) {
	f := newEmptySwapUpgradeFixture(t)
	base := swapCommand
	swapCommand = func(name string, args ...string) error {
		if name == "dd" {
			if err := base(name, args...); err != nil {
				return err
			}
			return errors.New("disk error")
		}
		return base(name, args...)
	}

	created, _, err := ensureAutomaticSwap(f.paths.meminfo, f.paths.swaps, f.paths.swap, f.paths.fstab, f.paths.sysctl)
	if err == nil || created {
		t.Fatalf("ensureAutomaticSwap() = created %v, err %v", created, err)
	}
	if _, statErr := os.Stat(f.paths.swap); !os.IsNotExist(statErr) {
		t.Fatalf("partial swap file remains: %v", statErr)
	}
	partials, _ := filepath.Glob(filepath.Join(filepath.Dir(f.paths.swap), ".ols-wpanel-swap-new-*"))
	if len(partials) != 0 {
		t.Fatalf("temporary allocation remains: %v", partials)
	}
}

func newEmptySwapUpgradeFixture(t *testing.T) *swapTransactionFixture {
	t.Helper()
	f := newSwapTransactionFixture(t)
	for _, path := range []string{f.paths.swap, f.paths.sysctl} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteSwapTestFile(t, f.paths.fstab, "rootfs / ext4 defaults 0 1\n")
	f.writeActive(t, false, 0)
	return f
}

func TestEnsureAutomaticSwapRollsBackPartiallySuccessfulActivation(t *testing.T) {
	f := newEmptySwapUpgradeFixture(t)
	base := swapCommand
	swapCommand = func(name string, args ...string) error {
		if err := base(name, args...); err != nil {
			return err
		}
		if name == "swapon" {
			return context.DeadlineExceeded
		}
		return nil
	}
	created, _, err := ensureAutomaticSwap(f.paths.meminfo, f.paths.swaps, f.paths.swap, f.paths.fstab, f.paths.sysctl)
	if created || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("created=%t err=%v", created, err)
	}
	active, stateErr := readSwapPathActive(f.paths.swaps, f.paths.swap)
	if active || stateErr != nil {
		t.Fatalf("activation remains: active=%t err=%v", active, stateErr)
	}
	if _, err := os.Stat(f.paths.swap); !os.IsNotExist(err) {
		t.Fatalf("new swap remains: %v", err)
	}
	data, _ := os.ReadFile(f.paths.fstab)
	if string(data) != "rootfs / ext4 defaults 0 1\n" || f.runtime != 60 {
		t.Fatalf("persistent/runtime rollback failed: %q, %d", data, f.runtime)
	}
}

func TestSwapCommandBudgetsAndIndependentRecoveryContext(t *testing.T) {
	if swapCommandBudget("dd") != 10*time.Minute || swapCommandBudget("swapoff") != 3*time.Minute || swapCommandBudget("sysctl") != time.Minute {
		t.Fatal("unexpected command budgets")
	}
	err := runSwapCommandWithTimeout("swapoff", []string{"/virtual-swap"}, 0, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if ctx.Err() != context.DeadlineExceeded || name != "swapoff" || len(args) != 1 {
			t.Fatalf("deadline/command not forwarded: %v %s %v", ctx.Err(), name, args)
		}
		return []byte("partial change"), errors.New("process killed")
	})
	if !errors.Is(err, context.DeadlineExceeded) || !containsAll(err.Error(), "超时", "partial change") {
		t.Fatalf("timeout not reported: %v", err)
	}
	if err := runSwapCommandWithTimeout("swapon", []string{"/virtual-swap"}, time.Minute, func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
		if ctx.Err() != nil {
			t.Fatal("recovery inherited the expired context")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 {
			t.Fatal("recovery has no independent budget")
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRunBoundedSwapCommandForwardsBudgetAndProcessFailure(t *testing.T) {
	before := swapProcessRunner
	t.Cleanup(func() { swapProcessRunner = before })
	processFailure := errors.New("injected process failure")
	swapProcessRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		deadline, ok := ctx.Deadline()
		if name != "dd" || len(args) != 1 || args[0] != "count=512" || !ok || time.Until(deadline) < 9*time.Minute {
			t.Fatalf("wrong invocation: %s %v %v", name, args, deadline)
		}
		return []byte("disk full"), processFailure
	}
	if err := runBoundedSwapCommand("dd", "count=512"); !errors.Is(err, processFailure) || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("process error lost: %v", err)
	}
}

func TestRollbackFstabAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fstab")
	original := "rootfs / ext4 defaults 0 1\n"
	mustWriteSwapTestFile(t, path, original+"\n/swapfile none swap sw 0 0\n")

	rollbackFstabAppend(path, int64(len(original)))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("fstab after rollback = %q, want %q", data, original)
	}
}

func mustWriteSwapTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
