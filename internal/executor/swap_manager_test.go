package executor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func TestReadSwapEntriesClassifiesAndMarksManagedSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swaps")
	content := "Filename Type Size Used Priority\n/dev/zram0 partition 524284 128 -2\n/dev/vda2 partition 1048572 0 -3\n/swapfile file 1048572 256 -4\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := readSwapEntries(path, "/swapfile", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}
	if entries[0].Type != "zram" || entries[0].Managed {
		t.Fatalf("zram entry = %#v", entries[0])
	}
	if entries[1].Type != "partition" || entries[1].Managed {
		t.Fatalf("partition entry = %#v", entries[1])
	}
	if entries[2].Type != "file" || !entries[2].Managed {
		t.Fatalf("managed file entry = %#v", entries[2])
	}
}

func TestHasManagedSwapEntryRequiresMarkerAndExactPath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fstab")
	if err := os.WriteFile(path, []byte("# user swap\n/swapfile none swap sw 0 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if hasManagedSwapEntry(path, "/swapfile") {
		t.Fatal("unmarked user swap must not be considered panel managed")
	}
	if err := os.WriteFile(path, []byte("# OLS WPanel managed swap\n/swapfile none swap sw 0 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !hasManagedSwapEntry(path, "/swapfile") {
		t.Fatal("exact managed block was not detected")
	}
}

func TestRemoveManagedSwapEntryPreservesOtherEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fstab")
	original := "UUID=root / ext4 defaults 0 1\n# user swap\n/dev/vda2 none swap sw 0 0\n# OLS WPanel managed swap\n/swapfile none swap sw 0 0\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	if err := removeManagedSwapEntry(path, "/swapfile"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !containsAll(got, "UUID=root", "/dev/vda2") || hasManagedSwapEntry(path, "/swapfile") {
		t.Fatalf("fstab after removal = %q", got)
	}
}

func TestValidateSwapSettings(t *testing.T) {
	for _, test := range []struct {
		size, swappiness int64
		valid            bool
	}{
		{512, 10, true},
		{1024, 1, true},
		{8192, 100, true},
		{256, 10, false},
		{513, 10, false},
		{8448, 10, false},
		{1024, 0, false},
		{1024, 101, false},
	} {
		err := validateSwapSettings(test.size, test.swappiness)
		if (err == nil) != test.valid {
			t.Fatalf("validateSwapSettings(%d, %d) error = %v, valid=%v", test.size, test.swappiness, err, test.valid)
		}
	}
}

func TestRecommendedSwappinessUsesWorkloadAndSwapType(t *testing.T) {
	gb := int64(1024 * 1024 * 1024)
	tests := []struct {
		name   string
		status SwapStatus
		sites  int
		want   int
		reason string
	}{
		{name: "unknown workload keeps default", status: SwapStatus{MemoryTotalBytes: 4 * gb, MemoryAvailableBytes: 3 * gb}, want: 60, reason: "system_default"},
		{name: "single wordpress with headroom", status: SwapStatus{MemoryTotalBytes: 4 * gb, MemoryAvailableBytes: 2 * gb, TotalBytes: gb}, sites: 1, want: 10, reason: "single_wordpress"},
		{name: "multiple wordpress keeps default", status: SwapStatus{MemoryTotalBytes: 4 * gb, MemoryAvailableBytes: 2 * gb, TotalBytes: gb}, sites: 3, want: 60, reason: "multiple_wordpress"},
		{name: "memory pressure keeps default", status: SwapStatus{MemoryTotalBytes: 4 * gb, MemoryAvailableBytes: gb / 2, TotalBytes: gb}, sites: 1, want: 60, reason: "memory_pressure"},
		{name: "swap pressure keeps default", status: SwapStatus{MemoryTotalBytes: 4 * gb, MemoryAvailableBytes: 2 * gb, TotalBytes: gb, UsedBytes: gb / 2}, sites: 1, want: 60, reason: "swap_pressure"},
		{name: "zram uses compressed swap", status: SwapStatus{MemoryTotalBytes: 4 * gb, MemoryAvailableBytes: 2 * gb, Entries: []SwapEntry{{Type: "zram"}}}, sites: 2, want: 100, reason: "zram"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, reason := RecommendedSwappiness(test.status, test.sites)
			if got != test.want || reason != test.reason {
				t.Fatalf("RecommendedSwappiness() = %d, %q; want %d, %q", got, reason, test.want, test.reason)
			}
		})
	}
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}

type swapTransactionFixture struct {
	paths     swapManagerPaths
	runtime   int
	newSizeMB int64
	commands  []string
}

func newSwapTransactionFixture(t *testing.T) *swapTransactionFixture {
	t.Helper()
	dir := t.TempDir()
	f := &swapTransactionFixture{runtime: 60, paths: swapManagerPaths{meminfo: filepath.Join(dir, "meminfo"), swaps: filepath.Join(dir, "swaps"), swap: filepath.Join(dir, "swapfile"), fstab: filepath.Join(dir, "fstab"), sysctl: filepath.Join(dir, "swappiness.conf")}}
	files := map[string]string{
		f.paths.meminfo: "MemTotal: 4194304 kB\nMemAvailable: 3145728 kB\n",
		f.paths.swap:    "original swap",
		f.paths.fstab:   "UUID=root / ext4 defaults 0 1\n" + managedSwapMarker + "\n" + f.paths.swap + " none swap sw 0 0\n",
		f.paths.sysctl:  managedSwapMarker + "\nvm.swappiness = 60\n",
	}
	for path, value := range files {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.writeActive(t, true, 512)
	oldPaths, oldCommand, oldStatfs, oldRead := swapPaths, swapCommand, swapStatfs, swapReadSwappiness
	t.Cleanup(func() {
		swapPaths, swapCommand, swapStatfs, swapReadSwappiness = oldPaths, oldCommand, oldStatfs, oldRead
	})
	swapPaths = f.paths
	swapReadSwappiness = func() (int, error) { return f.runtime, nil }
	swapStatfs = func(_ string, stat *syscall.Statfs_t) error {
		stat.Bsize = 4096
		stat.Blocks = 64 * 1024 * 1024 * 1024 / 4096
		stat.Bfree = 32 * 1024 * 1024 * 1024 / 4096
		stat.Bavail = stat.Bfree
		return nil
	}
	swapCommand = f.command(t)
	return f
}

func (f *swapTransactionFixture) writeActive(t *testing.T, active bool, sizeMB int64) {
	t.Helper()
	value := "Filename Type Size Used Priority\n"
	if active {
		value += fmt.Sprintf("%s file %d 16 -2\n", f.paths.swap, sizeMB*1024-4)
	}
	if err := os.WriteFile(f.paths.swaps, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *swapTransactionFixture) command(t *testing.T) func(string, ...string) error {
	return func(name string, args ...string) error {
		f.commands = append(f.commands, name+" "+strings.Join(args, " "))
		switch name {
		case "dd":
			var output string
			for _, arg := range args {
				if strings.HasPrefix(arg, "of=") {
					output = strings.TrimPrefix(arg, "of=")
				}
				if strings.HasPrefix(arg, "count=") {
					f.newSizeMB, _ = strconv.ParseInt(strings.TrimPrefix(arg, "count="), 10, 64)
				}
			}
			return os.WriteFile(output, []byte("replacement swap"), 0600)
		case "mkswap":
			return nil
		case "swapoff":
			f.writeActive(t, false, 0)
		case "swapon":
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			size := int64(512)
			if string(data) == "replacement swap" {
				size = f.newSizeMB
			}
			f.writeActive(t, true, size)
		case "sysctl":
			var value string
			if args[0] == "-w" {
				_, value, _ = strings.Cut(args[1], "=")
			} else {
				data, err := os.ReadFile(args[1])
				if err != nil {
					return err
				}
				_, value, _ = strings.Cut(strings.TrimSpace(string(data)), "vm.swappiness = ")
			}
			f.runtime, _ = strconv.Atoi(value)
		default:
			t.Fatalf("unexpected command %s %v", name, args)
		}
		return nil
	}
}

func TestManagedSwapChecksPeakSpaceForGrowthAndShrink(t *testing.T) {
	for _, shrink := range []bool{false, true} {
		t.Run(map[bool]string{false: "growth", true: "shrink"}[shrink], func(t *testing.T) {
			f := newSwapTransactionFixture(t)
			free := int64(8*1024*1024*1024 + 768*1024*1024)
			target := int64(1024)
			if shrink {
				f.writeActive(t, true, 1024)
				target = 512
				free = 1024 * 1024 * 1024
			}
			swapStatfs = func(_ string, stat *syscall.Statfs_t) error {
				stat.Bsize = 4096
				stat.Blocks = 32 * 1024 * 1024 * 1024 / 4096
				stat.Bfree = uint64(free / 4096)
				stat.Bavail = stat.Bfree
				return nil
			}
			if _, err := applyManagedSwapLocked(target, 10, f.paths); err == nil {
				t.Fatal("accepted insufficient peak disk space")
			}
			if len(f.commands) != 0 {
				t.Fatalf("mutation ran before space check: %v", f.commands)
			}
		})
	}
}

func TestManagedSwapRollbackRestoresFileFstabAndSwappiness(t *testing.T) {
	for _, failStage := range []string{"new swapon", "swappiness apply", "swappiness verify"} {
		t.Run(failStage, func(t *testing.T) {
			f := newSwapTransactionFixture(t)
			beforeFstab, _ := os.ReadFile(f.paths.fstab)
			beforeConfig, _ := os.ReadFile(f.paths.sysctl)
			base := swapCommand
			injected := false
			swapCommand = func(name string, args ...string) error {
				if !injected && failStage == "new swapon" && name == "swapon" {
					injected = true
					return errors.New("injected new swapon failure")
				}
				if err := base(name, args...); err != nil {
					return err
				}
				if !injected && name == "sysctl" && args[0] == "-p" {
					injected = true
					if failStage == "swappiness apply" {
						return errors.New("injected sysctl failure after change")
					}
					if failStage == "swappiness verify" {
						f.runtime = 11
					}
				}
				return nil
			}
			status, err := applyManagedSwapLocked(1024, 10, f.paths)
			if err == nil || !injected {
				t.Fatalf("err=%v injected=%v", err, injected)
			}
			file, _ := os.ReadFile(f.paths.swap)
			fstab, _ := os.ReadFile(f.paths.fstab)
			config, _ := os.ReadFile(f.paths.sysctl)
			if string(file) != "original swap" || string(fstab) != string(beforeFstab) || string(config) != string(beforeConfig) || f.runtime != 60 || !status.ManagedActive {
				t.Fatalf("rollback incomplete: file=%q fstab=%q config=%q runtime=%d status=%+v err=%v", file, fstab, config, f.runtime, status, err)
			}
			backups, _ := filepath.Glob(filepath.Join(filepath.Dir(f.paths.swap), ".ols-wpanel-swap-backup-*"))
			if len(backups) != 0 {
				t.Fatalf("unnecessary backups: %v", backups)
			}
		})
	}
}

func TestManagedSwapRollbackFailurePreservesBackupAndReportsState(t *testing.T) {
	f := newSwapTransactionFixture(t)
	base := swapCommand
	newActive := false
	swapCommand = func(name string, args ...string) error {
		if name == "swapoff" && newActive {
			return errors.New("injected rollback swapoff failure")
		}
		if err := base(name, args...); err != nil {
			return err
		}
		if name == "swapon" {
			newActive = true
		}
		if name == "sysctl" && args[0] == "-p" {
			return errors.New("injected apply failure")
		}
		return nil
	}
	status, err := applyManagedSwapLocked(1024, 10, f.paths)
	if err == nil || !containsAll(err.Error(), "新 Swap 无法停用", "备份保留于") || !status.ManagedActive {
		t.Fatalf("err=%v status=%+v", err, status)
	}
	backups, _ := filepath.Glob(filepath.Join(filepath.Dir(f.paths.swap), ".ols-wpanel-swap-backup-*"))
	if len(backups) != 1 {
		t.Fatalf("backups=%v", backups)
	}
	data, _ := os.ReadFile(backups[0])
	if string(data) != "original swap" {
		t.Fatal("lost original Swap")
	}
}

func TestManagedSwappinessRejectsForeignConfiguration(t *testing.T) {
	f := newSwapTransactionFixture(t)
	const foreign = "# administrator policy\nvm.swappiness = 20\n"
	if err := os.WriteFile(f.paths.sysctl, []byte(foreign), 0600); err != nil {
		t.Fatal(err)
	}
	if err := setManagedSwappiness(10, f.paths.sysctl); err == nil {
		t.Fatal("overwrote administrator configuration")
	}
	if _, err := applyManagedSwapLocked(1024, 10, f.paths); err == nil {
		t.Fatal("resized before checking administrator configuration")
	}
	data, _ := os.ReadFile(f.paths.sysctl)
	if string(data) != foreign || len(f.commands) != 0 {
		t.Fatalf("foreign configuration changed: %q %v", data, f.commands)
	}
}

func TestManagedSwapRefusesUnknownMemoryAndDeleteKeepsSystemPolicy(t *testing.T) {
	for _, memory := range []string{"", "MemAvailable: 0 kB\n", "MemAvailable: invalid kB\n"} {
		t.Run(memory, func(t *testing.T) {
			f := newSwapTransactionFixture(t)
			f.writeActive(t, true, 1024)
			os.WriteFile(f.paths.meminfo, []byte("MemTotal: 4194304 kB\n"+memory), 0600)
			if _, err := applyManagedSwapLocked(512, 10, f.paths); err == nil {
				t.Fatal("shrunk Swap without known memory")
			}
			if _, err := RemoveManagedSwap("REMOVE SWAP"); err == nil {
				t.Fatal("deleted Swap without known memory")
			}
			if len(f.commands) != 0 {
				t.Fatalf("mutation on unknown memory: %v", f.commands)
			}
		})
	}
	t.Run("delete preserves global swappiness", func(t *testing.T) {
		f := newSwapTransactionFixture(t)
		f.runtime = 10
		const policy = "# OLS WPanel managed swap\nvm.swappiness = 10\n"
		os.WriteFile(f.paths.sysctl, []byte(policy), 0600)
		status, err := RemoveManagedSwap("REMOVE SWAP")
		if err != nil {
			t.Fatal(err)
		}
		if status.ManagedActive || status.ManagedFile || f.runtime != 10 {
			t.Fatalf("status=%+v runtime=%d", status, f.runtime)
		}
		data, _ := os.ReadFile(f.paths.sysctl)
		if string(data) != policy {
			t.Fatal("deleting a file changed system Swap policy")
		}
	})
}

func TestSwapWorkloadKnownRequiresSuccessfulQuery(t *testing.T) {
	original := database.DB
	t.Cleanup(func() { database.DB = original })
	database.DB = nil
	if count, known := readActiveWordPressSiteCount(); count != 0 || known {
		t.Fatalf("nil database: %d %t", count, known)
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	database.DB = db
	if count, known := readActiveWordPressSiteCount(); count != 0 || known {
		t.Fatalf("missing schema considered known: %d %t", count, known)
	}
	if _, err := db.Exec("CREATE TABLE websites (site_type TEXT, status TEXT)"); err != nil {
		t.Fatal(err)
	}
	if count, known := readActiveWordPressSiteCount(); count != 0 || !known {
		t.Fatalf("empty workload should be known: %d %t", count, known)
	}
	if _, err := db.Exec("INSERT INTO websites VALUES ('wordpress', 'active'), ('wordpress', 'paused'), ('static', 'active')"); err != nil {
		t.Fatal(err)
	}
	if count, known := readActiveWordPressSiteCount(); count != 1 || !known {
		t.Fatalf("wrong active WordPress count: %d %t", count, known)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if count, known := readActiveWordPressSiteCount(); count != 0 || known {
		t.Fatalf("closed database considered known: %d %t", count, known)
	}
}

func TestNewSwapRollbackRemovesOnlyItsChanges(t *testing.T) {
	f := newSwapTransactionFixture(t)
	if err := os.Remove(f.paths.swap); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.paths.sysctl); err != nil {
		t.Fatal(err)
	}
	const originalFstab = "UUID=root / ext4 defaults 0 1\n/dev/zram0 none swap sw 0 0\n"
	os.WriteFile(f.paths.fstab, []byte(originalFstab), 0600)
	f.writeActive(t, false, 0)
	base := swapCommand
	swapCommand = func(name string, args ...string) error {
		if err := base(name, args...); err != nil {
			return err
		}
		if name == "sysctl" && args[0] == "-p" {
			return errors.New("injected final parameter failure")
		}
		return nil
	}
	status, err := applyManagedSwapLocked(1024, 10, f.paths)
	if err == nil || status.ManagedFile || status.ManagedActive || f.runtime != 60 {
		t.Fatalf("status=%+v err=%v runtime=%d", status, err, f.runtime)
	}
	if _, err := os.Stat(f.paths.swap); !os.IsNotExist(err) {
		t.Fatal("new Swap retained after successful rollback")
	}
	if _, err := os.Stat(f.paths.sysctl); !os.IsNotExist(err) {
		t.Fatal("new parameter file retained after successful rollback")
	}
	fstab, _ := os.ReadFile(f.paths.fstab)
	if string(fstab) != originalFstab {
		t.Fatalf("fstab not restored: %q", fstab)
	}
}

func TestSwapRejectsAmbiguousFstabAndUnmanagedReservedPath(t *testing.T) {
	f := newSwapTransactionFixture(t)
	owned, _ := os.ReadFile(f.paths.fstab)
	os.WriteFile(f.paths.fstab, append(owned, []byte(f.paths.swap+" none swap sw 0 0\n")...), 0600)
	if hasManagedSwapEntry(f.paths.fstab, f.paths.swap) {
		t.Fatal("duplicate references accepted as owned")
	}
	if status, err := getSwapStatus(f.paths); err != nil || status.CanManage {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	os.Remove(f.paths.swap)
	f.writeActive(t, false, 0)
	os.WriteFile(f.paths.fstab, []byte(f.paths.swap+" none swap sw 0 0\n"), 0600)
	if _, err := applyManagedSwapLocked(1024, 10, f.paths); err == nil {
		t.Fatal("took over administrator-reserved path")
	}
	if len(f.commands) != 0 {
		t.Fatalf("mutated an unowned path: %v", f.commands)
	}
	os.WriteFile(f.paths.fstab, []byte(managedSwapMarker), 0600)
	if hasManagedSwapEntry(f.paths.fstab, f.paths.swap) {
		t.Fatal("incomplete marker accepted")
	}
}

func TestSwapRechecksMemoryAfterAllocatingReplacement(t *testing.T) {
	f := newSwapTransactionFixture(t)
	base := swapCommand
	swapCommand = func(name string, args ...string) error {
		if err := base(name, args...); err != nil {
			return err
		}
		if name == "mkswap" {
			return os.WriteFile(f.paths.meminfo, []byte("MemTotal: 4194304 kB\nMemAvailable: 0 kB\n"), 0600)
		}
		return nil
	}
	if _, err := applyManagedSwapLocked(1024, 10, f.paths); err == nil {
		t.Fatal("stopped old Swap after memory headroom disappeared")
	}
	for _, command := range f.commands {
		if strings.HasPrefix(command, "swapoff") {
			t.Fatalf("unsafe swapoff: %v", f.commands)
		}
	}
	data, _ := os.ReadFile(f.paths.swap)
	if string(data) != "original swap" {
		t.Fatal("changed original despite failed second memory check")
	}
}

func TestSwapCommandPartialEffectsUseActualStateForRecovery(t *testing.T) {
	for _, stage := range []string{"original swapoff", "new swapon", "rollback swapoff", "delete swapoff"} {
		t.Run(stage, func(t *testing.T) {
			f := newSwapTransactionFixture(t)
			fstabBefore, _ := os.ReadFile(f.paths.fstab)
			base := swapCommand
			injected := false
			stops := 0
			swapCommand = func(name string, args ...string) error {
				if err := base(name, args...); err != nil {
					return err
				}
				if name == "swapoff" {
					stops++
				}
				if !injected && ((name == "swapoff" && stops == 1 && (stage == "original swapoff" || stage == "delete swapoff")) || (name == "swapon" && stage == "new swapon") || (name == "swapoff" && stops == 2 && stage == "rollback swapoff")) {
					injected = true
					return context.DeadlineExceeded
				}
				if stage == "rollback swapoff" && name == "sysctl" && args[0] == "-p" {
					return errors.New("trigger recovery after activation")
				}
				return nil
			}
			var status SwapStatus
			var err error
			if stage == "delete swapoff" {
				status, err = RemoveManagedSwap("REMOVE SWAP")
			} else {
				status, err = applyManagedSwapLocked(1024, 10, f.paths)
			}
			file, _ := os.ReadFile(f.paths.swap)
			fstabAfter, _ := os.ReadFile(f.paths.fstab)
			if !errors.Is(err, context.DeadlineExceeded) || !injected || !status.ManagedActive || string(file) != "original swap" || string(fstabAfter) != string(fstabBefore) || f.runtime != 60 {
				t.Fatalf("partial command was not recovered: err=%v injected=%t status=%+v file=%q fstab=%q runtime=%d", err, injected, status, file, fstabAfter, f.runtime)
			}
			backups, _ := filepath.Glob(filepath.Join(filepath.Dir(f.paths.swap), ".ols-wpanel-swap-backup-*"))
			if len(backups) != 0 {
				t.Fatalf("recovered transaction left backups: %v", backups)
			}
		})
	}
}

func TestSwapSuccessfulExitWithoutStateChangeDoesNotEraseFiles(t *testing.T) {
	for _, stage := range []string{"original swapoff", "new swapon"} {
		t.Run(stage, func(t *testing.T) {
			f := newSwapTransactionFixture(t)
			base := swapCommand
			injected := false
			swapCommand = func(name string, args ...string) error {
				if !injected && ((name == "swapoff" && stage == "original swapoff") || (name == "swapon" && stage == "new swapon")) {
					injected = true
					return nil
				}
				return base(name, args...)
			}
			status, err := applyManagedSwapLocked(1024, 10, f.paths)
			file, _ := os.ReadFile(f.paths.swap)
			if err == nil || !injected || !status.ManagedActive || string(file) != "original swap" {
				t.Fatalf("false success accepted: err=%v injected=%t status=%+v file=%q", err, injected, status, file)
			}
		})
	}
}

func TestSwapUnknownActivationStateKeepsBothFiles(t *testing.T) {
	f := newSwapTransactionFixture(t)
	base := swapCommand
	activationAttempted := false
	swapCommand = func(name string, args ...string) error {
		if activationAttempted && name == "swapoff" {
			return context.DeadlineExceeded
		}
		if err := base(name, args...); err != nil {
			return err
		}
		if name == "swapon" {
			activationAttempted = true
			mustWriteSwapTestFile(t, f.paths.swaps, "Filename Type Size Used Priority\n"+f.paths.swap+" file invalid 0 -2\n")
			return context.DeadlineExceeded
		}
		return nil
	}
	_, err := applyManagedSwapLocked(1024, 10, f.paths)
	if !errors.Is(err, context.DeadlineExceeded) || !containsAll(err.Error(), "保留文件", "备份保留于", "无法确认") {
		t.Fatalf("unknown state hidden: %v", err)
	}
	file, _ := os.ReadFile(f.paths.swap)
	backups, _ := filepath.Glob(filepath.Join(filepath.Dir(f.paths.swap), ".ols-wpanel-swap-backup-*"))
	if string(file) != "replacement swap" || len(backups) != 1 {
		t.Fatalf("potentially active files removed: file=%q backups=%v", file, backups)
	}
	original, _ := os.ReadFile(backups[0])
	if string(original) != "original swap" {
		t.Fatal("original backup lost")
	}
}

func TestSwapMalformedRunningStateIsUnknown(t *testing.T) {
	for _, content := range []string{"", "wrong header\n", "Filename Type Size Used Priority\n/swapfile file invalid 0 -2\n", "Filename Type Size Used Priority\n/swapfile file 1024\n", "Filename Type Size Used Priority\n/swapfile file 1024 1025 -2\n"} {
		t.Run(content, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "swaps")
			mustWriteSwapTestFile(t, path, content)
			if _, err := readSwapPathActive(path, "/swapfile"); err == nil {
				t.Fatal("malformed state treated as inactive")
			}
		})
	}
}

func TestSwapHeaderPageDoesNotTriggerSameCapacityRebuild(t *testing.T) {
	for _, action := range []string{"same capacity", "recommendation already met", "recommendation needs growth"} {
		t.Run(action, func(t *testing.T) {
			f := newSwapTransactionFixture(t)
			f.writeActive(t, true, 1024)
			if action == "recommendation needs growth" {
				f.writeActive(t, true, 512)
			}
			var status SwapStatus
			var err error
			if action == "same capacity" {
				status, err = applyManagedSwapLocked(1024, 10, f.paths)
			} else {
				status, err = ApplyRecommendedSwap()
			}
			if err != nil || !status.ManagedActive || !status.RecommendationSatisfied {
				t.Fatalf("header caused invalid target: status=%+v err=%v", status, err)
			}
			if action != "recommendation needs growth" {
				for _, command := range f.commands {
					if strings.HasPrefix(command, "swapoff ") || strings.HasPrefix(command, "dd ") {
						t.Fatalf("unnecessary rebuild: %v", f.commands)
					}
				}
			} else if f.newSizeMB != 1024 {
				t.Fatalf("complete target not rounded: %dMB", f.newSizeMB)
			}
		})
	}
}
