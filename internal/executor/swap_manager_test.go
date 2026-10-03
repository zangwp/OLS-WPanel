package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
