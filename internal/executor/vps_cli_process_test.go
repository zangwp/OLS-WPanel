package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func vpsCLIStatFixture(pid int, name string, user, system, start uint64, rss int64) string {
	fields := strings.Fields("S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0")
	fields[11], fields[12] = strconv.FormatUint(user, 10), strconv.FormatUint(system, 10)
	fields[19], fields[21] = strconv.FormatUint(start, 10), strconv.FormatInt(rss, 10)
	return fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(fields, " "))
}

func TestVPSCLIProcessStatParsing(t *testing.T) {
	stat, err := parseVPSCLIProcessStat(vpsCLIStatFixture(42, "worker ) (a)\n\x1b\x00", 75, 25, 123456, 7), 42)
	if err != nil || !stat.valid || stat.pid != 42 || stat.ticks != 100 || stat.startTime != 123456 || stat.rssPages != 7 || stat.name != "worker ) (a)" {
		t.Fatalf("unexpected stat: %+v, %v", stat, err)
	}
	for _, input := range []string{
		"42 worker 1 2", "42 (worker) S 0", vpsCLIStatFixture(43, "worker", 1, 0, 1, 1),
		vpsCLIStatFixture(42, "worker", math.MaxUint64, 1, 1, 1), vpsCLIStatFixture(42, "worker", 1, 0, 1, -1),
	} {
		if _, err := parseVPSCLIProcessStat(input, 42); err == nil {
			t.Fatalf("accepted invalid stat: %q", input)
		}
	}
}

func TestVPSCLICPUAndMemoryParsing(t *testing.T) {
	data := "cpu 10 2 3 70 1 2 1 1 900 800\ncpu0 1\ncpu1 1\nintr 123\n"
	ticks, cores, err := parseVPSCLICPUTicks(data)
	if err != nil || ticks != 90 || cores != 2 {
		t.Fatalf("guest double counting or wrong cores: %d %d %v", ticks, cores, err)
	}
	for _, input := range []string{"", "cpu 1 2\ncpu0 1", "cpu 1 2 3 4 5 6 7 8", "cpu 18446744073709551615 1 0 0 0 0 0 0\ncpu0 1"} {
		if _, _, err := parseVPSCLICPUTicks(input); err == nil {
			t.Fatalf("accepted invalid aggregate %q", input)
		}
	}
	if got := parseVPSCLIMemoryTotal("MemFree: 10 kB\nMemTotal: 4096 kB\n"); got != 4194304 {
		t.Fatalf("wrong MemTotal: %d", got)
	}
	for _, input := range []string{"", "MemTotal: -1 kB", "MemTotal: 1 MB", "MemTotal: 18446744073709551615 kB"} {
		if got := parseVPSCLIMemoryTotal(input); got != 0 {
			t.Fatalf("invalid MemTotal %q: %d", input, got)
		}
	}
}

func TestVPSCLIProcessWindowUsesOneCoreAndRejectsPIDReuse(t *testing.T) {
	at := time.Unix(1_000, 0)
	first := vpsCLIProcessSnapshot{at: at, ticks: 1000, cpuCount: 2, processes: map[int]vpsCLIProcessStat{}}
	second := vpsCLIProcessSnapshot{at: at.Add(300 * time.Millisecond), ticks: 1100, cpuCount: 2, memoryBytes: 4096000, processes: map[int]vpsCLIProcessStat{}}
	for _, row := range []struct {
		pid   int
		start uint64
		ticks uint64
		rss   int64
	}{{1, 1, 10, 10}, {2, 1, 10, 100}, {4, 1, 1000, 1}, {5, 1, 10, 1}, {6, 1, 1, 1}} {
		first.processes[row.pid] = vpsCLIProcessStat{pid: row.pid, name: "safe", valid: true, ticks: row.ticks, startTime: row.start, rssPages: row.rss}
	}
	for _, row := range []struct {
		pid   int
		start uint64
		ticks uint64
		rss   int64
	}{{1, 1, 85, 10}, {2, 1, 20, 100}, {3, 2, 90, 2}, {4, 2, 1100, 1}, {6, 1, 1, 1}} {
		second.processes[row.pid] = vpsCLIProcessStat{pid: row.pid, name: "safe", valid: true, ticks: row.ticks, startTime: row.start, rssPages: row.rss}
	}
	status := summarizeVPSCLIProcesses(first, second, 4096)
	if status.CPUBasis != "one_core" || status.CPUCount != 2 || status.SampleSeconds != .3 || !status.Incomplete {
		t.Fatalf("invalid sample identity: %+v", status)
	}
	if got := status.TopCPU[0]; got.PID != 1 || got.CPUPercent == nil || *got.CPUPercent != 150 {
		t.Fatalf("must use window delta, allow >100%%: %+v", got)
	}
	if got := status.TopMemory[0]; got.PID != 2 || got.RSSBytes == nil || *got.RSSBytes != 409600 || got.MemoryPercent == nil || *got.MemoryPercent != 10 {
		t.Fatalf("wrong RSS/physical memory: %+v", got)
	}
	for _, item := range status.TopCPU {
		if item.PID == 5 {
			t.Fatal("exited process remained in current ranking")
		}
		if (item.PID == 3 || item.PID == 4) && item.CPUPercent != nil {
			t.Fatalf("new/reused PID received invented CPU: %+v", item)
		}
		if item.PID == 6 && (item.CPUPercent == nil || *item.CPUPercent != 0) {
			t.Fatal("idle CPU should be measured zero, not unknown")
		}
	}
}

func TestVPSCLIProcessTopTenAndUnknownTotals(t *testing.T) {
	first := vpsCLIProcessSnapshot{at: time.Unix(1, 0), cpuCount: 1, ticks: 1, processes: map[int]vpsCLIProcessStat{}}
	second := vpsCLIProcessSnapshot{at: time.Unix(2, 0), cpuCount: 2, ticks: 101, processes: map[int]vpsCLIProcessStat{}, limited: true, unreadable: 1}
	for pid := 1; pid <= 20; pid++ {
		second.processes[pid] = vpsCLIProcessStat{pid: pid, name: "safe", valid: true, startTime: 1, rssPages: int64(pid)}
	}
	status := summarizeVPSCLIProcesses(first, second, 4096)
	if !status.Incomplete || len(status.Warnings) < 3 || len(status.TopCPU) != 10 || len(status.TopMemory) != 10 || status.TopMemory[0].PID != 20 {
		t.Fatalf("partial or bounded ranking wrong: %+v", status)
	}
	for _, item := range status.TopCPU {
		if item.CPUPercent != nil || item.MemoryPercent != nil {
			t.Fatal("unknown totals must not become zero percentages")
		}
	}
	data, err := json.Marshal(status)
	if err != nil || !strings.Contains(string(data), `"cpu_percent":null`) || !strings.Contains(string(data), `"memory_percent":null`) {
		t.Fatalf("nullable JSON contract: %s, %v", data, err)
	}
}

func writeVPSCLIProcessFixture(t *testing.T, root string, pid int, ticks uint64) {
	t.Helper()
	directory := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "stat"), []byte(vpsCLIStatFixture(pid, "fixture", ticks, 0, 1, 7)), 0600); err != nil {
		t.Fatal(err)
	}
}

func writeVPSCLISystemFixture(t *testing.T, root string, ticks int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte(fmt.Sprintf("cpu %d 0 0 0 0 0 0 0\ncpu0 0\nintr 0\n", ticks)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "meminfo"), []byte("MemTotal: 4096 kB\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestVPSCLIProcessActualFileSamplingAndExit(t *testing.T) {
	root := t.TempDir()
	writeVPSCLISystemFixture(t, root, 100)
	writeVPSCLIProcessFixture(t, root, 11, 10)
	writeVPSCLIProcessFixture(t, root, 12, 10)
	waited := false
	status, err := inspectVPSCLIProcessesFrom(context.Background(), root, vpsCLIProcessInterval, func(ctx context.Context, duration time.Duration) error {
		waited = true
		if duration != 300*time.Millisecond {
			t.Fatalf("unexpected sampling interval: %v", duration)
		}
		writeVPSCLISystemFixture(t, root, 200)
		writeVPSCLIProcessFixture(t, root, 11, 60)
		if err := os.Remove(filepath.Join(root, "12", "stat")); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if err != nil || !waited || len(status.TopCPU) != 1 || *status.TopCPU[0].CPUPercent != 50 || status.Incomplete {
		t.Fatalf("window/normal exit failure: %+v, %v", status, err)
	}
}

func TestVPSCLIProcessBudgetsAndPartialReads(t *testing.T) {
	root := t.TempDir()
	writeVPSCLISystemFixture(t, root, 100)
	for pid := 1; pid <= 3; pid++ {
		writeVPSCLIProcessFixture(t, root, pid, 10)
	}
	snapshot, err := readVPSCLIProcessSnapshot(context.Background(), root, 2)
	if err != nil || !snapshot.limited || len(snapshot.processes) != 2 {
		t.Fatalf("process budget not enforced: %+v %v", snapshot, err)
	}
	if err := os.WriteFile(filepath.Join(root, "2", "stat"), []byte(strings.Repeat("x", vpsCLIProcessReadMax+1)), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err = readVPSCLIProcessSnapshot(context.Background(), root, 10)
	if err != nil || snapshot.unreadable != 1 || snapshot.processes[2].valid {
		t.Fatalf("unreadable must become unknown: %+v %v", snapshot, err)
	}
	if err := os.Remove(filepath.Join(root, "meminfo")); err != nil {
		t.Fatal(err)
	}
	snapshot, err = readVPSCLIProcessSnapshot(context.Background(), root, 10)
	if err != nil || snapshot.memoryBytes != 0 || len(snapshot.warnings) == 0 {
		t.Fatalf("missing memory total must be explicit: %+v %v", snapshot, err)
	}
}

func TestVPSCLIProcessCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := inspectVPSCLIProcessesFrom(ctx, t.TempDir(), time.Second, waitVPSCLIProcessSample); !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled sample: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if err := waitVPSCLIProcessSample(ctx, time.Minute); !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("wait ignored cancellation: %v", err)
	}
}

func TestVPSCLIProcessLargeInterruptTailAndUnknownRSS(t *testing.T) {
	root := t.TempDir()
	writeVPSCLISystemFixture(t, root, 100)
	data := "cpu 100 0 0 0 0 0 0 0\ncpu0 0\nintr " + strings.Repeat("1 ", 100_000)
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	writeVPSCLIProcessFixture(t, root, 1, 1)
	snapshot, err := readVPSCLIProcessSnapshot(context.Background(), root, 10)
	if err != nil || snapshot.cpuCount != 1 || snapshot.ticks != 100 || len(snapshot.warnings) != 0 {
		t.Fatalf("large non-CPU tail invalidated CPU rows: %+v %v", snapshot, err)
	}
	snapshot.processes[1] = vpsCLIProcessStat{pid: 1, name: "overflow", valid: true, rssPages: math.MaxInt64}
	second := snapshot
	second.ticks++
	status := summarizeVPSCLIProcesses(snapshot, second, 4096)
	if !status.Incomplete || status.TopMemory[0].RSSBytes != nil {
		t.Fatalf("invalid RSS must be unknown: %+v", status)
	}
	dataBytes, err := json.Marshal(status)
	if err != nil || !strings.Contains(string(dataBytes), `"rss_bytes":null`) {
		t.Fatalf("RSS null JSON missing: %s %v", dataBytes, err)
	}
}

func TestVPSCLIProcessRSSIndependentOfMemoryTotal(t *testing.T) {
	first := vpsCLIProcessSnapshot{at: time.Unix(1, 0), cpuCount: 1, ticks: 100, processes: map[int]vpsCLIProcessStat{}}
	second := vpsCLIProcessSnapshot{at: time.Unix(2, 0), cpuCount: 1, ticks: 200, processes: map[int]vpsCLIProcessStat{}}
	for _, pid := range []int{1, 2} {
		stat := vpsCLIProcessStat{pid: pid, name: "fixture", valid: true, ticks: 10, startTime: 1, rssPages: int64(pid - 1)}
		first.processes[pid], second.processes[pid] = stat, stat
	}
	status := summarizeVPSCLIProcesses(first, second, 4096)
	for _, item := range status.TopCPU {
		if item.RSSBytes == nil || *item.RSSBytes != int64(item.PID-1)*4096 || item.MemoryPercent != nil {
			t.Fatalf("RSS must remain known independently of MemTotal: %+v", item)
		}
	}
}

func TestVPSCLIProcessRejectsTruncatedCPUList(t *testing.T) {
	root := t.TempDir()
	writeVPSCLISystemFixture(t, root, 100)
	var data strings.Builder
	data.WriteString("cpu 100 0 0 0 0 0 0 0\n")
	for i := range 10000 {
		fmt.Fprintf(&data, "cpu%d 0 0 0 0 0 0 0 0\n", i)
	}
	data.WriteString("intr 0\n")
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte(data.String()), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readVPSCLIProcessSnapshot(context.Background(), root, 10)
	if err != nil || snapshot.cpuCount != 0 || len(snapshot.warnings) == 0 {
		t.Fatalf("truncated CPU rows cannot identify a smaller host: %+v %v", snapshot, err)
	}
}

func TestVPSCLIProcessLinuxSmoke(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real procfs smoke requires Linux")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := inspectVPSCLIProcesses(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status := result.(vpsCLIProcessStatus)
	if status.CPUCount < 1 || status.SampleSeconds < .3 || len(status.TopCPU) < 1 || len(status.TopCPU) > 10 || len(status.TopMemory) != len(status.TopCPU) {
		t.Fatalf("invalid real procfs summary: %+v", status)
	}
	if _, err := time.Parse(time.RFC3339Nano, status.SampledAt); err != nil {
		t.Fatal(err)
	}
	for _, item := range status.TopCPU {
		if item.PID < 1 || strings.ContainsAny(item.Name, "\x1b\n\r\x00") {
			t.Fatalf("invalid process identity: %+v", item)
		}
		if item.CPUPercent != nil && (math.IsNaN(*item.CPUPercent) || math.IsInf(*item.CPUPercent, 0) || *item.CPUPercent < 0) {
			t.Fatalf("invalid CPU percentage: %+v", item)
		}
		if item.MemoryPercent != nil && (math.IsNaN(*item.MemoryPercent) || math.IsInf(*item.MemoryPercent, 0) || *item.MemoryPercent < 0) {
			t.Fatalf("invalid memory percentage: %+v", item)
		}
		if item.RSSBytes != nil && *item.RSSBytes < 0 {
			t.Fatalf("invalid resident memory: %+v", item)
		}
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := inspectVPSCLIProcesses(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("real entry ignored cancellation: %v", err)
	}
}
