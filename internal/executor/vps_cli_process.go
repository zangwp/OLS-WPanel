package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	vpsCLIProcessLimit    = 8192
	vpsCLIProcessReadMax  = 8192
	vpsCLIProcessInterval = 300 * time.Millisecond
)

type vpsCLIProcess struct {
	PID           int      `json:"pid"`
	Name          string   `json:"name"`
	CPUPercent    *float64 `json:"cpu_percent"`
	MemoryPercent *float64 `json:"memory_percent"`
	RSSBytes      *int64   `json:"rss_bytes"`
}

type vpsCLIProcessStatus struct {
	SampledAt     string          `json:"sampled_at"`
	SampleSeconds float64         `json:"sample_seconds"`
	CPUBasis      string          `json:"cpu_basis"`
	CPUCount      int             `json:"cpu_count"`
	Incomplete    bool            `json:"incomplete"`
	Warnings      []string        `json:"warnings"`
	TopCPU        []vpsCLIProcess `json:"top_cpu"`
	TopMemory     []vpsCLIProcess `json:"top_memory"`
}

type vpsCLIProcessStat struct {
	pid       int
	name      string
	ticks     uint64
	startTime uint64
	rssPages  int64
	valid     bool
}

type vpsCLIProcessSnapshot struct {
	at          time.Time
	ticks       uint64
	cpuCount    int
	memoryBytes uint64
	processes   map[int]vpsCLIProcessStat
	warnings    []string
	unreadable  int
	limited     bool
}

// inspectVPSCLIProcesses reads only procfs; it never reads command arguments,
// environment, database state, or credentials and never starts a process.
func inspectVPSCLIProcesses(ctx context.Context) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return inspectVPSCLIProcessesFrom(ctx, "/proc", vpsCLIProcessInterval, waitVPSCLIProcessSample)
}

func waitVPSCLIProcessSample(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func inspectVPSCLIProcessesFrom(ctx context.Context, root string, interval time.Duration, wait func(context.Context, time.Duration) error) (vpsCLIProcessStatus, error) {
	first, err := readVPSCLIProcessSnapshot(ctx, root, vpsCLIProcessLimit)
	if err != nil {
		return vpsCLIProcessStatus{}, err
	}
	if err := wait(ctx, interval); err != nil {
		return vpsCLIProcessStatus{}, err
	}
	second, err := readVPSCLIProcessSnapshot(ctx, root, vpsCLIProcessLimit)
	if err != nil {
		return vpsCLIProcessStatus{}, err
	}
	return summarizeVPSCLIProcesses(first, second, int64(os.Getpagesize())), nil
}

func readVPSCLIProcessFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, vpsCLIProcessReadMax+1))
	if err == nil && len(data) > vpsCLIProcessReadMax {
		err = errors.New("procfs record exceeds read budget")
	}
	return data, err
}

func readVPSCLICPUFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// CPU rows precede intr, whose line can be huge. A bounded prefix is enough
	// only when the parser has observed the end of all CPU rows.
	return io.ReadAll(io.LimitReader(f, 64*1024))
}

func readVPSCLIProcessSnapshot(ctx context.Context, root string, limit int) (vpsCLIProcessSnapshot, error) {
	snapshot := vpsCLIProcessSnapshot{at: time.Now(), processes: make(map[int]vpsCLIProcessStat), warnings: []string{}}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	data, err := readVPSCLICPUFile(filepath.Join(root, "stat"))
	if err == nil {
		snapshot.ticks, snapshot.cpuCount, err = parseVPSCLICPUTicks(string(data))
	}
	if err != nil {
		snapshot.warnings = append(snapshot.warnings, "CPU 总量读取失败，CPU 百分比未知。")
	}
	data, err = readVPSCLIProcessFile(filepath.Join(root, "meminfo"))
	if err == nil {
		snapshot.memoryBytes = parseVPSCLIMemoryTotal(string(data))
	}
	if err != nil || snapshot.memoryBytes == 0 {
		snapshot.warnings = append(snapshot.warnings, "物理内存总量读取失败，内存百分比未知。")
	}
	directory, err := os.Open(root)
	if err != nil {
		return snapshot, fmt.Errorf("无法读取进程目录: %w", err)
	}
	defer directory.Close()
	entriesRead := 0
	for {
		if err := ctx.Err(); err != nil {
			return snapshot, err
		}
		entries, readErr := directory.ReadDir(256)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return snapshot, err
			}
			entriesRead++
			if entriesRead > 32768 {
				snapshot.limited = true
				return snapshot, nil
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid <= 0 || !entry.IsDir() {
				continue
			}
			if len(snapshot.processes) >= limit {
				snapshot.limited = true
				return snapshot, nil
			}
			data, err := readVPSCLIProcessFile(filepath.Join(root, entry.Name(), "stat"))
			if errors.Is(err, os.ErrNotExist) {
				continue // Processes commonly exit between directory and stat reads.
			}
			stat := vpsCLIProcessStat{pid: pid, name: "未知"}
			if err == nil {
				stat, err = parseVPSCLIProcessStat(string(data), pid)
			}
			if err != nil {
				snapshot.unreadable++
			}
			snapshot.processes[pid] = stat
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return snapshot, fmt.Errorf("进程目录读取不完整: %w", readErr)
		}
	}
	return snapshot, ctx.Err()
}

// /proc/PID/stat's parenthesized comm may itself contain spaces and ')'.
func parseVPSCLIProcessStat(data string, expectedPID int) (vpsCLIProcessStat, error) {
	unknown := vpsCLIProcessStat{pid: expectedPID, name: "未知"}
	open, close := strings.IndexByte(data, '('), strings.LastIndexByte(data, ')')
	if open < 1 || close <= open {
		return unknown, errors.New("invalid process stat name")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(data[:open]))
	if err != nil || pid != expectedPID {
		return unknown, errors.New("process stat PID mismatch")
	}
	fields := strings.Fields(data[close+1:])
	if len(fields) < 22 {
		return unknown, errors.New("incomplete process stat")
	}
	user, e1 := strconv.ParseUint(fields[11], 10, 64)
	system, e2 := strconv.ParseUint(fields[12], 10, 64)
	start, e3 := strconv.ParseUint(fields[19], 10, 64)
	rss, e4 := strconv.ParseInt(fields[21], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || user > math.MaxUint64-system || rss < 0 {
		return unknown, errors.New("invalid process stat counters")
	}
	var name strings.Builder
	for _, r := range data[open+1 : close] {
		if unicode.IsPrint(r) && !unicode.IsControl(r) {
			name.WriteRune(r)
			if name.Len() >= 128 {
				break
			}
		}
	}
	if name.Len() == 0 {
		name.WriteString("未知")
	}
	return vpsCLIProcessStat{pid: pid, name: name.String(), ticks: user + system, startTime: start, rssPages: rss, valid: true}, nil
}

func parseVPSCLICPUTicks(data string) (uint64, int, error) {
	var total uint64
	count, complete := 0, false
	lines := strings.Split(data, "\n")
	if len(lines) == 0 {
		return 0, 0, errors.New("missing aggregate CPU stat")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 9 || fields[0] != "cpu" {
		return 0, 0, errors.New("invalid aggregate CPU stat")
	}
	// guest and guest_nice are already included in user/nice; do not count twice.
	for _, field := range fields[1:9] {
		n, err := strconv.ParseUint(field, 10, 64)
		if err != nil || n > math.MaxUint64-total {
			return 0, 0, errors.New("invalid aggregate CPU counter")
		}
		total += n
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.HasPrefix(fields[0], "cpu") {
			if _, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "cpu"), 10, 32); err != nil {
				return 0, 0, errors.New("invalid CPU row")
			}
			count++
		} else {
			complete = true
			break
		}
	}
	if count == 0 || !complete {
		return 0, 0, errors.New("missing or incomplete CPU count")
	}
	return total, count, nil
}

func parseVPSCLIMemoryTotal(data string) uint64 {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemTotal:" && fields[2] == "kB" {
			n, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil && n <= math.MaxUint64/1024 {
				return n * 1024
			}
		}
	}
	return 0
}

func summarizeVPSCLIProcesses(first, second vpsCLIProcessSnapshot, pageSize int64) vpsCLIProcessStatus {
	status := vpsCLIProcessStatus{SampledAt: second.at.UTC().Format(time.RFC3339Nano), SampleSeconds: second.at.Sub(first.at).Seconds(), CPUBasis: "one_core", CPUCount: second.cpuCount, Warnings: []string{}, TopCPU: []vpsCLIProcess{}, TopMemory: []vpsCLIProcess{}}
	addWarning := func(message string) {
		for _, previous := range status.Warnings {
			if previous == message {
				return
			}
		}
		status.Warnings = append(status.Warnings, message)
		status.Incomplete = true
	}
	for _, snapshot := range []vpsCLIProcessSnapshot{first, second} {
		for _, warning := range snapshot.warnings {
			addWarning(warning)
		}
	}
	if first.limited || second.limited {
		addWarning("进程数量超过读取预算，列表仅代表已采样的部分进程。")
	}
	if first.unreadable > 0 || second.unreadable > 0 {
		addWarning("部分进程信息不可读或格式异常，相关指标未知。")
	}
	cpuReady := first.cpuCount > 0 && first.cpuCount == second.cpuCount && second.ticks > first.ticks
	if !cpuReady {
		addWarning("CPU 采样总量无效或核心数发生变化，CPU 百分比未知。")
	}
	unknownCPU, unknownMemory := false, false
	for pid, current := range second.processes {
		item := vpsCLIProcess{PID: pid, Name: current.name}
		if current.valid && pageSize > 0 && current.rssPages <= math.MaxInt64/pageSize {
			rss := current.rssPages * pageSize
			item.RSSBytes = &rss
			if second.memoryBytes > 0 {
				percent := float64(rss) / float64(second.memoryBytes) * 100
				item.MemoryPercent = &percent
			}
		} else if current.valid {
			unknownMemory = true
		}
		previous, exists := first.processes[pid]
		if cpuReady && exists && previous.valid && current.valid && previous.startTime == current.startTime && current.ticks >= previous.ticks {
			percent := float64(current.ticks-previous.ticks) / float64(second.ticks-first.ticks) * float64(second.cpuCount) * 100
			item.CPUPercent = &percent
		} else if cpuReady {
			unknownCPU = true
		}
		status.TopCPU = append(status.TopCPU, item)
	}
	if unknownCPU {
		addWarning("部分进程缺少连续有效样本，CPU 百分比未知；进程可能刚启动或 PID 已复用。")
	}
	if unknownMemory {
		addWarning("部分进程的内存计数无效，内存占用未知。")
	}
	status.TopMemory = append(status.TopMemory, status.TopCPU...)
	sort.Slice(status.TopCPU, func(i, j int) bool {
		a, b := status.TopCPU[i], status.TopCPU[j]
		if (a.CPUPercent == nil) != (b.CPUPercent == nil) {
			return a.CPUPercent != nil
		}
		if a.CPUPercent != nil && *a.CPUPercent != *b.CPUPercent {
			return *a.CPUPercent > *b.CPUPercent
		}
		return a.PID < b.PID
	})
	sort.Slice(status.TopMemory, func(i, j int) bool {
		a, b := status.TopMemory[i], status.TopMemory[j]
		if (a.RSSBytes == nil) != (b.RSSBytes == nil) {
			return a.RSSBytes != nil
		}
		if a.RSSBytes != nil && *a.RSSBytes != *b.RSSBytes {
			return *a.RSSBytes > *b.RSSBytes
		}
		return a.PID < b.PID
	})
	if len(status.TopCPU) > 10 {
		status.TopCPU = status.TopCPU[:10]
		status.TopMemory = status.TopMemory[:10]
	}
	return status
}
