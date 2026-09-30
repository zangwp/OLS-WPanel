package executor

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	managedSwapMarker     = "# OLS WPanel managed swap"
	defaultSwappiness     = 10
	minimumSwapSizeMB     = 512
	maximumSwapSizeMB     = 8192
	swapSizeIncrementMB   = 256
	swapRemovalSafetyHead = int64(256 * 1024 * 1024)
)

type SwapEntry struct {
	Filename  string `json:"filename"`
	Type      string `json:"type"`
	SizeBytes int64  `json:"size_bytes"`
	UsedBytes int64  `json:"used_bytes"`
	Priority  int    `json:"priority"`
	Managed   bool   `json:"managed"`
}

type SwapStatus struct {
	Supported               bool        `json:"supported"`
	Entries                 []SwapEntry `json:"entries"`
	TotalBytes              int64       `json:"total_bytes"`
	UsedBytes               int64       `json:"used_bytes"`
	MemoryTotalBytes        int64       `json:"memory_total_bytes"`
	MemoryAvailableBytes    int64       `json:"memory_available_bytes"`
	RecommendedBytes        int64       `json:"recommended_bytes"`
	Swappiness              int         `json:"swappiness"`
	ManagedFile             bool        `json:"managed_file"`
	ManagedActive           bool        `json:"managed_active"`
	ManagedSizeBytes        int64       `json:"managed_size_bytes"`
	RecommendationSatisfied bool        `json:"recommendation_satisfied"`
	CanManage               bool        `json:"can_manage"`
	ManageReason            string      `json:"manage_reason,omitempty"`
}

type swapManagerPaths struct {
	meminfo string
	swaps   string
	swap    string
	fstab   string
	sysctl  string
}

var (
	swapManagerMu sync.Mutex
	swapPaths     = swapManagerPaths{
		meminfo: "/proc/meminfo",
		swaps:   "/proc/swaps",
		swap:    swapFilePath,
		fstab:   swapFstabPath,
		sysctl:  swapSysctlPath,
	}
)

// RecommendedSwapBytes intentionally keeps an emergency buffer rather than
// mirroring RAM. Small VPSes need more protection; larger hosts default to 1GB.
func RecommendedSwapBytes(memoryBytes int64) int64 {
	if memoryBytes > 0 && memoryBytes <= 1024*1024*1024 {
		return 2 * 1024 * 1024 * 1024
	}
	return 1024 * 1024 * 1024
}

func GetSwapStatus() (SwapStatus, error) {
	return getSwapStatus(swapPaths)
}

func getSwapStatus(paths swapManagerPaths) (SwapStatus, error) {
	status := SwapStatus{Supported: true, Entries: []SwapEntry{}, Swappiness: -1, CanManage: true}
	var err error
	status.MemoryTotalBytes, err = readMeminfoValue(paths.meminfo, "MemTotal:")
	if err != nil {
		return status, err
	}
	status.MemoryAvailableBytes, _ = readMeminfoValue(paths.meminfo, "MemAvailable:")
	status.RecommendedBytes = RecommendedSwapBytes(status.MemoryTotalBytes)

	managed := hasManagedSwapEntry(paths.fstab, paths.swap)
	entries, err := readSwapEntries(paths.swaps, paths.swap, managed)
	if err != nil {
		return status, err
	}
	status.Entries = entries
	for _, entry := range entries {
		status.TotalBytes += entry.SizeBytes
		status.UsedBytes += entry.UsedBytes
		if entry.Managed {
			status.ManagedActive = true
			status.ManagedSizeBytes = entry.SizeBytes
		}
	}
	if info, statErr := os.Stat(paths.swap); statErr == nil {
		if managed {
			status.ManagedFile = true
			if status.ManagedSizeBytes == 0 {
				status.ManagedSizeBytes = info.Size()
			}
		} else {
			status.CanManage = false
			status.ManageReason = paths.swap + " 已存在但不是 OLS WPanel 管理的文件"
		}
	} else if !os.IsNotExist(statErr) {
		return status, statErr
	}
	status.RecommendationSatisfied = status.TotalBytes >= status.RecommendedBytes
	if value, readErr := os.ReadFile("/proc/sys/vm/swappiness"); readErr == nil {
		status.Swappiness, _ = strconv.Atoi(strings.TrimSpace(string(value)))
	}
	return status, nil
}

func readSwapEntries(path, managedPath string, managed bool) ([]SwapEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries := []SwapEntry{}
	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		sizeKB, sizeErr := strconv.ParseInt(fields[2], 10, 64)
		usedKB, usedErr := strconv.ParseInt(fields[3], 10, 64)
		priority, priorityErr := strconv.Atoi(fields[4])
		if sizeErr != nil || usedErr != nil || priorityErr != nil {
			continue
		}
		entries = append(entries, SwapEntry{
			Filename: fields[0], Type: classifySwapEntry(fields[0], fields[1]),
			SizeBytes: sizeKB * 1024, UsedBytes: usedKB * 1024, Priority: priority,
			Managed: managed && fields[0] == managedPath,
		})
	}
	return entries, scanner.Err()
}

func classifySwapEntry(filename, kind string) string {
	if strings.Contains(strings.ToLower(filename), "zram") {
		return "zram"
	}
	if kind == "partition" {
		return "partition"
	}
	return "file"
}

func hasManagedSwapEntry(path, swapPath string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	wantLine := swapPath + " none swap sw 0 0"
	lines := strings.Split(string(data), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == managedSwapMarker && strings.TrimSpace(lines[i+1]) == wantLine {
			return true
		}
	}
	return false
}

func ApplyRecommendedSwap() (SwapStatus, error) {
	swapManagerMu.Lock()
	defer swapManagerMu.Unlock()
	status, err := getSwapStatus(swapPaths)
	if err != nil {
		return status, err
	}
	if status.RecommendationSatisfied {
		err = setManagedSwappiness(defaultSwappiness, swapPaths.sysctl)
		if err != nil {
			recordSwapOperation("swap_apply_recommended", status, err)
			return status, err
		}
		updated, statusErr := getSwapStatus(swapPaths)
		recordSwapOperation("swap_apply_recommended", updated, statusErr)
		return updated, statusErr
	}
	if !status.CanManage {
		return status, errors.New(status.ManageReason)
	}
	missing := status.RecommendedBytes - status.TotalBytes
	target := status.ManagedSizeBytes + roundUpSwapBytes(missing)
	if target < minimumSwapSizeMB*1024*1024 {
		target = minimumSwapSizeMB * 1024 * 1024
	}
	updated, err := applyManagedSwapLocked(target/(1024*1024), defaultSwappiness, swapPaths)
	recordSwapOperation("swap_apply_recommended", updated, err)
	return updated, err
}

func ApplyManagedSwap(sizeMB, swappiness int64) (SwapStatus, error) {
	swapManagerMu.Lock()
	defer swapManagerMu.Unlock()
	status, err := applyManagedSwapLocked(sizeMB, swappiness, swapPaths)
	recordSwapOperation("swap_apply_custom", status, err)
	return status, err
}

func applyManagedSwapLocked(sizeMB, swappiness int64, paths swapManagerPaths) (SwapStatus, error) {
	status, err := getSwapStatus(paths)
	if err != nil {
		return status, err
	}
	if !status.CanManage {
		return status, errors.New(status.ManageReason)
	}
	if err := validateSwapSettings(sizeMB, swappiness); err != nil {
		return status, err
	}
	targetBytes := sizeMB * 1024 * 1024
	if status.ManagedSizeBytes == targetBytes && status.ManagedActive {
		if err := setManagedSwappiness(int(swappiness), paths.sysctl); err != nil {
			return status, err
		}
		return getSwapStatus(paths)
	}
	if targetBytes < status.ManagedSizeBytes {
		managedUsed := managedSwapUsed(status)
		if status.MemoryAvailableBytes > 0 && status.MemoryAvailableBytes < managedUsed+swapRemovalSafetyHead {
			return status, errors.New("可用内存不足，无法安全缩小 Swap 文件")
		}
	}
	if err := checkSwapDiskSpace(targetBytes-status.ManagedSizeBytes, paths.swap); err != nil {
		return status, err
	}
	tempPath := paths.swap + ".ols-wpanel-new"
	backupPath := paths.swap + ".ols-wpanel-backup"
	_ = os.Remove(tempPath)
	_ = os.Remove(backupPath)
	if err := swapCommand("dd", "if=/dev/zero", "of="+tempPath, "bs=1M", "count="+strconv.FormatInt(sizeMB, 10), "status=none"); err != nil {
		_ = os.Remove(tempPath)
		return status, err
	}
	if err := os.Chmod(tempPath, 0600); err != nil {
		_ = os.Remove(tempPath)
		return status, err
	}
	if err := swapCommand("mkswap", tempPath); err != nil {
		_ = os.Remove(tempPath)
		return status, err
	}

	oldExists := status.ManagedFile
	oldActive := status.ManagedActive
	if oldActive {
		if err := swapCommand("swapoff", paths.swap); err != nil {
			_ = os.Remove(tempPath)
			return status, fmt.Errorf("停用旧 Swap 失败，未修改文件: %w", err)
		}
	}
	if oldExists {
		if err := os.Rename(paths.swap, backupPath); err != nil {
			if oldActive {
				_ = swapCommand("swapon", paths.swap)
			}
			_ = os.Remove(tempPath)
			return status, err
		}
	}
	if err := os.Rename(tempPath, paths.swap); err != nil {
		rollbackManagedSwap(paths.swap, backupPath, oldExists, oldActive)
		return status, err
	}
	if err := swapCommand("swapon", paths.swap); err != nil {
		_ = os.Remove(paths.swap)
		rollbackManagedSwap(paths.swap, backupPath, oldExists, oldActive)
		return status, fmt.Errorf("启用新 Swap 失败，已尝试恢复旧文件: %w", err)
	}
	if !hasManagedSwapEntry(paths.fstab, paths.swap) {
		if err := appendManagedSwapEntry(paths.fstab, paths.swap); err != nil {
			_ = swapCommand("swapoff", paths.swap)
			_ = os.Remove(paths.swap)
			rollbackManagedSwap(paths.swap, backupPath, oldExists, oldActive)
			return status, err
		}
	}
	_ = os.Remove(backupPath)
	if err := setManagedSwappiness(int(swappiness), paths.sysctl); err != nil {
		latest, _ := getSwapStatus(paths)
		return latest, err
	}
	return getSwapStatus(paths)
}

func SetSwapSwappiness(value int64) (SwapStatus, error) {
	swapManagerMu.Lock()
	defer swapManagerMu.Unlock()
	status, err := getSwapStatus(swapPaths)
	if err != nil {
		return status, err
	}
	if value < 1 || value > 100 {
		return status, errors.New("swappiness 必须在 1 到 100 之间")
	}
	err = setManagedSwappiness(int(value), swapPaths.sysctl)
	recordSwapOperation("swap_set_swappiness", status, err)
	if err != nil {
		return status, err
	}
	return getSwapStatus(swapPaths)
}

func RemoveManagedSwap(confirm string) (SwapStatus, error) {
	swapManagerMu.Lock()
	defer swapManagerMu.Unlock()
	status, err := getSwapStatus(swapPaths)
	if err != nil {
		return status, err
	}
	if confirm != "REMOVE SWAP" {
		return status, errors.New("确认词不正确")
	}
	if !status.ManagedFile {
		return status, errors.New("没有可删除的 OLS WPanel Swap 文件")
	}
	used := managedSwapUsed(status)
	if status.MemoryAvailableBytes > 0 && status.MemoryAvailableBytes < used+swapRemovalSafetyHead {
		return status, errors.New("可用内存不足，无法安全停用 Swap")
	}
	if status.ManagedActive {
		if err := swapCommand("swapoff", swapPaths.swap); err != nil {
			return status, fmt.Errorf("停用 Swap 失败，未删除文件: %w", err)
		}
	}
	if err := removeManagedSwapEntry(swapPaths.fstab, swapPaths.swap); err != nil {
		if status.ManagedActive {
			_ = swapCommand("swapon", swapPaths.swap)
		}
		return status, err
	}
	if err := os.Remove(swapPaths.swap); err != nil && !os.IsNotExist(err) {
		_ = appendManagedSwapEntry(swapPaths.fstab, swapPaths.swap)
		if status.ManagedActive {
			_ = swapCommand("swapon", swapPaths.swap)
		}
		return status, err
	}
	_ = os.Remove(swapPaths.sysctl)
	updated, statusErr := getSwapStatus(swapPaths)
	recordSwapOperation("swap_remove_managed", updated, statusErr)
	return updated, statusErr
}

func validateSwapSettings(sizeMB, swappiness int64) error {
	if sizeMB < minimumSwapSizeMB || sizeMB > maximumSwapSizeMB || sizeMB%swapSizeIncrementMB != 0 {
		return fmt.Errorf("Swap 文件必须为 %d-%dMB，且按 %dMB 递增", minimumSwapSizeMB, maximumSwapSizeMB, swapSizeIncrementMB)
	}
	if swappiness < 1 || swappiness > 100 {
		return errors.New("swappiness 必须在 1 到 100 之间")
	}
	return nil
}

func roundUpSwapBytes(value int64) int64 {
	increment := int64(swapSizeIncrementMB * 1024 * 1024)
	return ((value + increment - 1) / increment) * increment
}

func managedSwapUsed(status SwapStatus) int64 {
	for _, entry := range status.Entries {
		if entry.Managed {
			return entry.UsedBytes
		}
	}
	return 0
}

func checkSwapDiskSpace(additionalBytes int64, swapPath string) error {
	if additionalBytes <= 0 {
		return nil
	}
	var fs syscall.Statfs_t
	if err := swapStatfs(filepath.Dir(swapPath), &fs); err != nil {
		return fmt.Errorf("检查磁盘空间: %w", err)
	}
	free := int64(fs.Bavail) * int64(fs.Bsize)
	total := int64(fs.Blocks) * int64(fs.Bsize)
	used := total - int64(fs.Bfree)*int64(fs.Bsize)
	if free-additionalBytes < swapMinFreeBytes {
		return errors.New("创建后系统盘可用空间将不足 8GB")
	}
	if total <= 0 || (used+additionalBytes)*100/total > 85 {
		return errors.New("创建后系统盘使用率将超过 85%")
	}
	return nil
}

func appendManagedSwapEntry(path, swapPath string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintf(file, "\n%s\n%s none swap sw 0 0\n", managedSwapMarker, swapPath)
	return err
}

func removeManagedSwapEntry(path, swapPath string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	want := swapPath + " none swap sw 0 0"
	lines := strings.Split(string(data), "\n")
	filtered := make([]string, 0, len(lines))
	removed := false
	for i := 0; i < len(lines); i++ {
		if i+1 < len(lines) && strings.TrimSpace(lines[i]) == managedSwapMarker && strings.TrimSpace(lines[i+1]) == want {
			removed = true
			i++
			continue
		}
		filtered = append(filtered, lines[i])
	}
	if !removed {
		return errors.New("未找到面板管理的 fstab Swap 配置")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	temp := path + ".ols-wpanel-new"
	if err := os.WriteFile(temp, []byte(strings.Join(filtered, "\n")), info.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func setManagedSwappiness(value int, path string) error {
	if value < 1 || value > 100 {
		return errors.New("swappiness 必须在 1 到 100 之间")
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%s\nvm.swappiness = %d\n", managedSwapMarker, value)), 0644); err != nil {
		return err
	}
	return swapCommand("sysctl", "-p", path)
}

func rollbackManagedSwap(swapPath, backupPath string, oldExists, oldActive bool) {
	if !oldExists {
		return
	}
	_ = os.Rename(backupPath, swapPath)
	if oldActive {
		_ = swapCommand("swapon", swapPath)
	}
}

func recordSwapOperation(operation string, status SwapStatus, err error) {
	state := "success"
	message := fmt.Sprintf("total=%d recommended=%d managed=%d", status.TotalBytes, status.RecommendedBytes, status.ManagedSizeBytes)
	if err != nil {
		state = "failed"
		message = err.Error()
	}
	recordOperationLog(operation, swapFilePath, state, message)
}
