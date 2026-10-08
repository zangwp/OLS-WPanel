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

	"github.com/zangwp/OLS-WPanel/internal/database"
)

const (
	managedSwapMarker       = "# OLS WPanel managed swap"
	systemDefaultSwappiness = 60
	minimumSwapSizeMB       = 512
	maximumSwapSizeMB       = 8192
	swapSizeIncrementMB     = 256
	swapRemovalSafetyHead   = int64(256 * 1024 * 1024)
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
	RecommendedSwappiness   int         `json:"recommended_swappiness"`
	RecommendationReason    string      `json:"recommendation_reason"`
	ActiveWordPressSites    int         `json:"active_wordpress_sites"`
	WorkloadKnown           bool        `json:"workload_known"`
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
	swapManagerMu      sync.Mutex
	swapReadSwappiness = readRuntimeSwappiness
	swapPaths          = swapManagerPaths{
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
	if !managed {
		if data, readErr := os.ReadFile(paths.fstab); readErr == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 3 && fields[0] == paths.swap && fields[2] == "swap" {
					status.CanManage = false
					status.ManageReason = "fstab 中已有非受管或重复的 /swapfile 记录，请先检查原配置"
				}
			}
		}
	}
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
	if info, statErr := os.Lstat(paths.swap); statErr == nil {
		if !info.Mode().IsRegular() {
			status.CanManage = false
			status.ManageReason = paths.swap + " 不是普通文件，停止修改"
		} else if managed {
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
	status.RecommendationSatisfied = swapCapacityMeetsTarget(status.TotalBytes, status.RecommendedBytes, len(status.Entries))
	if value, readErr := swapReadSwappiness(); readErr == nil {
		status.Swappiness = value
	}
	status.ActiveWordPressSites, status.WorkloadKnown = readActiveWordPressSiteCount()
	status.RecommendedSwappiness, status.RecommendationReason = RecommendedSwappiness(status, status.ActiveWordPressSites)
	return status, nil
}

// RecommendedSwappiness keeps the kernel default for unknown or multi-site
// workloads, lowers disk-swap eagerness only for a lightly loaded single-site
// host, and lets zram absorb inactive pages more aggressively.
func RecommendedSwappiness(status SwapStatus, activeWordPressSites int) (int, string) {
	for _, entry := range status.Entries {
		if entry.Type == "zram" {
			return 100, "zram"
		}
	}
	if activeWordPressSites >= 2 {
		return systemDefaultSwappiness, "multiple_wordpress"
	}
	if status.MemoryTotalBytes > 0 {
		availablePercent := status.MemoryAvailableBytes * 100 / status.MemoryTotalBytes
		if availablePercent < 20 {
			return systemDefaultSwappiness, "memory_pressure"
		}
	}
	if status.TotalBytes > 0 && status.UsedBytes*100/status.TotalBytes >= 25 {
		return systemDefaultSwappiness, "swap_pressure"
	}
	if activeWordPressSites == 1 {
		return 10, "single_wordpress"
	}
	return systemDefaultSwappiness, "system_default"
}

func activeWordPressSiteCount() int {
	count, _ := readActiveWordPressSiteCount()
	return count
}

func readActiveWordPressSiteCount() (int, bool) {
	db := database.GetDB()
	if db == nil {
		return 0, false
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM websites WHERE site_type='wordpress' AND status='active'`).Scan(&count); err != nil {
		return 0, false
	}
	return count, true
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
			if strings.Join(strings.Fields(scanner.Text()), " ") != "Filename Type Size Used Priority" {
				return nil, errors.New("Swap 运行列表表头无效，无法确认实际状态")
			}
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 5 {
			return nil, errors.New("Swap 运行列表记录无效，无法确认实际状态")
		}
		sizeKB, sizeErr := strconv.ParseInt(fields[2], 10, 64)
		usedKB, usedErr := strconv.ParseInt(fields[3], 10, 64)
		priority, priorityErr := strconv.Atoi(fields[4])
		if sizeErr != nil || usedErr != nil || priorityErr != nil || sizeKB < 0 || usedKB < 0 || usedKB > sizeKB || sizeKB > (1<<63-1)/1024 {
			return nil, errors.New("Swap 运行列表数值无效，无法确认实际状态")
		}
		entries = append(entries, SwapEntry{
			Filename: fields[0], Type: classifySwapEntry(fields[0], fields[1]),
			SizeBytes: sizeKB * 1024, UsedBytes: usedKB * 1024, Priority: priority,
			Managed: managed && fields[0] == managedPath,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if first {
		return nil, errors.New("Swap 运行列表为空，无法确认实际状态")
	}
	return entries, nil
}

func readSwapPathActive(swapsPath, swapPath string) (bool, error) {
	entries, err := readSwapEntries(swapsPath, swapPath, true)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Filename == swapPath {
			return true, nil
		}
	}
	return false, nil
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
	owned, references := 0, 0
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == swapPath && fields[2] == "swap" {
			references++
		}
		if i+1 < len(lines) && strings.TrimSpace(lines[i]) == managedSwapMarker && strings.TrimSpace(lines[i+1]) == wantLine {
			owned++
		}
	}
	return owned == 1 && references == 1
}

func ApplyRecommendedSwap() (result SwapStatus, resultErr error) {
	swapManagerMu.Lock()
	defer swapManagerMu.Unlock()
	defer func() { recordSwapOperation("swap_apply_recommended", result, resultErr) }()
	status, err := getSwapStatus(swapPaths)
	if err != nil {
		return status, err
	}
	if status.RecommendationSatisfied {
		err = setManagedSwappiness(status.RecommendedSwappiness, swapPaths.sysctl)
		if err != nil {
			return refreshedSwapStatus(status, err)
		}
		updated, statusErr := getSwapStatus(swapPaths)
		return updated, statusErr
	}
	if !status.CanManage {
		return status, errors.New(status.ManageReason)
	}
	missing := status.RecommendedBytes - status.TotalBytes
	target := roundUpSwapBytes(status.ManagedSizeBytes + missing)
	if target < minimumSwapSizeMB*1024*1024 {
		target = minimumSwapSizeMB * 1024 * 1024
	}
	updated, err := applyManagedSwapLocked(target/(1024*1024), int64(status.RecommendedSwappiness), swapPaths)
	return updated, err
}

func ApplyManagedSwap(sizeMB, swappiness int64) (SwapStatus, error) {
	swapManagerMu.Lock()
	defer swapManagerMu.Unlock()
	status, err := applyManagedSwapLocked(sizeMB, swappiness, swapPaths)
	recordSwapOperation("swap_apply_custom", status, err)
	return status, err
}

func applyManagedSwapLocked(sizeMB, swappiness int64, paths swapManagerPaths) (result SwapStatus, resultErr error) {
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
	if status.ManagedActive && status.ManagedSizeBytes <= targetBytes && swapCapacityMeetsTarget(status.ManagedSizeBytes, targetBytes, 1) {
		if err := setManagedSwappiness(int(swappiness), paths.sysctl); err != nil {
			return status, err
		}
		return getSwapStatus(paths)
	}
	if status.ManagedActive || targetBytes < status.ManagedSizeBytes {
		if err := checkSwapRemovalMemory(status); err != nil {
			return status, err
		}
	}
	// The complete replacement is allocated while the original file still exists.
	// The peak applies to shrinking too, not only to the final net growth.
	if err := checkSwapDiskSpace(targetBytes, paths.swap); err != nil {
		return status, err
	}
	transaction, err := newSwapChangeTransaction(paths, status)
	if err != nil {
		return status, err
	}
	if err := requireManagedSwappiness(transaction.sysctl); err != nil {
		return status, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, transaction.rollback())
			if latest, readErr := getSwapStatus(paths); readErr == nil {
				result = latest
			} else {
				resultErr = errors.Join(resultErr, fmt.Errorf("回滚后状态读取失败: %w", readErr))
			}
		}
	}()
	temp, err := os.CreateTemp(filepath.Dir(paths.swap), ".ols-wpanel-swap-new-*")
	if err != nil {
		return status, err
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return status, err
	}
	defer os.Remove(tempPath)
	if err := swapCommand("dd", "if=/dev/zero", "of="+tempPath, "bs=1M", "count="+strconv.FormatInt(sizeMB, 10), "status=none"); err != nil {
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

	if status.ManagedActive {
		// Allocating the replacement can take time. Recheck memory immediately
		// before swapoff instead of trusting the pre-allocation snapshot.
		current, readErr := getSwapStatus(paths)
		if readErr != nil {
			return status, readErr
		}
		if !current.CanManage || !current.ManagedActive || current.ManagedSizeBytes != status.ManagedSizeBytes {
			return current, errors.New("准备期间原 Swap 状态发生变化，停止替换")
		}
		if err := checkSwapRemovalMemory(current); err != nil {
			return current, err
		}
		if err := transaction.stopOriginal(); err != nil {
			return status, err
		}
	}
	if status.ManagedFile {
		if err := transaction.moveOriginal(); err != nil {
			return status, err
		}
	}
	if err := os.Rename(tempPath, paths.swap); err != nil {
		return status, err
	}
	transaction.newInstalled = true
	activationErr := swapCommand("swapon", paths.swap)
	active, stateErr := readSwapPathActive(paths.swaps, paths.swap)
	if activationErr != nil || stateErr != nil {
		return status, fmt.Errorf("启用新 Swap 失败或无法确认运行状态: %w", errors.Join(activationErr, stateErr))
	}
	if !active {
		return status, errors.New("启用新 Swap 后未出现在实际运行列表中")
	}
	if !hasManagedSwapEntry(paths.fstab, paths.swap) {
		if err := appendManagedSwapEntry(paths.fstab, paths.swap); err != nil {
			return status, err
		}
	}
	if err := setManagedSwappiness(int(swappiness), paths.sysctl); err != nil {
		return status, err
	}
	updated, err := getSwapStatus(paths)
	if err != nil {
		return status, err
	}
	if !updated.ManagedActive || updated.Swappiness != int(swappiness) {
		return updated, errors.New("Swap 应用后状态验证失败")
	}
	if err := transaction.commit(); err != nil {
		return updated, err
	}
	return updated, nil
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
	updated, err := refreshedSwapStatus(status, err)
	recordSwapOperation("swap_set_swappiness", updated, err)
	return updated, err
}

func RemoveManagedSwap(confirm string) (result SwapStatus, resultErr error) {
	swapManagerMu.Lock()
	defer swapManagerMu.Unlock()
	defer func() { recordSwapOperation("swap_remove_managed", result, resultErr) }()
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
	if err := checkSwapRemovalMemory(status); err != nil {
		return status, err
	}
	transaction, err := newSwapChangeTransaction(swapPaths, status)
	if err != nil {
		return status, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, transaction.rollback())
			if latest, readErr := getSwapStatus(swapPaths); readErr == nil {
				result = latest
			} else {
				resultErr = errors.Join(resultErr, readErr)
			}
		}
	}()
	if status.ManagedActive {
		if err := transaction.stopOriginal(); err != nil {
			return status, err
		}
	}
	if err := transaction.moveOriginal(); err != nil {
		return status, err
	}
	if err := removeManagedSwapEntry(swapPaths.fstab, swapPaths.swap); err != nil {
		return status, err
	}
	updated, err := getSwapStatus(swapPaths)
	if err != nil {
		return status, err
	}
	if updated.ManagedFile || updated.ManagedActive {
		return updated, errors.New("Swap 删除后状态验证失败")
	}
	if err := transaction.commit(); err != nil {
		return updated, err
	}
	// swappiness applies to all Swap sources. Deleting this file does not reset
	// settings which may still be needed for existing partitions or zram.
	return updated, nil
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

func swapCapacityMeetsTarget(capacity, target int64, sources int) bool {
	if capacity >= target {
		return true
	}
	// /proc/swaps reports usable capacity, excluding each source's header page.
	// A nominal 1GiB file must satisfy a 1GiB recommendation without a rebuild.
	return capacity > 0 && sources > 0 && target-capacity <= int64(sources)*int64(os.Getpagesize())
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
	snapshot, err := readSwapFileSnapshot(path)
	if err != nil {
		return err
	}
	if !snapshot.exists {
		return errors.New("fstab 文件不存在，停止修改 Swap")
	}
	next := append(append([]byte{}, snapshot.data...), []byte(fmt.Sprintf("\n%s\n%s none swap sw 0 0\n", managedSwapMarker, swapPath))...)
	return writeSwapFileAtomic(path, next, snapshot.mode)
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
	return writeSwapFileAtomic(path, []byte(strings.Join(filtered, "\n")), info.Mode().Perm())
}

func setManagedSwappiness(value int, path string) error {
	if value < 1 || value > 100 {
		return errors.New("swappiness 必须在 1 到 100 之间")
	}
	before, err := readSwapFileSnapshot(path)
	if err != nil {
		return err
	}
	if err := requireManagedSwappiness(before); err != nil {
		return err
	}
	runtimeBefore, err := swapReadSwappiness()
	if err != nil {
		return fmt.Errorf("无法读取原 swappiness，停止修改: %w", err)
	}
	if err := writeSwapFileAtomic(path, []byte(fmt.Sprintf("%s\nvm.swappiness = %d\n", managedSwapMarker, value)), 0644); err != nil {
		return err
	}
	err = swapCommand("sysctl", "-p", path)
	if err == nil {
		current, readErr := swapReadSwappiness()
		if readErr != nil {
			err = readErr
		} else if current != value {
			err = fmt.Errorf("swappiness 实际值为 %d，与目标 %d 不一致", current, value)
		}
	}
	if err != nil {
		return errors.Join(err, restoreSwappiness(path, before, runtimeBefore))
	}
	return nil
}

func readRuntimeSwappiness() (int, error) {
	data, err := os.ReadFile("/proc/sys/vm/swappiness")
	if err != nil {
		return 0, err
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || value < 0 || value > 200 {
		return 0, errors.New("内核 swappiness 读取结果无效")
	}
	return value, nil
}

type swapFileSnapshot struct {
	exists bool
	data   []byte
	mode   os.FileMode
}

func readSwapFileSnapshot(path string) (swapFileSnapshot, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return swapFileSnapshot{}, nil
	}
	if err != nil {
		return swapFileSnapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return swapFileSnapshot{}, fmt.Errorf("拒绝修改非普通文件: %s", path)
	}
	data, err := os.ReadFile(path)
	return swapFileSnapshot{exists: true, data: data, mode: info.Mode().Perm()}, err
}

func requireManagedSwappiness(snapshot swapFileSnapshot) error {
	if snapshot.exists && !strings.HasPrefix(string(snapshot.data), managedSwapMarker+"\n") {
		return errors.New("swappiness 配置由管理员管理，拒绝覆盖未标记文件")
	}
	return nil
}

func writeSwapFileAtomic(path string, data []byte, mode os.FileMode) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".ols-wpanel-swap-config-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err = temp.Chmod(mode); err == nil {
		_, err = temp.Write(data)
	}
	if err == nil {
		err = temp.Sync()
	}
	err = errors.Join(err, temp.Close())
	if err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

func restoreSwapFile(path string, snapshot swapFileSnapshot) error {
	if snapshot.exists {
		return writeSwapFileAtomic(path, snapshot.data, snapshot.mode)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func restoreSwappiness(path string, snapshot swapFileSnapshot, original int) error {
	var failures []error
	if err := restoreSwapFile(path, snapshot); err != nil {
		failures = append(failures, fmt.Errorf("swappiness 配置回滚失败: %w", err))
	}
	if err := swapCommand("sysctl", "-w", fmt.Sprintf("vm.swappiness=%d", original)); err != nil {
		failures = append(failures, fmt.Errorf("swappiness 运行值回滚失败: %w", err))
	}
	if current, err := swapReadSwappiness(); err != nil {
		failures = append(failures, fmt.Errorf("swappiness 回滚验证失败: %w", err))
	} else if current != original {
		failures = append(failures, fmt.Errorf("swappiness 回滚验证失败：实际 %d，原值 %d", current, original))
	}
	return errors.Join(failures...)
}

func checkSwapRemovalMemory(status SwapStatus) error {
	if status.MemoryAvailableBytes <= 0 {
		return errors.New("无法确认可用内存，停止停用、缩小或删除 Swap")
	}
	if status.MemoryAvailableBytes < managedSwapUsed(status)+swapRemovalSafetyHead {
		return errors.New("可用内存不足，无法安全停用 Swap")
	}
	return nil
}

type swapChangeTransaction struct {
	paths                              swapManagerPaths
	fstab, sysctl                      swapFileSnapshot
	runtime                            int
	originalActive                     bool
	backup                             string
	oldStopped, oldMoved, newInstalled bool
}

func newSwapChangeTransaction(paths swapManagerPaths, status SwapStatus) (*swapChangeTransaction, error) {
	t := &swapChangeTransaction{paths: paths, originalActive: status.ManagedActive}
	var err error
	if t.fstab, err = readSwapFileSnapshot(paths.fstab); err != nil {
		return nil, err
	}
	if !t.fstab.exists {
		return nil, errors.New("fstab 文件不存在，停止修改 Swap")
	}
	if t.sysctl, err = readSwapFileSnapshot(paths.sysctl); err != nil {
		return nil, err
	}
	if t.runtime, err = swapReadSwappiness(); err != nil {
		return nil, fmt.Errorf("无法读取原 swappiness，停止修改: %w", err)
	}
	return t, nil
}

func (t *swapChangeTransaction) moveOriginal() error {
	if active, err := readSwapPathActive(t.paths.swaps, t.paths.swap); err != nil {
		return fmt.Errorf("移动原 Swap 前无法确认停用状态: %w", err)
	} else if active {
		return errors.New("原 Swap 仍在运行，拒绝移动文件")
	}
	file, err := os.CreateTemp(filepath.Dir(t.paths.swap), ".ols-wpanel-swap-backup-*")
	if err != nil {
		return err
	}
	backup := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(backup)
		return err
	}
	if err := os.Rename(t.paths.swap, backup); err != nil {
		_ = os.Remove(backup)
		return err
	}
	t.backup, t.oldMoved = backup, true
	return nil
}

func (t *swapChangeTransaction) stopOriginal() error {
	// A timed-out command may already have deactivated Swap. Mark the attempt
	// before execution so recovery checks the kernel even when the command fails.
	t.oldStopped = true
	commandErr := swapCommand("swapoff", t.paths.swap)
	active, stateErr := readSwapPathActive(t.paths.swaps, t.paths.swap)
	if stateErr == nil && active {
		t.oldStopped = false
	}
	if commandErr != nil || stateErr != nil {
		return fmt.Errorf("停用原 Swap 失败或无法确认状态，停止修改并尝试恢复: %w", errors.Join(commandErr, stateErr))
	}
	if active {
		return errors.New("停用原 Swap 后仍在实际运行列表中，未修改文件")
	}
	return nil
}

func (t *swapChangeTransaction) commit() error {
	if t.oldMoved {
		if active, err := readSwapPathActive(t.paths.swaps, t.backup); err != nil {
			return fmt.Errorf("清理旧 Swap 备份前无法确认停用状态: %w", err)
		} else if active {
			return errors.New("旧 Swap 备份仍在运行，拒绝删除文件")
		}
		if err := os.Remove(t.backup); err != nil {
			return fmt.Errorf("清理旧 Swap 备份失败: %w", err)
		}
	}
	return nil
}

func (t *swapChangeTransaction) rollback() error {
	if !t.oldStopped && !t.oldMoved && !t.newInstalled {
		return nil
	}
	var failures []error
	pathRestored := true
	if t.newInstalled {
		active, stateErr := readSwapPathActive(t.paths.swaps, t.paths.swap)
		if active || stateErr != nil {
			// swapon/swapoff may take effect before returning an error or timing out.
			// File removal requires a fresh, positive observation of inactivity.
			commandErr := swapCommand("swapoff", t.paths.swap)
			active, stateErr = readSwapPathActive(t.paths.swaps, t.paths.swap)
			if commandErr != nil {
				failures = append(failures, fmt.Errorf("新 Swap 回滚停用命令返回错误: %w", commandErr))
			}
			if active || stateErr != nil {
				pathRestored = false
				cause := stateErr
				if cause == nil {
					cause = errors.New("仍在实际运行列表中")
				}
				failures = append(failures, fmt.Errorf("新 Swap 无法停用，保留文件以防数据丢失: %w", cause))
			}
		}
	}
	if pathRestored && t.newInstalled {
		if err := os.Remove(t.paths.swap); err != nil && !os.IsNotExist(err) {
			pathRestored = false
			failures = append(failures, fmt.Errorf("移除失败的新 Swap 文件失败: %w", err))
		}
	}
	if pathRestored && t.oldMoved {
		if err := os.Rename(t.backup, t.paths.swap); err != nil {
			pathRestored = false
			failures = append(failures, fmt.Errorf("恢复旧 Swap 文件失败: %w", err))
		}
	}
	if pathRestored {
		if err := restoreSwapFile(t.paths.fstab, t.fstab); err != nil {
			failures = append(failures, fmt.Errorf("fstab 回滚失败: %w", err))
		}
		if t.originalActive && t.oldStopped {
			active, readErr := readSwapPathActive(t.paths.swaps, t.paths.swap)
			if !active || readErr != nil {
				if err := swapCommand("swapon", t.paths.swap); err != nil {
					failures = append(failures, fmt.Errorf("旧 Swap 重新启用命令返回错误: %w", err))
				}
				active, readErr = readSwapPathActive(t.paths.swaps, t.paths.swap)
			}
			if readErr != nil {
				failures = append(failures, fmt.Errorf("旧 Swap 启用回读失败: %w", readErr))
			} else if !active {
				failures = append(failures, errors.New("旧 Swap 重新启用后未出现在实际运行列表中"))
			}
		}
	}
	if err := restoreSwappiness(t.paths.sysctl, t.sysctl, t.runtime); err != nil {
		failures = append(failures, err)
	}
	if len(failures) > 0 && t.backup != "" {
		if _, err := os.Stat(t.backup); err == nil {
			failures = append(failures, fmt.Errorf("原 Swap 备份保留于 %s，请人工恢复", t.backup))
		}
	}
	return errors.Join(failures...)
}

func refreshedSwapStatus(before SwapStatus, cause error) (SwapStatus, error) {
	latest, err := getSwapStatus(swapPaths)
	if err != nil {
		return before, errors.Join(cause, err)
	}
	return latest, cause
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
