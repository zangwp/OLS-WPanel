package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	dnsManagedMarker = "# OLS WPanel managed DNS"
	dnsDropInPath    = "/etc/systemd/resolved.conf.d/50-ols-wpanel-dns.conf"
)

type DNSPreset struct {
	ID    string   `json:"id"`
	IPv4  []string `json:"ipv4"`
	IPv6  []string `json:"ipv6"`
	Order []string `json:"-"`
}

type DNSStatus struct {
	Supported        bool        `json:"supported"`
	Configurable     bool        `json:"configurable"`
	Manager          string      `json:"manager"`
	Current          []string    `json:"current"`
	CurrentSource    string      `json:"current_source"`
	Managed          bool        `json:"managed"`
	ActivePreset     string      `json:"active_preset"`
	IPv6Available    bool        `json:"ipv6_available"`
	Reason           string      `json:"reason,omitempty"`
	ReasonCode       string      `json:"reason_code,omitempty"`
	Presets          []DNSPreset `json:"presets"`
	LastProbePreset  string      `json:"last_probe_preset,omitempty"`
	IPv4ProbeOK      bool        `json:"ipv4_probe_ok"`
	IPv6ProbeOK      bool        `json:"ipv6_probe_ok"`
	IPv6Skipped      bool        `json:"ipv6_skipped"`
	TakeoverRequired bool        `json:"takeover_required"`
	RestoreAvailable bool        `json:"restore_available"`
	Immutable        bool        `json:"immutable"`
	BackupPath       string      `json:"backup_path,omitempty"`
	MaxServers       int         `json:"max_servers"`
	Warning          string      `json:"warning,omitempty"`
}

var (
	dnsManagerMu      sync.Mutex
	dnsCommandContext = exec.CommandContext
	dnsLookupHost     = func(ctx context.Context, resolver *net.Resolver, host string) error {
		_, err := resolver.LookupHost(ctx, host)
		return err
	}
	dnsPaths         = defaultDNSPaths()
	dnsSupported     = func() bool { return runtime.GOOS == "linux" }
	dnsProbeAddress  = probeDNSAddress
	dnsVerifyCurrent = verifySystemDNS
	dnsDetectManager = detectDNSManager
)

func DNSPresets() []DNSPreset {
	return []DNSPreset{
		{ID: "international", IPv4: []string{"1.1.1.1", "1.0.0.1"}, IPv6: []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}},
		{ID: "mainland_china", IPv4: []string{"223.5.5.5", "223.6.6.6"}, IPv6: []string{"2400:3200::1", "2400:3200:baba::1"}},
	}
}

func GetDNSStatus() DNSStatus {
	status := DNSStatus{Supported: dnsSupported(), Presets: DNSPresets(), Current: []string{}}
	if !status.Supported {
		status.Reason, status.ReasonCode = "DNS 设置仅支持 Linux", "unsupported"
		return status
	}
	status.Manager = dnsDetectManager()
	switch status.Manager {
	case "static-resolv.conf", "ols-resolv.conf":
		// glibc's resolv.conf MAXNS is 3. A fourth nameserver can appear in a
		// file while never being consulted by ordinary system applications.
		status.MaxServers = 3
		status.Warning = "普通 resolv.conf 最多使用 3 台 DNS；预设按检测通过后的优先顺序保留前三台，自定义超过上限将拒绝应用。"
	case "systemd-resolved":
		status.MaxServers = 4
	}
	status.Current, status.CurrentSource = readCurrentDNS(status.Manager)
	status.IPv6Available = hasIPv6DefaultRoute()
	if status.Manager != "systemd-resolved" && status.Manager != "static-resolv.conf" && status.Manager != "ols-resolv.conf" {
		status.Reason = dnsUnsupportedManagerReason(status.Manager)
		status.ReasonCode = "unsupported_manager"
		return status
	}
	target := dnsPaths.ResolvConf
	if status.Manager == "systemd-resolved" {
		target = dnsPaths.DropIn
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		active := dnsCommandContext(ctx, "systemctl", "is-active", "--quiet", "systemd-resolved").Run() == nil
		cancel()
		if !active {
			status.Reason, status.ReasonCode = "systemd-resolved 未运行，不能安全应用配置", "resolved_inactive"
			return status
		}
	}
	snapshot, err := dnsReadSnapshot(target, status.Manager == "systemd-resolved")
	if err != nil {
		status.Reason, status.ReasonCode = "DNS 配置文件身份或读取检查失败: "+err.Error(), "unsafe_config"
		return status
	}
	status.Immutable = snapshot.Immutable
	status.Managed = snapshot.Exists && strings.HasPrefix(string(snapshot.Data), dnsManagedMarker+"\n")
	if status.Manager == "systemd-resolved" && snapshot.Exists && !status.Managed {
		status.Reason, status.ReasonCode = "检测到同名 DNS 配置，但它不是由 OLS WPanel 创建的", "foreign_config"
		return status
	}
	if status.Managed {
		if status.Manager == "systemd-resolved" {
			status.ActivePreset = presetFromConfig(string(snapshot.Data))
		} else {
			status.ActivePreset = presetFromAddresses(parseResolvConf(string(snapshot.Data)))
		}
		backup, backupErr := readDNSBackup(dnsPaths, target)
		if backupErr == nil && backup != nil {
			status.BackupPath = dnsPaths.Backup
			status.RestoreAvailable = backup.accepts(snapshot.Data)
			if !status.RestoreAvailable {
				status.Reason, status.ReasonCode = "DNS 配置在接管后被其他程序修改；原始备份仍保留，请先检查差异", "config_changed"
				return status
			}
		} else if status.Manager == "systemd-resolved" && errors.Is(backupErr, os.ErrNotExist) {
			// Older releases created a resolved drop-in without a backup. Removing
			// only that exact marked drop-in retains their existing restore policy.
			status.RestoreAvailable = true
		} else {
			status.Reason, status.ReasonCode = "受管 DNS 原始备份不可用，拒绝继续覆盖: "+fmt.Sprint(backupErr), "backup_unavailable"
			return status
		}
	}
	status.TakeoverRequired = status.Manager == "static-resolv.conf"
	status.Configurable = true
	return status
}

func ProbeDNSPreset(ctx context.Context, presetID string) (DNSStatus, error) {
	preset, ok := findDNSPreset(presetID)
	if !ok {
		return GetDNSStatus(), errors.New("未知 DNS 预设")
	}
	status, _, err := probeDNSSelection(ctx, preset, false)
	return status, err
}

// Custom addresses are comma-separated IP literals, not hostnames or shell text.
func ParseCustomDNS(value string) (DNSPreset, error) {
	fields := strings.Split(value, ",")
	if len(fields) < 1 || len(fields) > 4 {
		return DNSPreset{}, errors.New("自定义 DNS 需要 1–4 个逗号分隔的 IP 地址")
	}
	preset := DNSPreset{ID: "custom", IPv4: []string{}, IPv6: []string{}}
	seen := map[string]bool{}
	for _, field := range fields {
		address, err := netip.ParseAddr(strings.TrimSpace(field))
		if err != nil || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() {
			return DNSPreset{}, errors.New("DNS 必须是有效 IPv4 / IPv6 地址，不能含端口、域名或网卡区域")
		}
		address = address.Unmap()
		if seen[address.String()] {
			return DNSPreset{}, errors.New("自定义 DNS 地址不能重复")
		}
		seen[address.String()] = true
		preset.Order = append(preset.Order, address.String())
		if address.Is4() {
			preset.IPv4 = append(preset.IPv4, address.String())
		} else {
			preset.IPv6 = append(preset.IPv6, address.String())
		}
	}
	return preset, nil
}

func ProbeCustomDNS(ctx context.Context, value string) (DNSStatus, error) {
	preset, err := ParseCustomDNS(value)
	if err != nil {
		return GetDNSStatus(), err
	}
	status, _, err := probeDNSSelection(ctx, preset, true)
	return status, err
}

func probeDNSSelection(ctx context.Context, preset DNSPreset, requireEveryAddress bool) (DNSStatus, DNSPreset, error) {
	status := GetDNSStatus()
	status.LastProbePreset = preset.ID
	selected := DNSPreset{ID: preset.ID, IPv4: []string{}, IPv6: []string{}}
	if !status.Supported {
		return status, selected, errors.New(status.Reason)
	}
	if requireEveryAddress && status.MaxServers > 0 && len(preset.IPv4)+len(preset.IPv6) > status.MaxServers {
		return status, selected, fmt.Errorf("当前 DNS 管理方式最多支持 %d 台服务器；自定义地址超过上限，未修改系统配置", status.MaxServers)
	}
	if requireEveryAddress && len(preset.IPv6) > 0 && !status.IPv6Available {
		status.IPv6Skipped = true
		return status, selected, errors.New("没有 IPv6 默认路由，自定义 IPv6 DNS 未应用")
	}
	for _, address := range preset.IPv4 {
		if dnsProbeAddress(ctx, "udp4", address) {
			selected.IPv4 = append(selected.IPv4, address)
		}
	}
	status.IPv4ProbeOK = len(selected.IPv4) > 0
	status.IPv6Skipped = !status.IPv6Available
	if status.IPv6Available {
		for _, address := range preset.IPv6 {
			if dnsProbeAddress(ctx, "udp6", address) {
				selected.IPv6 = append(selected.IPv6, address)
			}
		}
	}
	status.IPv6ProbeOK = len(selected.IPv6) > 0
	if err := ctx.Err(); err != nil {
		return status, selected, err
	}
	if requireEveryAddress && (len(selected.IPv4) != len(preset.IPv4) || len(selected.IPv6) != len(preset.IPv6)) {
		return status, selected, errors.New("至少一个自定义 DNS 地址检测失败，未修改系统配置")
	}
	if !status.IPv4ProbeOK && !status.IPv6ProbeOK {
		return status, selected, errors.New("IPv4 与 IPv6 均无可用 DNS，未修改系统配置")
	}
	if len(preset.Order) > 0 {
		selected.Order = append([]string{}, preset.Order...)
	}
	if !requireEveryAddress && status.MaxServers > 0 {
		verified := selectedDNSAddresses(selected)
		if len(verified) > status.MaxServers {
			selected = selectDNSAddresses(selected.ID, verified[:status.MaxServers])
		}
	}
	return status, selected, nil
}

func selectDNSAddresses(id string, addresses []string) DNSPreset {
	preset := DNSPreset{ID: id, IPv4: []string{}, IPv6: []string{}, Order: append([]string{}, addresses...)}
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip != nil && ip.To4() != nil {
			preset.IPv4 = append(preset.IPv4, address)
		} else {
			preset.IPv6 = append(preset.IPv6, address)
		}
	}
	return preset
}

func ApplyDNSPreset(ctx context.Context, presetID string) (DNSStatus, error) {
	preset, ok := findDNSPreset(presetID)
	if !ok {
		return GetDNSStatus(), errors.New("未知 DNS 预设")
	}
	return applyDNSSelection(ctx, preset, false)
}

// Callers must explicitly confirm takeover_required before invoking a write.
// These operations are exposed by the root CLI only; the web API remains read-only.
func ApplyCustomDNS(ctx context.Context, value string) (DNSStatus, error) {
	preset, err := ParseCustomDNS(value)
	if err != nil {
		return GetDNSStatus(), err
	}
	return applyDNSSelection(ctx, preset, true)
}

func applyDNSSelection(ctx context.Context, preset DNSPreset, requireEveryAddress bool) (DNSStatus, error) {
	dnsManagerMu.Lock()
	defer dnsManagerMu.Unlock()
	if !dnsSupported() {
		return GetDNSStatus(), errors.New("DNS 设置仅支持 Linux")
	}
	unlock, err := dnsAcquireLock(dnsPaths.Lock)
	if err != nil {
		return GetDNSStatus(), err
	}
	defer unlock()
	status := GetDNSStatus()
	if !status.Configurable {
		return status, errors.New(status.Reason)
	}
	manager := status.Manager
	target := dnsPaths.ResolvConf
	if manager == "systemd-resolved" {
		target = dnsPaths.DropIn
	}
	previous, err := dnsReadSnapshot(target, manager == "systemd-resolved")
	if err != nil {
		return status, err
	}
	probed, selected, err := probeDNSSelection(ctx, preset, requireEveryAddress)
	if err != nil {
		return probed, err
	}
	// Probes can take several seconds. Reject an external writer or a changed
	// manager instead of silently backing up or overwriting their new state.
	now, err := dnsReadSnapshot(target, manager == "systemd-resolved")
	if err != nil {
		return GetDNSStatus(), err
	}
	if dnsDetectManager() != manager || !sameDNSSnapshot(previous, now) {
		return GetDNSStatus(), errors.New("检测期间 DNS 管理方式或文件发生变化，未修改")
	}
	data := []byte(renderResolvedDNSFamilies(selected, len(selected.IPv4) > 0, len(selected.IPv6) > 0))
	if manager != "systemd-resolved" {
		data = renderStaticDNS(previous.Data, selectedDNSAddresses(selected))
	}
	backup, backupErr := readDNSBackup(dnsPaths, target)
	managed := previous.Exists && strings.HasPrefix(string(previous.Data), dnsManagedMarker+"\n")
	if backupErr != nil && !errors.Is(backupErr, os.ErrNotExist) {
		return status, backupErr
	}
	if !managed {
		backup = &dnsOriginalBackup{Version: 1, Target: target, Manager: manager, Original: previous}
	} else if backup == nil {
		if manager != "systemd-resolved" {
			return status, errors.New("原始 DNS 备份缺失，未修改")
		}
		backup = &dnsOriginalBackup{Version: 1, Target: target, Manager: manager, Original: dnsFileSnapshot{}}
	} else if !backup.accepts(previous.Data) {
		return status, errors.New("受管 DNS 已被其他程序修改，原始备份保留，未覆盖")
	}
	backup.ManagedHashes = []string{dnsContentHash(data)}
	if managed {
		backup.ManagedHashes = append(backup.ManagedHashes, dnsContentHash(previous.Data))
	}
	if err := writeDNSBackup(dnsPaths, backup); err != nil {
		return status, err
	}
	next := previous
	next.Exists, next.Data = true, data
	if !previous.Exists {
		next.Mode = 0o644
		next.UID, next.GID = dnsFileOwner()
	}
	if err := dnsWriteSnapshot(target, next); err != nil {
		return rollbackDNSStatus(ctx, manager, target, previous, fmt.Errorf("写入 DNS 失败: %w", err))
	}
	if manager == "systemd-resolved" {
		if err := restartResolved(ctx); err != nil {
			return rollbackDNSStatus(ctx, manager, target, previous, err)
		}
		active := activeDNSAddresses()
		if !containsAllDNS(active, selectedDNSAddresses(selected)) {
			return rollbackDNSStatus(ctx, manager, target, previous, errors.New("systemd-resolved 未加载选定 DNS"))
		}
	}
	if err := dnsVerifyCurrent(ctx); err != nil {
		return rollbackDNSStatus(ctx, manager, target, previous, fmt.Errorf("应用后解析验证失败: %w", err))
	}
	actual, err := dnsReadSnapshot(target, false)
	if err != nil || !sameDNSSnapshot(next, actual) {
		return rollbackDNSStatus(ctx, manager, target, previous, errors.New("应用后的 DNS 文件或属性回读不一致"))
	}
	updated := GetDNSStatus()
	updated.LastProbePreset, updated.IPv4ProbeOK, updated.IPv6ProbeOK, updated.IPv6Skipped = probed.LastProbePreset, probed.IPv4ProbeOK, probed.IPv6ProbeOK, probed.IPv6Skipped
	if !updated.Managed || !updated.Configurable {
		return updated, errors.New("DNS 写入完成，但管理状态验证失败；原始备份保留在 " + dnsPaths.Backup)
	}
	recordOperationLog("dns_apply_preset", preset.ID, "success", "manager="+manager)
	return updated, nil
}

func RestoreAutomaticDNS(ctx context.Context) (DNSStatus, error) {
	dnsManagerMu.Lock()
	defer dnsManagerMu.Unlock()
	if !dnsSupported() {
		return GetDNSStatus(), errors.New("DNS 设置仅支持 Linux")
	}
	unlock, err := dnsAcquireLock(dnsPaths.Lock)
	if err != nil {
		return GetDNSStatus(), err
	}
	defer unlock()
	status := GetDNSStatus()
	if !status.Managed {
		if !status.Configurable {
			return status, errors.New(status.Reason)
		}
		return status, nil
	}
	if !status.RestoreAvailable {
		return status, errors.New(status.Reason)
	}
	manager, target := status.Manager, dnsPaths.ResolvConf
	if manager == "systemd-resolved" {
		target = dnsPaths.DropIn
	}
	previous, err := dnsReadSnapshot(target, false)
	if err != nil {
		return status, err
	}
	backup, err := readDNSBackup(dnsPaths, target)
	if errors.Is(err, os.ErrNotExist) && manager == "systemd-resolved" {
		backup = &dnsOriginalBackup{Version: 1, Target: target, Manager: manager, Original: dnsFileSnapshot{}, ManagedHashes: []string{dnsContentHash(previous.Data)}}
		if err = writeDNSBackup(dnsPaths, backup); err != nil {
			return status, err
		}
	} else if err != nil {
		return status, err
	}
	if backup == nil || !backup.accepts(previous.Data) {
		return status, errors.New("备份与当前受管 DNS 不匹配，未恢复")
	}
	if err := dnsWriteSnapshot(target, backup.Original); err != nil {
		return rollbackDNSStatus(ctx, manager, target, previous, fmt.Errorf("恢复原始 DNS 配置失败: %w", err))
	}
	if manager == "systemd-resolved" {
		if err := restartResolved(ctx); err != nil {
			return rollbackDNSStatus(ctx, manager, target, previous, err)
		}
	}
	if err := dnsVerifyCurrent(ctx); err != nil {
		return rollbackDNSStatus(ctx, manager, target, previous, fmt.Errorf("原始 DNS 解析验证失败: %w", err))
	}
	actual, err := dnsReadSnapshot(target, true)
	if err != nil || !sameDNSSnapshot(backup.Original, actual) {
		return rollbackDNSStatus(ctx, manager, target, previous, errors.New("原始 DNS 文件或属性恢复验证失败"))
	}
	// Keep the root-only original for manual recovery. A future explicit takeover
	// refreshes it from the then-current unmarked file, never from a managed file.
	recordOperationLog("dns_restore_automatic", manager, "success", "")
	return GetDNSStatus(), nil
}

func findDNSPreset(id string) (DNSPreset, bool) {
	for _, preset := range DNSPresets() {
		if preset.ID == id {
			return preset, true
		}
	}
	return DNSPreset{}, false
}

func renderResolvedDNSConfig(preset DNSPreset, includeIPv6 bool) string {
	return renderResolvedDNSFamilies(preset, true, includeIPv6)
}

func renderResolvedDNSFamilies(preset DNSPreset, includeIPv4, includeIPv6 bool) string {
	servers := []string{}
	if includeIPv4 {
		servers = append(servers, preset.IPv4...)
	}
	if includeIPv6 {
		servers = append(servers, preset.IPv6...)
	}
	if len(preset.Order) > 0 {
		var ordered []string
		for _, address := range preset.Order {
			if containsAnyDNS(servers, []string{address}) {
				ordered = append(ordered, address)
			}
		}
		servers = ordered
	}
	return dnsManagedMarker + "\n[Resolve]\nDNS=" + strings.Join(servers, " ") + "\nDomains=~.\n"
}

func selectedDNSAddresses(preset DNSPreset) []string {
	if len(preset.Order) > 0 {
		return append([]string{}, preset.Order...)
	}
	return append(append([]string{}, preset.IPv4...), preset.IPv6...)
}

func presetFromConfig(config string) string {
	var addresses []string
	for _, line := range strings.Split(config, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "DNS=") {
			addresses = parseIPAddresses(strings.TrimPrefix(strings.TrimSpace(line), "DNS="))
		}
	}
	return presetFromAddresses(addresses)
}

func presetFromAddresses(addresses []string) string {
	for _, preset := range DNSPresets() {
		match := len(addresses) > 0
		allowed := append(append([]string{}, preset.IPv4...), preset.IPv6...)
		for _, address := range addresses {
			if !containsAnyDNS(allowed, []string{address}) {
				match = false
			}
		}
		if match {
			return preset.ID
		}
	}
	return "custom"
}

func detectDNSManager() string {
	info, err := os.Lstat(dnsPaths.ResolvConf)
	if err != nil {
		return "unavailable"
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(dnsPaths.ResolvConf)
		if err != nil {
			return "symbolic-link"
		}
		target = strings.ToLower(filepath.ToSlash(target))
		switch {
		case strings.Contains(target, "/systemd/resolve/"):
			return "systemd-resolved"
		case strings.Contains(target, "/networkmanager/"):
			return "NetworkManager"
		case strings.Contains(target, "/resolvconf/"), strings.Contains(target, "/openresolv/"):
			return "resolvconf"
		default:
			return "symbolic-link"
		}
	}
	if !info.Mode().IsRegular() {
		return "unknown"
	}
	data, err := readDNSStatusFile(dnsPaths.ResolvConf)
	if err != nil {
		return "unavailable"
	}
	if strings.HasPrefix(string(data), dnsManagedMarker+"\n") {
		return "ols-resolv.conf"
	}
	manager := managerFromResolvConf(string(data))
	if manager != "static-resolv.conf" {
		return manager
	}
	// A live NetworkManager can regenerate an unmarked regular resolv.conf.
	// Its supported DNS backend must be configured explicitly instead of silently
	// creating a competing OLS writer or forcing an immutable lock.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if dnsCommandContext(ctx, "systemctl", "is-active", "--quiet", "NetworkManager").Run() == nil {
		return "NetworkManager"
	}
	return manager
}

func activeDNSAddresses() []string {
	values, _ := readCurrentDNS(dnsDetectManager())
	return values
}

func readCurrentDNS(manager string) ([]string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if manager == "systemd-resolved" {
		if output, err := dnsCommandContext(ctx, "resolvectl", "dns", "--no-pager").Output(); err == nil {
			if values := parseIPAddresses(string(output)); len(values) > 0 {
				return values, "resolvectl"
			}
		}
	}
	data, err := readDNSStatusFile(dnsPaths.ResolvConf)
	if err != nil {
		return []string{}, "unavailable"
	}
	return parseResolvConf(string(data)), "/etc/resolv.conf"
}

// Status may follow a known resolver symlink for reading, but it never reads a
// device/FIFO or an unbounded file through an unknown link.
func readDNSStatusFile(path string) ([]byte, error) {
	file, err := openDNSStatusFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128*1024 {
		return nil, errors.New("DNS 状态来源不是有界普通文件")
	}
	data, err := io.ReadAll(io.LimitReader(file, 128*1024+1))
	if err != nil || len(data) > 128*1024 {
		return nil, errors.New("DNS 状态来源不可读取或过大")
	}
	return data, nil
}

func parseResolvConf(data string) []string {
	values := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" && net.ParseIP(fields[1]) != nil {
			values = append(values, fields[1])
		}
	}
	return uniqueDNSStrings(values)
}

func parseIPAddresses(value string) []string {
	result := []string{}
	for _, field := range strings.Fields(value) {
		candidate := strings.Trim(field, "[](),")
		if net.ParseIP(candidate) != nil {
			result = append(result, candidate)
		}
	}
	return uniqueDNSStrings(result)
}

func uniqueDNSStrings(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func containsAnyDNS(current, expected []string) bool {
	seen := make(map[string]bool, len(current))
	for _, address := range current {
		if ip := net.ParseIP(address); ip != nil {
			seen[ip.String()] = true
		}
	}
	for _, address := range expected {
		if ip := net.ParseIP(address); ip != nil && seen[ip.String()] {
			return true
		}
	}
	return false
}

func hasIPv6DefaultRoute() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := dnsCommandContext(ctx, "ip", "-6", "route", "show", "default").Output()
	return err == nil && strings.TrimSpace(string(output)) != ""
}

func probeDNSFamily(parent context.Context, network string, servers []string) bool {
	for _, server := range servers {
		if dnsProbeAddress(parent, network, server) {
			return true
		}
	}
	return false
}

func probeDNSAddress(parent context.Context, network, server string) bool {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 3 * time.Second}
		return dialer.DialContext(ctx, network, net.JoinHostPort(server, "53"))
	}}
	for _, host := range []string{"wordpress.org", "github.com"} {
		if err := dnsLookupHost(ctx, resolver, host); err != nil {
			return false
		}
	}
	return true
}

func restartResolved(ctx context.Context) error {
	output, err := dnsCommandContext(ctx, "systemctl", "restart", "systemd-resolved").CombinedOutput()
	if err != nil {
		return fmt.Errorf("重启 systemd-resolved 失败: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func verifySystemDNS(parent context.Context) error {
	for _, host := range []string{"wordpress.org", "github.com"} {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		err := dnsLookupHost(ctx, net.DefaultResolver, host)
		cancel()
		if err != nil {
			return fmt.Errorf("无法解析 %s: %w", host, err)
		}
	}
	return nil
}
