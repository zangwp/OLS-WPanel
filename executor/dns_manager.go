package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	dnsManagedMarker = "# OLS WPanel managed DNS"
	dnsDropInPath    = "/etc/systemd/resolved.conf.d/50-ols-wpanel-dns.conf"
)

type DNSPreset struct {
	ID   string   `json:"id"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

type DNSStatus struct {
	Supported       bool        `json:"supported"`
	Configurable    bool        `json:"configurable"`
	Manager         string      `json:"manager"`
	Current         []string    `json:"current"`
	Managed         bool        `json:"managed"`
	ActivePreset    string      `json:"active_preset"`
	IPv6Available   bool        `json:"ipv6_available"`
	Reason          string      `json:"reason,omitempty"`
	ReasonCode      string      `json:"reason_code,omitempty"`
	Presets         []DNSPreset `json:"presets"`
	LastProbePreset string      `json:"last_probe_preset,omitempty"`
	IPv4ProbeOK     bool        `json:"ipv4_probe_ok"`
	IPv6ProbeOK     bool        `json:"ipv6_probe_ok"`
	IPv6Skipped     bool        `json:"ipv6_skipped"`
}

var (
	dnsManagerMu      sync.Mutex
	dnsCommandContext = exec.CommandContext
	dnsLookupHost     = func(ctx context.Context, resolver *net.Resolver, host string) error {
		_, err := resolver.LookupHost(ctx, host)
		return err
	}
)

func DNSPresets() []DNSPreset {
	return []DNSPreset{
		{ID: "international", IPv4: []string{"1.1.1.1", "1.0.0.1"}, IPv6: []string{"2606:4700:4700::1111", "2606:4700:4700::1001"}},
		{ID: "mainland_china", IPv4: []string{"223.5.5.5", "223.6.6.6"}, IPv6: []string{"2400:3200::1", "2400:3200:baba::1"}},
	}
}

func GetDNSStatus() DNSStatus {
	status := DNSStatus{Supported: runtime.GOOS == "linux", Presets: DNSPresets(), Current: []string{}}
	if !status.Supported {
		status.Reason = "DNS 设置仅支持 Linux"
		status.ReasonCode = "unsupported"
		return status
	}
	status.Current = activeDNSAddresses()
	status.IPv6Available = hasIPv6DefaultRoute()
	status.Manager = detectDNSManager()
	if status.Manager != "systemd-resolved" {
		status.Reason = "当前 DNS 不由 systemd-resolved 管理，面板只读展示以避免覆盖云厂商网络配置"
		status.ReasonCode = "external_manager"
		return status
	}
	if data, err := os.ReadFile(dnsDropInPath); err == nil {
		if !strings.HasPrefix(string(data), dnsManagedMarker+"\n") {
			status.Reason = "检测到同名 DNS 配置，但它不是由 OLS WPanel 创建的"
			status.ReasonCode = "foreign_config"
			return status
		}
		status.Managed = true
		status.ActivePreset = presetFromConfig(string(data))
	} else if !os.IsNotExist(err) {
		status.Reason = "无法读取 systemd-resolved 配置"
		status.ReasonCode = "read_failed"
		return status
	}
	status.Configurable = true
	return status
}

func ProbeDNSPreset(ctx context.Context, presetID string) (DNSStatus, error) {
	preset, ok := findDNSPreset(presetID)
	if !ok {
		return GetDNSStatus(), errors.New("未知 DNS 预设")
	}
	status := GetDNSStatus()
	status.LastProbePreset = preset.ID
	status.IPv4ProbeOK = probeDNSFamily(ctx, "udp4", preset.IPv4)
	status.IPv6Skipped = !status.IPv6Available
	if status.IPv6Available {
		status.IPv6ProbeOK = probeDNSFamily(ctx, "udp6", preset.IPv6)
	}
	if !status.IPv4ProbeOK {
		return status, errors.New("IPv4 DNS 检测失败，未修改系统配置")
	}
	return status, nil
}

func ApplyDNSPreset(ctx context.Context, presetID string) (DNSStatus, error) {
	dnsManagerMu.Lock()
	defer dnsManagerMu.Unlock()
	preset, ok := findDNSPreset(presetID)
	if !ok {
		return GetDNSStatus(), errors.New("未知 DNS 预设")
	}
	status, err := ProbeDNSPreset(ctx, presetID)
	if err != nil {
		recordOperationLog("dns_apply_preset", presetID, "failed", err.Error())
		return status, err
	}
	if !status.Configurable {
		return status, errors.New(status.Reason)
	}
	oldData, readErr := os.ReadFile(dnsDropInPath)
	oldExists := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return status, readErr
	}
	if oldExists && !strings.HasPrefix(string(oldData), dnsManagedMarker+"\n") {
		return status, errors.New("拒绝覆盖非 OLS WPanel 管理的 DNS 配置")
	}
	includeIPv6 := status.IPv6Available && status.IPv6ProbeOK
	data := renderResolvedDNSConfig(preset, includeIPv6)
	if err := os.MkdirAll(filepath.Dir(dnsDropInPath), 0755); err != nil {
		return status, err
	}
	if err := writeDNSConfigAtomic(dnsDropInPath, []byte(data)); err != nil {
		return status, err
	}
	if err := restartResolved(ctx); err != nil {
		restoreDNSConfig(ctx, oldData, oldExists)
		recordOperationLog("dns_apply_preset", presetID, "failed", err.Error())
		return GetDNSStatus(), err
	}
	if !containsAnyDNS(activeDNSAddresses(), preset.IPv4) {
		restoreDNSConfig(ctx, oldData, oldExists)
		err = errors.New("systemd-resolved 未加载新的 IPv4 DNS，已自动恢复原配置")
		recordOperationLog("dns_apply_preset", presetID, "failed", err.Error())
		return GetDNSStatus(), err
	}
	if err := verifySystemDNS(ctx); err != nil {
		restoreDNSConfig(ctx, oldData, oldExists)
		err = fmt.Errorf("应用后解析验证失败，已自动恢复原 DNS: %w", err)
		recordOperationLog("dns_apply_preset", presetID, "failed", err.Error())
		return GetDNSStatus(), err
	}
	updated := GetDNSStatus()
	updated.LastProbePreset = preset.ID
	updated.IPv4ProbeOK = status.IPv4ProbeOK
	updated.IPv6ProbeOK = status.IPv6ProbeOK
	updated.IPv6Skipped = status.IPv6Skipped
	recordOperationLog("dns_apply_preset", presetID, "success", "ipv6="+fmt.Sprint(includeIPv6))
	return updated, nil
}

func RestoreAutomaticDNS(ctx context.Context) (DNSStatus, error) {
	dnsManagerMu.Lock()
	defer dnsManagerMu.Unlock()
	data, err := os.ReadFile(dnsDropInPath)
	if os.IsNotExist(err) {
		return GetDNSStatus(), nil
	}
	if err != nil {
		return GetDNSStatus(), err
	}
	if !strings.HasPrefix(string(data), dnsManagedMarker+"\n") {
		return GetDNSStatus(), errors.New("拒绝删除非 OLS WPanel 管理的 DNS 配置")
	}
	if err := os.Remove(dnsDropInPath); err != nil {
		return GetDNSStatus(), err
	}
	if err := restartResolved(ctx); err != nil {
		restoreDNSConfig(ctx, data, true)
		return GetDNSStatus(), fmt.Errorf("恢复自动 DNS 失败，已还原面板配置: %w", err)
	}
	if err := verifySystemDNS(ctx); err != nil {
		restoreDNSConfig(ctx, data, true)
		return GetDNSStatus(), fmt.Errorf("自动 DNS 验证失败，已还原面板配置: %w", err)
	}
	recordOperationLog("dns_restore_automatic", "systemd-resolved", "success", "")
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
	servers := append([]string{}, preset.IPv4...)
	if includeIPv6 {
		servers = append(servers, preset.IPv6...)
	}
	return dnsManagedMarker + "\n[Resolve]\nDNS=" + strings.Join(servers, " ") + "\nDomains=~.\n"
}

func presetFromConfig(config string) string {
	for _, preset := range DNSPresets() {
		match := true
		for _, address := range preset.IPv4 {
			if !strings.Contains(config, address) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	active := dnsCommandContext(ctx, "systemctl", "is-active", "--quiet", "systemd-resolved").Run() == nil
	target, linkErr := filepath.EvalSymlinks("/etc/resolv.conf")
	if active && linkErr == nil && strings.Contains(filepath.ToSlash(target), "/systemd/resolve/") {
		return "systemd-resolved"
	}
	return "external"
}

func activeDNSAddresses() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if output, err := dnsCommandContext(ctx, "resolvectl", "dns", "--no-pager").Output(); err == nil {
		if values := parseIPAddresses(string(output)); len(values) > 0 {
			return values
		}
	}
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return []string{}
	}
	values := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "nameserver" && net.ParseIP(fields[1]) != nil {
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
	sort.Strings(result)
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
		ctx, cancel := context.WithTimeout(parent, 4*time.Second)
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 3 * time.Second}
			return dialer.DialContext(ctx, network, net.JoinHostPort(server, "53"))
		}}
		err := dnsLookupHost(ctx, resolver, "wordpress.org")
		cancel()
		if err == nil {
			return true
		}
	}
	return false
}

func restartResolved(ctx context.Context) error {
	output, err := dnsCommandContext(ctx, "systemctl", "restart", "systemd-resolved").CombinedOutput()
	if err != nil {
		return fmt.Errorf("重启 systemd-resolved 失败: %s", strings.TrimSpace(string(output)))
	}
	return nil
}

func verifySystemDNS(parent context.Context) error {
	for _, host := range []string{"wordpress.org", "github.com"} {
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		err := dnsLookupHost(ctx, net.DefaultResolver, host)
		cancel()
		if err != nil {
			return fmt.Errorf("无法解析 %s", host)
		}
	}
	return nil
}

func writeDNSConfigAtomic(path string, data []byte) error {
	temp := path + ".new"
	if err := os.WriteFile(temp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}

func restoreDNSConfig(_ context.Context, data []byte, existed bool) {
	if existed {
		_ = writeDNSConfigAtomic(dnsDropInPath, data)
	} else {
		_ = os.Remove(dnsDropInPath)
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = restartResolved(rollbackCtx)
}
