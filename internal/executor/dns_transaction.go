package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

type dnsManagerPaths struct{ ResolvConf, DropIn, Backup, Lock string }

func defaultDNSPaths() dnsManagerPaths {
	return dnsManagerPaths{ResolvConf: "/etc/resolv.conf", DropIn: dnsDropInPath,
		Backup: "/var/lib/ols-wpanel/dns/original.json", Lock: "/run/ols-wpanel/dns.lock"}
}

type dnsFileSnapshot struct {
	Exists    bool   `json:"exists"`
	Data      []byte `json:"data"`
	Mode      uint32 `json:"mode"`
	UID       int    `json:"uid"`
	GID       int    `json:"gid"`
	Immutable bool   `json:"immutable"`
}

type dnsOriginalBackup struct {
	Version  int             `json:"version"`
	Target   string          `json:"target"`
	Manager  string          `json:"manager"`
	Original dnsFileSnapshot `json:"original"`
	// Both the old and the next managed content are accepted so interruption
	// between durable backup and atomic replacement leaves a usable restore path.
	ManagedHashes []string `json:"managed_hashes"`
}

var (
	dnsReadSnapshot     = readDNSFileSnapshot
	dnsWriteSnapshot    = writeDNSFileSnapshotAtomic
	dnsAcquireLock      = acquireDNSManagerLock
	dnsPrivateDirectory = ensureDNSPrivateDirectory
)

func dnsContentHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (b *dnsOriginalBackup) accepts(data []byte) bool {
	if !strings.HasPrefix(string(data), dnsManagedMarker+"\n") {
		return false
	}
	hash := dnsContentHash(data)
	for _, accepted := range b.ManagedHashes {
		if hash == accepted {
			return true
		}
	}
	return false
}

func sameDNSSnapshot(a, b dnsFileSnapshot) bool {
	if a.Exists != b.Exists {
		return false
	}
	if !a.Exists {
		return true
	}
	return a.Mode == b.Mode && a.UID == b.UID && a.GID == b.GID && a.Immutable == b.Immutable && bytes.Equal(a.Data, b.Data)
}

func readDNSBackup(paths dnsManagerPaths, target string) (*dnsOriginalBackup, error) {
	if err := dnsPrivateDirectory(paths.Backup, false); err != nil {
		return nil, err
	}
	snapshot, err := dnsReadSnapshot(paths.Backup, false)
	if err != nil {
		return nil, err
	}
	if !snapshot.Exists || snapshot.Mode != 0o600 || snapshot.Immutable {
		return nil, errors.New("DNS 原始备份必须是私有 0600 普通文件")
	}
	decoder := json.NewDecoder(bytes.NewReader(snapshot.Data))
	decoder.DisallowUnknownFields()
	var backup dnsOriginalBackup
	if err := decoder.Decode(&backup); err != nil {
		return nil, fmt.Errorf("DNS 备份格式无效: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("DNS 备份含额外内容")
	}
	if backup.Version != 1 || backup.Target != target || (target != paths.ResolvConf && target != paths.DropIn) {
		return nil, errors.New("DNS 备份目标不匹配")
	}
	if backup.Manager != "systemd-resolved" && backup.Manager != "static-resolv.conf" && backup.Manager != "ols-resolv.conf" {
		return nil, errors.New("DNS 备份管理方式无效")
	}
	if (target == paths.DropIn) != (backup.Manager == "systemd-resolved") {
		return nil, errors.New("DNS 备份管理方式与目标不匹配")
	}
	if len(backup.Original.Data) > 64*1024 || backup.Original.Mode & ^uint32(0o777) != 0 || backup.Original.Mode&0o022 != 0 || backup.Original.UID < 0 || backup.Original.GID < 0 {
		return nil, errors.New("DNS 原始备份身份无效")
	}
	if len(backup.ManagedHashes) < 1 || len(backup.ManagedHashes) > 2 {
		return nil, errors.New("DNS 备份校验值无效")
	}
	for _, hash := range backup.ManagedHashes {
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != sha256.Size {
			return nil, errors.New("DNS 备份校验值无效")
		}
	}
	return &backup, nil
}

func writeDNSBackup(paths dnsManagerPaths, backup *dnsOriginalBackup) error {
	if err := dnsPrivateDirectory(paths.Backup, true); err != nil {
		return err
	}
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	previous, err := dnsReadSnapshot(paths.Backup, true)
	if err != nil {
		return err
	}
	if previous.Exists && (previous.Mode != 0o600 || previous.Immutable) {
		return errors.New("拒绝覆盖身份异常的 DNS 原始备份")
	}
	next := previous
	next.Exists, next.Data, next.Mode = true, append(data, '\n'), 0o600
	if !previous.Exists {
		next.UID, next.GID = dnsFileOwner()
	}
	if err := dnsWriteSnapshot(paths.Backup, next); err != nil {
		return fmt.Errorf("保存原始 DNS 备份失败: %w", err)
	}
	check, err := readDNSBackup(paths, backup.Target)
	if err != nil || check == nil || check.Version != backup.Version || check.Manager != backup.Manager || check.Target != backup.Target || strings.Join(check.ManagedHashes, ",") != strings.Join(backup.ManagedHashes, ",") || !sameDNSSnapshot(check.Original, backup.Original) {
		return errors.New("原始 DNS 备份回读验证失败，未修改 DNS")
	}
	return nil
}

func dnsRollbackFailure(_ context.Context, manager, target string, previous dnsFileSnapshot, cause error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var failures []error
	current, readErr := dnsReadSnapshot(target, true)
	mayRestore := readErr == nil && (bytes.Equal(current.Data, previous.Data) || !current.Exists)
	if !mayRestore && readErr == nil {
		backup, backupErr := readDNSBackup(dnsPaths, target)
		mayRestore = backupErr == nil && (backup.accepts(current.Data) || bytes.Equal(current.Data, backup.Original.Data))
	}
	if !mayRestore {
		failures = append(failures, errors.New("回滚前发现未知 DNS 文件内容或身份变化，保留现场及原始备份"))
	} else if !sameDNSSnapshot(current, previous) {
		if err := dnsWriteSnapshot(target, previous); err != nil {
			failures = append(failures, fmt.Errorf("还原文件/属性失败: %w", err))
		}
	}
	if manager == "systemd-resolved" {
		if err := restartResolved(ctx); err != nil {
			failures = append(failures, err)
		}
	}
	actual, err := dnsReadSnapshot(target, true)
	if err != nil || !sameDNSSnapshot(previous, actual) {
		failures = append(failures, errors.New("原 DNS 文件/权限/属性回读不一致"))
	}
	if err := dnsVerifyCurrent(ctx); err != nil {
		failures = append(failures, fmt.Errorf("原 DNS 解析验证失败: %w", err))
	}
	if len(failures) > 0 {
		return fmt.Errorf("%w；自动回滚未验证成功: %v；原始备份保留在 %s，请勿继续重复修改", cause, errors.Join(failures...), dnsPaths.Backup)
	}
	return fmt.Errorf("%w；已恢复修改前 DNS 并通过文件、属性及解析验证", cause)
}

func rollbackDNSStatus(ctx context.Context, manager, target string, previous dnsFileSnapshot, cause error) (DNSStatus, error) {
	err := dnsRollbackFailure(ctx, manager, target, previous, cause)
	return GetDNSStatus(), err
}

func renderStaticDNS(original []byte, servers []string) []byte {
	// Keep search/domain/options and administrator comments verbatim. Remove
	// only nameserver directives and our marker, so restoration remains exact.
	lines := strings.Split(string(original), "\n")
	var kept []string
	for _, line := range lines {
		fields := strings.Fields(line)
		if line == dnsManagedMarker || (len(fields) > 0 && fields[0] == "nameserver") {
			continue
		}
		kept = append(kept, line)
	}
	var result strings.Builder
	result.WriteString(dnsManagedMarker + "\n")
	for _, server := range servers {
		result.WriteString("nameserver " + server + "\n")
	}
	result.WriteString(strings.Join(kept, "\n"))
	if !strings.HasSuffix(result.String(), "\n") {
		result.WriteByte('\n')
	}
	return []byte(result.String())
}

func managerFromResolvConf(data string) string {
	generated := false
	for _, line := range strings.Split(data, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if !strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.Contains(line, "networkmanager"):
			return "NetworkManager"
		case strings.Contains(line, "resolvconf"), strings.Contains(line, "openresolv"):
			return "resolvconf"
		case strings.Contains(line, "cloud-init"), strings.Contains(line, "cloudinit"):
			return "cloud-init"
		case strings.Contains(line, "dhclient"), strings.Contains(line, "dhcpcd"):
			return "dhcp"
		case strings.Contains(line, "netplan"):
			return "netplan"
		case strings.Contains(line, "generated"), strings.Contains(line, "automatically generated"):
			generated = true
		}
	}
	if generated {
		return "auto-generated"
	}
	return "static-resolv.conf"
}

func dnsUnsupportedManagerReason(manager string) string {
	switch manager {
	case "NetworkManager":
		return "检测到 NetworkManager 管理或生成 DNS；需使用它的连接配置修改，终端不静默接管"
	case "resolvconf":
		return "DNS 由 resolvconf/openresolv 生成；需通过对应服务修改，终端不覆盖生成文件"
	case "cloud-init":
		return "检测到 cloud-init 生成的 DNS 文件；需先确认云初始化网络配置，终端不静默接管"
	case "dhcp":
		return "检测到 DHCP 客户端生成的 DNS；需在客户端配置修改，终端不覆盖生成文件"
	case "netplan":
		return "检测到 netplan 生成的 DNS；需通过 netplan 配置修改，终端不覆盖生成文件"
	case "symbolic-link":
		return "resolv.conf 是未知或失效符号链接；无法确认管理者，终端保留只读"
	case "auto-generated":
		return "resolv.conf 标注为自动生成，但管理者未确认；请先检查来源，终端保留只读"
	case "unavailable":
		return "无法读取 resolv.conf，终端保留只读"
	default:
		return "无法确认 DNS 文件的管理方式，终端保留只读"
	}
}

func containsAllDNS(current, expected []string) bool {
	for _, address := range expected {
		if !containsAnyDNS(current, []string{address}) {
			return false
		}
	}
	return len(expected) > 0
}
