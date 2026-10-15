package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

const (
	vpsCLIHealthTimeout       = 12 * time.Second
	vpsCLIHealthCommandTime   = 1500 * time.Millisecond
	vpsCLIHealthOutputLimit   = 64 << 10
	vpsCLIHealthResolverLimit = 16 << 10
)

var errVPSCLIHealthOutputLimit = errors.New("体检读取超过大小上限")

type vpsCLIHealthCheck struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Summary  string `json:"summary"`
	NextStep string `json:"next_step"`
}

type vpsCLIHealthStatus struct {
	CheckedAt   time.Time           `json:"checked_at"`
	Status      string              `json:"status"`
	Checks      []vpsCLIHealthCheck `json:"checks"`
	Limitations []string            `json:"limitations"`
}

type vpsCLIHealthOperations struct {
	run            func(context.Context, string, ...string) (string, error)
	read           func(context.Context, string, int64) ([]byte, error)
	now            func() time.Time
	totalTimeout   time.Duration
	commandTimeout time.Duration
}

// inspectVPSCLIHealth reads the current host only. It does not open SQLite,
// initialize daemons, reconcile firewall rules, update packages or repair files.
func inspectVPSCLIHealth(ctx context.Context, cfg *config.Config) (any, error) {
	return inspectVPSCLIHealthWith(ctx, cfg, vpsCLIHealthOperations{
		run: runVPSCLIHealthCommand, read: readVPSCLIHealthFile, now: time.Now,
		totalTimeout: vpsCLIHealthTimeout, commandTimeout: vpsCLIHealthCommandTime,
	}), nil
}

func inspectVPSCLIHealthWith(ctx context.Context, cfg *config.Config, ops vpsCLIHealthOperations) vpsCLIHealthStatus {
	ctx, cancel := context.WithTimeout(ctx, ops.totalTimeout)
	defer cancel()
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		child, stop := context.WithTimeout(ctx, ops.commandTimeout)
		defer stop()
		return ops.run(child, name, args...)
	}
	result := vpsCLIHealthStatus{CheckedAt: ops.now().UTC(), Status: "ok", Checks: []vpsCLIHealthCheck{}, Limitations: []string{
		"仅检查当前主机的只读状态，不自动修复、安装软件或修改配置。",
		"未验证公网入站、云安全组、实际 DNS 查询、网站请求及数据库业务；本地正常不代表外部可达。",
		"软件包仅执行 dpkg --audit；完整依赖模拟检查请使用 o apt-check，不更新 APT 索引。",
	}}
	add := func(check vpsCLIHealthCheck) {
		result.Checks = append(result.Checks, check)
		if check.Status == "warning" || (check.Status == "unknown" && result.Status == "ok") {
			result.Status = check.Status
		}
	}
	services := inspectVPSCLIServices(ctx, cfg, run).(struct {
		Services []vpsCLIServiceState `json:"services"`
	}).Services
	for _, service := range services {
		check := vpsCLIHealthCheck{ID: "service_" + service.ID, Name: service.Name, Status: "unknown", Summary: "未能确认服务状态", NextStep: "使用 o services 查看该服务状态与日志；缺失服务不自动安装。"}
		if service.Error == "" && service.LoadState == "loaded" {
			switch service.ActiveState {
			case "active":
				if service.SubState == "running" || service.SubState == "exited" {
					check.Status, check.Summary = "ok", "systemd 服务处于 active / "+service.SubState
					check.NextStep = "如业务异常，继续检查服务日志和实际请求。"
				}
			case "inactive", "failed":
				check.Status, check.Summary = "warning", "systemd 服务处于 "+service.ActiveState
			}
		}
		add(check)
	}
	paths, invalidPaths := vpsCLIHealthDiskPaths(cfg)
	for _, metric := range []struct {
		id, name, field string
		threshold       int
	}{{"disk_space", "磁盘空间", "pcent", 85}, {"inodes", "磁盘 inode", "ipcent", 90}} {
		check := vpsCLIHealthCheck{ID: metric.id, Name: metric.name, Status: "ok", NextStep: "使用 o disk 查看各目录；清理前先确认备份与业务文件用途。"}
		var maximum int
		valid := 0
		var unknown bool
		for _, path := range paths {
			out, err := run(ctx, "df", "--output="+metric.field, "--", path)
			percent, parseErr := parseVPSCLIHealthPercent(out)
			if err != nil || parseErr != nil {
				unknown = true
				continue
			}
			if percent > maximum {
				maximum = percent
			}
			valid++
		}
		if valid == 0 {
			check.Summary = "未能读取任何目录的使用率"
		} else {
			check.Summary = fmt.Sprintf("已读取 %d 个目录，最高使用率 %d%%", valid, maximum)
		}
		if maximum >= metric.threshold {
			check.Status = "warning"
		}
		if unknown || invalidPaths {
			if check.Status == "ok" {
				check.Status = "unknown"
			}
			check.Summary += "；部分目录无数据、路径无效或读取失败，检查不完整"
		}
		add(check)
	}
	packages := vpsCLIHealthCheck{ID: "packages", Name: "dpkg 软件包状态", Status: "unknown", Summary: "未能完成软件包状态读取", NextStep: "使用 o apt-check 查看详情；请先核对错误，再决定是否修复。"}
	if out, err := run(ctx, "dpkg", "--audit"); err == nil {
		if strings.TrimSpace(out) == "" {
			packages.Status, packages.Summary = "ok", "dpkg 未报告未完成的软件包配置"
		} else {
			packages.Status, packages.Summary = "warning", "dpkg 报告待处理的软件包状态，请查看完整检查"
		}
	}
	add(packages)
	route := vpsCLIHealthCheck{ID: "default_route", Name: "本地默认路由", Status: "ok", NextStep: "使用 o network 核对网卡、网关及供应商网络配置。"}
	var families []string
	routeUnknown := false
	for _, family := range []string{"4", "6"} {
		out, err := run(ctx, "ip", "-"+family, "route", "show", "default")
		if err != nil {
			routeUnknown = true
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				if fields[0] != "default" {
					routeUnknown = true
					continue
				}
				families = append(families, "IPv"+family)
				break
			}
		}
	}
	if routeUnknown {
		route.Status, route.Summary = "unknown", "部分路由读取失败或无法识别，不能确认配置完整"
	} else if len(families) == 0 {
		route.Status, route.Summary = "warning", "未发现 IPv4 或 IPv6 默认路由"
	} else {
		route.Summary = "已发现 " + strings.Join(families, " / ") + " 默认路由；未测试外网连接"
	}
	add(route)
	dns := vpsCLIHealthCheck{ID: "dns_config", Name: "本地 DNS 配置", Status: "unknown", Summary: "未能读取本地解析配置", NextStep: "使用 o dns 查看解析器及系统接管方式；配置存在不代表实际解析成功。"}
	if data, err := ops.read(ctx, "/etc/resolv.conf", vpsCLIHealthResolverLimit); err == nil {
		count, invalid := 0, false
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(strings.SplitN(strings.SplitN(line, "#", 2)[0], ";", 2)[0])
			if len(fields) == 0 || fields[0] != "nameserver" {
				continue
			}
			if len(fields) != 2 || net.ParseIP(strings.SplitN(fields[1], "%", 2)[0]) == nil {
				invalid = true
			} else {
				count++
			}
		}
		if invalid || count == 0 {
			dns.Status, dns.Summary = "warning", "本地解析器为空或包含无效 nameserver 配置"
		} else {
			dns.Status, dns.Summary = "ok", fmt.Sprintf("已配置 %d 个本地解析器条目（可包含本地 stub）；未测试实际解析", count)
		}
	}
	add(dns)
	return result
}

func vpsCLIHealthDiskPaths(cfg *config.Config) ([]string, bool) {
	paths := []string{"/", "/www/wwwroot", config.DefaultBackupDir}
	if cfg != nil {
		if cfg.Paths.WWWRoot != "" {
			paths[1] = cfg.Paths.WWWRoot
		}
		if cfg.Panel.BackupDir != "" {
			paths[2] = cfg.Panel.BackupDir
		}
	}
	unique, invalid := []string{}, false
	seen := map[string]bool{}
	for _, directory := range paths {
		if !path.IsAbs(directory) || strings.ContainsAny(directory, "\x00\r\n") {
			invalid = true
			continue
		}
		directory = path.Clean(directory)
		if !seen[directory] {
			unique, seen[directory] = append(unique, directory), true
		}
	}
	return unique, invalid
}

func parseVPSCLIHealthPercent(out string) (int, error) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || len(strings.Fields(lines[0])) != 1 {
		return 0, errors.New("无法识别 df 输出")
	}
	field := strings.TrimSpace(lines[1])
	if !strings.HasSuffix(field, "%") {
		return 0, errors.New("文件系统未提供使用率")
	}
	value, err := strconv.Atoi(strings.TrimSuffix(field, "%"))
	if err != nil || value < 0 || value > 100 {
		return 0, errors.New("使用率超出范围")
	}
	return value, nil
}

// Only fixed read-only tools can enter the production runner. -- separates df
// paths from options; service names are validated by vpsCLIServiceUnit.
func runVPSCLIHealthCommand(ctx context.Context, command string, args ...string) (string, error) {
	allowed := false
	switch command {
	case "systemctl":
		allowed = len(args) == 3 && args[0] == "show" && vpsCLIUnitRE.MatchString(args[1]) && strings.HasSuffix(args[1], ".service") && args[2] == "--property=LoadState,ActiveState,SubState,UnitFileState"
	case "df":
		allowed = len(args) == 3 && (args[0] == "--output=pcent" || args[0] == "--output=ipcent") && args[1] == "--" && path.IsAbs(args[2]) && !strings.ContainsAny(args[2], "\x00\r\n")
	case "dpkg":
		allowed = len(args) == 1 && args[0] == "--audit"
	case "ip":
		allowed = len(args) == 4 && (args[0] == "-4" || args[0] == "-6") && args[1] == "route" && args[2] == "show" && args[3] == "default"
	}
	if !allowed {
		return "", errors.New("体检命令不在只读允许列表中")
	}
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"} {
		path := filepath.Join(dir, command)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return runVPSCLIHealthProcess(ctx, path, args...)
		}
	}
	return "", errors.New("体检工具不存在")
}

type vpsCLIHealthOutput struct {
	buffer   bytes.Buffer
	overflow bool
	cancel   context.CancelFunc
}

func (output *vpsCLIHealthOutput) Write(data []byte) (int, error) {
	remaining := vpsCLIHealthOutputLimit - output.buffer.Len()
	if len(data) > remaining {
		n, _ := output.buffer.Write(data[:remaining])
		output.overflow = true
		output.cancel()
		return n, errVPSCLIHealthOutputLimit
	}
	return output.buffer.Write(data)
}

func runVPSCLIHealthProcess(ctx context.Context, path string, args ...string) (string, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	output := &vpsCLIHealthOutput{cancel: cancel}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	cmd.WaitDelay = 200 * time.Millisecond
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	if output.overflow {
		return "", errVPSCLIHealthOutputLimit
	}
	return output.buffer.String(), err
}

func readVPSCLIHealthFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// /etc/resolv.conf commonly links to a systemd-generated regular file.
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("体检配置文件缺失、不可读或超过上限")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("体检配置文件在读取前发生变化")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > int(limit) {
		return nil, errVPSCLIHealthOutputLimit
	}
	return data, ctx.Err()
}
