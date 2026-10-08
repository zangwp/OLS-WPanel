package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

// IsVPSMaintenanceCLI identifies the terminal-only maintenance bridges. None
// starts the daemon, reconciles firewall rules, or migrates the database.
func IsVPSMaintenanceCLI(action string) bool {
	switch action {
	case "ports-status", "services-status", "service-log", "bbr-status", "ssh-port-status", "ssh-port-start", "ssh-port-confirm", "vps-history":
		return true
	}
	return false
}

func RunVPSMaintenanceCLI(ctx context.Context, action, value string, cfg *config.Config) (any, error) {
	if !IsVPSMaintenanceCLI(action) {
		return nil, errors.New("未知终端维护操作")
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("终端维护需要 Linux")
	}
	if err := ValidateVPSMaintenanceCLI(action, value, cfg); err != nil {
		return nil, err
	}
	switch action {
	case "ports-status":
		// This existing inspection performs only list/show/read operations.
		// Unlike ReconcileFirewallPortRules, it does not apply host rules.
		if database.GetDB() != nil {
			return GetFirewallPortStatus()
		}
		return inspectVPSCLIPortsWithoutDatabase(ctx, cfg), nil
	case "services-status":
		return inspectVPSCLIServices(ctx, cfg, vpsToolCommand), nil
	case "service-log":
		unit, err := vpsCLIServiceUnit(value, cfg)
		if err != nil {
			return nil, err
		}
		out, err := vpsToolCommand(ctx, "journalctl", "--unit="+unit, "--lines=40", "--no-pager", "--output=short-iso")
		if err != nil {
			return nil, fmt.Errorf("读取服务日志失败: %w", err)
		}
		return vpsCLIServiceLog{ID: value, Unit: unit, Lines: strings.Split(sanitizeVPSCLIText(out, 16384), "\n")}, nil
	case "bbr-status":
		return inspectVPSCLIBBR(ctx, "/etc", vpsToolCommand), nil
	case "ssh-port-status":
		return GetSSHPortStatus(), nil
	case "ssh-port-start":
		port, ip, _ := parseVPSCLISSHStart(value)
		return beginVPSCLISSHChange(port, ip)
	case "ssh-port-confirm":
		return confirmVPSCLISSHChange(value, os.Getenv("SSH_CONNECTION"))
	case "vps-history":
		entries, err := readVPSCLIHistory(vpsCLIStateDirectory)
		return struct {
			Entries []VPSCLIHistoryEntry `json:"entries"`
		}{entries}, err
	}
	return nil, errors.New("未知终端维护操作")
}

func inspectVPSCLIPortsWithoutDatabase(ctx context.Context, cfg *config.Config) FirewallPortStatus {
	_, _, _, policy, warning, _ := firewallPortTarget(ctx)
	listeners := detectListeners(ctx)
	warning = strings.TrimSpace(warning + " 未读取面板数据库，仅显示当前监听与实时访问策略；不会应用防火墙规则。")
	if _, err := portCommand(ctx, "ss", "-H", "-lntup"); err != nil {
		warning += " 监听读取失败，请检查 ss/iproute2 与权限。"
	}
	accessEnabled, accessRules, accessErr := readAccessState(ctx)
	if accessErr != nil {
		warning += " 访问策略读取失败。"
	}
	status := FirewallPortStatus{Backend: "nftables", Warning: warning, InputPolicy: policy, SSHPort: detectSSHPort(ctx, listeners), AccessEnabled: accessEnabled, AccessRules: accessRules, Listeners: listeners, Rules: []FirewallPortRule{}}
	if cfg != nil {
		status.PanelPort = cfg.Panel.Port
		if cfg.Panel.TLSPort > 0 && cfg.Panel.TLSCertPath != "" && cfg.Panel.TLSKeyPath != "" {
			status.PanelPort = cfg.Panel.TLSPort
		}
	}
	for i := range status.Listeners {
		l := &status.Listeners[i]
		if l.BindScope == "local" {
			l.HostExposure = "local_only"
			status.LocalListenerCount++
		} else {
			l.HostExposure = "rule_dependent"
			if policy == "accept" && !accessEnabled {
				l.HostExposure = "allowed_by_default"
			}
			status.NetworkListenerCount++
			if l.Port == 3306 || l.Port == 6379 {
				status.DangerousListenerCount++
			}
		}
	}
	status.ListenerCount = len(listeners)
	status.AnomalyCount = status.DangerousListenerCount
	return status
}

// ValidateVPSMaintenanceCLI allows main to reject malformed input before it
// opens the existing database for SSH transaction operation logs.
func ValidateVPSMaintenanceCLI(action, value string, cfg *config.Config) error {
	switch action {
	case "ports-status", "services-status", "bbr-status", "ssh-port-status", "vps-history":
		if value != "" {
			return errors.New("此只读操作不接受额外参数")
		}
	case "service-log":
		_, err := vpsCLIServiceUnit(value, cfg)
		return err
	case "ssh-port-start":
		_, _, err := parseVPSCLISSHStart(value)
		return err
	case "ssh-port-confirm":
		if !vpsCLISSHtokenRE.MatchString(value) {
			return errors.New("SSH 确认令牌格式无效")
		}
	default:
		return errors.New("未知终端维护操作")
	}
	return nil
}

var vpsCLIUnitRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,95}$`)
var vpsCLISSHtokenRE = regexp.MustCompile(`^[a-f0-9]{48}$`)

func vpsCLIServiceUnit(id string, cfg *config.Config) (string, error) {
	unit := map[string]string{"panel": "ols-wpanel", "ols": "lshttpd", "mariadb": "mariadb", "redis": "redis-server", "fail2ban": "fail2ban", "nftables": "nftables"}[id]
	if unit == "" {
		return "", errors.New("请选择面板、OLS、MariaDB、Redis、Fail2ban 或 nftables 服务")
	}
	if id == "panel" && cfg != nil && cfg.Systemd.ServiceName != "" {
		unit = cfg.Systemd.ServiceName
	}
	if !vpsCLIUnitRE.MatchString(unit) {
		return "", errors.New("配置中的服务名称无效")
	}
	if !strings.HasSuffix(unit, ".service") {
		unit += ".service"
	}
	return unit, nil
}

type vpsCLIServiceState struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Unit          string `json:"unit"`
	LoadState     string `json:"load_state"`
	ActiveState   string `json:"active_state"`
	SubState      string `json:"sub_state"`
	UnitFileState string `json:"unit_file_state"`
	Error         string `json:"error,omitempty"`
}

type vpsCLIServiceLog struct {
	ID    string   `json:"id"`
	Unit  string   `json:"unit"`
	Lines []string `json:"lines"`
}

func inspectVPSCLIServices(ctx context.Context, cfg *config.Config, run func(context.Context, string, ...string) (string, error)) any {
	items := make([]vpsCLIServiceState, 0, 6)
	for _, s := range []struct{ id, name string }{{"panel", "OLS WPanel"}, {"ols", "OpenLiteSpeed"}, {"mariadb", "MariaDB"}, {"redis", "Redis"}, {"fail2ban", "Fail2ban"}, {"nftables", "nftables"}} {
		item := vpsCLIServiceState{ID: s.id, Name: s.name}
		unit, err := vpsCLIServiceUnit(s.id, cfg)
		if err == nil {
			item.Unit = unit
			var out string
			out, err = run(ctx, "systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,UnitFileState")
			props := make(map[string]string)
			for _, line := range strings.Split(out, "\n") {
				if key, value, ok := strings.Cut(line, "="); ok {
					props[key] = sanitizeVPSCLIText(value, 128)
				}
			}
			item.LoadState, item.ActiveState, item.SubState, item.UnitFileState = props["LoadState"], props["ActiveState"], props["SubState"], props["UnitFileState"]
		}
		if err != nil {
			item.Error = sanitizeVPSCLIText(err.Error(), 300)
		}
		items = append(items, item)
	}
	return struct {
		Services []vpsCLIServiceState `json:"services"`
	}{items}
}

type vpsCLIBBRPersistent struct {
	Path            string `json:"path"`
	Managed         bool   `json:"managed"`
	Algorithm       string `json:"algorithm,omitempty"`
	QueueDiscipline string `json:"queue_discipline,omitempty"`
}

type vpsCLIBBRStatus struct {
	Algorithm           string                `json:"algorithm"`
	QueueDiscipline     string                `json:"queue_discipline"`
	AvailableAlgorithms []string              `json:"available_algorithms"`
	Persistent          []vpsCLIBBRPersistent `json:"persistent"`
	Errors              []string              `json:"errors"`
}

func inspectVPSCLIBBR(ctx context.Context, etc string, run func(context.Context, string, ...string) (string, error)) vpsCLIBBRStatus {
	s := vpsCLIBBRStatus{AvailableAlgorithms: []string{}, Persistent: []vpsCLIBBRPersistent{}, Errors: []string{}}
	for _, key := range []string{"net.ipv4.tcp_congestion_control", "net.core.default_qdisc", "net.ipv4.tcp_available_congestion_control"} {
		out, err := run(ctx, "sysctl", "-n", key)
		if err != nil {
			s.Errors = append(s.Errors, key+": "+sanitizeVPSCLIText(err.Error(), 200))
			continue
		}
		out = sanitizeVPSCLIText(strings.TrimSpace(out), 256)
		switch key {
		case "net.ipv4.tcp_congestion_control":
			s.Algorithm = out
		case "net.core.default_qdisc":
			s.QueueDiscipline = out
		default:
			s.AvailableAlgorithms = strings.Fields(out)
		}
	}
	paths, _ := filepath.Glob(filepath.Join(etc, "sysctl.d", "*.conf"))
	paths = append(paths, filepath.Join(etc, "sysctl.conf"))
	sort.Strings(paths)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				s.Errors = append(s.Errors, path+": "+sanitizeVPSCLIText(err.Error(), 200))
			}
			continue
		}
		item := parseVPSCLIBBRPersistent(path, string(data))
		if item.Algorithm != "" || item.QueueDiscipline != "" {
			s.Persistent = append(s.Persistent, item)
		}
	}
	return s
}

func parseVPSCLIBBRPersistent(path, content string) vpsCLIBBRPersistent {
	item := vpsCLIBBRPersistent{Path: path, Managed: strings.HasPrefix(content, "# OLS WPanel — 网络与内核优化") || strings.HasPrefix(content, "# OLS WPanel VPS tuning\n")}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.SplitN(strings.SplitN(line, "#", 2)[0], ";", 2)[0])
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = sanitizeVPSCLIText(strings.TrimSpace(value), 128)
		switch strings.TrimSpace(key) {
		case "net.ipv4.tcp_congestion_control":
			item.Algorithm = value
		case "net.core.default_qdisc":
			item.QueueDiscipline = value
		}
	}
	return item
}

func parseVPSCLISSHStart(value string) (int, string, error) {
	portText, ipText, ok := strings.Cut(value, ":")
	port, err := strconv.Atoi(portText)
	if !ok || err != nil || port < 1 || port > 65535 || strings.Trim(portText, "0123456789") != "" || net.ParseIP(ipText) == nil {
		return 0, "", errors.New("SSH 参数必须为 新端口:当前SSH客户端IP")
	}
	return port, net.ParseIP(ipText).String(), nil
}

func validateVPSCLISSHConnection(connection string, newPort int) error {
	fields := strings.Fields(connection)
	if len(fields) != 4 || net.ParseIP(fields[0]) == nil || net.ParseIP(fields[2]) == nil {
		return errors.New("未识别 SSH 会话；请通过新端口建立新的 SSH 连接后确认")
	}
	clientPort, e1 := strconv.Atoi(fields[1])
	serverPort, e2 := strconv.Atoi(fields[3])
	if e1 != nil || e2 != nil || clientPort < 1 || clientPort > 65535 || serverPort != newPort {
		return errors.New("请在新 SSH 端口的连接中执行确认；当前连接未通过检查")
	}
	return nil
}

func sanitizeVPSCLIText(text string, maxRunes int) string {
	runes := make([]rune, 0, maxRunes)
	for _, r := range text {
		if !unicode.IsPrint(r) && r != '\n' && r != '\t' {
			continue
		}
		if len(runes) >= maxRunes {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}
