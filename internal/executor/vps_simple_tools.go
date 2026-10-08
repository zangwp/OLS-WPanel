package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var vpsToolsMu sync.Mutex

func vpsToolCommand(ctx context.Context, command string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, command, args...).CombinedOutput()
	if len(out) > 16384 {
		out = out[len(out)-16384:]
	}
	if err != nil {
		return string(out), fmt.Errorf("%s: %w: %s", command, err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// All inputs are allowlisted. No shell strings or user-supplied paths are executed.
func RunSimpleVPSTool(ctx context.Context, action, value string) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("Linux required")
	}
	vpsToolsMu.Lock()
	defer vpsToolsMu.Unlock()
	unlock, err := lockSimpleVPSTools()
	if err != nil {
		return "", err
	}
	defer unlock()
	switch action {
	case "timezone":
		return setVPSTimezone(ctx, value, vpsToolCommand)
	case "hostname":
		return setVPSHostname(ctx, value, vpsToolCommand)
	case "locale-install":
		return installVPSLocale(ctx, value, vpsToolCommand)
	case "clean-preview":
		apt, e := vpsToolCommand(ctx, "du", "-sh", "/var/cache/apt/archives")
		if e != nil {
			return "", e
		}
		logs, e := vpsToolCommand(ctx, "journalctl", "--disk-usage")
		return apt + logs, e
	case "clean":
		first, e := vpsToolCommand(ctx, "apt-get", "clean")
		if e != nil {
			return "", e
		}
		last, e := vpsToolCommand(ctx, "journalctl", "--vacuum-time=14d")
		return first + last, e
	case "ip-priority":
		return setVPSIPPriority(value)
	case "tuning":
		return setVPSTuning(ctx, value)
	case "locale":
		if value != "en_US.UTF-8" && value != "zh_CN.UTF-8" && value != "zh_TW.UTF-8" {
			return "", fmt.Errorf("invalid locale")
		}
		if _, err := exec.LookPath("locale-gen"); err != nil {
			return "", fmt.Errorf("缺少 locales 软件包；请在 o 系统语言菜单选择安装后再设置 / Install locales from the o language menu first")
		}
		const path = "/etc/locale.gen"
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		line := value + " UTF-8"
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(line) + `\s*$`).Match(data) {
			if err = writePanelTLSFile(path, append(data, []byte("\n"+line+"\n")...), 0644); err != nil {
				return "", err
			}
		}
		if _, err = vpsToolCommand(ctx, "locale-gen", value); err != nil {
			return "", err
		}
		out, err := vpsToolCommand(ctx, "update-locale", "LANG="+value)
		return out + "重新登录 SSH 后生效 / Reconnect SSH to apply", err
	default:
		return "", fmt.Errorf("unknown VPS action")
	}
}

func buildVPSIPPriority(content, mode string) (string, error) {
	if mode != "ipv4" && mode != "ipv6" && mode != "default" {
		return "", fmt.Errorf("invalid IP priority")
	}
	external, _, err := splitIPPriorityContent(content)
	if err != nil {
		return "", err
	}
	content = external
	if mode == "default" {
		return content, nil
	}
	if ipPriorityExternalRE.MatchString(content) {
		return "", fmt.Errorf("existing administrator precedence rules; edit /etc/gai.conf manually")
	}
	rule := "precedence ::ffff:0:0/96 100"
	if mode == "ipv6" {
		rule = "precedence ::ffff:0:0/96 10\nprecedence ::/0 100"
	}
	return strings.TrimRight(content, "\n") + "\n" + ipPriorityBegin + "\n" + rule + "\n" + ipPriorityEnd + "\n", nil
}
func setVPSIPPriority(mode string) (string, error) {
	const path = "/etc/gai.conf"
	before, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	next, err := buildVPSIPPriority(string(before), mode)
	if err != nil {
		return "", err
	}
	if err = writePanelTLSFile(path, []byte(next), 0644); err != nil {
		return "", err
	}
	return "地址优先级已更新：" + map[string]string{"ipv4": "IPv4 优先", "ipv6": "IPv6 优先", "default": "系统规则"}[mode] + "；对遵循系统规则的新连接生效", nil
}

var vpsTuningKeys = []string{"net.core.somaxconn", "net.ipv4.tcp_max_syn_backlog"}

// Only migrate our installer-owned queue entries, preserving unrelated settings.
func stripInstallerQueues(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	if !strings.HasPrefix(string(data), "# OLS WPanel — 网络与内核优化") {
		return nil, fmt.Errorf("安装配置由管理员管理，停止修改连接队列")
	}
	re := regexp.MustCompile(`(?m)^\s*net\.(?:core\.somaxconn|ipv4\.tcp_max_syn_backlog)\s*=.*\n?`)
	return re.ReplaceAll(data, nil), nil
}

func setVPSTuning(ctx context.Context, mode string) (string, error) {
	return setVPSTuningAt(ctx, mode, "/etc/sysctl.d/99-ols-wpanel-vps.conf", "/etc/sysctl.d/.ols-wpanel-vps-original.json", "/etc/sysctl.d/99-ols-wpanel.conf", vpsToolCommand)
}

func setVPSTuningAt(ctx context.Context, mode, path, baseline, installerPath string, runCommand func(context.Context, string, ...string) (string, error)) (string, error) {
	if mode != "balanced" && mode != "website" && mode != "default" {
		return "", fmt.Errorf("invalid tuning mode")
	}
	const marker = "# OLS WPanel VPS tuning\n"
	installer, err := os.ReadFile(installerPath)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	cleanInstaller, err := stripInstallerQueues(installer)
	if err != nil {
		return "", err
	}
	old, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if len(old) > 0 && !strings.HasPrefix(string(old), marker) {
		return "", fmt.Errorf("administrator-owned tuning file")
	}
	original := map[string]string{}
	data, err := os.ReadFile(baseline)
	if err == nil {
		if err = json.Unmarshal(data, &original); err != nil {
			return "", err
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	current := map[string]string{}
	for _, key := range vpsTuningKeys {
		out, e := runCommand(ctx, "sysctl", "-n", key)
		if e != nil {
			return "", e
		}
		current[key] = strings.TrimSpace(out)
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(current[key]) {
			return "", fmt.Errorf("unexpected sysctl value")
		}
	}
	if len(original) == 0 && mode != "default" {
		original = current
		b, _ := json.Marshal(original)
		if err = writePanelTLSFile(baseline, b, 0600); err != nil {
			return "", err
		}
	}
	if mode == "default" && len(original) == 0 {
		return "当前没有可恢复的修改前记录", nil
	}
	values := map[string]string{"net.core.somaxconn": "4096", "net.ipv4.tcp_max_syn_backlog": "4096"}
	if mode == "website" {
		values = map[string]string{"net.core.somaxconn": "8192", "net.ipv4.tcp_max_syn_backlog": "8192"}
	}
	if mode == "default" {
		values = original
	}
	next := marker
	for _, key := range vpsTuningKeys {
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(values[key]) {
			return "", fmt.Errorf("invalid saved sysctl baseline")
		}
		next += key + " = " + values[key] + "\n"
	}
	if err = writePanelTLSFile(path, []byte(next), 0644); err != nil {
		return "", err
	}
	if string(cleanInstaller) != string(installer) {
		err = writePanelTLSFile(installerPath, cleanInstaller, 0644)
	}
	if err == nil {
		_, err = runCommand(ctx, "sysctl", "-p", path)
	}
	if err == nil {
		for _, key := range vpsTuningKeys {
			var out string
			out, err = runCommand(ctx, "sysctl", "-n", key)
			if err != nil {
				break
			}
			if strings.TrimSpace(out) != values[key] {
				err = fmt.Errorf("%s 实际值与目标值不一致", key)
				break
			}
		}
	}
	if err != nil {
		rollbackCtx, cancelRollback := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancelRollback()
		for _, key := range vpsTuningKeys {
			if _, restoreErr := runCommand(rollbackCtx, "sysctl", "-w", key+"="+current[key]); restoreErr != nil {
				err = errors.Join(err, fmt.Errorf("%s 运行值回滚失败: %w", key, restoreErr))
			}
		}
		for _, key := range vpsTuningKeys {
			out, readErr := runCommand(rollbackCtx, "sysctl", "-n", key)
			if readErr != nil {
				err = errors.Join(err, fmt.Errorf("%s 回滚验证失败: %w", key, readErr))
			} else if strings.TrimSpace(out) != current[key] {
				err = errors.Join(err, fmt.Errorf("%s 回滚验证失败：实际 %s，原值 %s", key, strings.TrimSpace(out), current[key]))
			}
		}
		if len(old) > 0 {
			if restoreErr := writePanelTLSFile(path, old, 0644); restoreErr != nil {
				err = fmt.Errorf("%w; file restoration failed: %v", err, restoreErr)
			}
		} else {
			if restoreErr := os.Remove(path); restoreErr != nil {
				err = fmt.Errorf("%w; file restoration failed: %v", err, restoreErr)
			}
		}
		if string(cleanInstaller) != string(installer) {
			if restoreErr := writePanelTLSFile(installerPath, installer, 0644); restoreErr != nil {
				err = fmt.Errorf("%w; installer restoration failed: %v", err, restoreErr)
			}
		}
		return "", err
	}
	if mode == "default" {
		// Persist the restored values so reboot cannot reintroduce installer values.
		if err = os.Remove(baseline); err != nil {
			return "", err
		}
	}
	return "连接队列配置已更新；未修改内核、BBR 或内存参数", nil
}

func SimpleVPSToolTimeout() time.Duration { return 2 * time.Minute }

func installVPSLocale(ctx context.Context, value string, run func(context.Context, string, ...string) (string, error)) (string, error) {
	if value != "" {
		return "", errors.New("locale-install 不接受额外参数")
	}
	out, err := run(ctx, "apt-get", "install", "-y", "--no-install-recommends", "locales")
	if err != nil {
		return out, fmt.Errorf("安装 locales 失败，请检查软件源、包管理器状态和网络: %w", err)
	}
	return out + "\nlocales 已安装，请选择需要的系统语言。", nil
}

func setVPSTimezone(ctx context.Context, value string, run func(context.Context, string, ...string) (string, error)) (string, error) {
	// Confirm membership in the operating system's timezone database. The shape
	// guard rejects path traversal and option-like input before any command.
	if value == "" || len(value) > 128 || !regexp.MustCompile(`^[A-Za-z0-9_+.-]+(?:/[A-Za-z0-9_+.-]+)*$`).MatchString(value) {
		return "", errors.New("无效时区名称")
	}
	for _, part := range strings.Split(value, "/") {
		if part == "." || part == ".." || strings.HasPrefix(part, "-") {
			return "", errors.New("无效时区名称")
		}
	}
	available, err := run(ctx, "timedatectl", "list-timezones", "--no-pager")
	if err != nil {
		return "", fmt.Errorf("无法读取系统时区列表，未修改时区: %w", err)
	}
	found := value == "UTC" // timedatectl accepts UTC even if it omits the alias.
	for _, zone := range strings.Fields(available) {
		found = found || zone == value
	}
	if !found {
		return "", errors.New("此时区不在系统支持列表中，请通过 timedatectl list-timezones 查看可选值")
	}
	if _, err := run(ctx, "timedatectl", "set-timezone", value); err != nil {
		return "", err
	}
	actual, err := run(ctx, "timedatectl", "show", "--property=Timezone", "--value")
	if err != nil || strings.TrimSpace(actual) != value {
		return "", errors.Join(errors.New("时区已提交，但实际状态验证失败，请检查 timedatectl"), err)
	}
	return "时区已更新为 " + value, nil
}

func setVPSHostname(ctx context.Context, value string, run func(context.Context, string, ...string) (string, error)) (string, error) {
	if value == "" || len(value) > 64 {
		return "", errors.New("主机名须为 1–64 个 ASCII 字符")
	}
	labelPattern := regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	for _, label := range strings.Split(value, ".") {
		if !labelPattern.MatchString(label) {
			return "", errors.New("主机名每段须为 1–63 个字母、数字或短横线，首尾须为字母或数字")
		}
	}
	value = strings.ToLower(value)
	if _, err := run(ctx, "hostnamectl", "set-hostname", "--static", value); err != nil {
		return "", err
	}
	actual, err := run(ctx, "hostnamectl", "--static")
	if err != nil || strings.TrimSpace(actual) != value {
		return "", errors.Join(errors.New("静态主机名已提交，但实际状态验证失败，请检查 hostnamectl"), err)
	}
	return "静态主机名已更新为 " + value + "；云镜像自动管理主机名时，重启可能恢复其配置", nil
}
