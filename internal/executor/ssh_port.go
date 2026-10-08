package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const sshMoveUnit = "ols-wpanel-ssh-port-rollback"

var sshConfigPath = "/etc/ssh/sshd_config"
var sshJailPath = "/etc/fail2ban/jail.d/zz-ols-wpanel-ssh-port.local"
var sshMoveRunDirectory = "/run"
var sshSystemdAvailable = systemdRunAvailable
var sshDefaultsPath = "/etc/default/ssh"

type SSHPortStatus struct {
	Port      int    `json:"port"`
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
	Service   string `json:"service"`
	Pending   bool   `json:"pending"`
}
type SSHPortChange struct {
	Token         string    `json:"token"`
	OldPort       int       `json:"old_port"`
	NewPort       int       `json:"new_port"`
	Deadline      time.Time `json:"deadline"`
	VerifyCommand string    `json:"verify_command"`
}

var sshMove struct {
	SSHPortChange
	dir, service, expectedConfig, expectedTable string
}

func sshMoveActive(ctx context.Context) bool {
	for _, u := range []string{sshMoveUnit + ".timer", sshMoveUnit + ".service"} {
		if _, e := portCommand(ctx, "systemctl", "is-active", "--quiet", u); e == nil {
			return true
		}
	}
	return false
}

func inspectSSHPort(ctx context.Context) SSHPortStatus {
	listeners := detectListeners(ctx)
	s := SSHPortStatus{Port: detectSSHPort(ctx, listeners), Pending: sshMoveActive(ctx)}
	fail := func(reason string) SSHPortStatus { s.Reason = reason; return s }
	if s.Pending {
		return fail("已有 SSH 端口变更，请完成验证或等待自动恢复")
	}
	if !sshSystemdAvailable() {
		return fail("缺少 systemd 自动恢复支持")
	}
	for _, u := range []string{"ssh.socket", "sshd.socket"} {
		if _, e := portCommand(ctx, "systemctl", "is-active", "--quiet", u); e == nil {
			return fail("当前使用 SSH socket 激活，暂不支持自动修改")
		}
		if out, _ := portCommand(ctx, "systemctl", "is-enabled", u); strings.HasPrefix(out, "enabled") {
			return fail("SSH socket 已设置开机启动，暂不支持自动修改")
		}
	}
	for _, u := range []string{"ssh.service", "sshd.service"} {
		if _, e := portCommand(ctx, "systemctl", "is-active", "--quiet", u); e == nil {
			s.Service = u
			break
		}
	}
	if s.Service == "" {
		return fail("未检测到运行中的标准 SSH 服务")
	}
	execStart, e := portCommand(ctx, "systemctl", "show", s.Service, "--property=ExecStart", "--value")
	if e != nil || !strings.Contains(execStart, "/usr/sbin/sshd") || strings.Contains(execStart, " -p") || strings.Contains(execStart, " -f") || strings.Contains(execStart, " -o") {
		return fail("SSH 使用自定义启动参数，暂不支持自动修改")
	}
	if env, _ := portCommand(ctx, "systemctl", "show", s.Service, "--property=Environment", "--value"); strings.Contains(env, "SSHD_OPTS=") {
		return fail("SSH 存在服务环境参数，请手动检查")
	}
	if data, e := os.ReadFile(sshDefaultsPath); e == nil {
		for _, l := range strings.Split(string(data), "\n") {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "SSHD_OPTS=") && strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, "SSHD_OPTS=")), "\"'") != "" {
				return fail("/etc/default/ssh 设置了自定义启动参数")
			}
		}
	}
	if out, _ := portCommand(ctx, "getenforce"); strings.EqualFold(out, "Enforcing") {
		return fail("SELinux 强制模式需要先配置 SSH 端口标签，请手动处理")
	}
	effective, e := portCommand(ctx, "/usr/sbin/sshd", "-T")
	if e != nil || validateSSHPorts(effective, s.Port) != nil {
		return fail("SSH 包含多个端口或固定 ListenAddress，暂不支持自动修改")
	}
	owned := false
	for _, l := range listeners {
		if l.Protocol == "tcp" && l.Port == s.Port && strings.Contains(l.Process, "sshd") {
			owned = true
		}
	}
	if !owned {
		return fail("配置端口与实际 SSH 监听不一致")
	}
	enabled, _, e := readAccessState(ctx)
	if e != nil || !enabled {
		return fail("请先应用上方端口访问策略，才能联动迁移 SSH 放行来源")
	}
	_, _, _, _, warning, writable := firewallPortTarget(ctx)
	if !writable {
		return fail(warning)
	}
	if boot, _ := portCommand(ctx, "systemctl", "is-enabled", "nftables"); boot != "enabled" {
		return fail("请先启用 nftables 开机加载，避免重启后新端口无法访问")
	}
	if loader, _ := portCommand(ctx, "systemctl", "show", "nftables", "--property=ExecStart", "--value"); !strings.Contains(loader, nftablesConfigPath) {
		return fail("nftables 使用自定义加载器，暂不支持自动保存")
	}
	s.Available = true
	return s
}

func GetSSHPortStatus() SSHPortStatus {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return inspectSSHPort(ctx)
}

func writeSSHFile(path string, data []byte, mode os.FileMode) error {
	tmp, e := os.CreateTemp(filepath.Dir(path), ".ols-ssh-*")
	if e != nil {
		return e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(data); e == nil {
		e = tmp.Chmod(mode)
	}
	if e == nil {
		e = tmp.Sync()
	}
	closeErr := tmp.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}

func sshJailConfig(ports string) string {
	return "# OLS WPanel SSH port migration\n[olswpanel-sshd]\naction = nftables-multiport[name=olswpanel-sshd, port=\"" + ports + "\"]\n         olswpanel-record[name=olswpanel-sshd]\n"
}

func reloadSSHJail(ctx context.Context) error {
	for _, args := range [][]string{{"-t"}, {"reload", "--restart", "olswpanel-sshd"}} {
		if out, e := portCommand(ctx, "fail2ban-client", args...); e != nil {
			return fmt.Errorf("Fail2ban SSH 防护更新失败: %s", out)
		}
	}
	return nil
}

func waitSSHListener(ctx context.Context, port int) error {
	for attempt := 0; attempt < 15; attempt++ {
		for _, l := range detectListeners(ctx) {
			if l.Protocol == "tcp" && l.Port == port && strings.Contains(l.Process, "sshd") {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("未检测到 SSH 在新端口 %d 上监听", port)
}

func waitSSHRetired(ctx context.Context, port int) error {
	for attempt := 0; attempt < 15; attempt++ {
		present := false
		for _, l := range detectListeners(ctx) {
			if l.Protocol == "tcp" && l.Port == port && strings.Contains(l.Process, "sshd") {
				present = true
			}
		}
		if !present {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("旧 SSH 端口仍在监听，未确认迁移")
}

func BeginSSHPortChange(newPort int, managementIP string) (SSHPortChange, error) {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	s := inspectSSHPort(ctx)
	if !s.Available {
		return SSHPortChange{}, errors.New(s.Reason)
	}
	if newPort < 1 || newPort > 65535 || newPort == s.Port {
		return SSHPortChange{}, errors.New("请输入不同于当前端口的有效端口")
	}
	for _, reserved := range []int{80, 443, 3306, 6379, 7080} {
		if newPort == reserved {
			return SSHPortChange{}, errors.New("该端口保留给网站、数据库或 WebAdmin，请选择其他 SSH 端口")
		}
	}
	for _, l := range detectListeners(ctx) {
		if l.Port == newPort {
			return SSHPortChange{}, errors.New("端口已被其他服务占用")
		}
	}
	for _, unit := range []string{accessRollbackUnit + ".timer", firewallRollbackUnit + ".timer"} {
		if _, e := portCommand(ctx, "systemctl", "is-active", "--quiet", unit); e == nil {
			return SSHPortChange{}, errors.New("请先完成其他防火墙变更")
		}
	}
	if net.ParseIP(managementIP) == nil {
		return SSHPortChange{}, errors.New("无法识别管理 IP")
	}
	_, rules, e := readAccessState(ctx)
	if e != nil {
		return SSHPortChange{}, e
	}
	dualRules, e := migrateSSHAccess(rules, s.Port, newPort, true)
	if e != nil {
		return SSHPortChange{}, e
	}
	finalRules, e := migrateSSHAccess(rules, s.Port, newPort, false)
	if e != nil {
		return SSHPortChange{}, e
	}
	// Do not migrate a source policy which already excludes this administrator.
	allowed := false
	for _, r := range finalRules {
		if r.Port == newPort && r.Protocol == "tcp" {
			if r.Source == "" {
				allowed = true
			} else {
				_, n, _ := net.ParseCIDR(r.Source)
				if n != nil && n.Contains(net.ParseIP(managementIP)) {
					allowed = true
				}
			}
		}
	}
	if !allowed {
		return SSHPortChange{}, errors.New("当前管理 IP 不在 SSH 允许来源内")
	}
	info, e := os.Lstat(sshConfigPath)
	if e != nil || !info.Mode().IsRegular() {
		return SSHPortChange{}, errors.New("SSH 主配置不是普通文件，暂不支持自动修改")
	}
	original, e := os.ReadFile(sshConfigPath)
	if e != nil {
		return SSHPortChange{}, e
	}
	dual, e := sshPortConfig(string(original), s.Port, newPort)
	if e != nil {
		return SSHPortChange{}, e
	}
	final, _ := sshPortConfig(string(original), newPort)
	dir, e := os.MkdirTemp(sshMoveRunDirectory, "ols-ssh-port-*")
	if e != nil {
		return SSHPortChange{}, e
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	for name, data := range map[string]string{"original": string(original), "dual": dual, "final": final, "dual.nft": accessRulesScript(dualRules, true), "final.nft": accessRulesScript(finalRules, true)} {
		if e = os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); e != nil {
			return SSHPortChange{}, e
		}
	}
	for _, candidate := range []struct {
		name  string
		ports []int
	}{{"dual", []int{s.Port, newPort}}, {"final", []int{newPort}}} {
		out, err := portCommand(ctx, "/usr/sbin/sshd", "-T", "-f", filepath.Join(dir, candidate.name))
		if err != nil {
			return SSHPortChange{}, fmt.Errorf("SSH 配置校验失败: %s", out)
		}
		if err = validateSSHPorts(out, candidate.ports...); err != nil {
			return SSHPortChange{}, err
		}
	}
	prior, e := portCommand(ctx, "nft", "--stateless", "list", "table", "inet", accessTable)
	if e != nil {
		return SSHPortChange{}, e
	}
	if e = os.WriteFile(filepath.Join(dir, "restore.nft"), []byte("add table inet "+accessTable+"\ndelete table inet "+accessTable+"\n"+prior+"\n"), 0600); e != nil {
		return SSHPortChange{}, e
	}
	// The added base-chain rule is uniquely tagged, so rollback removes only it.
	token, e := randomConfirmationToken()
	if e != nil {
		return SSHPortChange{}, e
	}
	tag := "ols-ssh-move-" + token
	var allows strings.Builder
	for _, r := range finalRules {
		if r.Port == newPort && r.Protocol == "tcp" {
			fmt.Fprint(&allows, "insert rule inet filter input ")
			if r.Source != "" {
				family := "ip"
				if strings.Contains(r.Source, ":") {
					family = "ip6"
				}
				fmt.Fprintf(&allows, "%s saddr %s ", family, r.Source)
			}
			fmt.Fprintf(&allows, "tcp dport %d counter accept comment \"%s\"\n", newPort, tag)
		}
	}
	if e = os.WriteFile(filepath.Join(dir, "allow.nft"), []byte(allows.String()), 0600); e != nil {
		return SSHPortChange{}, e
	}
	for _, name := range []string{"dual.nft", "final.nft", "allow.nft"} {
		if out, err := portCommand(ctx, "nft", "--check", "--file", filepath.Join(dir, name)); err != nil {
			return SSHPortChange{}, fmt.Errorf("防火墙预检失败: %s", out)
		}
	}
	// Backup only the files that this transaction can change.
	restoreFiles := ""
	for i, path := range []string{sshConfigPath, sshJailPath, nftablesConfigPath} {
		backup := filepath.Join(dir, fmt.Sprintf("backup-%d", i))
		st, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			restoreFiles += "rm -f -- " + shellLiteral(path) + "\n"
			continue
		}
		if err != nil || !st.Mode().IsRegular() {
			return SSHPortChange{}, fmt.Errorf("无法安全备份 %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return SSHPortChange{}, err
		}
		if err = os.WriteFile(backup, data, st.Mode().Perm()); err != nil {
			return SSHPortChange{}, err
		}
		restoreFiles += "cp -p -- " + shellLiteral(backup) + " " + shellLiteral(path+".ols-restore") + " && mv -f -- " + shellLiteral(path+".ols-restore") + " " + shellLiteral(path) + "\n"
	}
	jailActive := false
	if _, err := portCommand(ctx, "systemctl", "is-active", "--quiet", "fail2ban"); err == nil {
		if _, err = portCommand(ctx, "fail2ban-client", "status", "olswpanel-sshd"); err != nil {
			return SSHPortChange{}, errors.New("未找到面板管理的 Fail2ban SSH 规则，无法安全联动")
		}
		jailActive = true
	}
	rollback := "#!/bin/sh\nset -eu\n[ -f " + shellLiteral(filepath.Join(dir, "pending")) + " ] || exit 0\n" + restoreFiles + "/usr/sbin/sshd -t\nsystemctl reload " + s.Service + "\nnft --file " + shellLiteral(filepath.Join(dir, "restore.nft")) + "\n" +
		"nft -a list chain inet filter input | sed -n '/comment \"" + tag + "\"/s/.*# handle \\([0-9][0-9]*\\).*/\\1/p' | while read -r h; do nft delete rule inet filter input handle \"$h\"; done\n"
	if jailActive {
		rollback += "fail2ban-client reload --restart olswpanel-sshd\n"
	}
	rollback += "rm -f -- " + shellLiteral(filepath.Join(dir, "pending")) + "\n"
	if e = os.WriteFile(filepath.Join(dir, "rollback.sh"), []byte(rollback), 0700); e != nil {
		return SSHPortChange{}, e
	}
	verify := "#!/bin/sh\nset -eu\numask 077\n[ \"$(id -u)\" = 0 ] || exit 1\n[ \"${1-}\" = " + shellLiteral(token) + " ] || exit 1\nset -- ${OLS_SSH_CONNECTION-}\n[ \"${4-}\" = " + shellLiteral(strconv.Itoa(newPort)) + " ] || { echo 'Please run this command in the NEW SSH connection'; exit 1; }\n[ -f " + shellLiteral(filepath.Join(dir, "pending")) + " ] || exit 1\nprintf '%s' " + shellLiteral(token) + " > " + shellLiteral(filepath.Join(dir, "verified")) + "\necho 'New SSH port verified. Return to the panel to save.'\n"
	if e = os.WriteFile(filepath.Join(dir, "verify.sh"), []byte(verify), 0700); e != nil {
		return SSHPortChange{}, e
	}
	if e = os.WriteFile(filepath.Join(dir, "pending"), []byte(token), 0600); e != nil {
		return SSHPortChange{}, e
	}
	started := time.Now()
	_, _ = portCommand(ctx, "systemctl", "reset-failed", sshMoveUnit+".service")
	if out, err := portCommand(ctx, "systemd-run", "--unit="+sshMoveUnit, "--on-active=300s", "--timer-property=AccuracySec=1s", "--property=Type=oneshot", "/bin/sh", filepath.Join(dir, "rollback.sh")); err != nil {
		return SSHPortChange{}, fmt.Errorf("无法安排恢复任务: %s", out)
	}
	keep = true
	failed := func(err error) (SSHPortChange, error) {
		rctx, c := context.WithTimeout(context.Background(), 20*time.Second)
		defer c()
		if out, re := portCommand(rctx, "/bin/sh", filepath.Join(dir, "rollback.sh")); re != nil {
			return SSHPortChange{}, fmt.Errorf("%v；即时恢复失败，定时恢复仍会重试: %s", err, out)
		}
		_, _ = portCommand(rctx, "systemctl", "stop", sshMoveUnit+".timer")
		return SSHPortChange{}, fmt.Errorf("%w；已恢复原 SSH 配置", err)
	}
	if e = writeSSHFile(sshConfigPath, []byte(dual), info.Mode().Perm()); e != nil {
		return failed(e)
	}
	if e = writeSSHFile(sshJailPath, []byte(sshJailConfig(fmt.Sprintf("%d,%d", s.Port, newPort))), 0644); e != nil {
		return failed(e)
	}
	if jailActive {
		if e = reloadSSHJail(ctx); e != nil {
			return failed(e)
		}
	}
	for _, name := range []string{"allow.nft", "dual.nft"} {
		if out, err := portCommand(ctx, "nft", "--file", filepath.Join(dir, name)); err != nil {
			return failed(fmt.Errorf("应用防火墙失败: %s", out))
		}
	}
	if out, err := portCommand(ctx, "systemctl", "reload", s.Service); err != nil {
		return failed(fmt.Errorf("SSH 重载失败: %s", out))
	}
	if e = waitSSHListener(ctx, newPort); e != nil {
		return failed(e)
	}
	sshMove.SSHPortChange = SSHPortChange{Token: token, OldPort: s.Port, NewPort: newPort, Deadline: started.Add(240 * time.Second), VerifyCommand: "sudo env OLS_SSH_CONNECTION=\"$SSH_CONNECTION\" /bin/sh " + shellLiteral(filepath.Join(dir, "verify.sh")) + " " + shellLiteral(token)}
	sshMove.dir = dir
	sshMove.service = s.Service
	sshMove.expectedConfig = dual
	sshMove.expectedTable, e = portCommand(ctx, "nft", "--stateless", "list", "table", "inet", accessTable)
	if e != nil {
		return failed(e)
	}
	recordOperationLog("ssh_port_change", strconv.Itoa(newPort), "success", "awaiting new SSH login verification")
	return sshMove.SSHPortChange, nil
}

func ConfirmSSHPortChange(token string) error {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	if token == "" || token != sshMove.Token || time.Now().After(sshMove.Deadline) {
		return errors.New("变更已过期或令牌无效，请等待自动恢复")
	}
	proof, e := os.ReadFile(filepath.Join(sshMove.dir, "verified"))
	if e != nil || string(proof) != token {
		return errors.New("请先通过新 SSH 端口登录，并执行页面上的验证命令")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	current, e := os.ReadFile(sshConfigPath)
	if e != nil || string(current) != sshMove.expectedConfig {
		return errors.New("SSH 配置已被其他操作修改，请等待恢复后重新检查")
	}
	table, e := portCommand(ctx, "nft", "--stateless", "list", "table", "inet", accessTable)
	if e != nil || table != sshMove.expectedTable {
		return errors.New("端口策略已变化，请等待恢复")
	}
	final, e := os.ReadFile(filepath.Join(sshMove.dir, "final"))
	if e != nil {
		return e
	}
	rollback := func(cause error) error {
		rctx, c := context.WithTimeout(context.Background(), 20*time.Second)
		defer c()
		out, err := portCommand(rctx, "/bin/sh", filepath.Join(sshMove.dir, "rollback.sh"))
		if err != nil {
			return fmt.Errorf("%v；恢复失败，请通过旧 SSH 会话检查: %s", cause, out)
		}
		sshMove.Token = ""
		_, _ = portCommand(rctx, "systemctl", "stop", sshMoveUnit+".timer")
		return fmt.Errorf("%w；已恢复原 SSH 配置", cause)
	}
	if e = writeSSHFile(sshConfigPath, final, 0600); e != nil {
		return rollback(e)
	}
	if out, err := portCommand(ctx, "/usr/sbin/sshd", "-T"); err != nil {
		return rollback(fmt.Errorf("SSH 校验失败: %s", out))
	} else if err = validateSSHPorts(out, sshMove.NewPort); err != nil {
		return rollback(err)
	}
	if out, err := portCommand(ctx, "systemctl", "reload", sshMove.service); err != nil {
		return rollback(fmt.Errorf("SSH 重载失败: %s", out))
	}
	if e = waitSSHListener(ctx, sshMove.NewPort); e != nil {
		return rollback(e)
	}
	if e = waitSSHRetired(ctx, sshMove.OldPort); e != nil {
		return rollback(e)
	}
	if e = writeSSHFile(sshJailPath, []byte(sshJailConfig(strconv.Itoa(sshMove.NewPort))), 0644); e != nil {
		return rollback(e)
	}
	if _, err := portCommand(ctx, "systemctl", "is-active", "--quiet", "fail2ban"); err == nil {
		if e = reloadSSHJail(ctx); e != nil {
			return rollback(e)
		}
	}
	if out, err := portCommand(ctx, "nft", "--file", filepath.Join(sshMove.dir, "final.nft")); err != nil {
		return rollback(fmt.Errorf("端口策略更新失败: %s", out))
	}
	if _, e = portCommand(ctx, "systemctl", "stop", sshMoveUnit+".timer", sshMoveUnit+".service"); e != nil {
		return rollback(e)
	}
	if e = persistAccessRules(ctx); e != nil {
		return rollback(e)
	}
	_ = os.Remove(filepath.Join(sshMove.dir, "pending"))
	sshMove.Token = ""
	recordOperationLog("ssh_port_confirm", strconv.Itoa(sshMove.NewPort), "success", "old listener removed; policy saved")
	return nil
}
