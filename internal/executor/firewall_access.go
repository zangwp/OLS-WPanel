package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

const accessRollbackUnit = "ols-wpanel-access-rollback"

type FirewallAccessPreview struct {
	Rules         []FirewallAccessRule `json:"rules"`
	Fingerprint   string               `json:"fingerprint"`
	Script        string               `json:"script"`
	ExistingRules string               `json:"existing_rules"`
	SSHPort       int                  `json:"ssh_port"`
	PanelPort     int                  `json:"panel_port"`
}

// Protected by portRulesMu. The independent systemd timer survives panel exit.
var pendingAccess struct {
	token, rollback, dir, expected string
	deadline                       time.Time
	sshPort, panelPort             int
}
var accessCommentRE = regexp.MustCompile(`comment "ols-access:(tcp|udp):(\d+):([0-9a-fA-F:./]*)"`)

var persistAccessRules = persistCurrentNftablesRules

func readAccessState(ctx context.Context) (bool, []FirewallAccessRule, error) {
	out, err := portCommand(ctx, "nft", "--stateless", "list", "tables")
	if err != nil {
		return false, nil, errors.New("无法读取 nftables 表")
	}
	if !strings.Contains(out, "table inet "+accessTable+"\n") && !strings.HasSuffix(out, "table inet "+accessTable) {
		return false, []FirewallAccessRule{}, nil
	}
	out, err = portCommand(ctx, "nft", "--stateless", "list", "table", "inet", accessTable)
	if err != nil {
		return false, nil, err
	}
	rules := []FirewallAccessRule{}
	for _, m := range accessCommentRE.FindAllStringSubmatch(out, -1) {
		p, _ := strconv.Atoi(m[2])
		rules = append(rules, FirewallAccessRule{Protocol: m[1], Port: p, Source: m[3]})
	}
	return true, rules, nil
}

func previewAccess(ctx context.Context, req FirewallAccessRequest, ip string) (FirewallAccessPreview, error) {
	_, _, _, _, warning, writable := firewallPortTarget(ctx)
	if !writable {
		return FirewallAccessPreview{}, errors.New(warning)
	}
	loader, loaderErr := portCommand(ctx, "systemctl", "show", "nftables", "--property=ExecStart", "--value")
	if loaderErr != nil || !strings.Contains(loader, nftablesConfigPath) {
		return FirewallAccessPreview{}, errors.New("nftables 开机加载器未使用标准 /etc/nftables.conf，暂不支持自动保存")
	}
	listeners := detectListeners(ctx)
	ssh := detectSSHPort(ctx, listeners)
	panel, _ := PanelListenEndpoint(config.AppConfig)
	if !hasTCPListener(listeners, ssh) || !hasTCPListener(listeners, panel) {
		return FirewallAccessPreview{}, errors.New("未检测到 SSH 或面板监听，请先检查服务")
	}
	rules, err := normalizeAccessRules(req.Rules, ip, ssh, panel)
	if err != nil {
		return FirewallAccessPreview{}, err
	}
	exists, _, err := readAccessState(ctx)
	if err != nil {
		return FirewallAccessPreview{}, err
	}
	out, err := portCommand(ctx, "nft", "--stateless", "list", "ruleset")
	if err != nil {
		return FirewallAccessPreview{}, err
	}
	return FirewallAccessPreview{Rules: rules, Fingerprint: accessFingerprint(out, rules, ssh, panel), Script: accessRulesScript(rules, exists), ExistingRules: out, SSHPort: ssh, PanelPort: panel}, nil
}

func PreviewFirewallAccess(req FirewallAccessRequest, ip string) (FirewallAccessPreview, error) {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return previewAccess(ctx, req, ip)
}

func ApplyFirewallAccess(req FirewallAccessRequest, ip string) (FirewallProtectionResult, error) {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if sshMoveActive(ctx) {
		return FirewallProtectionResult{}, errors.New("SSH 端口变更尚未完成，请先确认或等待恢复")
	}
	if !systemdRunAvailable() {
		return FirewallProtectionResult{}, errors.New("需要 systemd 自动回退支持")
	}
	if active, _ := firewallProtectionPending(); active {
		return FirewallProtectionResult{}, errors.New("已有防火墙变更等待确认")
	}
	for _, unit := range []string{accessRollbackUnit + ".timer", accessRollbackUnit + ".service", firewallRollbackUnit + ".timer"} {
		if _, err := portCommand(ctx, "systemctl", "is-active", "--quiet", unit); err == nil {
			return FirewallProtectionResult{}, errors.New("已有防火墙回退任务，请等待其完成")
		}
	}
	preview, err := previewAccess(ctx, req, ip)
	if err != nil {
		return FirewallProtectionResult{}, err
	}
	if req.Fingerprint == "" || req.Fingerprint != preview.Fingerprint {
		return FirewallProtectionResult{}, errors.New("规则或选择已变化，请重新预览")
	}
	dir, err := os.MkdirTemp("/run", "ols-access-*")
	if err != nil {
		return FirewallProtectionResult{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	apply := filepath.Join(dir, "apply.nft")
	rollback := filepath.Join(dir, "rollback.nft")
	previous := ""
	exists, _, err := readAccessState(ctx)
	if err != nil {
		return FirewallProtectionResult{}, err
	}
	if exists {
		previous, err = portCommand(ctx, "nft", "--stateless", "list", "table", "inet", accessTable)
		if err != nil {
			return FirewallProtectionResult{}, err
		}
	}
	// add is idempotent: rollback also works when applying the new table failed.
	undo := "add table inet " + accessTable + "\ndelete table inet " + accessTable + "\n" + previous + "\n"
	if err = os.WriteFile(apply, []byte(preview.Script), 0600); err != nil {
		return FirewallProtectionResult{}, err
	}
	if err = os.WriteFile(rollback, []byte(undo), 0600); err != nil {
		return FirewallProtectionResult{}, err
	}
	if out, e := portCommand(ctx, "nft", "--check", "--file", apply); e != nil {
		return FirewallProtectionResult{}, fmt.Errorf("规则校验失败: %s", out)
	}
	token, err := randomConfirmationToken()
	if err != nil {
		return FirewallProtectionResult{}, err
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		return FirewallProtectionResult{}, err
	}
	_, _ = portCommand(ctx, "systemctl", "reset-failed", accessRollbackUnit+".service")
	rollbackStarted := time.Now()
	if out, e := portCommand(ctx, "systemd-run", "--unit="+accessRollbackUnit, "--on-active=90s", "--timer-property=AccuracySec=1s", "--property=Type=oneshot", nft, "--file", rollback); e != nil {
		return FirewallProtectionResult{}, fmt.Errorf("无法安排自动回退: %s", out)
	}
	keep = true // Never remove the file while the timer could still need it.
	if out, e := portCommand(ctx, "nft", "--file", apply); e != nil {
		return FirewallProtectionResult{}, fmt.Errorf("应用失败，将自动回退: %s", out)
	}
	expected, err := portCommand(ctx, "nft", "--stateless", "list", "table", "inet", accessTable)
	if err != nil {
		return FirewallProtectionResult{}, err
	}
	pendingAccess.token = token
	pendingAccess.rollback = rollback
	pendingAccess.dir = dir
	pendingAccess.expected = expected
	pendingAccess.deadline = rollbackStarted.Add(85 * time.Second)
	pendingAccess.sshPort = preview.SSHPort
	pendingAccess.panelPort = preview.PanelPort
	recordOperationLog("firewall_access_apply", accessTable, "success", "waiting for manual confirmation")
	return FirewallProtectionResult{ConfirmationToken: token, Deadline: pendingAccess.deadline.Add(-15 * time.Second)}, nil
}

func ConfirmFirewallAccess(token string) error {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	if token == "" || token != pendingAccess.token || time.Now().After(pendingAccess.deadline.Add(-15*time.Second)) {
		return errors.New("确认无效或剩余时间不足，请等待回退后重试")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if sshMoveActive(ctx) {
		return errors.New("SSH 端口变更尚未完成，请先确认或等待恢复")
	}
	listeners := detectListeners(ctx)
	panelPort, _ := PanelListenEndpoint(config.AppConfig)
	if panelPort == 0 || panelPort != pendingAccess.panelPort || detectSSHPort(ctx, listeners) != pendingAccess.sshPort ||
		!hasTCPListener(listeners, pendingAccess.sshPort) || !hasTCPListener(listeners, panelPort) {
		return errors.New("SSH 或面板入口已变化，不能确认；请等待自动回退后重新预览")
	}
	current, err := portCommand(ctx, "nft", "--stateless", "list", "table", "inet", accessTable)
	if err != nil || current != pendingAccess.expected {
		return errors.New("规则已变化，不能确认；请等待自动回退")
	}
	bootState, _ := portCommand(ctx, "systemctl", "is-enabled", "nftables")
	if bootState != "enabled" && bootState != "disabled" {
		return errors.New("无法确认 nftables 开机状态，等待自动回退")
	}
	committed := false
	defer func() {
		if !committed && bootState == "disabled" {
			restoreCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			_, _ = portCommand(restoreCtx, "systemctl", "disable", "nftables")
		}
	}()
	// Require a usable boot loader before saving. Enabling does not restart or flush rules.
	if out, e := portCommand(ctx, "systemctl", "enable", "nftables"); e != nil {
		return fmt.Errorf("无法启用开机加载，等待自动回退: %s", out)
	}
	// Stop the timer AND service before saving so a concurrent rollback cannot
	// leave a restrictive configuration on disk while runtime has reverted.
	if _, err = portCommand(ctx, "systemctl", "stop", accessRollbackUnit+".timer", accessRollbackUnit+".service"); err != nil {
		rollbackCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		if _, restoreErr := portCommand(rollbackCtx, "nft", "--file", pendingAccess.rollback); restoreErr != nil {
			return errors.New("无法停止回退任务且即时恢复失败，请通过 SSH 检查规则；未保存配置")
		}
		pendingAccess.token = ""
		return errors.New("无法停止回退任务，已恢复原规则，未保存配置")
	}
	current, err = portCommand(ctx, "nft", "--stateless", "list", "table", "inet", accessTable)
	if err == nil && current == pendingAccess.expected {
		err = persistAccessRules(ctx)
	} else {
		err = errors.New("规则已回退或变化，未保存")
	}
	if err != nil {
		rollbackCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		if out, e := portCommand(rollbackCtx, "nft", "--file", pendingAccess.rollback); e != nil {
			return fmt.Errorf("保存失败且回退失败，请通过 SSH 检查: %s (%v)", out, err)
		}
		pendingAccess.token = ""
		return err
	}
	pendingAccess.token = ""
	_ = os.RemoveAll(pendingAccess.dir)
	committed = true
	recordOperationLog("firewall_access_confirm", accessTable, "success", "saved; nftables enabled")
	return nil
}
