package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func readUninstallSafetyScript(t *testing.T) string {
	t.Helper()
	for _, path := range []string{"../install.sh", "install.sh"} {
		data, err := os.ReadFile(path)
		if err == nil {
			return string(data)
		}
	}
	t.Fatal("cannot read install.sh")
	return ""
}

func extractUninstallSafetyFunction(t *testing.T, script, name, nextMarker string) string {
	t.Helper()
	start := strings.Index(script, name+"() {")
	if start < 0 {
		t.Fatalf("cannot find shell function %s", name)
	}
	endOffset := strings.Index(script[start:], "\n"+nextMarker)
	if endOffset < 0 {
		t.Fatalf("cannot find marker %q after shell function %s", nextMarker, name)
	}
	return script[start : start+endOffset]
}

func TestOrdinaryUninstallDisclosesDeletedAndPreservedDataBeforeMutation(t *testing.T) {
	script := readUninstallSafetyScript(t)
	uninstall := extractUninstallSafetyFunction(t, script, "do_uninstall", "do_purge() {")

	for _, required := range []string{
		"普通卸载将永久删除 /www/ols-wpanel 全部内容",
		"面板数据库 panel.db 与 config.json",
		"面板自身 TLS 证书和私钥",
		"面板本地备份、共享安装包缓存与该目录内的登录凭据/密钥",
		"普通卸载保留站点文件、站点日志、站点证书、OpenLiteSpeed/LSPHP 站点配置、MariaDB 数据库和共享系统软件",
		"/www/wwwroot（网站文件）",
		"/www/wwwlogs（网站日志）",
		"/www/server/certificates（站点 SSL 证书，不包括已删除的面板 TLS 身份）",
		"/usr/local/lsws/conf/ols-wpanel（站点 OLS/LSPHP 配置）",
	} {
		if !strings.Contains(uninstall, required) {
			t.Errorf("ordinary uninstall is missing scope disclosure %q", required)
		}
	}

	disclosure := strings.Index(uninstall, "普通卸载将永久删除")
	firstMutation := strings.Index(uninstall, "systemctl stop ols-wpanel")
	if disclosure < 0 || firstMutation < 0 || disclosure >= firstMutation {
		t.Fatalf("ordinary uninstall disclosure offset=%d must precede first mutation offset=%d", disclosure, firstMutation)
	}
}

func TestPurgeRequiresExactSecondConfirmationBeforeMutation(t *testing.T) {
	script := readUninstallSafetyScript(t)
	purge := extractUninstallSafetyFunction(t, script, "do_purge", "# ============================================================\n# 权限、平台与发布包安全预检")

	for _, required := range []string{
		"全部 OpenLiteSpeed/LSPHP 站点配置",
		"/www/wwwroot、/www/wwwlogs、/www/server/certificates",
		"面板状态、凭据、备份和共享安装包缓存",
		"共享系统软件：OpenLiteSpeed、LSPHP 8.3/8.4/8.5、MariaDB、Redis、Fail2ban",
		"可能同时被非 OLS 工作负载使用",
		"选择“彻底清空”后的第二次确认",
		"请输入精确的 ${BOLD}PURGE${NC}",
		`read -r -p "  > " purge_confirmation < /dev/tty 2>/dev/null || purge_confirmation=""`,
		`if ! is_exact_purge_confirmation "$purge_confirmation"; then`,
	} {
		if !strings.Contains(purge, required) {
			t.Errorf("purge is missing destructive-scope control %q", required)
		}
	}

	guard := strings.Index(purge, `if ! is_exact_purge_confirmation "$purge_confirmation"; then`)
	firstMutation := strings.Index(purge, "systemctl stop ols-wpanel")
	if guard < 0 || firstMutation < 0 || guard >= firstMutation {
		t.Fatalf("purge confirmation guard offset=%d must precede first mutation offset=%d", guard, firstMutation)
	}
	for _, forbidden := range []string{"输入 ${BOLD}yes${NC}", `"$confirm" != "yes"`} {
		if strings.Contains(purge, forbidden) {
			t.Errorf("purge still accepts obsolete confirmation %q", forbidden)
		}
	}
}

func TestUninstallCleanupUsesExactOLSOwnedResources(t *testing.T) {
	script := readUninstallSafetyScript(t)
	cleanup := extractUninstallSafetyFunction(t, script, "cleanup_ols_runtime_integrations", "do_uninstall() {")

	for _, required := range []string{
		"/etc/cron.d/ols_wpanel_cron",
		"/etc/systemd/system/ols-wpanel.service",
		"/etc/systemd/system/ols-wpanel.service.d",
		"/run/systemd/system/ols-wpanel.service.d",
		"/etc/systemd/system.control/ols-wpanel.service.d",
		"/run/systemd/system.control/ols-wpanel.service.d",
		"/run/systemd/transient/ols-wpanel.service",
		"/etc/systemd/system/olswpanel-whitelist.timer",
		"/etc/systemd/system/olswpanel-whitelist.service",
		"/etc/systemd/system/lsws.service.d/ols-wpanel.conf",
		"/etc/systemd/system/mariadb.service.d/ols-wpanel.conf",
		"/etc/systemd/system/redis-server.service.d/ols-wpanel.conf",
		"/etc/fail2ban/jail.d/olswpanel.conf",
		"/etc/fail2ban/action.d/olswpanel-record.conf",
		"/etc/fail2ban/filter.d/olswpanel.conf",
		"/etc/fail2ban/filter.d/olswpanel-404.conf",
		"/etc/fail2ban/filter.d/olswpanel-login.conf",
		"/etc/fail2ban/filter.d/olswpanel-sqli.conf",
		"-maxdepth 1 -type f -name 'olswpanel-*' -print0",
		"^# OLS WPanel Generated - [A-Za-z0-9._-]+$",
	} {
		if !strings.Contains(cleanup, required) {
			t.Errorf("OLS integration cleanup is missing exact resource or ownership guard %q", required)
		}
	}

	for _, forbidden := range []string{
		"/etc/cron.d/*",
		"rm -f /etc/logrotate.d/olswpanel-*",
		"rm -rf /etc/logrotate.d",
		"rm -f /etc/fail2ban/*",
		"rm -rf /etc/fail2ban",
		"rm -f /etc/systemd/system/olswpanel-*",
		"rm -rf /etc/systemd/system",
		"rm -f /etc/openlitespeed/conf.d/olswpanel-*",
	} {
		if strings.Contains(cleanup, forbidden) {
			t.Errorf("OLS integration cleanup contains overly broad deletion %q", forbidden)
		}
	}
	if got := strings.Count(script, "\n    cleanup_ols_runtime_integrations\n"); got != 2 {
		t.Fatalf("cleanup_ols_runtime_integrations call count = %d, want 2 (uninstall and purge)", got)
	}
}

func TestPanelCommandMigrationProtectsUnrelatedOneCharacterCommands(t *testing.T) {
	script := readUninstallSafetyScript(t)
	for _, required := range []string{
		"assert_panel_command_paths_available() {",
		"for command_path in /usr/local/bin/o /usr/local/bin/O",
		"# OLS WPanel CLI — o",
		"命令路径 ${command_path} 已被非 OLS WPanel 文件占用",
		"remove_managed_panel_command() {",
		"remove_managed_panel_command /usr/local/bin/o '# OLS WPanel CLI — o'",
		"remove_managed_panel_command /usr/local/bin/O '# OLS WPanel CLI — o'",
		"面板 CLI (o / O)",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("installer is missing panel command migration control %q", required)
		}
	}
	if got := strings.Count(script, "\nassert_panel_command_paths_available\n"); got != 1 {
		t.Fatalf("panel command collision guard call count = %d, want 1", got)
	}
	for _, forbidden := range []string{
		"rm -f /usr/local/bin/o",
		"rm -f /usr/local/bin/O",
		"rm -f /usr/local/bin/olsw",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("installer contains unguarded panel command deletion %q", forbidden)
		}
	}
}

func TestExactPurgeConfirmationRejectsNearMisses(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	script := readUninstallSafetyScript(t)
	confirmation := extractUninstallSafetyFunction(t, script, "is_exact_purge_confirmation", "cleanup_ols_runtime_integrations() {")
	fixture := `set -euo pipefail
` + confirmation + `
is_exact_purge_confirmation PURGE
for candidate in '' yes purge Purge ' PURGE' 'PURGE '; do
    if is_exact_purge_confirmation "$candidate"; then
        echo "unexpected acceptance: [$candidate]" >&2
        exit 1
    fi
done
`
	cmd := exec.Command(bash, "-c", fixture)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("exact purge confirmation fixture failed: %v\n%s", err, output)
	}
}

func TestPanelVersionFloorRejectsOldOrMalformedVersions(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	script := readUninstallSafetyScript(t)
	versionCheck := extractUninstallSafetyFunction(t, script, "panel_version_at_least", "write_panel_service_unit() {")
	fixture := "set -euo pipefail\n" + versionCheck + `
panel_version_at_least v2.0.1 v2.0.1
panel_version_at_least v2.0.10 v2.0.1
panel_version_at_least v3.0.0 v2.0.1
for candidate in v2.0.0 v1.99.99 2.0.1 v2.0.1-rc.1 v2.0 vbad; do
    if panel_version_at_least "$candidate" v2.0.1; then
        echo "unexpected acceptance: $candidate" >&2
        exit 1
    fi
done
`
	if output, err := exec.Command(bash, "-c", fixture).CombinedOutput(); err != nil {
		t.Fatalf("panel version guard fixture failed: %v\n%s", err, output)
	}
}

func TestIntegrationCleanupToleratesMissingOrFailingServices(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	stubDir := t.TempDir()
	for _, name := range []string{"systemctl", "fail2ban-client", "rm", "find"} {
		stub := filepath.Join(stubDir, name)
		if err := os.WriteFile(stub, []byte("#!/usr/bin/env bash\nexit 1\n"), 0o755); err != nil {
			t.Fatalf("write %s failure stub: %v", name, err)
		}
	}
	script := readUninstallSafetyScript(t)
	cleanup := extractUninstallSafetyFunction(t, script, "cleanup_ols_runtime_integrations", "do_uninstall() {")
	fixture := `set -euo pipefail
` + cleanup + `
cleanup_ols_runtime_integrations
echo completed
`
	cmd := exec.Command(bash, "-c", fixture)
	cmd.Env = append(os.Environ(), "PATH="+stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("best-effort cleanup aborted on missing resources: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "completed") {
		t.Fatalf("cleanup fixture did not complete:\n%s", output)
	}
}

func TestInstallerFailureAndCertificateGuidanceAreEvidenceBased(t *testing.T) {
	script := readUninstallSafetyScript(t)
	for _, required := range []string{
		"请先保存本次终端完整输出",
		"网络/DNS 与系统时间、APT 错误、发行包哈希/签名",
		"现有服务冲突",
		"不要在未定位原因前直接重装系统",
		"openssl x509 -in ${CERT_FILE} -noout -fingerprint -sha256",
		"指纹不一致时立即停止，不要输入任何凭据",
		"长期公网使用请替换为由受信任 CA 签发",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("installer guidance is missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"安装失败通常与系统环境不纯净有关",
		"建议使用纯净版 Debian 13 重装系统后再安装",
		"请点击「高级」→「继续访问」即可进入面板",
		"系统已恢复安装前状态",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("installer still contains misleading guidance %q", forbidden)
		}
	}
}
