package tests

import (
	"os"
	"strings"
	"testing"
)

const (
	installScriptPath   = "../install.sh"
	installCNScriptPath = "../install-cn.sh"
)

func TestInstallRequiredWebServicesOrder(t *testing.T) {
	script := readInstallScript(t, installScriptPath)

	guardConfigured := requiredIndex(t, script, `log_info "systemd 进程守护配置完成"`)
	daemonReload := requiredLastIndexBefore(t, script, "systemctl daemon-reload", guardConfigured)
	redisStart := requiredIndex(t, script, "systemctl_start_required redis-server")
	olsRestart := requiredLastIndex(t, script, "systemctl restart lshttpd")
	olsConfigCheck := requiredLastIndexBefore(t, script, "/usr/local/lsws/bin/openlitespeed -t", olsRestart)
	mariaDBStart := requiredIndex(t, script, "systemctl_start_required mariadb")
	panelStart := requiredIndex(t, script, "systemctl_start_required ols-wpanel")

	if !(daemonReload < guardConfigured && guardConfigured < redisStart && redisStart < olsConfigCheck && olsConfigCheck < olsRestart && olsRestart < mariaDBStart && mariaDBStart < panelStart) {
		t.Fatalf("required service order is invalid: daemon_reload=%d guard_log=%d redis=%d ols_check=%d ols_restart=%d mariadb=%d panel=%d",
			daemonReload, guardConfigured, redisStart, olsConfigCheck, olsRestart, mariaDBStart, panelStart)
	}
}

func TestInstallRequiredWebServicesUseSharedStartHelper(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	cnScript := readInstallScript(t, installCNScriptPath)

	if got := strings.Count(script, "systemctl_start_required() {"); got != 1 {
		t.Fatalf("systemctl_start_required helper definitions = %d, want 1", got)
	}
	for _, call := range []string{
		"systemctl_start_required redis-server",
	} {
		if got := countExactLine(script, call); got != 1 {
			t.Errorf("%q exact calls = %d, want 1", call, got)
		}
		if strings.Contains(cnScript, call) {
			t.Errorf("install-cn.sh duplicates main installer call %q", call)
		}
	}

	for _, forbidden := range []string{
		"systemctl restart php8.3-fpm",
		"systemctl restart openlitespeed",
		"systemctl_start_required php8.3-fpm",
		"systemctl_start_required openlitespeed",
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("install.sh contains forbidden restart command %q", forbidden)
		}
	}
}

func TestManagedServiceDropInUsesSystemdSections(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	shared := `cat > "$DROPDIR/ols-wpanel.conf" << SYSTEMDEOF
[Unit]
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Restart=on-failure
RestartSec=5s
SYSTEMDEOF`
	if got := strings.Count(script, shared); got != 1 {
		t.Fatalf("managed-service systemd drop-in definitions = %d, want exact [Unit]/[Service] layout once", got)
	}
	ols := `cat > "$DROPDIR/ols-wpanel.conf" << 'OLSSYSTEMDEOF'
[Unit]
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
PIDFile=/tmp/lshttpd/lshttpd.pid
KillMode=mixed
Restart=on-failure
RestartSec=5s
OLSSYSTEMDEOF`
	if got := strings.Count(script, ols); got != 1 {
		t.Fatalf("OpenLiteSpeed systemd drop-in definitions = %d, want one PID-compatible policy", got)
	}
	if strings.Contains(script, "[Service]\nRestart=always\nRestartSec=5s\nStartLimitIntervalSec=0") {
		t.Fatal("StartLimitIntervalSec must not be emitted in the [Service] section")
	}
}

func TestInstallerProvidesSafeDefaultOpenLiteSpeedVHost(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	for _, required := range []string{
		"virtualHost olsw_default {",
		"enableScript           0",
		"map                     olsw_default *",
		"id -u www-data",
		"id -g www-data",
		"install -d -o www-data -g www-data -m 0755 \"$OLS_DEFAULT_ROOT\"",
		"systemctl_wait_active_required lshttpd",
		"require_ols_listeners",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("install.sh missing empty-site safety control %q", required)
		}
	}
}

func readInstallScript(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func requiredIndex(t *testing.T, script, text string) int {
	t.Helper()
	index := strings.Index(script, text)
	if index < 0 {
		t.Fatalf("install.sh missing %q", text)
	}
	return index
}

func requiredLastIndexBefore(t *testing.T, script, text string, before int) int {
	t.Helper()
	index := strings.LastIndex(script[:before], text)
	if index < 0 {
		t.Fatalf("install.sh missing %q before offset %d", text, before)
	}
	return index
}

func requiredLastIndex(t *testing.T, script, text string) int {
	t.Helper()
	index := strings.LastIndex(script, text)
	if index < 0 {
		t.Fatalf("install.sh missing %q", text)
	}
	return index
}

func countExactLine(script, want string) int {
	count := 0
	for _, line := range strings.Split(script, "\n") {
		if strings.TrimSpace(line) == want {
			count++
		}
	}
	return count
}
