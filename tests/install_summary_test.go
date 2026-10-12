package tests

import (
	"strings"
	"testing"
)

func TestInstallerSummaryFormatsCredentialValuesSeparately(t *testing.T) {
	script := readUninstallSafetyScript(t)
	summary := extractUninstallSafetyFunction(t, script, "print_install_summary", "print_install_summary\n")
	for _, required := range []string{"1. 浏览器身份验证", "2. 面板账户登录", `printf '  用户名\n    %s\n  密码\n    %s\n' "$BASIC_USER" "$BASIC_PASS"`, `printf '  用户名\n    %s\n  密码\n    %s\n' "$WEB_USER" "$WEB_PASS"`, `NO_COLOR`, `PUBLIC_HOST`, `LOCAL_HOST`} {
		if !strings.Contains(summary, required) {
			t.Fatalf("installation summary is missing %q", required)
		}
	}
}

func TestInstallerSummaryDoesNotReprintCredentialsOnRepair(t *testing.T) {
	script := readUninstallSafetyScript(t)
	summary := extractUninstallSafetyFunction(t, script, "print_install_summary", "print_install_summary\n")
	vars := `BOLD='' YELLOW='' NC='' TERM=dumb NO_COLOR=1
INSTALLER_RELEASE_VERSION=v1.18.0 STATUS=running REPAIR_MODE=false PORT_OK=true REPAIR_INACTIVE_HEALTH_VERIFIED=false INSTALL_STARTED_SECONDS=0
PUBLIC_IP=192.0.2.24 PUBLIC_HOST=192.0.2.24 LOCAL_IP=10.0.0.24 LOCAL_HOST=10.0.0.24 VALIDATED_TLS_PORT=8443 PANEL_SUFFIX=example-only
BASIC_USER=browser-admin BASIC_PASS='synthetic%pass\literal' WEB_USER=panel-admin WEB_PASS=synthetic-panel-password CERT_FILE=/example/cert.pem
`
	for _, repair := range []bool{false, true} {
		invocation := "\nprint_install_summary\n"
		if repair {
			invocation = "\nREPAIR_MODE=true\nprint_install_summary\n"
		}
		out, err := lifecycleBash(t, vars+summary+invocation)
		if err != nil {
			t.Fatalf("summary failed: %v\n%s", err, out)
		}
		for _, value := range []string{"browser-admin", `synthetic%pass\literal`, "panel-admin", "synthetic-panel-password"} {
			want := 1
			if repair {
				want = 0
			}
			if strings.Count(string(out), value) != want {
				t.Fatalf("repair=%t credential count for %q is incorrect", repair, value)
			}
		}
	}
}

func TestInstallerStageTimingReportsSeparateDurations(t *testing.T) {
	script := readUninstallSafetyScript(t)
	stage := extractShellFunction(t, script, "log_install_stage", "assert_supported_platform")
	fixture := `log_info() { printf '%s\n' "$1"; }
INSTALL_STAGE='' INSTALL_STAGE_STARTED_SECONDS=0
unset SECONDS
SECONDS=100
` + stage + `
log_install_stage '下载组件'
SECONDS=107
log_install_stage '配置服务'
SECONDS=111
log_install_stage ''
test -z "$INSTALL_STAGE"
`
	out, err := lifecycleBash(t, fixture)
	if err != nil {
		t.Fatalf("stage timing failed: %v\n%s", err, out)
	}
	want := "下载组件...\n下载组件耗时: 7 秒\n配置服务...\n配置服务耗时: 4 秒\n"
	if string(out) != want {
		t.Fatalf("unexpected stage timings: %q, want %q", out, want)
	}
}
