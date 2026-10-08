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
INSTALLER_RELEASE_VERSION=v1.18.0 STATUS=running REPAIR_MODE=false PORT_OK=true REPAIR_INACTIVE_HEALTH_VERIFIED=false
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
