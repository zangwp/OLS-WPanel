package tests

import (
	"strings"
	"testing"
)

func TestInstallerSummaryKeepsSeparateCopyableLoginSteps(t *testing.T) {
	script := readUninstallSafetyScript(t)
	summary := extractUninstallSafetyFunction(t, script, "print_install_summary", "print_install_summary\n")
	for _, required := range []string{"1. 浏览器身份验证", "2. 面板账户登录", `│ 用户名 │ %-*s │`, `│ 密码   │ %-*s │`, `NO_COLOR`, `PUBLIC_HOST`, `LOCAL_HOST`} {
		if !strings.Contains(summary, required) {
			t.Fatalf("installation summary is missing %q", required)
		}
	}
}

func TestInstallerSummaryPreservesCredentialsAcrossLayoutsAndRepair(t *testing.T) {
	script := readUninstallSafetyScript(t)
	summary := extractUninstallSafetyFunction(t, script, "print_install_summary", "print_install_summary\n")
	vars := `BOLD='' YELLOW='' NC='' TERM=dumb NO_COLOR=1
INSTALLER_RELEASE_VERSION=v1.18.0 STATUS=running REPAIR_MODE=false PORT_OK=true REPAIR_INACTIVE_HEALTH_VERIFIED=false INSTALL_STARTED_SECONDS=0
PUBLIC_IP=192.0.2.24 PUBLIC_HOST=192.0.2.24 LOCAL_IP=10.0.0.24 LOCAL_HOST=10.0.0.24 VALIDATED_TLS_PORT=8443 PANEL_SUFFIX=example-only
BASIC_USER=browser-admin BASIC_PASS='synthetic%pass\literal' WEB_USER=panel-admin WEB_PASS=synthetic-panel-password CERT_FILE=/example/cert.pem
`
	for _, tc := range []struct {
		columns string
		repair  bool
	}{{"80", false}, {"40", false}, {"invalid", false}, {"80", true}} {
		repair := tc.repair
		invocation := "\nprint_install_summary\n"
		if repair {
			invocation = "\nREPAIR_MODE=true\nunset BASIC_USER BASIC_PASS WEB_USER WEB_PASS\nprint_install_summary\n"
		}
		out, err := lifecycleBash(t, vars+"\nCOLUMNS="+tc.columns+"\n"+summary+invocation)
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
		if !repair {
			if !strings.Contains(string(out), "https://192.0.2.24:8443/example-only/") {
				t.Fatal("summary must retain the complete copyable login URL")
			}
			text := string(out)
			if strings.Count(text, "┌────────┬") != 2 || strings.Count(text, "└────────┴") != 2 {
				t.Fatalf("credentials must have two separate tables: %s", out)
			}
			browser, panel, ok := strings.Cut(text, "2. 面板账户登录")
			if !ok || !strings.Contains(browser, "browser-admin") || !strings.Contains(browser, `synthetic%pass\literal`) ||
				!strings.Contains(panel, "panel-admin") || !strings.Contains(panel, "synthetic-panel-password") {
				t.Fatalf("credentials must remain in their respective login tables: %s", out)
			}
		}
	}
}

func TestInstallerSummaryLabelsAddressesAndDoesNotInventUnknownURL(t *testing.T) {
	script := readUninstallSafetyScript(t)
	summary := extractUninstallSafetyFunction(t, script, "print_install_summary", "print_install_summary\n")
	vars := `BOLD='' YELLOW='' NC='' TERM=dumb NO_COLOR=1
INSTALLER_RELEASE_VERSION=v2.0.2 STATUS=running REPAIR_MODE=false PORT_OK=true REPAIR_INACTIVE_HEALTH_VERIFIED=false INSTALL_STARTED_SECONDS=0
VALIDATED_TLS_PORT=8443 PANEL_SUFFIX=example-only BASIC_USER=browser-admin BASIC_PASS=example-basic-password WEB_USER=panel-admin WEB_PASS=example-panel-password CERT_FILE=/example/cert.pem
`
	for _, tc := range []struct {
		name, addresses string
		want            []string
	}{
		{"both families", `PUBLIC_IP=2001:db8::24 PUBLIC_HOST='[2001:db8::24]' LOCAL_IP=192.0.2.24 LOCAL_HOST=192.0.2.24`, []string{"IPv6 / 外部地址", "https://[2001:db8::24]:8443/example-only/", "IPv4 / 网卡地址", "https://192.0.2.24:8443/example-only/"}},
		{"interface fallback", `PUBLIC_IP='<未知>' PUBLIC_HOST='<未知>' LOCAL_IP=192.0.2.24 LOCAL_HOST=192.0.2.24`, []string{"网卡地址", "https://192.0.2.24:8443/example-only/"}},
		{"unknown", `PUBLIC_IP='<未知>' PUBLIC_HOST='<未知>' LOCAL_IP='<未知>' LOCAL_HOST='<未知>'`, []string{"暂未识别到地址"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := lifecycleBash(t, vars+tc.addresses+"\n"+summary+"\nprint_install_summary\n")
			if err != nil {
				t.Fatalf("summary failed: %v\n%s", err, out)
			}
			for _, want := range tc.want {
				if !strings.Contains(string(out), want) {
					t.Fatalf("summary omitted %q", want)
				}
			}
			if strings.Contains(string(out), "https://<未知>") {
				t.Fatal("unknown addresses must not become a clickable URL")
			}
		})
	}
}

func TestInstallerSummaryTableRetainsLongCredentialsAndAlignedBorders(t *testing.T) {
	script := readUninstallSafetyScript(t)
	summary := extractUninstallSafetyFunction(t, script, "print_install_summary", "print_install_summary\n")
	vars := `BOLD='' YELLOW='' NC='' TERM=dumb NO_COLOR=1
INSTALLER_RELEASE_VERSION=v2.0.2 STATUS=running REPAIR_MODE=false PORT_OK=true REPAIR_INACTIVE_HEALTH_VERIFIED=false INSTALL_STARTED_SECONDS=0
PUBLIC_IP=192.0.2.24 PUBLIC_HOST=192.0.2.24 LOCAL_IP=192.0.2.24 LOCAL_HOST=192.0.2.24 VALIDATED_TLS_PORT=8443 PANEL_SUFFIX=example-only CERT_FILE=/example/cert.pem
BASIC_USER=admin WEB_USER=wpadmin BASIC_PASS=example-basic-password
`
	for _, password := range []string{"Ab12Cd34Ef56Gh78", "long-example-password-percent%literal\\backslash-0123456789"} {
		out, err := lifecycleBash(t, vars+"WEB_PASS='"+password+"'\n"+summary+"\nprint_install_summary\n")
		if err != nil || strings.Count(string(out), password) != 1 {
			t.Fatalf("password must remain complete and literal: %v\n%s", err, out)
		}
		width, rows := 0, 0
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.HasPrefix(line, "│") && !strings.HasPrefix(line, "┌") && !strings.HasPrefix(line, "├") && !strings.HasPrefix(line, "└") {
				continue
			}
			columns := 0
			for _, char := range line {
				columns++
				if strings.ContainsRune("用户名密码", char) {
					columns++
				}
			}
			if width == 0 {
				width = columns
			} else if columns != width {
				t.Fatalf("unaligned credential table: %d columns, want %d: %q", columns, width, line)
			}
			rows++
		}
		if rows != 10 {
			t.Fatalf("two credential tables must each contain five rows, got %d", rows)
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
