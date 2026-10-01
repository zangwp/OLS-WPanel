package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestInstallRegistersOLSNativeUnitBeforeDropIn(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	call := requiredIndex(t, script, "\nensure_ols_systemd_unit\n")
	dropIn := requiredIndex(t, script, `DROPDIR="/etc/systemd/system/lshttpd.service.d"`)
	guard := requiredLastIndexBefore(t, script, "if ! $REPAIR_MODE; then", call)
	if !(guard < call && call < dropIn) {
		t.Fatal("native unit registration must run inside the fresh-install guard before the OLS drop-in")
	}
}

func TestInstallOLSNativeUnitRegistration(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	script := readInstallScript(t, installScriptPath)
	helper := extractShellFunction(t, script, "ensure_ols_systemd_unit", "systemctl_wait_active_required")
	for _, tc := range []struct {
		name, native, legacy, fail string
		missingVendor, conflict    bool
		wantFailure, wantInstall   bool
	}{
		{name: "preserve native", native: "/usr/lib/systemd/system/lshttpd.service"},
		{name: "preserve custom native", native: "/etc/systemd/system/lshttpd.service"},
		{name: "Debian generated SysV", legacy: "/run/systemd/generator.late/lsws.service", wantInstall: true},
		{name: "generated normal", legacy: "/run/systemd/generator/lsws.service", wantInstall: true},
		{name: "missing units", wantInstall: true},
		{name: "custom legacy conflict", legacy: "/etc/systemd/system/lsws.service", wantFailure: true},
		{name: "masked native", conflict: true, wantFailure: true},
		{name: "missing vendor", missingVendor: true, wantFailure: true},
		{name: "stop failure", legacy: "/run/systemd/generator.late/lsws.service", fail: "stop", wantFailure: true},
		{name: "disable failure", legacy: "/run/systemd/generator.late/lsws.service", fail: "disable", wantFailure: true},
		{name: "install failure", fail: "install", wantFailure: true},
		{name: "alias failure", fail: "ln", wantFailure: true},
		{name: "reload failure", fail: "daemon-reload", wantFailure: true},
		{name: "registration failure", fail: "registration", wantFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.ToSlash(t.TempDir())
			vendor, target, alias := root+"/vendor.service", root+"/lshttpd.service", root+"/lsws.service"
			if !tc.missingVendor {
				if err := os.WriteFile(vendor, []byte("[Service]\nType=forking\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.conflict {
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			fixtureHelper := strings.NewReplacer(
				"/usr/local/lsws/admin/misc/lshttpd.service", vendor,
				"/etc/systemd/system/lshttpd.service", target,
				"/etc/systemd/system/lsws.service", alias,
			).Replace(helper)
			fixture := fmt.Sprintf(`set -e
native=%s
legacy=%s
failure=%s
target=%s
registered=0
log_error() { printf 'ERROR: %%s\n' "$*" >&2; exit 1; }
log_info() { :; }
systemctl() {
    if [[ "$1" == show ]]; then
        if [[ "$2" == lshttpd.service ]]; then
            if [[ "$registered" == 1 && "$failure" != registration ]]; then
                printf '%%s\n' "$target"
            else
                printf '%%s\n' "$native"
            fi
        else
            printf '%%s\n' "$legacy"
        fi
        return 0
    fi
    printf 'systemctl %%s\n' "$*"
    [[ "$failure" != "$1" ]]
}
install() { printf 'install %%s\n' "$*"; [[ "$failure" != install ]] || return 1; registered=1; }
ln() { printf 'ln %%s\n' "$*"; [[ "$failure" != ln ]]; }
%s
ensure_ols_systemd_unit
`, strconv.Quote(tc.native), strconv.Quote(tc.legacy), strconv.Quote(tc.fail), strconv.Quote(target), fixtureHelper)
			output, err := exec.Command(bash, "-c", fixture).CombinedOutput()
			if (err != nil) != tc.wantFailure {
				t.Fatalf("failure=%v, want %v: %s", err, tc.wantFailure, output)
			}
			got := string(output)
			if tc.wantInstall {
				if !strings.Contains(got, "install -o root -g root -m 0644 ") || !strings.Contains(got, "ln -s lshttpd.service "+alias) {
					t.Fatalf("native unit and alias were not registered: %s", got)
				}
				if tc.legacy != "" {
					stop := strings.Index(got, "systemctl stop lsws.service")
					disable := strings.Index(got, "systemctl disable lsws.service")
					install := strings.Index(got, "install -o")
					if !(stop >= 0 && stop < disable && disable < install) {
						t.Fatalf("legacy service must be stopped and disabled before installation: %s", got)
					}
				}
			} else if tc.native != "" || tc.conflict || tc.missingVendor || strings.HasPrefix(tc.legacy, "/etc/") {
				if strings.Contains(got, "install -o") || strings.Contains(got, "systemctl stop") {
					t.Fatalf("existing or conflicting services were modified: %s", got)
				}
			}
		})
	}
}
