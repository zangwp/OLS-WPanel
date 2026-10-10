package executor

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

func olsTrustedProxyTestMain(managed string) string {
	return "serverName OLS-WPanel\nuseIpInProxyHeader 2\nmodule cache {\n  enableCache 0\n}\naccessControl {\n  allow ALL, 198.51.100.0/24T\n  deny\n}\ninclude " + filepath.ToSlash(managed) + "\n"
}

func TestOLSTrustedProxyACLPreservesDenyRestrictionsAndAllowsTrustRemoval(t *testing.T) {
	managed := filepath.Join(t.TempDir(), "sites.conf")
	base := olsTrustedProxyTestMain(managed)
	protected := strings.Replace(base, "  deny\n", "  deny 192.0.2.0/24\n", 1)
	if _, err := renderOLSTrustedProxyMainConfig([]byte(protected), managed, []string{"192.0.2.5/32"}); err == nil || !strings.Contains(err.Error(), "deny") {
		t.Fatal("a more-specific trusted host could override the administrator deny subnet")
	}
	trusted, err := renderOLSTrustedProxyMainConfig([]byte(base), managed, []string{"192.0.2.5/32"})
	if err != nil {
		t.Fatal(err)
	}
	trusted = bytes.Replace(trusted, []byte("  deny\n"), []byte("  deny 192.0.2.0/24\n"), 1)
	if _, err := renderOLSTrustedProxyMainConfig(trusted, managed, []string{"192.0.2.5/32"}); err == nil {
		t.Fatal("continuing managed trust ignored newly configured deny")
	}
	restored, err := renderOLSTrustedProxyMainConfig(trusted, managed, nil)
	if err != nil || string(restored) != protected {
		t.Fatalf("removing managed trust did not preserve deny: %v", err)
	}
}

func TestOLSTrustedProxyACLEmptyUnmanagedRequestDoesNotRewriteMain(t *testing.T) {
	main, managed, _ := newOLSTrustedProxyFixture(t)
	base := "# administrator custom server config\ninclude /custom/extra.conf\n"
	if err := os.WriteFile(main, []byte(base), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(managed); err != nil {
		t.Fatal(err)
	}
	runOLSCommand = func(string, ...string) ([]byte, error) { t.Fatal("empty unchanged list invoked OLS"); return nil, nil }
	if err := applyOLSTrustedProxyRanges(main, managed, nil); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(main); string(data) != base {
		t.Fatal("empty list rewrote unrelated configuration")
	}
}

func TestOLSTrustedProxyACLAtomicApplyAndRecoveryPreserveMetadata(t *testing.T) {
	for _, recover := range []bool{false, true} {
		t.Run(fmt.Sprintf("recovery=%t", recover), func(t *testing.T) {
			main, managed, _ := newOLSTrustedProxyFixture(t)
			if err := os.Chmod(main, 0600); err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS == "linux" && os.Geteuid() == 0 {
				if err := os.Chown(main, 65534, 65534); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Stat(main)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			runOLSCommand = func(string, ...string) ([]byte, error) {
				calls++
				if recover && calls == 1 {
					return nil, errors.New("test failure")
				}
				return []byte("ok"), nil
			}
			err = applyOLSTrustedProxyRanges(main, managed, []string{"192.0.2.0/24"})
			if (err != nil) != recover {
				t.Fatalf("unexpected application result: %v", err)
			}
			after, err := os.Stat(main)
			if err != nil {
				t.Fatal(err)
			}
			if before.Mode().Perm() != after.Mode().Perm() {
				t.Fatalf("permissions changed: %v -> %v", before.Mode(), after.Mode())
			}
			if runtime.GOOS == "linux" {
				beforeUID, beforeGID, err := fileOwnerIDs(before)
				if err != nil {
					t.Fatal(err)
				}
				afterUID, afterGID, err := fileOwnerIDs(after)
				if err != nil || beforeUID != afterUID || beforeGID != afterGID {
					t.Fatalf("owner/group changed: %d:%d -> %d:%d: %v", beforeUID, beforeGID, afterUID, afterGID, err)
				}
			}
		})
	}
}

func TestOLSTrustedProxyACLReconcilesWithoutChangingAdministratorRules(t *testing.T) {
	managed := filepath.Join(t.TempDir(), "sites.conf")
	for _, newline := range []string{"\n", "\r\n"} {
		t.Run(fmt.Sprintf("CRLF=%t", newline == "\r\n"), func(t *testing.T) {
			base := strings.ReplaceAll(olsTrustedProxyTestMain(managed), "\n", newline)
			ranges := []string{"2001:db8:100::/48", "192.0.2.0/24", "198.51.100.0/24", "192.0.2.0/24"}
			got, err := renderOLSTrustedProxyMainConfig([]byte(base), managed, ranges)
			if err != nil {
				t.Fatal(err)
			}
			want := "  allow ALL, 198.51.100.0/24T, 192.0.2.0/24T, 2001:db8:100::/48T" + newline
			if !bytes.Contains(got, []byte(want)) || strings.Count(string(got), "\n  allow ") != 1 || strings.Count(string(got), "198.51.100.0/24T") != 2 {
				t.Fatalf("real allow directive did not preserve and extend the existing ACL: %s", got)
			}
			again, err := renderOLSTrustedProxyMainConfig(got, managed, ranges)
			if err != nil || !bytes.Equal(got, again) {
				t.Fatalf("reconciliation is not idempotent: %v", err)
			}
			changed, err := renderOLSTrustedProxyMainConfig(got, managed, []string{"203.0.113.0/24"})
			if err != nil || !bytes.Contains(changed, []byte("  allow ALL, 198.51.100.0/24T, 203.0.113.0/24T"+newline)) || bytes.Contains(changed, []byte("192.0.2.0/24T")) {
				t.Fatalf("old panel-owned ranges not replaced independently: %v", err)
			}
			restored, err := renderOLSTrustedProxyMainConfig(changed, managed, nil)
			if err != nil || string(restored) != base {
				t.Fatalf("removing panel trust changed administrator configuration: %v\n%s", err, restored)
			}
		})
	}
}

func TestOLSTrustedProxyACLReconcilesActualInstallerMainConfiguration(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	const startMarker = "cat > \"$OLS_MAIN_CONF\" << 'OLSHTTPEOF'\n"
	text := strings.ReplaceAll(string(script), "\r\n", "\n")
	start := strings.Index(text, startMarker)
	if start < 0 {
		t.Fatal("actual installer main config not found")
	}
	start += len(startMarker)
	end := strings.Index(text[start:], "\nOLSHTTPEOF\n")
	if end < 0 {
		t.Fatal("actual installer main config end not found")
	}
	base := []byte(text[start : start+end+1])
	const managed = "/usr/local/lsws/conf/ols-wpanel/sites.conf"
	updated, err := renderOLSTrustedProxyMainConfig(base, managed, []string{"192.0.2.0/24", "2001:db8:100::/48"})
	if err != nil || !bytes.Contains(updated, []byte("ALL, 192.0.2.0/24T, 2001:db8:100::/48T")) {
		t.Fatalf("installer main cannot be reconciled: %v", err)
	}
	restored, err := renderOLSTrustedProxyMainConfig(updated, managed, nil)
	if err != nil || !bytes.Equal(restored, base) {
		t.Fatalf("installer main not restored byte for byte: %v", err)
	}
}

func TestOLSTrustedProxyACLRefusesAmbiguousOrManuallyChangedConfiguration(t *testing.T) {
	managed := filepath.Join(t.TempDir(), "sites.conf")
	base := olsTrustedProxyTestMain(managed)
	withMarker, err := renderOLSTrustedProxyMainConfig([]byte(base), managed, []string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"restricted ACL":       strings.Replace(base, "ALL, ", "", 1),
		"duplicate allow":      strings.Replace(base, "  deny", "  allow ALL\n  deny", 1),
		"duplicate server ACL": base + "accessControl {\n  allow ALL\n}\n",
		"duplicate proxy mode": base + "useIpInProxyHeader 2\n",
		"unsafe proxy mode":    strings.Replace(base, "useIpInProxyHeader 2", "useIpInProxyHeader 1", 1),
		"missing proxy mode":   strings.Replace(base, "useIpInProxyHeader 2\n", "", 1),
		"extra root include":   base + "include /administrator/extra.conf\n",
		"wrong registry":       strings.Replace(base, filepath.ToSlash(managed), "/foreign/sites.conf", 1),
		"ACL include":          strings.Replace(base, "  deny", "  include /administrator/acl.conf\n  deny", 1),
		"inline ACL":           strings.Replace(base, "accessControl {\n", "accessControl { allow ALL }\n", 1),
		"multiline allow":      strings.Replace(base, "  allow ALL,", "  allow ALL, \\\n", 1),
		"unbalanced block":     strings.TrimSuffix(base, "\n") + "\n}\n",
		"edited managed allow": strings.Replace(string(withMarker), "198.51.100.0/24T, 192.0.2.0/24T", "198.51.100.0/24T, 203.0.113.0/24T", 1),
		"corrupt marker":       strings.Replace(string(withMarker), `"sha256":"`, `"sha256":"changed`, 1),
		"marker outside ACL":   olsTrustedProxyACLMarker + "{}\n" + base,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderOLSTrustedProxyMainConfig([]byte(content), managed, []string{"192.0.2.0/24"}); err == nil {
				t.Fatal("unknown/changed administrator configuration was automatically accepted")
			}
		})
	}
}

func TestOLSTrustedProxyACLRejectsInvalidRangesAndOLSLineOverflow(t *testing.T) {
	managed := filepath.Join(t.TempDir(), "sites.conf")
	for _, ranges := range [][]string{{"ALL"}, {"192.0.2.0/24T"}, {"192.0.2.0/24\nallow ALL"}, {"192.0.2.0/24 # injected"}} {
		if _, err := renderOLSTrustedProxyMainConfig([]byte(olsTrustedProxyTestMain(managed)), managed, ranges); err == nil {
			t.Fatalf("invalid network accepted: %v", ranges)
		}
	}
	var many []string
	for index := range 600 {
		many = append(many, fmt.Sprintf("2001:db8:%x::/48", index))
	}
	if _, err := renderOLSTrustedProxyMainConfig([]byte(olsTrustedProxyTestMain(managed)), managed, many); err == nil {
		t.Fatal("generated allow line exceeds OLS's 8192-byte parser buffer")
	}
}

func newOLSTrustedProxyFixture(t *testing.T) (main, managed, base string) {
	t.Helper()
	root := t.TempDir()
	main, managed = filepath.Join(root, "httpd_config.conf"), filepath.Join(root, "sites.conf")
	base = olsTrustedProxyTestMain(managed)
	for path, content := range map[string]string{main: base, managed: "# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.\n"} {
		if err := os.WriteFile(path, []byte(content), 0640); err != nil {
			t.Fatal(err)
		}
	}
	previousConfig, previousCommand := config.AppConfig, runOLSCommand
	config.AppConfig = &config.Config{Paths: config.PathsConfig{OLSMainConfig: main, OLSManagedConfig: managed, OLSBinary: filepath.Join(root, "openlitespeed")}}
	t.Cleanup(func() { config.AppConfig, runOLSCommand = previousConfig, previousCommand })
	return
}

func TestOLSTrustedProxyACLApplyUsesActualMainAndNoUnusedFile(t *testing.T) {
	main, managed, base := newOLSTrustedProxyFixture(t)
	var calls []string
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		data, err := os.ReadFile(main)
		if err != nil || !bytes.Contains(data, []byte("allow ALL, 198.51.100.0/24T, 192.0.2.0/24T")) {
			t.Fatal("OLS was called before the trusted network reached its real main allow directive")
		}
		return []byte("ok"), nil
	}
	if err := applyOLSTrustedProxyRanges(main, managed, []string{"192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !strings.HasSuffix(calls[0], " -t") || calls[1] != "systemctl restart lshttpd" {
		t.Fatalf("unexpected apply sequence: %v", calls)
	}
	if err := applyOLSTrustedProxyRanges(main, managed, []string{"192.0.2.0/24"}); err != nil || len(calls) != 2 {
		t.Fatal("unchanged trusted ACL restarted OLS")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(main), "trusted-ip-list")); !os.IsNotExist(err) {
		t.Fatal("application still relies on the unused trusted-ip-list file")
	}
	runOLSCommand = func(string, ...string) ([]byte, error) { return []byte("ok"), nil }
	if err := applyOLSTrustedProxyRanges(main, managed, nil); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(main); string(data) != base {
		t.Fatal("disable did not restore exact administrator configuration")
	}
}

func TestOLSTrustedProxyACLApplyRestoresExactMainAfterFailure(t *testing.T) {
	for _, failure := range []string{"configuration check", "restart", "recovery check", "recovery write"} {
		t.Run(failure, func(t *testing.T) {
			main, managed, base := newOLSTrustedProxyFixture(t)
			tests, restarts := 0, 0
			runOLSCommand = func(name string, args ...string) ([]byte, error) {
				if len(args) == 1 && args[0] == "-t" {
					tests++
					if tests == 1 && failure != "restart" {
						if failure == "recovery write" {
							if err := os.Remove(main); err != nil {
								t.Fatal(err)
							}
							if err := os.Mkdir(main, 0700); err != nil {
								t.Fatal(err)
							}
						}
						return []byte("bad configuration"), errors.New("test failure")
					}
					if tests == 2 && failure == "recovery check" {
						return []byte("recovery failed"), errors.New("recovery failure")
					}
				} else if name == "systemctl" && strings.Join(args, " ") == "restart lshttpd" {
					restarts++
					if restarts == 1 && failure == "restart" {
						return []byte("restart failed"), errors.New("restart failure")
					}
				} else {
					t.Fatalf("unexpected command %s %v", name, args)
				}
				return []byte("ok"), nil
			}
			err := applyOLSTrustedProxyRanges(main, managed, []string{"192.0.2.0/24"})
			if err == nil {
				t.Fatal("failed trusted ACL application reported success")
			}
			if failure == "recovery write" {
				if !strings.Contains(err.Error(), "恢复原 OpenLiteSpeed 主配置失败") || tests != 1 || restarts != 0 {
					t.Fatalf("recovery write failure concealed: %v", err)
				}
				return
			}
			if data, _ := os.ReadFile(main); string(data) != base {
				t.Fatal("failed application changed original main configuration")
			}
			if tests != 2 || (failure == "configuration check" && restarts != 1) || (failure == "restart" && restarts != 2) || (failure == "recovery check" && restarts != 0) {
				t.Fatalf("unexpected recovery sequence: test=%d restart=%d", tests, restarts)
			}
		})
	}
}

func TestOLSTrustedProxyACLRejectsForeignAndNonRegularFilesBeforeCommands(t *testing.T) {
	for _, state := range []string{"foreign registry", "missing main", "main directory", "registry directory", "main symlink"} {
		t.Run(state, func(t *testing.T) {
			main, managed, base := newOLSTrustedProxyFixture(t)
			switch state {
			case "foreign registry":
				if err := os.WriteFile(managed, []byte("# custom registry\n"), 0640); err != nil {
					t.Fatal(err)
				}
			case "missing main", "main directory", "main symlink":
				if err := os.Remove(main); err != nil {
					t.Fatal(err)
				}
				if state == "main directory" {
					if err := os.Mkdir(main, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if state == "main symlink" {
					outside := filepath.Join(t.TempDir(), "original-main.conf")
					if err := os.WriteFile(outside, []byte(base), 0640); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, main); err != nil {
						t.Skipf("host cannot create symlink: %v", err)
					}
				}
			case "registry directory":
				if err := os.Remove(managed); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(managed, 0700); err != nil {
					t.Fatal(err)
				}
			}
			runOLSCommand = func(string, ...string) ([]byte, error) { t.Fatal("unsafe input invoked OLS"); return nil, nil }
			if err := applyOLSTrustedProxyRanges(main, managed, []string{"192.0.2.0/24"}); err == nil {
				t.Fatal("unsafe file accepted")
			}
		})
	}
}

func openOLSTrustedProxySelectionDB(t *testing.T) {
	t.Helper()
	previous := database.DB
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "selected-cdn.db"))
	if err != nil {
		t.Fatal(err)
	}
	database.DB = db
	t.Cleanup(func() { db.Close(); database.DB = previous })
	for _, statement := range []string{
		`CREATE TABLE websites (id INTEGER PRIMARY KEY, cdn_realip_enabled INTEGER)`,
		`CREATE TABLE cdn_realip_groups (id INTEGER PRIMARY KEY, provider TEXT, ip_ranges TEXT, enabled INTEGER)`,
		`CREATE TABLE website_cdn_realip_groups (website_id INTEGER, group_id INTEGER)`,
		`CREATE TABLE security_settings (skey TEXT, svalue TEXT)`,
		`INSERT INTO websites VALUES (1,1),(2,0)`,
		`INSERT INTO cdn_realip_groups VALUES (1,'custom','192.0.2.0/24'||char(10)||'2001:db8:100::/48',1),(2,'custom','203.0.113.0/24',0),(3,'custom','198.18.0.0/15',1),(4,'custom','198.19.0.0/16',1)`,
		`INSERT INTO website_cdn_realip_groups VALUES (1,1),(1,2),(2,4)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
}

func TestApplyOLSTrustedProxyListUsesOnlyActuallySelectedEnabledGroups(t *testing.T) {
	main, _, _ := newOLSTrustedProxyFixture(t)
	openOLSTrustedProxySelectionDB(t)
	commands := 0
	runOLSCommand = func(string, ...string) ([]byte, error) { commands++; return []byte("ok"), nil }
	if err := ApplyOLSTrustedProxyList(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(main)
	if err != nil || !bytes.Contains(data, []byte("192.0.2.0/24T, 2001:db8:100::/48T")) || commands != 2 {
		t.Fatalf("selected networks missing: %s %v", data, err)
	}
	for _, unselected := range []string{"203.0.113.0/24T", "198.18.0.0/15T", "198.19.0.0/16T"} {
		if bytes.Contains(data, []byte(unselected)) {
			t.Fatalf("unselected/disabled CDN was trusted: %s", unselected)
		}
	}
}

func TestOLSTrustedProxyUpgradeRunsOnlyWhenSelectedRunningAndChanged(t *testing.T) {
	for _, state := range []string{"running", "stopped", "paused", "disabled", "unbound", "foreign", "invalid main", "apply failure"} {
		t.Run(state, func(t *testing.T) {
			main, managed, base := newOLSTrustedProxyFixture(t)
			openOLSTrustedProxySelectionDB(t)
			previousPaused, previousActive := olsIPv6UpgradePaused, olsTrustedProxyUpgradeActive
			t.Cleanup(func() { olsIPv6UpgradePaused, olsTrustedProxyUpgradeActive = previousPaused, previousActive })
			olsIPv6UpgradePaused = func() bool { return state == "paused" }
			activeChecks, commands := 0, 0
			olsTrustedProxyUpgradeActive = func() bool { activeChecks++; return state != "stopped" }
			switch state {
			case "disabled":
				database.DB.Exec(`UPDATE websites SET cdn_realip_enabled=0`)
			case "unbound":
				database.DB.Exec(`DELETE FROM website_cdn_realip_groups`)
			case "foreign":
				os.WriteFile(managed, []byte("# administrator registry\n"), 0640)
			case "invalid main":
				base = strings.Replace(base, "useIpInProxyHeader 2", "useIpInProxyHeader 1", 1)
				os.WriteFile(main, []byte(base), 0640)
			}
			runOLSCommand = func(string, ...string) ([]byte, error) {
				commands++
				if state == "apply failure" && commands == 1 {
					return []byte("bad config"), errors.New("test failure")
				}
				return []byte("ok"), nil
			}
			if err := ensureManagedOLSTrustedProxyACL(); err != nil {
				t.Fatalf("optional upgrade blocked startup: %v", err)
			}
			data, _ := os.ReadFile(main)
			if state == "running" {
				if string(data) == base || commands != 2 || activeChecks != 1 {
					t.Fatalf("upgrade did not apply: commands=%d active=%d", commands, activeChecks)
				}
				if err := ensureManagedOLSTrustedProxyACL(); err != nil || commands != 2 || activeChecks != 1 {
					t.Fatal("unchanged upgrade restarted OLS")
				}
			} else {
				if string(data) != base {
					t.Fatal("skipped/failed upgrade changed the main config")
				}
				if state == "apply failure" {
					if commands != 3 {
						t.Fatalf("upgrade did not check and recover: %d", commands)
					}
				} else if commands != 0 {
					t.Fatalf("skip state invoked OLS: %d", commands)
				}
			}
		})
	}
}

func TestOLSTrustedProxyPreviewUsesProductionReconciliation(t *testing.T) {
	output := os.Getenv("OLS_TRUSTED_PROXY_PREVIEW_PATH")
	if output == "" {
		t.Skip("preview export not requested")
	}
	managed := "/usr/local/lsws/conf/ols-wpanel/sites.conf"
	base := "serverName OLS-WPanel\nuseIpInProxyHeader 2\naccessControl {\n  allow ALL\n}\ninclude " + managed + "\n"
	content, err := renderOLSTrustedProxyMainConfig([]byte(base), managed, []string{"192.0.2.0/24", "2001:db8:100::/48"})
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(content, []byte("accessControl {\n"))
	end := start + bytes.Index(content[start:], []byte("\n}\n")) + 3
	snippet := append([]byte("# Test fixture reconciled by renderOLSTrustedProxyMainConfig.\nuseIpInProxyHeader 2\n"), content[start:end]...)
	if !bytes.Contains(snippet, []byte("  allow ALL, 192.0.2.0/24T, 2001:db8:100::/48T\n")) || !bytes.HasSuffix(snippet, []byte("\n}\n")) {
		t.Fatal("preview does not contain the complete actual ACL block")
	}
	if err := os.WriteFile(output, snippet, 0644); err != nil {
		t.Fatal(err)
	}
}
