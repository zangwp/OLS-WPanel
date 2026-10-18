package executor

import (
	"bytes"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func seedAutomaticCloudflareProxy(t *testing.T) {
	t.Helper()
	for _, sql := range []string{
		`INSERT INTO cdn_realip_groups VALUES(10,'cloudflare','',1,1)`,
		`INSERT INTO security_settings VALUES('cloudflare_realip_ips','103.21.244.0/22'||char(10)||'2606:4700::/32')`,
		`INSERT INTO security_settings VALUES('googlebot_ips','66.249.64.0/19'),('bingbot_ips','157.55.39.0/24')`,
	} {
		if _, err := database.GetDB().Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAutomaticCloudflareProxyTrustDoesNotRequireWebsiteBindings(t *testing.T) {
	for _, state := range []string{"unbound", "website-disabled", "builtin-disabled", "builtin-static", "custom-unbound", "missing-cache", "invalid-cache", "stopped"} {
		t.Run(state, func(t *testing.T) {
			main, _, base := newOLSTrustedProxyFixture(t)
			openOLSTrustedProxySelectionDB(t)
			seedAutomaticCloudflareProxy(t)
			sql := ""
			switch state {
			case "unbound":
				sql = `DELETE FROM website_cdn_realip_groups`
			case "website-disabled":
				sql = `UPDATE websites SET cdn_realip_enabled=0`
			case "builtin-disabled":
				sql = `UPDATE cdn_realip_groups SET enabled=0 WHERE id=10`
			case "builtin-static":
				sql = `UPDATE cdn_realip_groups SET ip_ranges='203.0.113.0/24' WHERE id=10`
			case "custom-unbound":
				sql = `UPDATE cdn_realip_groups SET builtin=0 WHERE id=10`
			case "missing-cache":
				sql = `UPDATE security_settings SET svalue='' WHERE skey='cloudflare_realip_ips'`
			case "invalid-cache":
				sql = `UPDATE security_settings SET svalue='0.0.0.0/0' WHERE skey='cloudflare_realip_ips'`
			case "stopped":
				refreshTrustedProxyReady = func() error { return errors.New("OpenLiteSpeed stopped") }
			}
			if sql != "" {
				if _, err := database.GetDB().Exec(sql); err != nil {
					t.Fatal(err)
				}
			}
			commands := 0
			runOLSCommand = func(string, ...string) ([]byte, error) { commands++; return []byte("ok"), nil }
			err := ApplyOLSTrustedProxyList()
			data, _ := os.ReadFile(main)
			failure := state == "missing-cache" || state == "invalid-cache" || state == "stopped"
			if failure {
				if err == nil || commands != 0 || string(data) != base {
					t.Fatalf("invalid or stopped automatic trust changed runtime: %v commands=%d", err, commands)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			wantAutomatic := state == "unbound" || state == "website-disabled"
			for _, network := range []string{"103.21.244.0/22T", "2606:4700::/32T"} {
				if bytes.Contains(data, []byte(network)) != wantAutomatic {
					t.Fatal("automatic group ignored its administrator scope", state, network)
				}
			}
			for _, excluded := range []string{"66.249.64.0/19T", "157.55.39.0/24T", "203.0.113.0/24T", "198.18.0.0/15T", "198.19.0.0/16T"} {
				if bytes.Contains(data, []byte(excluded)) {
					t.Fatal("unselected, disabled or crawler network became trusted", excluded)
				}
			}
			firstCommands := commands
			if err := ApplyOLSTrustedProxyList(); err != nil || commands != firstCommands {
				t.Fatal("unchanged automatic trust restarted OLS", err)
			}
		})
	}
}

func TestOfficialRefreshUpdatesUnboundAutomaticCloudflareACL(t *testing.T) {
	for _, state := range []string{"unbound", "website-disabled", "unbound-stopped"} {
		t.Run(state, func(t *testing.T) {
			newOfficialRefreshDB(t)
			main, _, base := newOLSTrustedProxyFixture(t)
			if _, err := database.GetDB().Exec(`DELETE FROM website_cdn_realip_groups`); err != nil {
				t.Fatal(err)
			}
			if state == "website-disabled" {
				if _, err := database.GetDB().Exec(`UPDATE websites SET cdn_realip_enabled=0`); err != nil {
					t.Fatal(err)
				}
			}
			if state == "unbound-stopped" {
				refreshTrustedProxyReady = func() error { return errors.New("OpenLiteSpeed stopped") }
			}
			commands, applications := 0, 0
			runOLSCommand = func(string, ...string) ([]byte, error) { commands++; return []byte("ok"), nil }
			result := executeRefreshWhitelistLocked(&Task{}, func() error { applications++; return nil })
			data, _ := os.ReadFile(main)
			if state == "unbound-stopped" {
				if result.Success || commands != 0 || applications != 0 || string(data) != base || refreshCacheValue(t, "cloudflare_realip_ips") != oldRefreshCF {
					t.Fatal("unbound refresh started a stopped service or changed its cache", result)
				}
				return
			}
			if !result.Success || commands != 2 || applications != 1 || !strings.Contains(string(data), "103.21.244.0/22T") || !strings.Contains(string(data), "2606:4700::/32T") {
				t.Fatal("unbound official cache was not connected to the actual server ACL", result, commands)
			}
			if result = executeRefreshWhitelistLocked(&Task{}, func() error { applications++; return nil }); !result.Success || commands != 2 || applications != 2 {
				t.Fatal("unchanged unbound refresh restarted OLS", result, commands)
			}
		})
	}
}

func TestAutomaticCloudflareUpgradeUsesCachedRangesWithoutBindings(t *testing.T) {
	for _, state := range []string{"running", "stopped", "paused", "missing-cache"} {
		t.Run(state, func(t *testing.T) {
			main, _, base := newOLSTrustedProxyFixture(t)
			openOLSTrustedProxySelectionDB(t)
			seedAutomaticCloudflareProxy(t)
			database.GetDB().Exec(`DELETE FROM website_cdn_realip_groups`)
			if state == "missing-cache" {
				database.GetDB().Exec(`UPDATE security_settings SET svalue='' WHERE skey='cloudflare_realip_ips'`)
			}
			previousPaused, previousActive := olsIPv6UpgradePaused, olsTrustedProxyUpgradeActive
			t.Cleanup(func() { olsIPv6UpgradePaused, olsTrustedProxyUpgradeActive = previousPaused, previousActive })
			olsIPv6UpgradePaused = func() bool { return state == "paused" }
			olsTrustedProxyUpgradeActive = func() bool { return state != "stopped" }
			commands := 0
			runOLSCommand = func(string, ...string) ([]byte, error) { commands++; return []byte("ok"), nil }
			if err := ensureManagedOLSTrustedProxyACL(); err != nil {
				t.Fatal("optional reconciliation blocked panel startup", err)
			}
			data, _ := os.ReadFile(main)
			if state == "running" {
				if commands != 2 || !strings.Contains(string(data), "103.21.244.0/22T") {
					t.Fatal("upgrade ignored cached unbound official Cloudflare ranges")
				}
				if err := ensureManagedOLSTrustedProxyACL(); err != nil || commands != 2 {
					t.Fatal("unchanged upgrade restarted OLS", err)
				}
			} else if commands != 0 || string(data) != base {
				t.Fatal("upgrade changed a paused/stopped or cacheless service", state)
			}
		})
	}
}

func TestFirstAutomaticCloudflareRefreshFailureRestoresExactPreviousACL(t *testing.T) {
	for _, state := range []string{"fail2ban", "external-main-edit"} {
		t.Run(state, func(t *testing.T) {
			newOfficialRefreshDB(t)
			main, _, base := newOLSTrustedProxyFixture(t)
			if _, err := database.GetDB().Exec(`DELETE FROM website_cdn_realip_groups`); err != nil {
				t.Fatal(err)
			}
			before := refreshSettingsRows(t)
			commands, applications := 0, 0
			var edited []byte
			runOLSCommand = func(string, ...string) ([]byte, error) { commands++; return []byte("ok"), nil }
			result := executeRefreshWhitelistLocked(&Task{}, func() error {
				applications++
				if applications == 1 {
					if state == "external-main-edit" {
						current, err := os.ReadFile(main)
						if err != nil {
							t.Fatal(err)
						}
						edited = append(current, []byte("# concurrent administrator edit\n")...)
						if err := os.WriteFile(main, edited, 0640); err != nil {
							t.Fatal(err)
						}
					}
					return errors.New("Fail2ban apply failed")
				}
				return nil
			})
			if result.Success || applications != 2 || !reflect.DeepEqual(before, refreshSettingsRows(t)) {
				t.Fatal("failed first automatic application lost original cache", result, applications)
			}
			data, _ := os.ReadFile(main)
			if state == "external-main-edit" {
				if !bytes.Equal(data, edited) || commands != 2 || !strings.Contains(result.Message, "恢复未完成") {
					t.Fatal("rollback overwrote concurrent administrator changes or hid incomplete recovery", result, commands)
				}
			} else if string(data) != base || commands != 4 || !strings.Contains(result.Message, "已恢复") {
				t.Fatal("rollback recomputed trust instead of restoring the original main file", result, commands)
			}
		})
	}
}
