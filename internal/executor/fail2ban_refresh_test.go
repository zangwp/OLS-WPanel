package executor

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

// The full official fixture includes broad CDN prefixes that intentionally do
// not pass the stricter crawler-import validator (/13, /14, /15 and /29).
const refreshOfficialCFV4 = "173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n103.31.4.0/22\n141.101.64.0/18\n108.162.192.0/18\n190.93.240.0/20\n188.114.96.0/20\n197.234.240.0/22\n198.41.128.0/17\n162.158.0.0/15\n104.16.0.0/13\n104.24.0.0/14\n172.64.0.0/13\n131.0.72.0/22"
const refreshOfficialCFV6 = "2400:cb00::/32\n2606:4700::/32\n2803:f800::/32\n2405:b500::/32\n2405:8100::/32\n2a06:98c0::/29\n2c0f:f248::/32"
const oldRefreshCF = refreshOfficialCFV4 + "\n" + refreshOfficialCFV6
const newRefreshCF = "103.21.244.0/22\n2606:4700::/32"

func TestFetchCloudflareRequiresBothValidMatchingFamilies(t *testing.T) {
	for _, scenario := range []string{"complete", "full-official-22", "v4-download", "v6-download", "empty-v4", "empty-v6", "html-v4", "wrong-v4-family", "wrong-v6-family", "mapped-v6", "private-v4", "wide-v4", "wide-v6"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			run := func(binary string, args ...string) (string, error) {
				calls++
				if binary != "curl" || !strings.Contains(strings.Join(args, " "), "--proto =https --proto-redir =https --connect-timeout 5 --max-time 20") {
					t.Fatal("unbounded download")
				}
				isV4 := strings.HasSuffix(args[len(args)-1], "ips-v4/")
				if (scenario == "v4-download" && isV4) || (scenario == "v6-download" && !isV4) {
					return "", errors.New("download failed")
				}
				if (scenario == "empty-v4" && isV4) || (scenario == "empty-v6" && !isV4) {
					return " \r\n", nil
				}
				if scenario == "html-v4" && isV4 {
					return "<html>temporarily unavailable</html>", nil
				}
				if scenario == "wrong-v4-family" && isV4 {
					return "2606:4700::/32", nil
				}
				if scenario == "wrong-v6-family" && !isV4 {
					return "103.21.244.0/22", nil
				}
				if scenario == "mapped-v6" && !isV4 {
					return "::ffff:103.21.244.0/118", nil
				}
				if scenario == "private-v4" && isV4 {
					return "10.0.0.0/16", nil
				}
				if scenario == "wide-v4" && isV4 {
					return "104.0.0.0/7", nil
				}
				if scenario == "wide-v6" && !isV4 {
					return "2606::/15", nil
				}
				if scenario == "full-official-22" {
					if isV4 {
						return refreshOfficialCFV4, nil
					}
					return refreshOfficialCFV6, nil
				}
				if isV4 {
					return "103.21.244.1/22\r\n103.21.244.0/22\n", nil
				}
				return "2606:4700::/32\n", nil
			}
			got, err := fetchCloudflareIPsWithCommand(run)
			if scenario == "complete" {
				if err != nil || strings.Join(got, "\n") != newRefreshCF || calls != 2 {
					t.Fatal("full canonical list not returned", got, err)
				}
			} else if scenario == "full-official-22" {
				if err != nil || len(got) != 22 || strings.Join(got, "\n") != oldRefreshCF || calls != 2 {
					t.Fatal("full official ranges rejected", got, err)
				}
				if _, err := NormalizeOfficialIPRanges(refreshOfficialCFV4); err == nil {
					t.Fatal("crawler-import validation was loosened for CDN prefixes")
				}
			} else if err == nil || got != nil {
				t.Fatal("partial/invalid source accepted", got, err)
			}
		})
	}
}

func TestFetchBingbotRejectsEmptyInvalidAndIncompleteOfficialLists(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		body        string
		want        []string
		downloadErr bool
	}{
		{"dual-stack-canonical-deduplicated", `{"prefixes":[{"ipv4Prefix":"157.55.39.1/24"},{"ipv4Prefix":"157.55.39.0/24"},{"ipv6Prefix":"2620:1ec:c11::1/48"}]}`, []string{"157.55.39.0/24", "2620:1ec:c11::/48"}, false},
		{"ipv4-only", `{"prefixes":[{"ipv4Prefix":"157.55.39.0/24"}]}`, []string{"157.55.39.0/24"}, false},
		{"ipv6-only", `{"prefixes":[{"ipv6Prefix":"2620:1ec:c11::/48"}]}`, []string{"2620:1ec:c11::/48"}, false},
		{"http-200-empty-prefixes", `{"prefixes":[]}`, nil, false},
		{"http-200-missing-prefixes", `{}`, nil, false},
		{"http-200-null-prefixes", `{"prefixes":null}`, nil, false},
		{"empty-entry-with-good-prefix", `{"prefixes":[{"ipv4Prefix":"157.55.39.0/24"},{}]}`, nil, false},
		{"empty-body", "", nil, false},
		{"html-body", "<html>temporarily unavailable</html>", nil, false},
		{"invalid-json-prefix-type", `{"prefixes":[{"ipv4Prefix":42}]}`, nil, false},
		{"partial-command-failure", `{"prefixes":[{"ipv4Prefix":"157.55.39.0/24"}]}`, nil, true},
		{"bad-prefix-with-good-prefix", `{"prefixes":[{"ipv4Prefix":"157.55.39.0/24"},{"ipv6Prefix":"invalid/48"}]}`, nil, false},
		{"bare-ip-not-cidr", `{"prefixes":[{"ipv4Prefix":"157.55.39.1"}]}`, nil, false},
		{"wrong-v4-family", `{"prefixes":[{"ipv4Prefix":"2620:1ec:c11::/48"}]}`, nil, false},
		{"wrong-v6-family", `{"prefixes":[{"ipv6Prefix":"157.55.39.0/24"}]}`, nil, false},
		{"mapped-v6", `{"prefixes":[{"ipv6Prefix":"::ffff:157.55.39.0/120"}]}`, nil, false},
		{"private-v4", `{"prefixes":[{"ipv4Prefix":"10.0.0.0/16"}]}`, nil, false},
		{"loopback-v4", `{"prefixes":[{"ipv4Prefix":"127.0.0.0/16"}]}`, nil, false},
		{"private-v6", `{"prefixes":[{"ipv6Prefix":"fc00::/32"}]}`, nil, false},
		{"overwide-v4", `{"prefixes":[{"ipv4Prefix":"157.54.0.0/15"}]}`, nil, false},
		{"overwide-v6", `{"prefixes":[{"ipv6Prefix":"2620::/31"}]}`, nil, false},
		{"over-512-prefixes", `{"prefixes":[` + strings.Repeat(`{"ipv4Prefix":"157.55.39.0/24"},`, 512) + `{"ipv4Prefix":"157.55.39.0/24"}]}`, nil, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			got, err := fetchBingbotIPsWithCommand(func(binary string, args ...string) (string, error) {
				calls++
				if binary != "curl" || args[len(args)-1] != "https://www.bing.com/toolbox/bingbot.json" || !strings.Contains(strings.Join(args, " "), "-f -L --proto =https --proto-redir =https --connect-timeout 5 --max-time 20") {
					t.Fatal("download did not use the fixed official URL, HTTPS-only redirects and timeout", binary, args)
				}
				if scenario.downloadErr {
					return scenario.body, errors.New("download failed after partial output")
				}
				return scenario.body, nil
			})
			if calls != 1 {
				t.Fatal("unexpected download count", calls)
			}
			if scenario.want != nil {
				if err != nil || !reflect.DeepEqual(got, scenario.want) {
					t.Fatal("valid official prefixes were not canonicalized", got, err)
				}
			} else if err == nil || got != nil {
				t.Fatal("invalid or partial official response was accepted", got, err)
			}
		})
	}
}

func TestOfficialRefreshBingValidationKeepsGoodCacheAndMetadata(t *testing.T) {
	for _, scenario := range []struct {
		name        string
		body        string
		downloadErr bool
		valid       bool
	}{
		{"valid-dual-stack", `{"prefixes":[{"ipv4Prefix":"207.46.13.1/24"},{"ipv6Prefix":"2620:1ec:c11::1/48"}]}`, false, true},
		{"http-200-empty-prefixes", `{"prefixes":[]}`, false, false},
		{"http-200-missing-prefixes", `{}`, false, false},
		{"invalid-prefix", `{"prefixes":[{"ipv4Prefix":"not-an-ip/24"}]}`, false, false},
		{"wrong-field-family", `{"prefixes":[{"ipv6Prefix":"207.46.13.0/24"}]}`, false, false},
		{"download-failed-with-valid-body", `{"prefixes":[{"ipv4Prefix":"207.46.13.0/24"}]}`, true, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			newOfficialRefreshDB(t)
			if _, err := database.GetDB().Exec(`DELETE FROM website_cdn_realip_groups`); err != nil {
				t.Fatal(err)
			}
			if _, err := database.GetDB().Exec(`UPDATE security_settings SET description=NULL,updated_at='2026-10-09 12:00:00.123' WHERE skey='bingbot_ips'`); err != nil {
				t.Fatal(err)
			}
			bingRow := func() []any {
				t.Helper()
				row := make([]any, 3)
				if err := database.GetDB().QueryRow(`SELECT svalue,description,CAST(updated_at AS TEXT) FROM security_settings WHERE skey='bingbot_ips'`).Scan(&row[0], &row[1], &row[2]); err != nil {
					t.Fatal(err)
				}
				return row
			}
			before := bingRow()
			refreshOfficialBingbotIPs = func() ([]string, error) {
				return fetchBingbotIPsWithCommand(func(string, ...string) (string, error) {
					if scenario.downloadErr {
						return scenario.body, errors.New("download failed")
					}
					return scenario.body, nil
				})
			}
			want := "157.55.39.0/24"
			if scenario.valid {
				want = "207.46.13.0/24\n2620:1ec:c11::/48"
			}
			applications := 0
			result := executeRefreshWhitelistLocked(&Task{}, func() error {
				applications++
				if got := refreshCacheValue(t, "bingbot_ips"); got != want {
					t.Fatal("application received an empty or invalid Bing cache", got)
				}
				return nil
			})
			if !result.Success || applications != 1 {
				t.Fatal("official refresh failed instead of using known-good cache", result, applications)
			}
			if !strings.Contains(refreshCacheValue(t, "official_whitelist_ips"), want) {
				t.Fatal("combined cache dropped Bing ranges")
			}
			if !scenario.valid {
				if !reflect.DeepEqual(before, bingRow()) || !strings.Contains(result.Message, "Bingbot: 获取失败，沿用缓存 1 条") {
					t.Fatal("failed Bing fetch changed known-good cache/nullable description/timestamp or hid fallback", result, before, bingRow())
				}
			} else if reflect.DeepEqual(before, bingRow()) || !strings.Contains(result.Message, "Bingbot: 2 条") {
				t.Fatal("valid dual-stack Bing data was not published", result, bingRow())
			}
		})
	}
}

func newOfficialRefreshDB(t *testing.T) {
	t.Helper()
	previous := database.DB
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "refresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	database.DB = db
	t.Cleanup(func() { db.Close(); database.DB = previous })
	for _, stmt := range []string{
		`CREATE TABLE security_settings(skey TEXT PRIMARY KEY,svalue TEXT NOT NULL,description TEXT DEFAULT '',updated_at DATETIME NOT NULL)`,
		`CREATE TABLE websites(id INTEGER PRIMARY KEY,cdn_realip_enabled INTEGER)`,
		`CREATE TABLE cdn_realip_groups(id INTEGER PRIMARY KEY,provider TEXT,ip_ranges TEXT,enabled INTEGER)`,
		`CREATE TABLE website_cdn_realip_groups(website_id INTEGER,group_id INTEGER)`,
		`INSERT INTO websites VALUES(1,1),(2,0)`,
		`INSERT INTO cdn_realip_groups VALUES(1,'cloudflare','',1),(2,'custom','203.0.113.0/24',1)`,
		`INSERT INTO website_cdn_realip_groups VALUES(1,1),(1,2)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	for key, value := range map[string]string{"cloudflare_realip_ips": oldRefreshCF, "official_whitelist_ips": oldRefreshCF, "googlebot_ips": "66.249.64.0/19", "bingbot_ips": "157.55.39.0/24", "last_whitelist_update": "2026-10-09 12:00:00"} {
		if _, err := db.Exec(`INSERT INTO security_settings VALUES(?,?,?,'2026-10-09 12:00:00')`, key, value, "old "+key); err != nil {
			t.Fatal(err)
		}
	}
	oldCF, oldGoogle, oldBing, oldReady := refreshOfficialCloudflareIPs, refreshOfficialGooglebotIPs, refreshOfficialBingbotIPs, refreshTrustedProxyReady
	t.Cleanup(func() {
		refreshOfficialCloudflareIPs, refreshOfficialGooglebotIPs, refreshOfficialBingbotIPs, refreshTrustedProxyReady = oldCF, oldGoogle, oldBing, oldReady
	})
	refreshOfficialCloudflareIPs = func() ([]string, error) { return strings.Split(newRefreshCF, "\n"), nil }
	refreshOfficialGooglebotIPs = func() ([]string, string, error) { return []string{"66.249.64.0/19"}, "official", nil }
	refreshOfficialBingbotIPs = func() ([]string, error) { return []string{"157.55.39.0/24"}, nil }
	refreshTrustedProxyReady = func() error { return nil }
}
func refreshCacheValue(t *testing.T, key string) string {
	t.Helper()
	var value string
	if err := database.GetDB().QueryRow(`SELECT svalue FROM security_settings WHERE skey=?`, key).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}
func refreshSettingsRows(t *testing.T) [][]any {
	t.Helper()
	rows, err := database.GetDB().Query(`SELECT skey,svalue,description,CAST(updated_at AS TEXT) FROM security_settings ORDER BY skey`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result [][]any
	for rows.Next() {
		r := make([]any, 4)
		if err := rows.Scan(&r[0], &r[1], &r[2], &r[3]); err != nil {
			t.Fatal(err)
		}
		result = append(result, r)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	return result
}

func TestOfficialRefreshReconcilesSelectedCFACLAndDoesNotRestartUnchanged(t *testing.T) {
	newOfficialRefreshDB(t)
	main, _, _ := newOLSTrustedProxyFixture(t)
	commands := 0
	runOLSCommand = func(string, ...string) ([]byte, error) { commands++; return []byte("ok"), nil }
	applications := 0
	apply := func() error {
		applications++
		if refreshCacheValue(t, "cloudflare_realip_ips") != newRefreshCF {
			t.Fatal("Fail2ban saw stale Cloudflare cache")
		}
		return nil
	}
	result := executeRefreshWhitelistLocked(&Task{}, apply)
	if !result.Success {
		t.Fatal(result.Message)
	}
	data, _ := os.ReadFile(main)
	for _, network := range []string{"103.21.244.0/22T", "2606:4700::/32T", "203.0.113.0/24T", "198.51.100.0/24T"} {
		if !strings.Contains(string(data), network) {
			t.Fatal("selected/custom/administrator trust missing", network)
		}
	}
	if strings.Contains(string(data), "173.245.48.0/20T") || commands != 2 || applications != 1 {
		t.Fatal("ACL not using new snapshot", commands, applications)
	}
	result = executeRefreshWhitelistLocked(&Task{}, apply)
	if !result.Success || commands != 2 || applications != 2 {
		t.Fatal("unchanged refresh restarted OLS", result, commands)
	}
}

func TestOfficialRefreshPartialCFDownloadKeepsGoodCacheAndOriginalTimestamp(t *testing.T) {
	newOfficialRefreshDB(t)
	main, managed, _ := newOLSTrustedProxyFixture(t)
	oldContent, err := renderOLSTrustedProxyMainConfig([]byte(olsTrustedProxyTestMain(managed)), managed, append(strings.Split(oldRefreshCF, "\n"), "203.0.113.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(main, oldContent, 0640); err != nil {
		t.Fatal(err)
	}
	runOLSCommand = func(string, ...string) ([]byte, error) {
		t.Fatal("failed download restarted unchanged good ACL")
		return nil, nil
	}
	refreshOfficialCloudflareIPs = func() ([]string, error) {
		return fetchCloudflareIPsWithCommand(func(_ string, args ...string) (string, error) {
			if strings.HasSuffix(args[len(args)-1], "ips-v6/") {
				return "", errors.New("IPv6 unavailable")
			}
			return "103.21.244.0/22", nil
		})
	}
	result := executeRefreshWhitelistLocked(&Task{}, func() error {
		if refreshCacheValue(t, "cloudflare_realip_ips") != oldRefreshCF {
			t.Fatal("partial cache deployed to Fail2ban")
		}
		return nil
	})
	if !result.Success || !strings.Contains(result.Message, "获取失败，沿用缓存") {
		t.Fatal("fallback not explained", result)
	}
	var value, description, stamp string
	if err := database.GetDB().QueryRow(`SELECT svalue,description,CAST(updated_at AS TEXT) FROM security_settings WHERE skey='cloudflare_realip_ips'`).Scan(&value, &description, &stamp); err != nil || value != oldRefreshCF || description != "old cloudflare_realip_ips" || stamp != "2026-10-09 12:00:00" {
		t.Fatal("known good complete cache/metadata overwritten", value, description, stamp, err)
	}
	data, _ := os.ReadFile(main)
	if string(data) != string(oldContent) {
		t.Fatal("failed source modified original ACL")
	}
}

func TestOfficialRefreshUnselectedDisabledStaticOrStoppedCFNeverStartsOLS(t *testing.T) {
	for _, state := range []string{"unbound", "website-disabled", "group-disabled", "static-group", "stopped", "paused"} {
		t.Run(state, func(t *testing.T) {
			newOfficialRefreshDB(t)
			switch state {
			case "unbound":
				database.GetDB().Exec(`DELETE FROM website_cdn_realip_groups WHERE group_id=1`)
			case "website-disabled":
				database.GetDB().Exec(`UPDATE websites SET cdn_realip_enabled=0`)
			case "group-disabled":
				database.GetDB().Exec(`UPDATE cdn_realip_groups SET enabled=0 WHERE id=1`)
			case "static-group":
				database.GetDB().Exec(`UPDATE cdn_realip_groups SET ip_ranges='192.0.2.0/24' WHERE id=1`)
			}
			readyChecks := 0
			refreshTrustedProxyReady = func() error { readyChecks++; return errors.New("service " + state + "; keep original configuration") }
			runOLSCommandOld := runOLSCommand
			runOLSCommand = func(string, ...string) ([]byte, error) {
				t.Fatal("inactive/unselected OLS was invoked")
				return nil, nil
			}
			t.Cleanup(func() { runOLSCommand = runOLSCommandOld })
			before := refreshSettingsRows(t)
			applications := 0
			result := executeRefreshWhitelistLocked(&Task{}, func() error { applications++; return nil })
			if state == "stopped" || state == "paused" {
				if result.Success || readyChecks != 1 || applications != 0 || !reflect.DeepEqual(before, refreshSettingsRows(t)) {
					t.Fatal("stopped service cache changed or failure concealed", result)
				}
			} else if !result.Success || readyChecks != 0 || applications != 1 || refreshCacheValue(t, "cloudflare_realip_ips") != newRefreshCF {
				t.Fatal("unselected cache-only refresh unexpectedly touched OLS", result)
			}
		})
	}
}

func TestOfficialRefreshFailureRestoresCacheACLAndAppliedFail2banSnapshot(t *testing.T) {
	for _, failure := range []string{"ols-test", "ols-restart", "fail2ban", "recovery-fail2ban", "cache-restore"} {
		t.Run(failure, func(t *testing.T) {
			newOfficialRefreshDB(t)
			main, managed, _ := newOLSTrustedProxyFixture(t)
			original, err := renderOLSTrustedProxyMainConfig([]byte(olsTrustedProxyTestMain(managed)), managed, append(strings.Split(oldRefreshCF, "\n"), "203.0.113.0/24"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(main, original, 0640); err != nil {
				t.Fatal(err)
			}
			// Historical nullable descriptions and DATETIME storage must survive
			// rollback exactly, including the original SQL timestamp bytes.
			if _, err := database.GetDB().Exec(`UPDATE security_settings SET description=NULL,updated_at='2026-10-09 12:00:00.123' WHERE skey='cloudflare_realip_ips'`); err != nil {
				t.Fatal(err)
			}
			before := refreshSettingsRows(t)
			testCalls, restarts := 0, 0
			runOLSCommand = func(name string, args ...string) ([]byte, error) {
				if len(args) == 1 && args[0] == "-t" {
					testCalls++
					if failure == "ols-test" && testCalls == 1 {
						return []byte("bad config"), errors.New("test failed")
					}
				} else if name == "systemctl" && strings.Join(args, " ") == "restart lshttpd" {
					restarts++
					if failure == "ols-restart" && restarts == 1 {
						return []byte("bad restart"), errors.New("restart failed")
					}
				} else {
					t.Fatal("unexpected command", name, args)
				}
				return []byte("ok"), nil
			}
			jail := filepath.Join(t.TempDir(), "jail.snapshot")
			os.WriteFile(jail, []byte(oldRefreshCF), 0600)
			applications := 0
			result := executeRefreshWhitelistLocked(&Task{}, func() error {
				applications++
				current := refreshCacheValue(t, "cloudflare_realip_ips")
				if err := os.WriteFile(jail, []byte(current), 0600); err != nil {
					t.Fatal(err)
				}
				if failure == "cache-restore" && applications == 1 {
					if _, err := database.GetDB().Exec(`CREATE TRIGGER block_cf_restore BEFORE UPDATE ON security_settings WHEN NEW.skey='cloudflare_realip_ips' AND NEW.svalue='` + strings.ReplaceAll(oldRefreshCF, "'", "''") + `' BEGIN SELECT RAISE(FAIL,'restore rejected'); END`); err != nil {
						t.Fatal(err)
					}
				}
				if failure == "fail2ban" && applications == 1 || failure == "recovery-fail2ban" || failure == "cache-restore" {
					return errors.New("jail reload failed")
				}
				return nil
			})
			if result.Success {
				t.Fatal("failed apply claimed success")
			}
			if failure == "cache-restore" {
				if !strings.Contains(result.Message, "恢复未完成") || applications != 1 || refreshCacheValue(t, "cloudflare_realip_ips") != newRefreshCF {
					t.Fatal("unsafe runtime restore from wrong database snapshot", result)
				}
				return
			}
			if !reflect.DeepEqual(before, refreshSettingsRows(t)) {
				t.Fatal("cache binding/metadata not restored exactly")
			}
			data, _ := os.ReadFile(main)
			if string(data) != string(original) {
				t.Fatal("old ACL not restored")
			}
			if failure == "recovery-fail2ban" {
				if !strings.Contains(result.Message, "恢复未完成") || applications != 2 {
					t.Fatal("recovery failure hidden", result)
				}
			} else if !strings.Contains(result.Message, "已恢复") {
				t.Fatal("successful compensation not explained", result)
			}
			if failure == "fail2ban" {
				data, _ := os.ReadFile(jail)
				if string(data) != oldRefreshCF || applications != 2 {
					t.Fatal("old jail configuration not reapplied")
				}
			}
		})
	}
}
