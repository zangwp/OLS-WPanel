package executor

import (
	"os"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func TestInitialCloudflareRefreshHonorsScheduleAndCache(t *testing.T) {
	for _, state := range []string{"empty", "cached", "schedule-disabled", "builtin-disabled", "invalid-cache", "missing-setting"} {
		t.Run(state, func(t *testing.T) {
			openOLSTrustedProxySelectionDB(t)
			seedAutomaticCloudflareProxy(t)
			db := database.GetDB()
			statements := []string{`INSERT INTO security_settings VALUES('auto_whitelist_enabled','true')`}
			if state != "cached" {
				statements = append(statements, `UPDATE security_settings SET svalue='' WHERE skey='cloudflare_realip_ips'`)
			}
			switch state {
			case "schedule-disabled":
				statements = append(statements, `UPDATE security_settings SET svalue='false' WHERE skey='auto_whitelist_enabled'`)
			case "builtin-disabled":
				statements = append(statements, `UPDATE cdn_realip_groups SET enabled=0 WHERE id=10`)
			case "invalid-cache":
				statements = append(statements, `UPDATE security_settings SET svalue='0.0.0.0/0' WHERE skey='cloudflare_realip_ips'`)
			case "missing-setting":
				statements = append(statements, `DELETE FROM security_settings WHERE skey='auto_whitelist_enabled'`)
			}
			for _, statement := range statements {
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			needed, err := needsInitialCloudflareRefresh(db)
			wantError := state == "invalid-cache" || state == "missing-setting"
			if needed != (state == "empty") || (err != nil) != wantError {
				t.Fatalf("initial refresh needed=%v err=%v for %s", needed, err, state)
			}
		})
	}
}

func TestCloudflareTrustStatusInspectsActualConfig(t *testing.T) {
	for _, state := range []string{"missing", "invalid", "pending", "configured", "edited", "disabled"} {
		t.Run(state, func(t *testing.T) {
			main, _, base := newOLSTrustedProxyFixture(t)
			openOLSTrustedProxySelectionDB(t)
			seedAutomaticCloudflareProxy(t)
			db := database.GetDB()
			query := ""
			want := state
			switch state {
			case "missing":
				query = `UPDATE security_settings SET svalue='' WHERE skey='cloudflare_realip_ips'`
			case "invalid":
				query = `UPDATE security_settings SET svalue='0.0.0.0/0' WHERE skey='cloudflare_realip_ips'`
				want = "missing"
			case "disabled":
				query = `UPDATE cdn_realip_groups SET enabled=0 WHERE id=10`
			case "configured", "edited":
				runOLSCommand = func(string, ...string) ([]byte, error) { return []byte("ok"), nil }
				if err := ApplyOLSTrustedProxyList(); err != nil {
					t.Fatal(err)
				}
				if state == "edited" {
					if err := os.WriteFile(main, []byte(base+"include /etc/unmanaged.conf\n"), 0640); err != nil {
						t.Fatal(err)
					}
					want = "unknown"
				}
			}
			if query != "" {
				if _, err := db.Exec(query); err != nil {
					t.Fatal(err)
				}
			}
			runOLSCommand = func(string, ...string) ([]byte, error) { t.Fatal("status must not run commands"); return nil, nil }
			before, err := os.ReadFile(main)
			if err != nil {
				t.Fatal(err)
			}
			if got := cloudflareTrustConfigStatus(db); got != want {
				t.Fatalf("status=%q want=%q", got, want)
			}
			after, err := os.ReadFile(main)
			if err != nil || string(before) != string(after) {
				t.Fatal("status changed the config", err)
			}
		})
	}
}
