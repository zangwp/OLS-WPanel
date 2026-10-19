package database

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func securityVerificationRecord(siteID int, key string) SiteSecurityVerificationRecord {
	return SiteSecurityVerificationRecord{SiteID: siteID, Key: key, State: "runtime_verified", CheckedAt: time.Now().UTC().Format(time.RFC3339Nano), ReasonCode: "core_debug_display_disabled", Source: "isolated_wp_core", Fingerprint: strings.Repeat("a", 64)}
}

func TestSiteSecurityVerificationFreshSchemaAndVersionedUpgradeAgree(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "upgrade from 1.0.80"}[legacy], func(t *testing.T) {
			previous := DB
			if err := Open(filepath.Join(t.TempDir(), "security.db")); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { DB.Close(); DB = previous })
			if legacy {
				if _, err := DB.Exec(`CREATE TABLE websites(id INTEGER PRIMARY KEY,name TEXT NOT NULL);
				INSERT INTO websites VALUES(7,'preserved website');
				CREATE TABLE schema_version(version TEXT NOT NULL,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
				INSERT INTO schema_version(version) VALUES('1.0.80')`); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := RunMigrations(); err != nil {
					t.Fatal(err)
				}
				if _, err := DB.Exec(`INSERT INTO websites(id,name,domain,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path)
				VALUES(7,'preserved website','site.example','wp_site','/www/site','/www/logs','wpdb','wpuser','/tmp/php.sock','/ols/site.conf')`); err != nil {
					t.Fatal(err)
				}
			}
			if err := RunUpgrades(); err != nil {
				t.Fatal(err)
			}
			original := securityVerificationRecord(7, "debug_display")
			if err := SaveSiteSecurityVerification(context.Background(), DB, original); err != nil {
				t.Fatal(err)
			}
			for repeat := 0; repeat < 2; repeat++ {
				if err := EnsureSiteSecurityVerificationSchema(DB); err != nil {
					t.Fatal(err)
				}
				if err := RunUpgrades(); err != nil {
					t.Fatal(err)
				}
				got, err := LoadSiteSecurityVerifications(context.Background(), DB, 7)
				if err != nil || !reflect.DeepEqual(got["debug_display"], original) {
					t.Fatalf("repeated migration changed verification: %+v %v", got, err)
				}
				var name string
				if err := DB.QueryRow(`SELECT name FROM websites WHERE id=7`).Scan(&name); err != nil || name != "preserved website" {
					t.Fatalf("upgrade modified website: %s %v", name, err)
				}
			}
			if _, err := DB.Exec(`DELETE FROM websites WHERE id=7`); err != nil {
				t.Fatal(err)
			}
			got, err := LoadSiteSecurityVerifications(context.Background(), DB, 7)
			if err != nil || len(got) != 0 {
				t.Fatalf("site deletion retained verification records: %+v %v", got, err)
			}
		})
	}
}

func TestSiteSecurityVerificationUpsertIsBoundedAndSurvivesReopen(t *testing.T) {
	previous := DB
	path := filepath.Join(t.TempDir(), "persisted.db")
	if err := Open(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DB.Close(); DB = previous })
	if _, err := DB.Exec(`CREATE TABLE websites(id INTEGER PRIMARY KEY); INSERT INTO websites VALUES(1),(2)`); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSiteSecurityVerificationSchema(DB); err != nil {
		t.Fatal(err)
	}
	keys := []string{"https", "login_protection", "sql_injection", "sensitive_files", "uploads_php", "xmlrpc", "application_passwords", "file_editing", "debug_display", "wp_updates"}
	for n := 0; n < 3; n++ {
		for _, key := range keys {
			record := securityVerificationRecord(1, key)
			record.State = "configured"
			record.ReasonCode = "core_runtime_unavailable"
			if err := SaveSiteSecurityVerification(context.Background(), DB, record); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := SaveSiteSecurityVerification(context.Background(), DB, securityVerificationRecord(2, "debug_display")); err != nil {
		t.Fatal(err)
	}
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	if err := Open(path); err != nil {
		t.Fatal(err)
	}
	for siteID, want := range map[int]int{1: 10, 2: 1, 3: 0} {
		records, err := LoadSiteSecurityVerifications(context.Background(), DB, siteID)
		if err != nil || len(records) != want {
			t.Fatalf("reopened site=%d got=%d want=%d err=%v", siteID, len(records), want, err)
		}
		if siteID == 1 {
			for _, record := range records {
				if record.State != "configured" || record.ReasonCode != "core_runtime_unavailable" {
					t.Fatalf("failed recheck retained stale success: %+v", record)
				}
			}
		}
	}
	if err := SaveSiteSecurityVerification(context.Background(), DB, securityVerificationRecord(99, "debug_display")); err == nil {
		t.Fatal("missing website accepted")
	}
}

func TestSiteSecurityVerificationStoreRejectsUnavailableInvalidAndCancelledOperations(t *testing.T) {
	if err := SaveSiteSecurityVerification(context.Background(), nil, securityVerificationRecord(1, "https")); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := LoadSiteSecurityVerifications(context.Background(), nil, 1); err == nil {
		t.Fatal("missing database read accepted")
	}
	for _, mutate := range []func(*SiteSecurityVerificationRecord){
		func(r *SiteSecurityVerificationRecord) { r.Key = "custom_unbounded_key" },
		func(r *SiteSecurityVerificationRecord) { r.Fingerprint = "invalid" },
		func(r *SiteSecurityVerificationRecord) { r.Source = "raw config\nsecret" },
		func(r *SiteSecurityVerificationRecord) { r.CheckedAt = "not a date" },
	} {
		r := securityVerificationRecord(1, "https")
		mutate(&r)
		if validSiteSecurityVerificationRecord(r) {
			t.Fatalf("unsafe record accepted: %+v", r)
		}
	}
	previous := DB
	if err := Open(filepath.Join(t.TempDir(), "cancelled.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DB.Close(); DB = previous })
	if _, err := DB.Exec(`CREATE TABLE websites(id INTEGER PRIMARY KEY); INSERT INTO websites VALUES(1)`); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSiteSecurityVerificationSchema(DB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := SaveSiteSecurityVerification(ctx, DB, securityVerificationRecord(1, "https")); err == nil {
		t.Fatal("cancelled write accepted")
	}
	if _, err := LoadSiteSecurityVerifications(ctx, DB, 1); err == nil {
		t.Fatal("cancelled read accepted")
	}
}
