package database

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestCloudflareCoverageSchemaMigrates177PreservingCredentialsAndOwnership(t *testing.T) {
	previousDB := DB
	if err := Open(filepath.Join(t.TempDir(), "legacy-cloudflare.db")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { DB.Close(); DB = previousDB })
	// This is the actual previous 1.0.77 shape, deliberately created before
	// RunMigrations so fresh CREATE TABLE defaults cannot hide an upgrade bug.
	const legacySchema = `CREATE TABLE website_cloudflare_security (
 site_id INTEGER PRIMARY KEY, hostname TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 0, account_id TEXT NOT NULL DEFAULT '',
 zone_id TEXT NOT NULL DEFAULT '', token_ciphertext TEXT NOT NULL DEFAULT '',
 rule_ref TEXT NOT NULL, ruleset_id TEXT NOT NULL DEFAULT '',
 rule_id TEXT NOT NULL DEFAULT '', applied_hash TEXT NOT NULL DEFAULT '',
 pending_hash TEXT NOT NULL DEFAULT '', sync_status TEXT NOT NULL DEFAULT 'disabled',
 last_error TEXT NOT NULL DEFAULT '', last_sync_at TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`
	if _, err := DB.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`INSERT INTO website_cloudflare_security VALUES(7,'www.example.com',1,'account-before','zone-before','dummy-encrypted-token-before','owned-ref-before','ruleset-before','rule-before','applied-before','pending-before','error','existing retry reason','2026-10-09 12:34:56','2026-10-09 12:35:00')`); err != nil {
		t.Fatal(err)
	}
	const originalColumns = `SELECT site_id,hostname,enabled,account_id,zone_id,token_ciphertext,rule_ref,ruleset_id,rule_id,applied_hash,pending_hash,sync_status,last_error,last_sync_at,updated_at FROM website_cloudflare_security WHERE site_id=7`
	readOriginal := func() []any {
		t.Helper()
		values, dest := make([]any, 15), make([]any, 15)
		for i := range values {
			dest[i] = &values[i]
		}
		if err := DB.QueryRow(originalColumns).Scan(dest...); err != nil {
			t.Fatal(err)
		}
		return values
	}
	before := readOriginal()
	if _, err := DB.Query(`SELECT zone_name,covered_hostnames,coverage_error FROM website_cloudflare_security`); err == nil {
		t.Fatal("legacy fixture unexpectedly contains the new coverage columns")
	}
	var migrate func() error
	for _, upgrade := range upgrades {
		if upgrade.Version == "1.0.78" {
			if migrate != nil || upgrade.Func == nil || reflect.ValueOf(upgrade.Func).Pointer() != reflect.ValueOf(ensureCloudflareSecurityCoverageSchema).Pointer() {
				t.Fatal("1.0.78 must register exactly the production coverage migration")
			}
			migrate = upgrade.Func
		}
	}
	if migrate == nil {
		t.Fatal("coverage migration is missing from the versioned upgrade chain")
	}
	if err := migrate(); err != nil {
		t.Fatal("actual 1.0.78 migration failed:", err)
	}
	for repeat := 0; repeat < 2; repeat++ {
		if err := ensureCloudflareSecurityCoverageSchema(); err != nil {
			t.Fatal("repeated production schema ensure failed:", err)
		}
		if !reflect.DeepEqual(before, readOriginal()) {
			t.Fatal("coverage upgrade changed an existing credential, enabled state, binding, retry or ownership field")
		}
		var zoneName, covered, coverageError string
		if err := DB.QueryRow(`SELECT zone_name,covered_hostnames,coverage_error FROM website_cloudflare_security WHERE site_id=7`).Scan(&zoneName, &covered, &coverageError); err != nil || zoneName != "" || covered != "[]" || coverageError != "" {
			t.Fatal("legacy row did not receive the empty coverage defaults", err)
		}
	}
	// A newly inserted row into the upgraded table must get the same defaults.
	if _, err := DB.Exec(`INSERT INTO website_cloudflare_security(site_id,hostname,rule_ref) VALUES(8,'new.example.com','new-ref')`); err != nil {
		t.Fatal(err)
	}
	var zoneName, covered, coverageError string
	if err := DB.QueryRow(`SELECT zone_name,covered_hostnames,coverage_error FROM website_cloudflare_security WHERE site_id=8`).Scan(&zoneName, &covered, &coverageError); err != nil || zoneName != "" || covered != "[]" || coverageError != "" {
		t.Fatal("upgraded table insertion defaults differ from legacy migration defaults", err)
	}
}
