package database

import "fmt"

// Keep credentials outside security_settings: that table has a generic read API.
// Do not cascade deletion: an orphaned owned remote rule must be cleaned up first.
const cloudflareSecuritySchema = `CREATE TABLE IF NOT EXISTS website_cloudflare_security (
 site_id INTEGER PRIMARY KEY,
 hostname TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 0,
 account_id TEXT NOT NULL DEFAULT '',
 zone_id TEXT NOT NULL DEFAULT '',
 zone_name TEXT NOT NULL DEFAULT '',
 covered_hostnames TEXT NOT NULL DEFAULT '[]',
 coverage_error TEXT NOT NULL DEFAULT '',
 token_ciphertext TEXT NOT NULL DEFAULT '',
 rule_ref TEXT NOT NULL,
 ruleset_id TEXT NOT NULL DEFAULT '',
 rule_id TEXT NOT NULL DEFAULT '',
 applied_hash TEXT NOT NULL DEFAULT '',
 pending_hash TEXT NOT NULL DEFAULT '',
 sync_status TEXT NOT NULL DEFAULT 'disabled',
 last_error TEXT NOT NULL DEFAULT '',
 last_sync_at TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`

func ensureCloudflareSecurityCoverageSchema() error {
	if _, err := DB.Exec(cloudflareSecuritySchema); err != nil {
		return err
	}
	rows, err := DB.Query(`PRAGMA table_info(website_cloudflare_security)`)
	if err != nil {
		return err
	}
	columns := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var def any
		if err = rows.Scan(&cid, &name, &kind, &notnull, &def, &pk); err != nil {
			rows.Close()
			return err
		}
		columns[name] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, col := range []struct{ name, definition string }{{"zone_name", "TEXT NOT NULL DEFAULT ''"}, {"covered_hostnames", "TEXT NOT NULL DEFAULT '[]'"}, {"coverage_error", "TEXT NOT NULL DEFAULT ''"}} {
		if !columns[col.name] {
			if _, err := DB.Exec(fmt.Sprintf("ALTER TABLE website_cloudflare_security ADD COLUMN %s %s", col.name, col.definition)); err != nil {
				return err
			}
		}
	}
	return nil
}
