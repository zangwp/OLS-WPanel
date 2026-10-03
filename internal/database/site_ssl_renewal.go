package database

const siteSSLRenewalSchema = `CREATE TABLE IF NOT EXISTS site_ssl_renewal (
 site_id INTEGER PRIMARY KEY REFERENCES websites(id) ON DELETE CASCADE,
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 last_attempt TEXT NOT NULL DEFAULT '',
 last_status TEXT NOT NULL DEFAULT ''
)`

// Absent preferences preserve automatic renewal on existing installations.
func SiteSSLRenewalEnabled(siteID int) (bool, error) {
	var enabled bool
	err := DB.QueryRow(`SELECT COALESCE((SELECT enabled FROM site_ssl_renewal WHERE site_id=?),1)`, siteID).Scan(&enabled)
	return enabled, err
}

func RecordSiteSSLRenewal(siteID int, status string) error {
	_, err := DB.Exec(`INSERT INTO site_ssl_renewal(site_id,last_attempt,last_status) VALUES(?,strftime('%Y-%m-%dT%H:%M:%SZ','now'),?) ON CONFLICT(site_id) DO UPDATE SET last_attempt=excluded.last_attempt,last_status=excluded.last_status`, siteID, status)
	return err
}
