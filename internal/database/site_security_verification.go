package database

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"
)

const siteSecurityVerificationSchema = `CREATE TABLE IF NOT EXISTS site_security_verifications (
	site_id INTEGER NOT NULL,
	check_key TEXT NOT NULL CHECK (check_key IN ('https','login_protection','sql_injection','sensitive_files','uploads_php','xmlrpc','application_passwords','file_editing','debug_display','wp_updates')),
	state TEXT NOT NULL CHECK (state IN ('effective','runtime_verified','ready','configured','disabled','unsupported','error','unknown')),
	checked_at TEXT NOT NULL CHECK (length(checked_at) BETWEEN 20 AND 35),
	reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 100),
	source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 64),
	fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
	valid_until TEXT NOT NULL DEFAULT '' CHECK (length(valid_until) <= 35),
	PRIMARY KEY (site_id, check_key),
	FOREIGN KEY (site_id) REFERENCES websites(id) ON DELETE CASCADE
) WITHOUT ROWID`

// Each site has at most ten records. No request, configuration or credential
// content is stored; the fingerprint is only a SHA-256 configuration digest.
type SiteSecurityVerificationRecord struct {
	SiteID                                                             int
	Key, State, CheckedAt, ReasonCode, Source, Fingerprint, ValidUntil string
}

var siteSecurityVerificationToken = regexp.MustCompile(`^[a-z][a-z0-9_]{0,99}$`)

func EnsureSiteSecurityVerificationSchema(db *sql.DB) error {
	if db == nil {
		return errors.New("security verification database unavailable")
	}
	_, err := db.Exec(siteSecurityVerificationSchema)
	return err
}

func validSiteSecurityVerificationRecord(record SiteSecurityVerificationRecord) bool {
	if record.SiteID <= 0 || len(record.Fingerprint) != 64 || !siteSecurityVerificationToken.MatchString(record.ReasonCode) || len(record.Source) > 64 || !siteSecurityVerificationToken.MatchString(record.Source) {
		return false
	}
	for _, char := range record.Fingerprint {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	switch record.Key {
	case "https", "login_protection", "sql_injection", "sensitive_files", "uploads_php", "xmlrpc", "application_passwords", "file_editing", "debug_display", "wp_updates":
	default:
		return false
	}
	switch record.State {
	case "effective", "runtime_verified", "ready", "configured", "disabled", "unsupported", "error", "unknown":
	default:
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, record.CheckedAt); err != nil {
		return false
	}
	if record.ValidUntil != "" {
		if _, err := time.Parse(time.RFC3339Nano, record.ValidUntil); err != nil {
			return false
		}
	}
	return true
}

func SaveSiteSecurityVerification(ctx context.Context, db *sql.DB, record SiteSecurityVerificationRecord) error {
	if db == nil {
		return errors.New("security verification database unavailable")
	}
	if !validSiteSecurityVerificationRecord(record) {
		return errors.New("invalid security verification record")
	}
	_, err := db.ExecContext(ctx, `INSERT INTO site_security_verifications
		(site_id,check_key,state,checked_at,reason_code,source,fingerprint,valid_until) VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(site_id,check_key) DO UPDATE SET state=excluded.state,checked_at=excluded.checked_at,
		reason_code=excluded.reason_code,source=excluded.source,fingerprint=excluded.fingerprint,valid_until=excluded.valid_until`,
		record.SiteID, record.Key, record.State, record.CheckedAt, record.ReasonCode, record.Source, record.Fingerprint, record.ValidUntil)
	return err
}

func LoadSiteSecurityVerifications(ctx context.Context, db *sql.DB, siteID int) (map[string]SiteSecurityVerificationRecord, error) {
	if db == nil || siteID <= 0 {
		return nil, errors.New("security verification database unavailable")
	}
	rows, err := db.QueryContext(ctx, `SELECT check_key,state,checked_at,reason_code,source,fingerprint,valid_until
		FROM site_security_verifications WHERE site_id=? LIMIT 11`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make(map[string]SiteSecurityVerificationRecord)
	for rows.Next() {
		record := SiteSecurityVerificationRecord{SiteID: siteID}
		if err := rows.Scan(&record.Key, &record.State, &record.CheckedAt, &record.ReasonCode, &record.Source, &record.Fingerprint, &record.ValidUntil); err != nil {
			return nil, err
		}
		if !validSiteSecurityVerificationRecord(record) || len(records) >= 10 {
			return nil, errors.New("invalid security verification records")
		}
		records[record.Key] = record
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return records, nil
}
