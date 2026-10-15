package database

import (
	"database/sql"
	"fmt"
)

// EnsureBackupScheduleSchema records the beginning of the current enabled
// period independently of successful backup rows. Triggers cover every writer
// of backup_settings, including single-site settings and bulk compensation.
func EnsureBackupScheduleSchema(db *sql.DB) error {
	// Some old-schema upgrade callers create the canonical base tables later.
	// Defer until all dependencies exist; malformed existing columns still fail
	// below instead of silently marking a broken tracking schema as complete.
	var bases int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('websites','backup_settings','db_backups')`).Scan(&bases); err != nil {
		return err
	}
	if bases != 3 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS backup_schedule_state (
		 site_id INTEGER PRIMARY KEY REFERENCES websites(id) ON DELETE CASCADE,
		 enabled_at TEXT NOT NULL CHECK(datetime(enabled_at) IS NOT NULL))`,
		`CREATE TRIGGER IF NOT EXISTS backup_schedule_enabled_insert AFTER INSERT ON backup_settings
		 WHEN NEW.enabled=1 BEGIN
		 INSERT INTO backup_schedule_state(site_id,enabled_at) VALUES(NEW.site_id,CURRENT_TIMESTAMP)
		 ON CONFLICT(site_id) DO UPDATE SET enabled_at=excluded.enabled_at; END`,
		`CREATE TRIGGER IF NOT EXISTS backup_schedule_enabled_update AFTER UPDATE OF enabled ON backup_settings
		 WHEN OLD.enabled!=1 AND NEW.enabled=1 BEGIN
		 INSERT INTO backup_schedule_state(site_id,enabled_at) VALUES(NEW.site_id,CURRENT_TIMESTAMP)
		 ON CONFLICT(site_id) DO UPDATE SET enabled_at=excluded.enabled_at; END`,
		`CREATE TRIGGER IF NOT EXISTS backup_schedule_disabled AFTER UPDATE OF enabled ON backup_settings
		 WHEN NEW.enabled!=1 BEGIN DELETE FROM backup_schedule_state WHERE site_id=NEW.site_id; END`,
		`CREATE TRIGGER IF NOT EXISTS backup_schedule_deleted AFTER DELETE ON backup_settings
		 BEGIN DELETE FROM backup_schedule_state WHERE site_id=OLD.site_id; END`,
		// A legacy successful backup is evidence that protection already began;
		// retain its existing stale alert. Never-successful legacy settings get
		// a fresh grace period instead of an invented historical enable date.
		`INSERT OR IGNORE INTO backup_schedule_state(site_id,enabled_at)
		 SELECT bs.site_id,COALESCE((SELECT MIN(b.created_at) FROM db_backups b
		 WHERE b.site_id=bs.site_id AND b.auto=1),CURRENT_TIMESTAMP)
		 FROM backup_settings bs WHERE bs.enabled=1`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("backup schedule schema: %w", err)
		}
	}
	return tx.Commit()
}
