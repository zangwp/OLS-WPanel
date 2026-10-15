package database

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func TestBackupScheduleTrackingPreservesLegacyAndReenableGrace(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "backup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`PRAGMA foreign_keys=ON;
	 CREATE TABLE websites(id INTEGER PRIMARY KEY);
	 CREATE TABLE backup_settings(site_id INTEGER PRIMARY KEY,enabled INTEGER,keep_count INTEGER);
	 CREATE TABLE db_backups(site_id INTEGER,auto INTEGER,created_at TEXT);
	 INSERT INTO websites VALUES(1),(2);
	 INSERT INTO backup_settings VALUES(1,1,7),(2,1,7);
	 INSERT INTO db_backups VALUES(1,1,'2020-01-01 04:00:00');`)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureBackupScheduleSchema(db); err != nil {
		t.Fatal(err)
	}
	read := func(id int) string {
		t.Helper()
		var value string
		if err := db.QueryRow(`SELECT enabled_at FROM backup_schedule_state WHERE site_id=?`, id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if got := read(1); got != "2020-01-01 04:00:00" {
		t.Fatal("legacy successful backup lost its stale boundary", got)
	}
	first := read(2)
	if first == "" || first == read(1) {
		t.Fatal("never-successful legacy site did not receive grace")
	}
	if _, err := db.Exec(`UPDATE backup_schedule_state SET enabled_at='2021-02-03 04:05:06' WHERE site_id=2`); err != nil {
		t.Fatal(err)
	}
	if err := EnsureBackupScheduleSchema(db); err != nil {
		t.Fatal(err)
	}
	if got := read(2); got != "2021-02-03 04:05:06" {
		t.Fatal("startup reset the grace anchor", got)
	}
	if _, err := db.Exec(`UPDATE backup_settings SET keep_count=12,enabled=1 WHERE site_id=2`); err != nil {
		t.Fatal(err)
	}
	if got := read(2); got != "2021-02-03 04:05:06" {
		t.Fatal("retention-only edit reset the grace anchor", got)
	}
	if _, err := db.Exec(`UPDATE backup_settings SET enabled=0 WHERE site_id=2`); err != nil {
		t.Fatal(err)
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM backup_schedule_state WHERE site_id=2`).Scan(&count)
	if count != 0 {
		t.Fatal("disabled schedule retained an enabled period")
	}
	if _, err := db.Exec(`UPDATE backup_settings SET enabled=1 WHERE site_id=2`); err != nil {
		t.Fatal(err)
	}
	if got := read(2); got == "2021-02-03 04:05:06" {
		t.Fatal("reenabling reused an expired grace period")
	}
	if _, err := db.Exec(`DELETE FROM websites WHERE id=2`); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM backup_schedule_state WHERE site_id=2`).Scan(&count)
	if count != 0 {
		t.Fatal("website deletion orphaned schedule tracking")
	}
}
