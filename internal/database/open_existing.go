package database

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
)

// OpenExisting is for short terminal tasks that must never create an empty
// database. It preserves the existing journal mode and schema; readOnly also
// prevents accidental writes by the caller.
func OpenExisting(dbPath string, readOnly bool) error {
	if DB != nil {
		return errors.New("database is already open")
	}
	if !filepath.IsAbs(dbPath) {
		return errors.New("existing database path must be absolute")
	}
	info, err := os.Lstat(dbPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("existing database is missing or is not a regular file")
	}
	mode := "rw"
	if readOnly {
		mode = "ro"
	}
	parameters := url.Values{
		"mode": {mode}, "_pragma": {"busy_timeout(5000)", "foreign_keys(1)"},
	}
	if readOnly {
		parameters.Add("_pragma", "query_only(1)")
	}
	uriPath := filepath.ToSlash(dbPath)
	if filepath.VolumeName(dbPath) != "" {
		uriPath = "/" + uriPath
	}
	dsn := (&url.URL{Scheme: "file", Path: uriPath, RawQuery: parameters.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open existing sqlite: %w", err)
	}
	initialized := false
	defer func() {
		if !initialized {
			_ = db.Close()
		}
	}()
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return fmt.Errorf("read existing sqlite: %w", err)
	}
	var foreignKeys int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		return errors.New("existing sqlite foreign keys are not enabled")
	}
	DB = db
	initialized = true
	return nil
}
