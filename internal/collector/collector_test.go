package collector

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/housekeeping"

	_ "modernc.org/sqlite"
)

func TestMonitoringRetentionKeepsBoundaryAndRetriesAfterDatabaseFailure(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	previous := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = previous; db.Close() })
	start := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	var retention housekeeping.Cleanup
	// The first attempt fails because the table is not ready. The next ordinary
	// collection tick must retry instead of postponing retention for an hour.
	cleanupDue(&retention, start)
	if _, err := db.Exec(`CREATE TABLE monitoring_metrics (id INTEGER PRIMARY KEY, recorded_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	retry := start.Add(time.Minute)
	cutoff := retry.Add(-15 * 24 * time.Hour)
	for id, recorded := range []time.Time{cutoff.Add(-time.Second), cutoff, retry} {
		if _, err := db.Exec(`INSERT INTO monitoring_metrics VALUES (?, ?)`, id, recorded.Format("2006-01-02 15:04:05")); err != nil {
			t.Fatal(err)
		}
	}
	cleanupDue(&retention, retry)
	assertMetricCount(t, db, 0, 0)
	assertMetricCount(t, db, 1, 1)
	assertMetricCount(t, db, 2, 1)
	cleanupDue(&retention, retry.Add(59*time.Minute))
	assertMetricCount(t, db, 1, 1)
	cleanupDue(&retention, retry.Add(time.Hour))
	assertMetricCount(t, db, 1, 0)
	assertMetricCount(t, db, 2, 1)
}

func assertMetricCount(t *testing.T, db *sql.DB, id, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_metrics WHERE id=?`, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("metric %d count = %d, want %d", id, got, want)
	}
}
