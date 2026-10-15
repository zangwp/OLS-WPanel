package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/housekeeping"
)

func appendCleanupTestLogin(t *testing.T, dir string, at time.Time) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, wpSecurityLoginLog), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := fmt.Fprintf(f, "203.0.113.10 [%s] OLS_WPANEL_LOGIN_FAILED\n", at.UTC().Format(time.RFC3339))
	closeErr := f.Close()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func countCleanupTestEvents(t *testing.T, ip string) int {
	t.Helper()
	var count int
	if err := database.GetDB().QueryRow(`SELECT COUNT(*) FROM wp_security_events WHERE ip_address = ?`, ip).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestWPSecurityEventCycleKeepsFiveMinuteIngestAndHourlyPrune(t *testing.T) {
	openTestDB(t)
	dir := t.TempDir()
	seedWPSecurityEventSite(t, dir)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-91 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	insertWPSecurityEvent(t, "203.0.113.20", SecurityEventWPLoginFailed, "/old", expired)
	appendCleanupTestLogin(t, dir, now)

	var cleanup housekeeping.Cleanup
	runWPSecurityEventIngestCycle(now, &cleanup)
	if got := countCleanupTestEvents(t, "203.0.113.20"); got != 0 {
		t.Fatalf("startup retained %d expired events", got)
	}
	if got := countCleanupTestEvents(t, "203.0.113.10"); got != 1 {
		t.Fatalf("startup ingested %d events, want 1", got)
	}

	// An expired row arriving after the startup prune remains until the hourly
	// cleanup; new login evidence must still be ingested on every five-minute tick.
	insertWPSecurityEvent(t, "203.0.113.20", SecurityEventWPLoginFailed, "/old", expired)
	for tick := 1; tick <= 12; tick++ {
		at := now.Add(time.Duration(tick) * 5 * time.Minute)
		appendCleanupTestLogin(t, dir, at)
		runWPSecurityEventIngestCycle(at, &cleanup)
		if got := countCleanupTestEvents(t, "203.0.113.10"); got != tick+1 {
			t.Fatalf("tick %d ingested %d events, want %d", tick, got, tick+1)
		}
		wantExpired := 1
		if tick == 12 {
			wantExpired = 0
		}
		if got := countCleanupTestEvents(t, "203.0.113.20"); got != wantExpired {
			t.Fatalf("tick %d retained %d expired events, want %d", tick, got, wantExpired)
		}
	}
}

func TestWPSecurityEventCycleRetriesFailedPruneOnNextIngest(t *testing.T) {
	openTestDB(t)
	dir := t.TempDir()
	seedWPSecurityEventSite(t, dir)
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-91 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	insertWPSecurityEvent(t, "203.0.113.20", SecurityEventWPLoginFailed, "/old", expired)
	if _, err := database.GetDB().Exec(`CREATE TRIGGER reject_wp_prune BEFORE DELETE ON wp_security_events
		BEGIN SELECT RAISE(FAIL, 'cleanup unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	var cleanup housekeeping.Cleanup
	appendCleanupTestLogin(t, dir, now)
	runWPSecurityEventIngestCycle(now, &cleanup)
	if got := countCleanupTestEvents(t, "203.0.113.20"); got != 1 {
		t.Fatalf("failed prune retained %d expired events, want 1", got)
	}
	if got := countCleanupTestEvents(t, "203.0.113.10"); got != 1 {
		t.Fatalf("failed prune interrupted ingest: got %d events, want 1", got)
	}
	if _, err := database.GetDB().Exec(`DROP TRIGGER reject_wp_prune`); err != nil {
		t.Fatal(err)
	}
	appendCleanupTestLogin(t, dir, now.Add(5*time.Minute))
	runWPSecurityEventIngestCycle(now.Add(5*time.Minute), &cleanup)
	if got := countCleanupTestEvents(t, "203.0.113.20"); got != 0 {
		t.Fatalf("next ingest did not retry prune: retained %d expired events", got)
	}
	if got := countCleanupTestEvents(t, "203.0.113.10"); got != 2 {
		t.Fatalf("retry tick ingested %d events, want 2", got)
	}
	insertWPSecurityEvent(t, "203.0.113.20", SecurityEventWPLoginFailed, "/old", expired)
	appendCleanupTestLogin(t, dir, now.Add(10*time.Minute))
	runWPSecurityEventIngestCycle(now.Add(10*time.Minute), &cleanup)
	if got := countCleanupTestEvents(t, "203.0.113.20"); got != 1 {
		t.Fatalf("successful retry did not defer next prune: retained %d events, want 1", got)
	}
	if got := countCleanupTestEvents(t, "203.0.113.10"); got != 3 {
		t.Fatalf("post-retry ingest got %d events, want 3", got)
	}
}

func TestPruneWPSecurityEventsPreservesRetentionBoundary(t *testing.T) {
	for _, retentionDays := range []int{-1, 0, wpSecurityEventRetentionDays} {
		t.Run(fmt.Sprint(retentionDays), func(t *testing.T) {
			openTestDB(t)
			seedWPSecurityEventSite(t, t.TempDir())
			now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
			cutoff := now.UTC().Add(-wpSecurityEventRetentionDays * 24 * time.Hour)
			for i, offset := range []time.Duration{-time.Second, 0, time.Second} {
				insertWPSecurityEvent(t, fmt.Sprintf("203.0.113.%d", i+1), SecurityEventWPLoginFailed, "/boundary",
					cutoff.Add(offset).Format("2006-01-02 15:04:05"))
			}
			if err := pruneWPSecurityEvents(now, retentionDays); err != nil {
				t.Fatal(err)
			}
			for i, want := range []int{0, 1, 1} {
				if got := countCleanupTestEvents(t, fmt.Sprintf("203.0.113.%d", i+1)); got != want {
					t.Fatalf("boundary row %d count = %d, want %d", i, got, want)
				}
			}
		})
	}
}
