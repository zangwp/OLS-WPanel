package accountsecurity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func auditFixture(t *testing.T) (*AuditService, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := InitAuditSchema(db); err != nil {
		t.Fatal(err)
	}
	s := NewAuditService(db)
	t.Cleanup(func() { s.Close(); db.Close() })
	return s, db
}

func waitAuditStatus(t *testing.T, db *sql.DB, id, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var got string
		if err := db.QueryRow(`SELECT notification_status FROM account_security_events WHERE id=?`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got == want {
			return
		}
		time.Sleep(time.Millisecond * 5)
	}
	t.Fatalf("event did not reach %s", want)
}

func TestAuditEnvironmentDetectionAndFailureVisibility(t *testing.T) {
	s, _ := auditFixture(t)
	ctx := context.Background()
	first, err := s.Record(ctx, Event{Username: "admin", Event: "login_success", IP: "192.0.2.1", UserAgent: "A"})
	if err != nil || !first.Anomaly {
		t.Fatalf("first environment should notify: %+v %v", first, err)
	}
	second, err := s.Record(ctx, Event{Username: "admin", Event: "login_success", IP: "192.0.2.1", UserAgent: "A"})
	if err != nil || second.Anomaly {
		t.Fatal("known environment was classified as new")
	}
	changed, err := s.Record(ctx, Event{Username: "admin", Event: "login_success", IP: "192.0.2.1", UserAgent: "B"})
	if err != nil || !changed.Anomaly {
		t.Fatal("changed user agent was missed")
	}
	for _, e := range []Event{{Username: "wrong-name", Event: "login_failure"}, {Event: "login_blocked"}, {Username: "another-admin", Event: "logout"}} {
		if _, err := s.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.List(ctx, "admin", 1, 500)
	if err != nil || page.Total != 5 || page.PageSize != 100 {
		t.Fatalf("unexpected scoped audit %+v %v", page, err)
	}
	for _, e := range page.Events {
		if e.Username == "another-admin" {
			t.Fatal("other successful account activity leaked")
		}
	}
}

func TestAuditTransactionRollbackAndNotificationDedup(t *testing.T) {
	s, db := auditFixture(t)
	var sent atomic.Int32
	s.SetNotifier(func(context.Context, Event) error { sent.Add(1); return nil })
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	rolled, err := s.RecordTx(ctx, tx, Event{Username: "admin", Event: "recovery_used", IP: "192.0.2.2", UserAgent: "Browser"})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := s.DispatchPending(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_security_events WHERE id=?`, rolled.ID).Scan(&count); err != nil || count != 0 || sent.Load() != 0 {
		t.Fatal("rolled-back event escaped")
	}
	event, err := s.Record(ctx, Event{Username: "admin", Event: "recovery_used", IP: "192.0.2.2", UserAgent: "Browser"})
	if err != nil {
		t.Fatal(err)
	}
	waitAuditStatus(t, db, event.ID, "sent")
	duplicate, err := s.Record(ctx, Event{Username: "admin", Event: "recovery_used", IP: "192.0.2.2", UserAgent: "Browser"})
	if err != nil || duplicate.NotificationStatus != "suppressed" || sent.Load() != 1 {
		t.Fatalf("not deduplicated %+v %v", duplicate, err)
	}
}

func TestAuditNotificationDisableFailureAndAccountRateLimit(t *testing.T) {
	s, db := auditFixture(t)
	ctx := context.Background()
	s.SetNotifier(func(context.Context, Event) error { return errors.New("simulated transport error") })
	for i := 0; i < 6; i++ {
		event, err := s.Record(ctx, Event{Username: "admin", Event: "login_success", IP: fmt.Sprintf("192.0.2.%d", i+1), UserAgent: "Browser"})
		if err != nil {
			t.Fatal(err)
		}
		if i < 5 {
			waitAuditStatus(t, db, event.ID, "failed")
		} else if event.NotificationStatus != "suppressed" {
			t.Fatal("account hourly limit bypassed")
		}
	}
	if err := s.SetNotificationsEnabled(ctx, "admin", false, Event{}); err != nil {
		t.Fatal(err)
	}
	event, err := s.Record(ctx, Event{Username: "admin", Event: "mfa_disabled"})
	if err != nil || event.NotificationStatus != "disabled" {
		t.Fatal("disabled notification enqueued")
	}
}

func TestAuditRetentionCapAndFailClosed(t *testing.T) {
	s, db := auditFixture(t)
	ctx := context.Background()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO account_security_events(id,username,event,ip,user_agent,created_at) VALUES(?,'admin','login_failure','','',?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < AuditMaxEvents+3; i++ {
		if _, err := stmt.Exec(fmt.Sprintf("fixture-%d", i), time.Now().UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	stmt.Close()
	if _, err := tx.Exec(`INSERT INTO account_security_events(id,username,event,ip,user_agent,created_at) VALUES('expired','admin','login_failure','','',?)`, time.Now().Add(-AuditRetention-time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Record(ctx, Event{Username: "admin", Event: "logout"}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_security_events`).Scan(&count); err != nil || count != AuditMaxEvents {
		t.Fatalf("storage cap %d %v", count, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM account_security_events WHERE id='expired'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired audit retained")
	}
	if _, err := db.Exec(`DROP TABLE account_security_preferences`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Record(ctx, Event{Username: "admin", Event: "login_success", IP: "192.0.2.9"}); err == nil {
		t.Fatal("failed preference lookup became successful safe login")
	}
	if _, err := db.Exec(`DROP TABLE account_security_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(ctx, "admin", 1, 20); err == nil {
		t.Fatal("audit read failure became empty history")
	}
}

func TestAuditRenameKeepsHistoryAndPreferencesTransactional(t *testing.T) {
	s, db := auditFixture(t)
	ctx := context.Background()
	if err := s.SetNotificationsEnabled(ctx, "before", false, Event{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Record(ctx, Event{Username: "before", Event: "mfa_enabled"}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RenameUserTx(ctx, tx, "before", "after"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	page, err := s.List(ctx, "after", 1, 20)
	if err != nil || page.Total != 2 {
		t.Fatalf("lost history %+v %v", page, err)
	}
	enabled, err := s.NotificationsEnabled(ctx, "after")
	if err != nil || enabled {
		t.Fatal("notification preference reset on rename")
	}
}

func TestAuditWorkerCancelsAndQueueIsBounded(t *testing.T) {
	s, db := auditFixture(t)
	started := make(chan struct{}, 1)
	s.SetNotifier(func(ctx context.Context, _ Event) error { started <- struct{}{}; <-ctx.Done(); return ctx.Err() })
	if _, err := s.Record(context.Background(), Event{Username: "admin", Event: "recovery_used"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if cap(s.queue) != 32 {
		t.Fatal("notification queue is unbounded")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("worker ignored shutdown cancellation")
	}
	var status string
	if err := db.QueryRow(`SELECT notification_status FROM account_security_events WHERE event='recovery_used'`).Scan(&status); err != nil || status != "pending" {
		t.Fatal("shutdown must preserve unsent notification")
	}
}

func TestAuditQueuedNotificationFollowsRenamedAccountPreference(t *testing.T) {
	s, db := auditFixture(t)
	ctx := context.Background()
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	s.SetNotifier(func(ctx context.Context, event Event) error {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	if _, err := s.Record(ctx, Event{Username: "queue-blocker", Event: "credentials_changed"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker not started")
	}
	event, err := s.Record(ctx, Event{Username: "before", Event: "recovery_used"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetNotificationsEnabled(ctx, "before", false, Event{}); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RenameUserTx(ctx, tx, "before", "after"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	close(release)
	waitAuditStatus(t, db, event.ID, "disabled")
	if calls.Load() != 1 {
		t.Fatal("queued notification ignored renamed account preference")
	}
}
