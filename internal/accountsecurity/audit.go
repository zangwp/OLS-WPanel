package accountsecurity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const AuditRetention = 90 * 24 * time.Hour
const AuditMaxEvents = 10000

var ErrNotificationsUnconfigured = errors.New("account security notifications are not configured")

// Event deliberately has no arbitrary payload: credentials, codes and bearer
// tokens must never enter the audit trail or its notification transport.
type Event struct {
	ID                 string    `json:"id"`
	Username           string    `json:"username"`
	Event              string    `json:"event"`
	IP                 string    `json:"ip"`
	UserAgent          string    `json:"user_agent"`
	CreatedAt          time.Time `json:"created_at"`
	Anomaly            bool      `json:"anomaly"`
	NotificationStatus string    `json:"notification_status"`
	TargetID           string    `json:"target_id,omitempty"`
}

type AuditPage struct {
	Events   []Event `json:"events"`
	Total    int     `json:"total"`
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
}

type AuditService struct {
	db       *sql.DB
	mu       sync.Mutex
	notifyMu sync.Mutex
	notifier func(context.Context, Event) error
	inFlight map[string]bool
	queue    chan Event
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	now      func() time.Time
}

func InitAuditSchema(db *sql.DB) error {
	if db == nil {
		return errors.New("audit database unavailable")
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS account_security_events (
		 id TEXT PRIMARY KEY, username TEXT NOT NULL, event TEXT NOT NULL,
		 ip TEXT NOT NULL, user_agent TEXT NOT NULL, created_at INTEGER NOT NULL,
		 anomaly INTEGER NOT NULL DEFAULT 0, notification_status TEXT NOT NULL DEFAULT 'none',
		 target_id TEXT NOT NULL DEFAULT '')`,
		`CREATE INDEX IF NOT EXISTS idx_account_security_events_user_time ON account_security_events(username,created_at DESC,id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_account_security_events_time ON account_security_events(created_at DESC,id DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_account_security_events_pending ON account_security_events(notification_status,created_at)`,
		`CREATE TABLE IF NOT EXISTS account_security_preferences (username TEXT PRIMARY KEY, notifications_enabled INTEGER NOT NULL DEFAULT 1 CHECK(notifications_enabled IN (0,1)))`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("initialize account audit: %w", err)
		}
	}
	return nil
}

// One worker and a fixed queue bound memory and concurrent outbound sends.
// Call Close before closing the database during graceful shutdown.
func NewAuditService(db *sql.DB) *AuditService {
	ctx, cancel := context.WithCancel(context.Background())
	s := &AuditService{db: db, queue: make(chan Event, 32), inFlight: make(map[string]bool), ctx: ctx, cancel: cancel, done: make(chan struct{}), now: time.Now}
	go s.worker()
	return s
}

func (s *AuditService) SetNotifier(fn func(context.Context, Event) error) {
	s.notifyMu.Lock()
	s.notifier = fn
	s.notifyMu.Unlock()
}

func (s *AuditService) Close() { s.cancel(); <-s.done }

func auditText(value string, maxRunes int) string {
	runes := []rune(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, value))
	return string(runes[:min(len(runes), maxRunes)])
}

func validAuditEvent(event string) bool {
	switch event {
	case "login_success", "login_failure", "login_blocked", "credentials_changed", "mfa_enabled", "mfa_disabled", "recovery_used", "recovery_regenerated", "session_revoked", "sessions_revoked", "logout", "notifications_changed":
		return true
	}
	return false
}

func (s *AuditService) Record(ctx context.Context, event Event) (Event, error) {
	if s == nil || s.db == nil {
		return Event{}, errors.New("audit database unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Event{}, err
	}
	defer tx.Rollback()
	event, err = s.RecordTx(ctx, tx, event)
	if err != nil {
		return Event{}, err
	}
	if err = tx.Commit(); err != nil {
		return Event{}, err
	}
	// Persistence is authoritative. Transport errors are recorded on the event,
	// never converted into a misleading rollback of an already committed action.
	if err := s.DispatchPending(ctx); err != nil {
		log.Printf("account security notification dispatch unavailable")
	}
	return event, nil
}

// RecordTx lets credential/MFA changes and their audit record commit together.
// The caller must call DispatchPending only after a successful commit.
func (s *AuditService) RecordTx(ctx context.Context, tx *sql.Tx, event Event) (Event, error) {
	if s == nil || tx == nil {
		return Event{}, errors.New("audit transaction unavailable")
	}
	if !validAuditEvent(event.Event) {
		return Event{}, errors.New("invalid audit event")
	}
	event.ID = uuid.NewString()
	event.Username = auditText(event.Username, 256)
	event.UserAgent = auditText(event.UserAgent, 512)
	if ip := net.ParseIP(event.IP); ip != nil {
		event.IP = ip.String()
	} else {
		event.IP = "unknown"
	}
	if event.TargetID != "" {
		if _, err := uuid.Parse(event.TargetID); err != nil {
			return Event{}, errors.New("invalid audit target")
		}
	}
	event.CreatedAt = s.now().UTC()
	event.Anomaly = false
	event.NotificationStatus = "none"
	cutoff := event.CreatedAt.Add(-AuditRetention).UnixMilli()
	if _, err := tx.ExecContext(ctx, `DELETE FROM account_security_events WHERE created_at < ?`, cutoff); err != nil {
		return Event{}, err
	}
	if event.Event == "login_success" {
		var known bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM account_security_events WHERE username=? AND event='login_success' AND ip=? AND user_agent=?)`, event.Username, event.IP, event.UserAgent).Scan(&known); err != nil {
			return Event{}, err
		}
		// An IP/UA pair is an environment hint, not proof of device identity.
		event.Anomaly = !known
	}
	notify := event.Anomaly || event.Event == "recovery_used" || event.Event == "mfa_disabled" || event.Event == "credentials_changed"
	if notify {
		enabled, err := notificationsEnabled(ctx, tx, event.Username)
		if err != nil {
			return Event{}, err
		}
		event.NotificationStatus = "disabled"
		if enabled {
			var duplicates, recent int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_security_events WHERE username=? AND event=? AND ip=? AND user_agent=? AND created_at>=? AND notification_status IN ('pending','sent','failed')`, event.Username, event.Event, event.IP, event.UserAgent, event.CreatedAt.Add(-15*time.Minute).UnixMilli()).Scan(&duplicates); err != nil {
				return Event{}, err
			}
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_security_events WHERE username=? AND created_at>=? AND notification_status IN ('pending','sent','failed')`, event.Username, event.CreatedAt.Add(-time.Hour).UnixMilli()).Scan(&recent); err != nil {
				return Event{}, err
			}
			event.NotificationStatus = "pending"
			if duplicates > 0 || recent >= 5 {
				event.NotificationStatus = "suppressed"
			}
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO account_security_events (id,username,event,ip,user_agent,created_at,anomaly,notification_status,target_id) VALUES (?,?,?,?,?,?,?,?,?)`, event.ID, event.Username, event.Event, event.IP, event.UserAgent, event.CreatedAt.UnixMilli(), event.Anomaly, event.NotificationStatus, event.TargetID)
	if err != nil {
		return Event{}, err
	}
	// Bound storage even under a login-failure flood. The cap is global.
	if _, err = tx.ExecContext(ctx, `DELETE FROM account_security_events WHERE id IN (SELECT id FROM account_security_events ORDER BY created_at DESC,id DESC LIMIT -1 OFFSET ?)`, AuditMaxEvents); err != nil {
		return Event{}, err
	}
	return event, nil
}

type auditQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func notificationsEnabled(ctx context.Context, db auditQuerier, username string) (bool, error) {
	var enabled bool
	err := db.QueryRowContext(ctx, `SELECT notifications_enabled FROM account_security_preferences WHERE username=?`, username).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	return enabled, err
}

func (s *AuditService) NotificationsEnabled(ctx context.Context, username string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("audit database unavailable")
	}
	return notificationsEnabled(ctx, s.db, username)
}

func (s *AuditService) SetNotificationsEnabled(ctx context.Context, username string, enabled bool, event Event) error {
	if s == nil || s.db == nil {
		return errors.New("audit database unavailable")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO account_security_preferences(username,notifications_enabled) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET notifications_enabled=excluded.notifications_enabled`, username, enabled); err != nil {
		return err
	}
	event.Username = username
	event.Event = "notifications_changed"
	if _, err = s.RecordTx(ctx, tx, event); err != nil {
		return err
	}
	return tx.Commit()
}

// RenameUserTx preserves ownership of history and preferences when the panel's
// administrator is renamed. The username on old events follows the account.
func (s *AuditService) RenameUserTx(ctx context.Context, tx *sql.Tx, oldUsername, newUsername string) error {
	if tx == nil {
		return errors.New("audit transaction unavailable")
	}
	if oldUsername == newUsername {
		return nil
	}
	enabled, err := notificationsEnabled(ctx, tx, oldUsername)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO account_security_preferences(username,notifications_enabled) VALUES(?,?) ON CONFLICT(username) DO UPDATE SET notifications_enabled=excluded.notifications_enabled`, newUsername, enabled); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM account_security_preferences WHERE username=?`, oldUsername); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE account_security_events SET username=? WHERE username=?`, newUsername, oldUsername)
	return err
}

const auditColumns = `id,username,event,ip,user_agent,created_at,anomaly,notification_status,target_id`

func scanAudit(rows interface{ Scan(...any) error }) (Event, error) {
	var event Event
	var timestamp int64
	err := rows.Scan(&event.ID, &event.Username, &event.Event, &event.IP, &event.UserAgent, &timestamp, &event.Anomaly, &event.NotificationStatus, &event.TargetID)
	event.CreatedAt = time.UnixMilli(timestamp).UTC()
	return event, err
}

func (s *AuditService) List(ctx context.Context, username string, page, pageSize int) (AuditPage, error) {
	if s == nil || s.db == nil {
		return AuditPage{}, errors.New("audit database unavailable")
	}
	page = max(1, min(page, 10000))
	if pageSize <= 0 {
		pageSize = 20
	}
	pageSize = min(pageSize, 100)
	result := AuditPage{Events: make([]Event, 0), Page: page, PageSize: pageSize}
	cutoff := s.now().Add(-AuditRetention).UnixMilli()
	// This is a single-administrator panel: failed attempts against nonexistent
	// usernames and BasicAuth bans must remain visible to the administrator.
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM account_security_events WHERE (username=? OR event IN ('login_failure','login_blocked')) AND created_at>=?`, username, cutoff).Scan(&result.Total); err != nil {
		return result, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditColumns+` FROM account_security_events WHERE (username=? OR event IN ('login_failure','login_blocked')) AND created_at>=? ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`, username, cutoff, pageSize, (page-1)*pageSize)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		event, err := scanAudit(rows)
		if err != nil {
			return result, err
		}
		result.Events = append(result.Events, event)
	}
	return result, rows.Err()
}

func (s *AuditService) DispatchPending(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("audit database unavailable")
	}
	if s.ctx.Err() != nil {
		return s.ctx.Err()
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+auditColumns+` FROM account_security_events WHERE notification_status='pending' ORDER BY created_at,id LIMIT 32`)
	if err != nil {
		return err
	}
	events := make([]Event, 0, 32)
	for rows.Next() {
		event, err := scanAudit(rows)
		if err != nil {
			rows.Close()
			return err
		}
		events = append(events, event)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	for _, event := range events {
		if s.inFlight[event.ID] {
			continue
		}
		select {
		case s.queue <- event:
			s.inFlight[event.ID] = true
		default:
			return nil
		}
	}
	return nil
}

func (s *AuditService) worker() {
	defer close(s.done)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if s.db != nil {
				if _, err := s.db.ExecContext(s.ctx, `DELETE FROM account_security_events WHERE created_at<?`, s.now().Add(-AuditRetention).UnixMilli()); err != nil && s.ctx.Err() == nil {
					log.Printf("account security audit retention cleanup failed")
				}
			}
			if err := s.DispatchPending(s.ctx); err != nil && s.ctx.Err() == nil {
				log.Printf("account security pending notifications could not be read")
			}
		case event := <-s.queue:
			s.deliver(event)
		}
	}
}

func (s *AuditService) deliver(event Event) {
	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()
	// A rename or retention cleanup may have happened since queueing. Reload
	// the committed event instead of notifying using stale ownership metadata.
	var current Event
	var timestamp int64
	var enabled bool
	// Read ownership and preference in one SQLite snapshot. Two independent
	// queries could straddle RenameUserTx and treat the old name as default-on.
	readErr := s.db.QueryRowContext(ctx, `SELECT `+auditColumns+`,COALESCE((SELECT notifications_enabled FROM account_security_preferences p WHERE p.username=account_security_events.username),1) FROM account_security_events WHERE id=? AND notification_status='pending'`, event.ID).Scan(&current.ID, &current.Username, &current.Event, &current.IP, &current.UserAgent, &timestamp, &current.Anomaly, &current.NotificationStatus, &current.TargetID, &enabled)
	current.CreatedAt = time.UnixMilli(timestamp).UTC()
	if errors.Is(readErr, sql.ErrNoRows) {
		s.notifyMu.Lock()
		delete(s.inFlight, event.ID)
		s.notifyMu.Unlock()
		return
	}
	if readErr == nil {
		event = current
	}
	status := "unconfigured"
	if readErr != nil {
		status = "failed"
	} else if !enabled {
		status = "disabled"
	} else {
		s.notifyMu.Lock()
		notifier := s.notifier
		s.notifyMu.Unlock()
		if notifier != nil {
			err := notifier(ctx, event)
			switch {
			case err == nil:
				status = "sent"
			case errors.Is(err, ErrNotificationsUnconfigured):
				status = "unconfigured"
			default:
				status = "failed"
			}
		}
	}
	if s.ctx.Err() != nil {
		return
	} // Leave pending for the next process after shutdown.
	statusCtx, statusCancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer statusCancel()
	if _, updateErr := s.db.ExecContext(statusCtx, `UPDATE account_security_events SET notification_status=? WHERE id=? AND notification_status='pending'`, status, event.ID); updateErr != nil {
		log.Printf("account security notification delivery status could not be saved")
	}
	if status == "failed" {
		log.Printf("account security notification failed (event %s)", event.ID)
	}
	s.notifyMu.Lock()
	delete(s.inFlight, event.ID)
	s.notifyMu.Unlock()
}
