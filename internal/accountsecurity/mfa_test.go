package accountsecurity

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base32"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func newMFATestService(t *testing.T) (*MFAService, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "panel.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = db.Close() })
	if err := InitMFASchema(db); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "account-mfa.key")
	s, err := NewMFAService(db, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(1710000000, 0) }
	return s, keyPath
}

func enrollMFA(t *testing.T, s *MFAService, id int64) ([]byte, []string) {
	t.Helper()
	setup, err := s.Setup(context.Background(), id, "test-session", "owner")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := s.Confirm(context.Background(), id, "test-session", totp(secret, s.now().Unix()/30, 6), nil)
	if err != nil {
		t.Fatal(err)
	}
	return secret, codes
}

func TestTOTPRFC6238SHA1Vectors(t *testing.T) {
	// RFC 6238 Appendix B: 20-byte ASCII secret, 30-second step, SHA-1.
	for _, tc := range []struct {
		timestamp int64
		want      string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if got := totp([]byte("12345678901234567890"), tc.timestamp/30, 8); got != tc.want {
			t.Fatalf("time %d: %s want %s", tc.timestamp, got, tc.want)
		}
	}
}

func TestMFAEnrollmentEncryptedAndSessionBound(t *testing.T) {
	s, key := newMFATestService(t)
	ctx := context.Background()
	setup, err := s.Setup(ctx, 1, "owner-session", "owner:中文")
	if err != nil {
		t.Fatal(err)
	}
	if setup.ExpiresAt != s.now().Add(10*time.Minute).Unix() || !strings.HasPrefix(setup.OTPAuthURL, "otpauth://totp/") {
		t.Fatal("invalid setup metadata")
	}
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	var cipher []byte
	var ownerHash string
	if err := s.db.QueryRow(`SELECT pending_secret,pending_session_hash FROM account_mfa WHERE admin_id=1`).Scan(&cipher, &ownerHash); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, secret) || bytes.Contains(cipher, []byte(setup.Secret)) || ownerHash == "owner-session" {
		t.Fatal("secret or bearer session persisted in plaintext")
	}
	status, err := s.Status(ctx, 1)
	if err != nil || status.Enabled {
		t.Fatal("pending setup prematurely enabled MFA")
	}
	if _, err = s.Setup(ctx, 1, "other-session", "owner"); !errors.Is(err, ErrPendingExpired) {
		t.Fatalf("other session replaced pending setup: %v", err)
	}
	code := totp(secret, s.now().Unix()/30, 6)
	if _, err = s.Confirm(ctx, 1, "other-session", code, nil); !errors.Is(err, ErrPendingExpired) {
		t.Fatalf("other session confirmed enrollment: %v", err)
	}
	codes, err := s.Confirm(ctx, 1, "owner-session", code, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("got %d recovery codes", len(codes))
	}
	var hash string
	if err = s.db.QueryRow(`SELECT code_hash FROM account_mfa_recovery LIMIT 1`).Scan(&hash); err != nil {
		t.Fatal(err)
	}
	for _, recovery := range codes {
		if strings.Contains(hash, recovery) || len(strings.ReplaceAll(recovery, "-", "")) != 32 {
			t.Fatal("recovery code persistence/entropy contract")
		}
	}
	status, err = s.Status(ctx, 1)
	if err != nil || !status.Enabled || status.PendingExpiresAt != 0 || status.RecoveryCodesRemaining != 10 {
		t.Fatalf("status: %+v %v", status, err)
	}
	if _, err = s.Setup(ctx, 1, "owner-session", "owner"); !errors.Is(err, ErrMFAEnabled) {
		t.Fatalf("enabled MFA allowed rebind: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(key)
		if info.Mode().Perm() != 0600 {
			t.Fatal("key permissions are not private")
		}
	}
}

func TestMFAPendingExpiryAndFreshSetup(t *testing.T) {
	s, _ := newMFATestService(t)
	ctx := context.Background()
	setup, _ := s.Setup(ctx, 1, "session", "owner")
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	s.now = func() time.Time { return time.Unix(setup.ExpiresAt, 0) }
	if _, err := s.Confirm(ctx, 1, "session", totp(secret, s.now().Unix()/30, 6), nil); !errors.Is(err, ErrPendingExpired) {
		t.Fatalf("expired enrollment accepted: %v", err)
	}
	if _, err := s.Setup(ctx, 1, "replacement-session", "owner"); err != nil {
		t.Fatal(err)
	}
}

func TestMFATOTPReplayAndClockWindowPersistAcrossRestart(t *testing.T) {
	s, key := newMFATestService(t)
	ctx := context.Background()
	secret, _ := enrollMFA(t, s, 1)
	if _, err := s.Verify(ctx, 1, totp(secret, s.now().Unix()/30, 6), nil); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("confirm code replay accepted: %v", err)
	}
	future := s.now().Add(30 * time.Second)
	if _, err := s.Verify(ctx, 1, totp(secret, future.Unix()/30, 6), nil); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewMFAService(s.db, key)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = func() time.Time { return future }
	if _, err = restarted.Verify(ctx, 1, totp(secret, future.Unix()/30, 6), nil); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay across restart: %v", err)
	}
	if _, err = restarted.Verify(ctx, 1, totp(secret, (future.Unix()/30)+2, 6), nil); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("far future accepted: %v", err)
	}
	if _, err = restarted.Verify(ctx, 1, totp(secret, (future.Unix()/30)-2, 6), nil); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("expired code accepted: %v", err)
	}
}

func TestMFARecoveryConcurrentConsumptionExactlyOnce(t *testing.T) {
	s, _ := newMFATestService(t)
	_, codes := enrollMFA(t, s, 1)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recovery, err := s.Verify(context.Background(), 1, codes[0], nil)
			if err == nil && recovery {
				successes.Add(1)
			} else if !errors.Is(err, ErrInvalidCode) && !errors.Is(err, ErrMFARateLimited) {
				t.Errorf("unexpected concurrent verify: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("recovery consumed %d times", successes.Load())
	}
	status, err := s.Status(context.Background(), 1)
	if err != nil || status.RecoveryCodesRemaining != 9 {
		t.Fatalf("remaining %+v %v", status, err)
	}
}

func TestMFARegenerationAndDisableConsumeProof(t *testing.T) {
	s, _ := newMFATestService(t)
	ctx := context.Background()
	_, codes := enrollMFA(t, s, 1)
	replacement, err := s.Regenerate(ctx, 1, codes[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Verify(ctx, 1, codes[1], nil); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("old recovery survived regeneration: %v", err)
	}
	if err = s.Disable(ctx, 1, replacement[0], nil); err != nil {
		t.Fatal(err)
	}
	status, err := s.Status(ctx, 1)
	if err != nil || status.Enabled || status.RecoveryCodesRemaining != 0 {
		t.Fatalf("disable state %+v %v", status, err)
	}
	var secret []byte
	if err = s.db.QueryRow(`SELECT secret FROM account_mfa WHERE admin_id=1`).Scan(&secret); err != nil || len(secret) != 0 {
		t.Fatal("disabled key retained")
	}
}

func TestMFAAuditFailureRollsBackStateAndRecoveryConsumption(t *testing.T) {
	s, _ := newMFATestService(t)
	ctx := context.Background()
	setup, _ := s.Setup(ctx, 1, "session", "owner")
	secret, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(setup.Secret)
	code := totp(secret, s.now().Unix()/30, 6)
	auditErr := errors.New("injected audit write failure")
	fail := func(*sql.Tx, string) error { return auditErr }
	if codes, err := s.Confirm(ctx, 1, "session", code, fail); !errors.Is(err, auditErr) || codes != nil {
		t.Fatalf("failed audit returned codes: %v %v", codes, err)
	}
	status, _ := s.Status(ctx, 1)
	if status.Enabled {
		t.Fatal("enrollment committed without audit")
	}
	codes, err := s.Confirm(ctx, 1, "session", code, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Regenerate(ctx, 1, codes[0], fail); !errors.Is(err, auditErr) {
		t.Fatal(err)
	}
	status, _ = s.Status(ctx, 1)
	if status.RecoveryCodesRemaining != 10 {
		t.Fatal("audit failure consumed recovery code")
	}
	if recovered, err := s.Verify(ctx, 1, codes[0], nil); err != nil || !recovered {
		t.Fatalf("rolled-back recovery no longer usable: %v", err)
	}
}

func TestMFAMissingCorruptAndWrongKeysFailClosed(t *testing.T) {
	s, key := newMFATestService(t)
	_, codes := enrollMFA(t, s, 1)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMFAService(s.db, key); err == nil {
		t.Fatal("missing key recreated for existing enrollment")
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing key unexpectedly regenerated")
	}
	var originalSecret []byte
	if err := s.db.QueryRow(`SELECT secret FROM account_mfa WHERE admin_id=1`).Scan(&originalSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE account_mfa SET secret=NULL WHERE admin_id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMFAService(s.db, key); err == nil {
		t.Fatal("enabled but damaged enrollment allowed key replacement")
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("damaged enrollment caused key regeneration")
	}
	if _, err := s.db.Exec(`UPDATE account_mfa SET secret=? WHERE admin_id=1`, originalSecret); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewMFAService(s.db, key); err == nil {
		t.Fatal("corrupt key accepted")
	}
	if err := os.WriteFile(key, bytes.Repeat([]byte{4}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	wrong, err := NewMFAService(s.db, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrong.Verify(context.Background(), 1, codes[0], nil); err == nil {
		t.Fatal("recovery allowed bypassing lost decryption key")
	}
}

func TestMFARateLimitBlocksValidProofAndResets(t *testing.T) {
	s, _ := newMFATestService(t)
	ctx := context.Background()
	_, codes := enrollMFA(t, s, 1)
	for range 5 {
		if _, err := s.Verify(ctx, 1, "invalid", nil); !errors.Is(err, ErrInvalidCode) {
			t.Fatal(err)
		}
	}
	if _, err := s.Verify(ctx, 1, codes[0], nil); !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf("valid proof bypassed immediate limit: %v", err)
	}
	s.now = func() time.Time { return time.Unix(1710000301, 0) }
	if _, err := s.Verify(ctx, 1, codes[0], nil); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("current-password"), bcrypt.MinCost)
	for range 10 {
		if err := s.CheckSensitivePassword(ctx, 1, string(hash), "wrong-password"); !errors.Is(err, ErrInvalidPassword) {
			t.Fatal(err)
		}
	}
	if err := s.CheckSensitivePassword(ctx, 1, string(hash), "current-password"); !errors.Is(err, ErrMFARateLimited) {
		t.Fatalf("sensitive password bypassed limit: %v", err)
	}
}

func TestMFACiphertextCannotMoveBetweenAccounts(t *testing.T) {
	s, _ := newMFATestService(t)
	_, codes := enrollMFA(t, s, 1)
	if _, err := s.db.Exec(`INSERT INTO account_mfa(admin_id,enabled,secret,last_counter) SELECT 2,enabled,secret,last_counter FROM account_mfa WHERE admin_id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(context.Background(), 2, codes[0], nil); err == nil {
		t.Fatal("ciphertext accepted under another account identity")
	}
}
