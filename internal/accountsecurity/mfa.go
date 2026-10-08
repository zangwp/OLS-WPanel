package accountsecurity

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCode     = errors.New("invalid or already used verification code")
	ErrInvalidPassword = errors.New("current password is incorrect")
	ErrMFARateLimited  = errors.New("too many security attempts; wait five minutes")
	ErrMFAEnabled      = errors.New("two-factor authentication is already enabled")
	ErrMFADisabled     = errors.New("two-factor authentication is not enabled")
	ErrPendingExpired  = errors.New("setup expired or belongs to a different session; start again")
)

// MFAAudit runs before committing the same transaction as the security mutation.
// An audit failure rolls back code consumption and all credential changes.
type MFAAudit func(*sql.Tx, string) error

type MFAService struct {
	db   *sql.DB
	aead cipher.AEAD
	now  func() time.Time
}

type MFAStatus struct {
	Enabled                bool  `json:"enabled"`
	RecoveryCodesRemaining int   `json:"recovery_codes_remaining"`
	PendingExpiresAt       int64 `json:"pending_expires_at"`
}

type MFASetup struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
	ExpiresAt  int64  `json:"expires_at"`
}

func InitMFASchema(db *sql.DB) error {
	if db == nil {
		return errors.New("MFA database unavailable")
	}
	for _, statement := range []string{
		`CREATE TABLE IF NOT EXISTS account_mfa (admin_id INTEGER PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, secret BLOB, last_counter INTEGER NOT NULL DEFAULT -1, pending_secret BLOB, pending_session_hash TEXT NOT NULL DEFAULT '', pending_expires INTEGER NOT NULL DEFAULT 0)`,
		`CREATE TABLE IF NOT EXISTS account_mfa_recovery (admin_id INTEGER NOT NULL, code_hash TEXT NOT NULL, PRIMARY KEY(admin_id,code_hash))`,
		`CREATE TABLE IF NOT EXISTS account_mfa_attempts (bucket TEXT PRIMARY KEY, window_start INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			return err
		}
	}
	return nil
}

// MFAEnabled deliberately fails on schema/read errors. An uninitialized MFA
// service must never make an enabled account fall back to password-only login.
func MFAEnabled(ctx context.Context, db *sql.DB, adminID int64) (bool, error) {
	var enabled bool
	err := db.QueryRowContext(ctx, `SELECT enabled FROM account_mfa WHERE admin_id=?`, adminID).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return enabled, err
}

func NewMFAService(db *sql.DB, keyPath string) (*MFAService, error) {
	if db == nil || keyPath == "" {
		return nil, errors.New("MFA database and key path are required")
	}
	key, err := loadMFAKey(db, keyPath)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &MFAService{db: db, aead: aead, now: time.Now}, nil
}

func loadMFAKey(db *sql.DB, keyPath string) ([]byte, error) {
	info, err := os.Lstat(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM account_mfa WHERE enabled=1 OR length(secret)>0 OR length(pending_secret)>0`).Scan(&count); err != nil {
			return nil, err
		}
		if count != 0 {
			return nil, errors.New("MFA encryption key missing; restore the original key alongside the database")
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err != nil {
			return nil, err
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := file.Write(key)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return nil, err
		}
		return key, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("MFA key must be a regular private file with mode 0600")
	}
	file, err := os.Open(keyPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	key, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("invalid MFA encryption key; restore the original key")
	}
	return key, nil
}

func (s *MFAService) seal(adminID int64, secret []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, secret, []byte(fmt.Sprintf("ols-mfa-v1:%d", adminID))), nil
}

func (s *MFAService) open(adminID int64, encrypted []byte) ([]byte, error) {
	if len(encrypted) < s.aead.NonceSize() {
		return nil, errors.New("invalid encrypted MFA secret")
	}
	return s.aead.Open(nil, encrypted[:s.aead.NonceSize()], encrypted[s.aead.NonceSize():], []byte(fmt.Sprintf("ols-mfa-v1:%d", adminID)))
}

// SHA-1 here is the standard HMAC algorithm used by interoperable RFC 6238 TOTP.
func totp(secret []byte, counter int64, digits int) string {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(data[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	number := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1000000)
	if digits == 8 {
		modulus = 100000000
	}
	return fmt.Sprintf("%0*d", digits, number%modulus)
}

func validCounter(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	counter := now.Unix() / 30
	// A future-step code cannot be used again after the clock catches up.
	for _, step := range []int64{0, -1, 1} {
		candidate := counter + step
		if candidate > last && subtle.ConstantTimeCompare([]byte(totp(secret, candidate, 6)), []byte(code)) == 1 {
			return candidate, true
		}
	}
	return 0, false
}

func sessionHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func recoveryHash(code string) string {
	sum := sha256.Sum256([]byte("ols-mfa-recovery-v1:" + strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))))
	return hex.EncodeToString(sum[:])
}

func (s *MFAService) Status(ctx context.Context, adminID int64) (MFAStatus, error) {
	var status MFAStatus
	err := s.db.QueryRowContext(ctx, `SELECT enabled,pending_expires,(SELECT COUNT(*) FROM account_mfa_recovery WHERE admin_id=?) FROM account_mfa WHERE admin_id=?`, adminID, adminID).Scan(&status.Enabled, &status.PendingExpiresAt, &status.RecoveryCodesRemaining)
	if errors.Is(err, sql.ErrNoRows) {
		return status, nil
	}
	if status.PendingExpiresAt <= s.now().Unix() {
		status.PendingExpiresAt = 0
	}
	return status, err
}

// Begin with a write before reading MFA state. This serializes competing proof
// consumers across SQLite connections/processes, not just within one Go object.
func (s *MFAService) begin(ctx context.Context, bucket string, limit int) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = tx.Rollback()
		}
	}()
	now := s.now().Unix()
	if _, err = tx.ExecContext(ctx, `INSERT INTO account_mfa_attempts(bucket,window_start,attempts) VALUES(?,?,0) ON CONFLICT(bucket) DO NOTHING`, bucket, now); err != nil {
		return nil, err
	}
	var start int64
	var attempts int
	if err = tx.QueryRowContext(ctx, `SELECT window_start,attempts FROM account_mfa_attempts WHERE bucket=?`, bucket).Scan(&start, &attempts); err != nil {
		return nil, err
	}
	if now-start >= 300 {
		if _, err = tx.ExecContext(ctx, `UPDATE account_mfa_attempts SET window_start=?,attempts=0 WHERE bucket=?`, now, bucket); err != nil {
			return nil, err
		}
		attempts = 0
	}
	if attempts >= limit {
		return nil, ErrMFARateLimited
	}
	ok = true
	return tx, nil
}

func failProof(tx *sql.Tx, bucket string, failure error) error {
	if _, err := tx.Exec(`UPDATE account_mfa_attempts SET attempts=attempts+1 WHERE bucket=?`, bucket); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return failure
}

// This additional account-level bound applies immediately, including to
// sensitive requests whose correct password is followed by an invalid MFA code.
func (s *MFAService) CheckSensitivePassword(ctx context.Context, id int64, hash, password string) error {
	bucket := fmt.Sprintf("sensitive:%d", id)
	tx, err := s.begin(ctx, bucket, 10)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE account_mfa_attempts SET attempts=attempts+1 WHERE bucket=?`, bucket); err != nil {
		return err
	}
	valid := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	if err = tx.Commit(); err != nil {
		return err
	}
	if !valid {
		return ErrInvalidPassword
	}
	return nil
}

func (s *MFAService) Setup(ctx context.Context, id int64, session, username string) (MFASetup, error) {
	var result MFASetup
	if session == "" {
		return result, ErrPendingExpired
	}
	tx, err := s.begin(ctx, fmt.Sprintf("proof:%d", id), 5)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var enabled bool
	var owner string
	var expiry int64
	err = tx.QueryRowContext(ctx, `SELECT enabled,pending_session_hash,pending_expires FROM account_mfa WHERE admin_id=?`, id).Scan(&enabled, &owner, &expiry)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}
	if enabled {
		return result, ErrMFAEnabled
	}
	if expiry > s.now().Unix() && owner != sessionHash(session) {
		return result, ErrPendingExpired
	}
	secret := make([]byte, 20)
	if _, err = rand.Read(secret); err != nil {
		return result, err
	}
	encrypted, err := s.seal(id, secret)
	if err != nil {
		return result, err
	}
	result.Secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	result.ExpiresAt = s.now().Add(10 * time.Minute).Unix()
	query := url.Values{"secret": {result.Secret}, "issuer": {"OLS WPanel"}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	result.OTPAuthURL = "otpauth://totp/" + url.PathEscape("OLS WPanel:"+username) + "?" + query.Encode()
	_, err = tx.ExecContext(ctx, `INSERT INTO account_mfa(admin_id,pending_secret,pending_session_hash,pending_expires) VALUES(?,?,?,?) ON CONFLICT(admin_id) DO UPDATE SET pending_secret=excluded.pending_secret,pending_session_hash=excluded.pending_session_hash,pending_expires=excluded.pending_expires`, id, encrypted, sessionHash(session), result.ExpiresAt)
	if err != nil {
		return MFASetup{}, err
	}
	if err = tx.Commit(); err != nil {
		return MFASetup{}, err
	}
	return result, nil
}

func replaceRecovery(tx *sql.Tx, id int64) ([]string, error) {
	if _, err := tx.Exec(`DELETE FROM account_mfa_recovery WHERE admin_id=?`, id); err != nil {
		return nil, err
	}
	codes := make([]string, 10)
	for i := range codes {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		code := strings.ToUpper(hex.EncodeToString(raw))
		codes[i] = code[:8] + "-" + code[8:16] + "-" + code[16:24] + "-" + code[24:]
		if _, err := tx.Exec(`INSERT INTO account_mfa_recovery(admin_id,code_hash) VALUES(?,?)`, id, recoveryHash(codes[i])); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

func auditMFA(tx *sql.Tx, audit MFAAudit, event string) error {
	if audit != nil {
		return audit(tx, event)
	}
	return nil
}

func (s *MFAService) Confirm(ctx context.Context, id int64, session, code string, audit MFAAudit) ([]string, error) {
	bucket := fmt.Sprintf("proof:%d", id)
	tx, err := s.begin(ctx, bucket, 5)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var encrypted []byte
	var owner string
	var expires int64
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT enabled,pending_secret,pending_session_hash,pending_expires FROM account_mfa WHERE admin_id=?`, id).Scan(&enabled, &encrypted, &owner, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrPendingExpired
	}
	if err != nil {
		return nil, err
	}
	if enabled {
		return nil, ErrMFAEnabled
	}
	if session == "" || owner != sessionHash(session) || expires <= s.now().Unix() {
		return nil, ErrPendingExpired
	}
	secret, err := s.open(id, encrypted)
	if err != nil {
		return nil, err
	}
	counter, valid := validCounter(secret, strings.TrimSpace(code), s.now(), -1)
	if !valid {
		return nil, failProof(tx, bucket, ErrInvalidCode)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE account_mfa SET enabled=1,secret=pending_secret,last_counter=?,pending_secret=NULL,pending_session_hash='',pending_expires=0 WHERE admin_id=?`, counter, id); err != nil {
		return nil, err
	}
	codes, err := replaceRecovery(tx, id)
	if err != nil {
		return nil, err
	}
	if err = auditMFA(tx, audit, "mfa_enabled"); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE account_mfa_attempts SET attempts=0 WHERE bucket=?`, bucket); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return codes, nil
}

func (s *MFAService) consume(tx *sql.Tx, id int64, code string) (bool, error) {
	var encrypted []byte
	var last int64
	var enabled bool
	if err := tx.QueryRow(`SELECT enabled,secret,last_counter FROM account_mfa WHERE admin_id=?`, id).Scan(&enabled, &encrypted, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrMFADisabled
		}
		return false, err
	}
	if !enabled {
		return false, ErrMFADisabled
	}
	secret, err := s.open(id, encrypted)
	if err != nil {
		return false, err
	}
	code = strings.TrimSpace(code)
	if counter, valid := validCounter(secret, code, s.now(), last); valid {
		_, err = tx.Exec(`UPDATE account_mfa SET last_counter=? WHERE admin_id=? AND last_counter<?`, counter, id, counter)
		return false, err
	}
	// 128-bit random recovery codes are not human passwords; a domain-separated
	// SHA-256 hash permits atomic lookup/consumption without persisting plaintext.
	if len(strings.ReplaceAll(code, "-", "")) != 32 {
		return false, ErrInvalidCode
	}
	result, err := tx.Exec(`DELETE FROM account_mfa_recovery WHERE admin_id=? AND code_hash=?`, id, recoveryHash(code))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, ErrInvalidCode
	}
	return true, nil
}

func (s *MFAService) mutate(ctx context.Context, id int64, code, action string, audit MFAAudit) ([]string, bool, error) {
	bucket := fmt.Sprintf("proof:%d", id)
	tx, err := s.begin(ctx, bucket, 5)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback()
	recovery, err := s.consume(tx, id, code)
	if errors.Is(err, ErrInvalidCode) {
		return nil, false, failProof(tx, bucket, err)
	}
	if err != nil {
		return nil, false, err
	}
	if recovery {
		if err = auditMFA(tx, audit, "recovery_used"); err != nil {
			return nil, false, err
		}
	}
	var codes []string
	switch action {
	case "mfa_disabled":
		if _, err = tx.Exec(`UPDATE account_mfa SET enabled=0,secret=NULL,last_counter=-1,pending_secret=NULL,pending_session_hash='',pending_expires=0 WHERE admin_id=?`, id); err != nil {
			return nil, false, err
		}
		if _, err = tx.Exec(`DELETE FROM account_mfa_recovery WHERE admin_id=?`, id); err != nil {
			return nil, false, err
		}
	case "recovery_regenerated":
		codes, err = replaceRecovery(tx, id)
		if err != nil {
			return nil, false, err
		}
	}
	if action != "" {
		if err = auditMFA(tx, audit, action); err != nil {
			return nil, false, err
		}
	}
	if _, err = tx.Exec(`UPDATE account_mfa_attempts SET attempts=0 WHERE bucket=?`, bucket); err != nil {
		return nil, false, err
	}
	if err = tx.Commit(); err != nil {
		return nil, false, err
	}
	return codes, recovery, nil
}

func (s *MFAService) Verify(ctx context.Context, id int64, code string, audit MFAAudit) (bool, error) {
	_, recovery, err := s.mutate(ctx, id, code, "", audit)
	return recovery, err
}
func (s *MFAService) Disable(ctx context.Context, id int64, code string, audit MFAAudit) error {
	_, _, err := s.mutate(ctx, id, code, "mfa_disabled", audit)
	return err
}
func (s *MFAService) Regenerate(ctx context.Context, id int64, code string, audit MFAAudit) ([]string, error) {
	codes, _, err := s.mutate(ctx, id, code, "recovery_regenerated", audit)
	return codes, err
}
