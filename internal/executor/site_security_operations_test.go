package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func operationsSecurityReport() models.WebsiteSecurityStatus {
	report := models.WebsiteSecurityStatus{CheckedAt: time.Now().UTC().Format(time.RFC3339)}
	for _, key := range []string{"file_lock", "file_editing", "uptime_monitor", "anomaly_monitor", "backup"} {
		report.Checks = append(report.Checks, newWebsiteSecurityCheck(key, "disabled", securityBool(false), nil, report.CheckedAt))
	}
	return report
}

func TestWebsiteFileLockInheritanceRequiresAppliedPolicyAndKnownLifecycle(t *testing.T) {
	for _, tc := range []struct {
		name, applyStatus, maintenance, state, reason string
		policy                                        bool
		readErr                                       error
		covered                                       bool
	}{
		{"applied", "ready", "locked", "ready", "file_lock_applied", true, nil, true},
		{"policy removed", "ready", "locked", "error", "file_lock_policy_not_confirmed", false, nil, false},
		{"apply pending", "applying", "locked", "error", "file_lock_not_ready", true, nil, false},
		{"apply failed", "failed", "locked", "error", "file_lock_not_ready", true, nil, false},
		{"authorized maintenance", "ready", "unlocked", "configured", "file_lock_temporarily_unlocked", false, nil, false},
		{"unlock transition", "ready", "unlocking", "configured", "file_lock_temporarily_unlocked", true, nil, false},
		{"relock transition", "ready", "relocking", "configured", "file_lock_temporarily_unlocked", true, nil, false},
		{"relock failed with constant restored", "ready", "relock_failed", "error", "file_lock_not_ready", true, nil, false},
		{"uncertain", "ready", "unknown", "unknown", "file_lock_state_unknown", true, nil, false},
		{"read failed", "ready", "locked", "unknown", "file_lock_state_unknown", true, errors.New("unavailable"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := operationsSecurityReport()
			site := &models.Website{FileLockEnabled: true, FileLockApplyStatus: tc.applyStatus}
			applyWebsiteFileLockSecurityStatus(&report, site, tc.policy, tc.maintenance, tc.readErr)
			lock := securityVerificationCheck(t, report, "file_lock")
			editor := securityVerificationCheck(t, report, "file_editing")
			if lock.State != tc.state || lock.ReasonCode != tc.reason || lock.Effective != nil || lock.CanVerify {
				t.Fatalf("lock evidence: %+v", lock)
			}
			if tc.covered {
				if editor.State != "ready" || editor.ReasonCode != "file_editing_managed_by_file_lock" || editor.EvidenceSource != "file_lock_apply" || editor.Details["protected_by"] != "file_lock" || editor.CanVerify || editor.Effective != nil || editor.RuntimeReady == nil || !*editor.RuntimeReady {
					t.Fatalf("inherited protection confused with core proof: %+v", editor)
				}
			} else if editor.State != "disabled" || editor.RuntimeReady != nil || editor.Effective != nil {
				t.Fatalf("unconfirmed file lock inherited coverage: %+v", editor)
			}
		})
	}
}

func TestWebsiteFileLockCollectorAndVerifierPreserveInheritedEvidence(t *testing.T) {
	site := securityVerificationWebsite(t)
	site.FileLockEnabled, site.FileLockApplyStatus, site.DisableFileEditing = true, FileLockApplyStatusReady, false
	if err := os.WriteFile(filepath.Join(site.WebRoot, "wp-config.php"), []byte("<?php\ndefine('DISALLOW_FILE_MODS', true);\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldMaintenance, oldCore := websiteSecurityMaintenanceState, verifyWebsiteSecurityCore
	t.Cleanup(func() { websiteSecurityMaintenanceState, verifyWebsiteSecurityCore = oldMaintenance, oldCore })
	websiteSecurityMaintenanceState = func(context.Context, int) (string, error) { return "locked", nil }
	verifyWebsiteSecurityCore = func(context.Context, *models.Website) (map[string]bool, error) {
		t.Fatal("inherited file protection ran the independent core verifier")
		return nil, nil
	}
	// Simulate an older-version core cache with the same lock configuration. It
	// must not override current lifecycle/application evidence.
	fingerprint, ok := websiteSecurityFingerprint(site)
	if !ok {
		t.Fatal("fixture fingerprint unavailable")
	}
	cached := newWebsiteSecurityCheck("file_editing", "runtime_verified", securityBool(true), nil, time.Now().UTC().Format(time.RFC3339))
	cached.RuntimeReady, cached.EvidenceSource = securityBool(true), "isolated_wp_core"
	rememberWebsiteSecurityVerification(site, cached, fingerprint)
	for _, lifecycle := range []string{"locked", "unlocked", "relock_failed", "unknown"} {
		websiteSecurityMaintenanceState = func(context.Context, int) (string, error) { return lifecycle, nil }
		report := CollectWebsiteSecurityStatus(context.Background(), site)
		editor := securityVerificationCheck(t, report, "file_editing")
		if lifecycle == "locked" {
			if editor.ReasonCode != "file_editing_managed_by_file_lock" || editor.CanVerify || editor.EvidenceSource == "isolated_wp_core" {
				t.Fatalf("collector retained wrong coverage source: %+v", editor)
			}
			verified, err := VerifyWebsiteSecurityStatus(context.Background(), site, "file_editing")
			if err != nil || securityVerificationCheck(t, verified, "file_editing").ReasonCode != editor.ReasonCode {
				t.Fatalf("manual API replaced inherited protection: %+v %v", verified, err)
			}
		} else if editor.State == "ready" || editor.State == "runtime_verified" || editor.Effective != nil && *editor.Effective {
			t.Fatalf("lifecycle=%s retained stale coverage: %+v", lifecycle, editor)
		}
	}
	if site.DisableFileEditing {
		t.Fatal("inherited protection rewrote the independent setting")
	}
}

func TestWebsiteFileLockCollectorReportsRealMaintenanceFlagTransitions(t *testing.T) {
	site := securityVerificationWebsite(t)
	site.FileLockEnabled, site.DisableFileEditing = false, false
	if err := os.WriteFile(filepath.Join(site.WebRoot, "wp-config.php"), []byte("<?php\ndefine('DISALLOW_FILE_MODS', true);\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := websiteSecurityMaintenanceState
	t.Cleanup(func() { websiteSecurityMaintenanceState = old })
	for _, tc := range []struct{ window, applyStatus, state, reason string }{
		{"locked", "", "disabled", "disabled_by_policy"},
		{"unlocked", "", "configured", "file_lock_temporarily_unlocked"},
		{"relocking", "applying", "configured", "file_lock_temporarily_unlocked"},
		{"relock_failed", "failed", "error", "file_lock_not_ready"},
		{"unknown", "failed", "unknown", "file_lock_state_unknown"},
	} {
		t.Run(tc.window, func(t *testing.T) {
			site.FileLockApplyStatus = tc.applyStatus
			websiteSecurityMaintenanceState = func(context.Context, int) (string, error) { return tc.window, nil }
			if tc.window != "locked" {
				fingerprint, ok := websiteSecurityFingerprint(site)
				if !ok {
					t.Fatal("fixture fingerprint unavailable")
				}
				cached := newWebsiteSecurityCheck("file_editing", "runtime_verified", securityBool(true), securityBool(true), time.Now().UTC().Format(time.RFC3339))
				cached.EvidenceSource = "isolated_wp_core"
				rememberWebsiteSecurityVerification(site, cached, fingerprint)
			}
			report := CollectWebsiteSecurityStatus(context.Background(), site)
			lock := securityVerificationCheck(t, report, "file_lock")
			editor := securityVerificationCheck(t, report, "file_editing")
			if lock.State != tc.state || lock.ReasonCode != tc.reason || editor.State == "ready" || editor.State == "runtime_verified" || editor.EvidenceSource == "file_lock_apply" || editor.Effective != nil && *editor.Effective {
				t.Fatalf("real lifecycle flags hidden/misclassified: lock=%+v editor=%+v", lock, editor)
			}
		})
	}
}

func resetWebsiteAvailabilityEvidence(t *testing.T) {
	t.Helper()
	websiteAvailabilityObservations.Lock()
	previous := websiteAvailabilityObservations.entries
	websiteAvailabilityObservations.entries = make(map[string]websiteAvailabilityObservation)
	websiteAvailabilityObservations.Unlock()
	t.Cleanup(func() {
		websiteAvailabilityObservations.Lock()
		websiteAvailabilityObservations.entries = previous
		websiteAvailabilityObservations.Unlock()
	})
}

func TestWebsiteAvailabilitySummaryUsesOnlyMatchingFreshActualObservations(t *testing.T) {
	resetWebsiteAvailabilityEvidence(t)
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, state, reason      string
		observation              bool
		alerts, active           bool
		domain                   string
		ssl                      bool
		interval, code, failures int
		age                      time.Duration
	}{
		{"pending", "configured", "uptime_check_pending", false, true, true, "site.example", true, 5, 200, 0, 0},
		{"actual success", "ready", "uptime_check_succeeded", true, true, true, "site.example", true, 5, 200, 0, time.Minute},
		{"actual failure", "error", "uptime_check_failed", true, true, true, "site.example", true, 5, 503, 1, time.Minute},
		{"network failure", "error", "uptime_check_failed", true, true, true, "site.example", true, 5, 0, 1, time.Minute},
		{"global gate disabled", "configured", "uptime_alert_disabled", true, false, true, "site.example", true, 5, 200, 0, time.Minute},
		{"inactive", "configured", "site_not_active", true, true, false, "site.example", true, 5, 200, 0, time.Minute},
		{"renamed", "configured", "uptime_check_pending", true, true, true, "old.example", true, 5, 200, 0, time.Minute},
		{"TLS changed", "configured", "uptime_check_pending", true, true, true, "site.example", false, 5, 200, 0, time.Minute},
		{"interval changed", "configured", "uptime_check_pending", true, true, true, "site.example", true, 10, 200, 0, time.Minute},
		{"stale", "configured", "uptime_check_stale", true, true, true, "site.example", true, 5, 200, 0, 8 * time.Minute},
		{"future sample", "configured", "uptime_check_stale", true, true, true, "site.example", true, 5, 200, 0, -2 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			websiteAvailabilityObservations.Lock()
			websiteAvailabilityObservations.entries = make(map[string]websiteAvailabilityObservation)
			websiteAvailabilityObservations.Unlock()
			if tc.observation {
				recordWebsiteAvailabilityObservation("42", tc.domain, tc.ssl, tc.interval, tc.code, tc.failures, now.Add(-tc.age))
			}
			site := &models.Website{ID: 42, Domain: "site.example", SSLEnabled: true, MonitoringEnabled: true, MonitoringInterval: 5, Status: models.StatusActive}
			if !tc.active {
				site.Status = models.StatusPaused
			}
			report := operationsSecurityReport()
			ApplyWebsiteAvailabilitySecurityStatus(&report, site, tc.alerts, now)
			check := securityVerificationCheck(t, report, "uptime_monitor")
			if check.State != tc.state || check.ReasonCode != tc.reason || check.Effective != nil || check.CanVerify {
				t.Fatalf("summary=%+v", check)
			}
			if tc.state == "ready" && (check.EvidenceSource != "website_http" || check.RuntimeReady == nil || !*check.RuntimeReady || check.EvidenceAt != now.Add(-tc.age).Format(time.RFC3339)) {
				t.Fatalf("success lacks actual evidence: %+v", check)
			}
		})
	}
}

func TestWebsiteAnomalySummaryReflectsPersistedCheckOutcome(t *testing.T) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, state, reason, lastError string
		enabled                        bool
		lastSuccess, nextCheck         int64
	}{
		{"disabled", "disabled", "disabled_by_policy", "sample_failed", false, now.Unix() - 60, now.Unix() + 3600},
		{"first baseline pending", "configured", "anomaly_check_pending", "", true, 0, 0},
		{"successful baseline", "ready", "anomaly_check_succeeded", "", true, now.Unix() - 60, now.Unix() + 3500},
		{"sample failed after baseline", "error", "anomaly_check_failed", "sample_failed", true, now.Unix() - 60, now.Unix() + 3500},
		{"never sampled error", "error", "anomaly_check_failed", "site_busy", true, 0, now.Unix() + 3500},
		{"stale", "configured", "anomaly_check_stale", "", true, now.Unix() - 7200, now.Unix() - 3600},
		{"overdue", "configured", "anomaly_check_stale", "", true, now.Unix() - 600, now.Unix() - 400},
		{"future invalid", "unknown", "anomaly_state_unknown", "", true, now.Unix() + 120, now.Unix() + 3600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := operationsSecurityReport()
			ApplyWebsiteAnomalySecurityStatus(&report, tc.enabled, tc.lastSuccess, tc.nextCheck, tc.lastError, now)
			check := securityVerificationCheck(t, report, "anomaly_monitor")
			if check.State != tc.state || check.ReasonCode != tc.reason || check.Effective != nil || check.CanVerify {
				t.Fatalf("summary=%+v", check)
			}
			if tc.state == "ready" && (check.EvidenceSource != "wordpress_inventory" || check.EvidenceAt != time.Unix(tc.lastSuccess, 0).UTC().Format(time.RFC3339) || check.RuntimeReady == nil || !*check.RuntimeReady) {
				t.Fatalf("success lacks persisted sample evidence: %+v", check)
			}
		})
	}
}

func TestWebsiteAvailabilityCheckerRecordsCompletedResultsAndRecovery(t *testing.T) {
	resetWebsiteAvailabilityEvidence(t)
	db := openAlertTestDB(t)
	mustExec(t, db, `CREATE TABLE websites(id INTEGER PRIMARY KEY,domain TEXT,status TEXT,ssl_enabled INTEGER,monitoring_enabled INTEGER,monitoring_interval INTEGER)`)
	var responseCode atomic.Int32
	responseCode.Store(http.StatusOK)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" || r.URL.Query().Get("wp_hc") == "" {
			t.Errorf("unexpected availability request: %v", r)
		}
		w.WriteHeader(int(responseCode.Load()))
	}))
	defer server.Close()
	domain := strings.TrimPrefix(server.URL, "http://")
	if _, err := db.Exec(`INSERT INTO websites VALUES(42,?,'active',0,1,5)`, domain); err != nil {
		t.Fatal(err)
	}
	site := &models.Website{ID: 42, Domain: domain, Status: models.StatusActive, MonitoringEnabled: true, MonitoringInterval: 5}
	for _, tc := range []struct {
		code          int
		state, reason string
	}{
		{200, "ready", "uptime_check_succeeded"},
		{503, "error", "uptime_check_failed"},
		{200, "ready", "uptime_check_succeeded"},
	} {
		responseCode.Store(int32(tc.code))
		delete(siteLastCheck, "42")
		checkSitesState()
		report := operationsSecurityReport()
		ApplyWebsiteAvailabilitySecurityStatus(&report, site, true, time.Now())
		check := securityVerificationCheck(t, report, "uptime_monitor")
		if check.State != tc.state || check.ReasonCode != tc.reason || check.Details["status_code"] != strconv.Itoa(tc.code) {
			t.Fatalf("completed HTTP result not reflected: %+v", check)
		}
	}
}

func TestWebsiteFileLockMaintenanceReaderRejectsUnknownAndPrivateRecords(t *testing.T) {
	db := openAlertTestDB(t)
	mustExec(t, db, `CREATE TABLE websites(id INTEGER PRIMARY KEY,maintenance_security TEXT)`)
	mustExec(t, db, `INSERT INTO websites VALUES(42,'{}')`)
	for _, tc := range []struct {
		raw, state string
		invalid    bool
	}{
		{`{}`, "locked", false},
		{`{"hash":"private-password-hash","password_ciphertext":"private-secret","window":{"state":"unlocked"}}`, "unlocked", false},
		{`{"window":{"state":"relock_failed"}}`, "relock_failed", false},
		{`null`, "unknown", true},
		{`{"window":`, "unknown", true},
	} {
		if _, err := db.Exec(`UPDATE websites SET maintenance_security=? WHERE id=42`, tc.raw); err != nil {
			t.Fatal(err)
		}
		state, err := readWebsiteSecurityMaintenanceState(context.Background(), 42)
		if state != tc.state || (err != nil) != tc.invalid || strings.Contains(state, "private") {
			t.Fatalf("raw=%q state=%q err=%v", tc.raw, state, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if state, err := readWebsiteSecurityMaintenanceState(ctx, 42); state != "unknown" || err == nil {
		t.Fatalf("canceled read=%q %v", state, err)
	}
}
