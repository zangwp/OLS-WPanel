package executor

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestSiteSecurityManualHistorySurvivesRestartAndDoesNotRunPHPOnRead(t *testing.T) {
	site := securityVerificationWebsite(t)
	old := verifyWebsiteSecurityCore
	t.Cleanup(func() { verifyWebsiteSecurityCore = old })
	verifyWebsiteSecurityCore = func(context.Context, *models.Website) (map[string]bool, error) {
		return map[string]bool{"debug_display": true}, nil
	}
	first, err := VerifyWebsiteSecurityStatus(context.Background(), site, "debug_display")
	if err != nil {
		t.Fatal(err)
	}
	observed := securityVerificationCheck(t, first, "debug_display").Verification
	if observed == nil || observed.Status != "unchanged" {
		t.Fatalf("successful manual check was not saved: %+v", observed)
	}
	// Restart closes the actual SQLite handle. Reading old records must neither
	// rerun PHP nor promote an old success to a current runtime observation.
	if _, err := database.GetDB().Exec(`UPDATE site_security_verifications SET checked_at='2020-01-02T03:04:05Z' WHERE site_id=?`, site.ID); err != nil {
		t.Fatal(err)
	}
	if err := database.GetDB().Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(filepath.Dir(site.WebRoot), "verification.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	database.DB = db
	t.Cleanup(func() { db.Close() })
	verifyWebsiteSecurityCore = func(context.Context, *models.Website) (map[string]bool, error) {
		t.Fatal("ordinary page read ran PHP")
		return nil, nil
	}
	report := CollectWebsiteSecurityStatus(context.Background(), site)
	check := securityVerificationCheck(t, report, "debug_display")
	if report.VerificationUnavailable || check.State != "configured" || check.RuntimeReady != nil || check.Effective != nil || check.Verification == nil || check.Verification.Status != "unchanged" || check.Verification.State != "runtime_verified" || check.Verification.CheckedAt != "2020-01-02T03:04:05Z" {
		t.Fatalf("restart lost history or represented it as current proof: %+v", check)
	}
}

func TestSiteSecurityHistoryNeverReplacesCurrentErrorsOrDisabledPolicies(t *testing.T) {
	site := securityVerificationWebsite(t)
	old := verifyWebsiteSecurityCore
	t.Cleanup(func() { verifyWebsiteSecurityCore = old })
	verifyWebsiteSecurityCore = func(context.Context, *models.Website) (map[string]bool, error) {
		return map[string]bool{"application_passwords": true}, nil
	}
	if _, err := VerifyWebsiteSecurityStatus(context.Background(), site, "application_passwords"); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"disabled", "unsupported", "error", "unknown"} {
		report := models.WebsiteSecurityStatus{SiteID: site.ID, Checks: []models.WebsiteSecurityCheck{{Key: "application_passwords", State: state, ReasonCode: "current_fact", Effective: securityBool(false)}}}
		before := report.Checks[0]
		applySavedWebsiteSecurityVerification(context.Background(), site, &report)
		after := report.Checks[0]
		if after.Verification == nil || after.Verification.State != "runtime_verified" {
			t.Fatalf("missing separate history: %+v", after)
		}
		after.Verification = nil
		if !reflect.DeepEqual(before, after) {
			t.Fatalf("history hid %s current state: before=%+v after=%+v", state, before, after)
		}
	}
}

func TestSiteSecurityFingerprintsExcludeUnrelatedMetadataAndScopeRelevantChanges(t *testing.T) {
	site := securityVerificationWebsite(t)
	keys := []string{"https", "application_passwords", "debug_display", "wp_updates", "sensitive_files"}
	read := func() map[string]string {
		t.Helper()
		r := newWebsiteSecurityFingerprintReader(site)
		out := map[string]string{}
		for _, key := range keys {
			value, ok := r.check(key)
			if !ok {
				t.Fatalf("fingerprint %s unavailable", key)
			}
			out[key] = value
		}
		return out
	}
	original := read()
	site.Name = "renamed site"
	site.UpdatedAt = time.Now().Add(time.Hour)
	site.LogRetentionDays = 99
	site.MonitoringEnabled = true
	site.MonitoringInterval = 60
	expiry := time.Now().Add(time.Hour)
	site.ExpiresAt = &expiry
	site.CreatedAt = time.Now()
	site.SSLLastError = "unrelated previous issuance result"
	if got := read(); !reflect.DeepEqual(original, got) {
		t.Fatalf("unrelated metadata invalidated observations: before=%v after=%v", original, got)
	}
	site.PHPVersion = "8.4"
	php := read()
	if php["application_passwords"] == original["application_passwords"] || php["debug_display"] == original["debug_display"] || php["wp_updates"] == original["wp_updates"] {
		t.Fatal("PHP change did not invalidate core checks")
	}
	if php["https"] != original["https"] || php["sensitive_files"] != original["sensitive_files"] {
		t.Fatal("PHP change invalidated unrelated TLS/request checks")
	}
	if err := os.MkdirAll(filepath.Join(site.WebRoot, "wp-includes"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site.WebRoot, "wp-includes", "version.php"), []byte("<?php $wp_version = '7.0';"), 0600); err != nil {
		t.Fatal(err)
	}
	core := read()
	if core["application_passwords"] == php["application_passwords"] || core["https"] != php["https"] {
		t.Fatal("core update invalidation was not scoped")
	}
	if err := os.WriteFile(site.SSLCertPath, []byte("replacement certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	cert := read()
	if cert["https"] == core["https"] || cert["debug_display"] != core["debug_display"] {
		t.Fatal("certificate replacement invalidation was not scoped")
	}
}

func TestSiteSecurityUnavailableHistoryAndFailedSaveAreExplicit(t *testing.T) {
	site := securityVerificationWebsite(t)
	oldCore := verifyWebsiteSecurityCore
	t.Cleanup(func() { verifyWebsiteSecurityCore = oldCore })
	verifyWebsiteSecurityCore = func(context.Context, *models.Website) (map[string]bool, error) {
		return map[string]bool{"debug_display": true}, nil
	}
	if _, err := VerifyWebsiteSecurityStatus(context.Background(), site, "debug_display"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(site.WebRoot, "wp-config.php")); err != nil {
		t.Fatal(err)
	}
	got := securityVerificationCheck(t, CollectWebsiteSecurityStatus(context.Background(), site), "debug_display")
	if got.Verification == nil || got.Verification.Status != "unavailable" || got.State == "runtime_verified" {
		t.Fatalf("unreadable configuration retained current proof: %+v", got)
	}
	if err := os.WriteFile(filepath.Join(site.WebRoot, "wp-config.php"), []byte("<?php\ndefine('WP_DEBUG_DISPLAY', false);\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetDB().Exec(`DROP TABLE site_security_verifications`); err != nil {
		t.Fatal(err)
	}
	if report := CollectWebsiteSecurityStatus(context.Background(), site); !report.VerificationUnavailable {
		t.Fatal("history read error was silent")
	}
	report, err := VerifyWebsiteSecurityStatus(context.Background(), site, "debug_display")
	if !errors.Is(err, ErrWebsiteSecurityVerificationSave) || !report.VerificationUnavailable {
		t.Fatalf("save error was represented as success: err=%v report=%+v", err, report)
	}
	db := database.DB
	database.DB = nil
	t.Cleanup(func() { database.DB = db })
	if report := CollectWebsiteSecurityStatus(context.Background(), site); !report.VerificationUnavailable {
		t.Fatal("missing history database was silent")
	}
	if _, err := VerifyWebsiteSecurityStatus(context.Background(), site, "debug_display"); !errors.Is(err, ErrWebsiteSecurityVerificationSave) {
		t.Fatalf("missing database accepted verified result: %v", err)
	}
}

func TestSiteSecurityFingerprintFailureCannotReuseCollectorSuccessOrClaimSaved(t *testing.T) {
	site := securityVerificationWebsite(t)
	if err := os.Remove(site.SSLCertPath); err != nil {
		t.Fatal(err)
	}
	oldCollect, oldTLS := collectWebsiteSecurityForVerification, verifyWebsiteSecurityTLS
	t.Cleanup(func() { collectWebsiteSecurityForVerification, verifyWebsiteSecurityTLS = oldCollect, oldTLS })
	collectWebsiteSecurityForVerification = func(context.Context, *models.Website) models.WebsiteSecurityStatus {
		return models.WebsiteSecurityStatus{SiteID: site.ID, CheckedAt: time.Now().UTC().Format(time.RFC3339), Checks: []models.WebsiteSecurityCheck{{Key: "https", State: "effective", Configured: securityBool(true), Effective: securityBool(true), CanVerify: true}}}
	}
	verifyWebsiteSecurityTLS = func(context.Context, string) (string, map[string]string) {
		t.Fatal("unsafe configuration reached TLS verification")
		return "", nil
	}
	report, err := VerifyWebsiteSecurityStatus(context.Background(), site, "https")
	if err == nil || errors.Is(err, ErrWebsiteSecurityVerificationSave) {
		t.Fatalf("unsafe fingerprint was not an explicit verification failure: %v", err)
	}
	check := securityVerificationCheck(t, report, "https")
	if check.State != "error" || check.Effective != nil || check.Verification != nil {
		t.Fatalf("prior collected success was represented as a saved check: %+v", check)
	}
	records, err := database.LoadSiteSecurityVerifications(context.Background(), database.GetDB(), site.ID)
	if err != nil || len(records) != 0 {
		t.Fatalf("unsafe check wrote history: %+v %v", records, err)
	}
}
