package executor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func securityTLSFixture(t *testing.T, host string, expired bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	if expired {
		leaf.NotAfter = now.Add(-time.Minute)
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}, roots
}

func TestSiteSecurityTLSVerificationRequiresTrustHostnameAndValidity(t *testing.T) {
	for _, tc := range []struct {
		name, host, want             string
		expired, insecure, untrusted bool
	}{
		{"valid", "site.example.com", "tls_verified", false, false, false},
		{"wrong hostname", "other.example.com", "tls_domain_mismatch", false, false, false},
		{"expired", "site.example.com", "tls_certificate_invalid", true, false, false},
		{"untrusted", "site.example.com", "tls_untrusted", false, false, true},
		{"insecure bypass cannot verify", "site.example.com", "tls_untrusted", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair, roots := securityTLSFixture(t, "site.example.com", tc.expired)
			requests := 0
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodHead || r.Host != tc.host || r.URL.RawQuery != "" {
					t.Errorf("unexpected probe: %v", r)
				}
				w.Header().Set("Location", "https://external.example/never-follow")
				w.WriteHeader(http.StatusFound)
			}))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
			server.StartTLS()
			defer server.Close()
			if tc.untrusted {
				roots = x509.NewCertPool()
			}
			transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: tc.host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: tc.insecure}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			reason, details := verifySiteTLSWithClient(context.Background(), tc.host, client)
			if reason != tc.want {
				t.Fatalf("reason=%s want=%s", reason, tc.want)
			}
			if tc.want == "tls_verified" && (requests != 1 || details["expires_at"] == "") {
				t.Fatalf("missing evidence/redirect followed: requests=%d details=%v", requests, details)
			}
		})
	}
}

func securityVerificationWebsite(t *testing.T) *models.Website {
	t.Helper()
	old := config.AppConfig
	root := t.TempDir()
	webRoot := filepath.Join(root, "site")
	if err := os.Mkdir(webRoot, 0750); err != nil {
		t.Fatal(err)
	}
	config.AppConfig = &config.Config{Paths: config.PathsConfig{WWWRoot: root, OLSVHostsAvailable: root, Certificates: root}}
	t.Cleanup(func() { config.AppConfig = old })
	wpConfig := renderWPNativePolicy("<?php\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('WP_DEBUG_DISPLAY', false);\n", false, true)
	if err := os.WriteFile(filepath.Join(webRoot, "wp-config.php"), []byte(wpConfig), 0600); err != nil {
		t.Fatal(err)
	}
	vhost := filepath.Join(root, "site.conf")
	if err := os.WriteFile(vhost, []byte("# fixture deliberately has no HTTP probe rules"), 0600); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(root, "fullchain.pem"), filepath.Join(root, "privkey.pem")
	for _, path := range []string{certPath, keyPath} {
		if err := os.WriteFile(path, []byte("fingerprint fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(root, "verification.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	previousDB := database.DB
	database.DB = db
	t.Cleanup(func() { db.Close(); database.DB = previousDB })
	if _, err := db.Exec(`CREATE TABLE websites(id INTEGER PRIMARY KEY,maintenance_security TEXT NOT NULL DEFAULT '{}'); INSERT INTO websites(id) VALUES(731)`); err != nil {
		t.Fatal(err)
	}
	if err := database.EnsureSiteSecurityVerificationSchema(db); err != nil {
		t.Fatal(err)
	}
	return &models.Website{ID: 731, Domain: "site.example.com", SiteType: "wordpress", Status: models.StatusActive, WebRoot: webRoot, OLSVHostConfigPath: vhost, DisableApplicationPasswords: true, DisableFileEditing: true, SSLEnabled: true, SSLCertPath: certPath, SSLKeyPath: keyPath}
}

func securityVerificationCheck(t *testing.T, report models.WebsiteSecurityStatus, key string) models.WebsiteSecurityCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.Key == key {
			return check
		}
	}
	t.Fatalf("missing %s", key)
	return models.WebsiteSecurityCheck{}
}

func TestSiteSecurityUpdateChecksRemainVerifiableWithFileProtection(t *testing.T) {
	for _, tc := range []struct {
		name                string
		disable, stopPolicy bool
		state               string
		canVerify           bool
	}{
		{"locked with checks enabled", false, false, "configured", true},
		{"explicitly disabled", true, true, "disabled", false},
		{"stale stop-checks policy", false, true, "error", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := securityVerificationWebsite(t)
			site.DisableWPUpdates = tc.disable
			site.FileLockEnabled, site.FileLockApplyStatus = true, FileLockApplyStatusReady
			wpConfig := renderWPNativePolicy("<?php\ndefine('DISALLOW_FILE_MODS', true);\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('WP_DEBUG_DISPLAY', false);\n", tc.stopPolicy, true)
			configPath := filepath.Join(site.WebRoot, "wp-config.php")
			if err := os.WriteFile(configPath, []byte(wpConfig), 0600); err != nil {
				t.Fatal(err)
			}
			oldMaintenance, oldCore := websiteSecurityMaintenanceState, verifyWebsiteSecurityCore
			t.Cleanup(func() { websiteSecurityMaintenanceState, verifyWebsiteSecurityCore = oldMaintenance, oldCore })
			websiteSecurityMaintenanceState = func(context.Context, int) (string, error) { return "locked", nil }
			coreCalls := 0
			verifyWebsiteSecurityCore = func(context.Context, *models.Website) (map[string]bool, error) {
				coreCalls++
				return map[string]bool{"wp_updates": true}, nil
			}
			report := CollectWebsiteSecurityStatus(context.Background(), site)
			check := securityVerificationCheck(t, report, "wp_updates")
			if check.State != tc.state || check.CanVerify != tc.canVerify {
				t.Fatalf("file protection altered update-check policy: %+v", check)
			}
			verified, err := VerifyWebsiteSecurityStatus(context.Background(), site, "wp_updates")
			if err != nil {
				t.Fatal(err)
			}
			check = securityVerificationCheck(t, verified, "wp_updates")
			if tc.state == "configured" {
				if coreCalls != 1 || check.State != "runtime_verified" || check.ReasonCode != "core_updates_allowed" || check.EvidenceSource != "isolated_wp_core" || check.Effective != nil {
					t.Fatalf("locked site lost core update-discovery verification: calls=%d check=%+v", coreCalls, check)
				}
				cached := securityVerificationCheck(t, CollectWebsiteSecurityStatus(context.Background(), site), "wp_updates")
				if cached.State != "configured" || cached.Verification == nil || cached.Verification.State != "runtime_verified" || cached.Verification.Status != "unchanged" || cached.Verification.ReasonCode != check.ReasonCode {
					t.Fatalf("file protection discarded history or replaced current configuration state: %+v", cached)
				}
			} else if coreCalls != 0 || check.State != tc.state {
				t.Fatalf("disabled/mismatched update policy was verified: calls=%d check=%+v", coreCalls, check)
			}
			if lock := securityVerificationCheck(t, verified, "file_lock"); lock.State != "ready" || lock.ReasonCode != "file_lock_applied" {
				t.Fatalf("update check changed file protection evidence: %+v", lock)
			}
			if content, err := os.ReadFile(configPath); err != nil || string(content) != wpConfig {
				t.Fatalf("verification changed file protection policy: %v", err)
			}
		})
	}
}

func TestSiteSecurityCoreVerificationHistoryIsScopedAndDetectsChanges(t *testing.T) {
	site := securityVerificationWebsite(t)
	old := verifyWebsiteSecurityCore
	t.Cleanup(func() { verifyWebsiteSecurityCore = old })
	verifyWebsiteSecurityCore = func(context.Context, *models.Website) (map[string]bool, error) {
		return map[string]bool{"application_passwords": true}, nil
	}
	report, err := VerifyWebsiteSecurityStatus(context.Background(), site, "application_passwords")
	if err != nil {
		t.Fatal(err)
	}
	check := securityVerificationCheck(t, report, "application_passwords")
	if check.State != "runtime_verified" || check.Effective != nil || check.EvidenceSource != "isolated_wp_core" || check.RuntimeReady == nil || !*check.RuntimeReady {
		t.Fatalf("core check invented request proof: %+v", check)
	}
	cached := CollectWebsiteSecurityStatus(context.Background(), site)
	if check := securityVerificationCheck(t, cached, "application_passwords"); check.State != "configured" || check.RuntimeReady != nil || check.Verification == nil || check.Verification.State != "runtime_verified" || check.Verification.Status != "unchanged" {
		t.Fatalf("unchanged configuration lost history or historical evidence replaced current state: %+v", check)
	}
	if err := os.WriteFile(filepath.Join(site.WebRoot, "wp-config.php"), []byte("<?php\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed := CollectWebsiteSecurityStatus(context.Background(), site)
	if got := securityVerificationCheck(t, changed, "application_passwords"); got.State == "runtime_verified" || got.Effective != nil && *got.Effective {
		t.Fatalf("changed policy retained proof: %+v", got)
	} else if got.Verification == nil || got.Verification.Status != "changed" {
		t.Fatalf("changed policy discarded history instead of marking it changed: %+v", got)
	}
}

func TestSiteSecurityFailedReverificationClearsPriorCoreProof(t *testing.T) {
	site := securityVerificationWebsite(t)
	old := verifyWebsiteSecurityCore
	t.Cleanup(func() { verifyWebsiteSecurityCore = old })
	verifyWebsiteSecurityCore = func(context.Context, *models.Website) (map[string]bool, error) {
		return map[string]bool{"file_editing": true}, nil
	}
	if _, err := VerifyWebsiteSecurityStatus(context.Background(), site, "file_editing"); err != nil {
		t.Fatal(err)
	}
	verifyWebsiteSecurityCore = func(context.Context, *models.Website) (map[string]bool, error) {
		return nil, errors.New("bootstrap failed")
	}
	report, err := VerifyWebsiteSecurityStatus(context.Background(), site, "file_editing")
	if err != nil {
		t.Fatal(err)
	}
	check := securityVerificationCheck(t, report, "file_editing")
	if check.State != "configured" || check.RuntimeReady != nil || check.Effective != nil || check.ReasonCode != "core_runtime_unavailable" {
		t.Fatalf("failed verification retained success: %+v", check)
	}
	latest := securityVerificationCheck(t, CollectWebsiteSecurityStatus(context.Background(), site), "file_editing")
	if latest.Verification == nil || latest.Verification.State != "configured" || latest.Verification.ReasonCode != "core_runtime_unavailable" || latest.Verification.Status != "unchanged" {
		t.Fatalf("failed recheck did not replace the older successful history: %+v", latest)
	}
}

func TestSiteSecurityVerificationRejectsUnsafeInputsAndPausedSites(t *testing.T) {
	if _, err := VerifyWebsiteSecurityStatus(context.Background(), nil, "https"); err == nil {
		t.Fatal("nil site accepted")
	}
	site := securityVerificationWebsite(t)
	if _, err := VerifyWebsiteSecurityStatus(context.Background(), site, "unknown"); err == nil {
		t.Fatal("unknown verification accepted")
	}
	site.Status = models.StatusPaused
	old := verifyWebsiteSecurityTLS
	verifyWebsiteSecurityTLS = func(context.Context, string) (string, map[string]string) {
		t.Fatal("paused site was probed")
		return "", nil
	}
	t.Cleanup(func() { verifyWebsiteSecurityTLS = old })
	report, err := VerifyWebsiteSecurityStatus(context.Background(), site, "https")
	if err != nil {
		t.Fatal(err)
	}
	if check := securityVerificationCheck(t, report, "https"); check.ReasonCode != "site_not_active" || check.Effective != nil {
		t.Fatalf("paused site claimed live result: %+v", check)
	}
}

func TestSiteSecurityFingerprintIgnoresIdenticalVHostRegeneration(t *testing.T) {
	site := securityVerificationWebsite(t)
	before, ok := websiteSecurityFingerprint(site, "https")
	if !ok {
		t.Fatal("fingerprint unavailable")
	}
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(site.OLSVHostConfigPath, future, future); err != nil {
		t.Fatal(err)
	}
	after, ok := websiteSecurityFingerprint(site, "https")
	if !ok || before != after {
		t.Fatal("identical configuration timestamp discarded historical observation")
	}
}

func TestSiteSecurityTLSObservationCannotOutliveCertificate(t *testing.T) {
	site := securityVerificationWebsite(t)
	fingerprint, ok := websiteSecurityFingerprint(site, "https")
	if !ok {
		t.Fatal("fingerprint unavailable")
	}
	expires := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	check := newWebsiteSecurityCheck("https", "effective", securityBool(true), securityBool(true), time.Now().UTC().Format(time.RFC3339))
	check.Details = map[string]string{"expires_at": expires.Format(time.RFC3339)}
	if err := rememberWebsiteSecurityVerification(context.Background(), site, &check, fingerprint); err != nil {
		t.Fatal(err)
	}
	records, err := database.LoadSiteSecurityVerifications(context.Background(), database.GetDB(), site.ID)
	if err != nil || records["https"].ValidUntil != expires.Format(time.RFC3339) {
		t.Fatalf("certificate expiry was not preserved: records=%+v err=%v", records, err)
	}
	if _, err := database.GetDB().Exec(`UPDATE site_security_verifications SET valid_until=? WHERE site_id=?`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), site.ID); err != nil {
		t.Fatal(err)
	}
	got := securityVerificationCheck(t, CollectWebsiteSecurityStatus(context.Background(), site), "https")
	if got.State != "configured" || got.Effective != nil || got.Verification == nil || got.Verification.Status != "changed" {
		t.Fatalf("expired certificate retained a current verified badge: %+v", got)
	}
}
