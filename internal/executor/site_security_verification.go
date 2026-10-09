package executor

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var websiteSecurityVerifyKeys = map[string]bool{"https": true, "login_protection": true, "sql_injection": true, "sensitive_files": true, "uploads_php": true, "xmlrpc": true, "application_passwords": true, "file_editing": true, "debug_display": true, "wp_updates": true}

func WebsiteSecurityCheckVerifiable(key string) bool { return websiteSecurityVerifyKeys[key] }

func newWebsiteSecurityCheck(key, state string, configured, effective *bool, checkedAt string) models.WebsiteSecurityCheck {
	check := models.WebsiteSecurityCheck{Key: key, State: state, Configured: configured, Effective: effective, CanVerify: WebsiteSecurityCheckVerifiable(key)}
	check.Action = map[string]string{"https": "ssl", "login_protection": "protection", "sql_injection": "protection", "xmlrpc": "wp-policy", "application_passwords": "wp-policy", "file_editing": "file-editing", "debug_display": "cache", "wp_updates": "wp-updates", "file_lock": "file-lock", "uptime_monitor": "monitor", "anomaly_monitor": "anomaly", "backup": "backups", "sensitive_files": "logs", "uploads_php": "logs"}[key]
	check.ReasonCode = map[string]string{"unknown": "not_checked", "configured": "configured_not_run", "disabled": "disabled_by_policy", "unsupported": "not_applicable", "error": "configuration_check_failed", "ready": "service_ready", "effective": "request_verified", "runtime_verified": "core_policy_verified"}[state]
	if state == "unsupported" || state == "disabled" {
		check.CanVerify = false
	}
	if key == "https" && state == "configured" {
		check.ReasonCode = "https_setting_enabled"
	}
	if configured != nil && *configured {
		check.EvidenceSource, check.EvidenceAt = "saved_configuration", checkedAt
		if key == "application_passwords" || key == "file_editing" || key == "debug_display" || key == "wp_updates" {
			check.EvidenceSource = "wp_config"
		}
		if key == "sensitive_files" || key == "uploads_php" || key == "xmlrpc" || key == "sql_injection" {
			check.EvidenceSource = "ols_configuration"
		}
	}
	return check
}

func setWebsiteSecurityEvidence(report *models.WebsiteSecurityStatus, key, reason, source, at string, details map[string]string) {
	for i := range report.Checks {
		check := &report.Checks[i]
		if check.Key != key {
			continue
		}
		check.ReasonCode, check.EvidenceSource, check.EvidenceAt, check.Details = reason, source, at, details
		if check.State == "ready" || check.State == "effective" || check.State == "runtime_verified" {
			check.RuntimeReady = securityBool(true)
		}
		if source == "ols_security_log" || source == "wp_login_audit" {
			check.RecentEventAt = at
		}
		return
	}
}

type websiteSecurityCachedVerification struct {
	fingerprint string
	expires     time.Time
	check       models.WebsiteSecurityCheck
}

var websiteSecurityVerificationCache = struct {
	sync.Mutex
	entries map[string]websiteSecurityCachedVerification
}{entries: make(map[string]websiteSecurityCachedVerification)}

// Fingerprint all configuration inputs. A policy edit or certificate replacement
// invalidates an earlier observation rather than retaining a stale green badge.
func websiteSecurityFingerprint(site *models.Website) (string, bool) {
	cfg := config.AppConfig
	if cfg == nil || site == nil {
		return "", false
	}
	vhost, err := readSiteSecurityFile(cfg.Paths.OLSVHostsAvailable, site.OLSVHostConfigPath, 256*1024)
	if err != nil {
		return "", false
	}
	wpConfig := []byte(nil)
	if site.SiteType == "wordpress" {
		wpConfig, err = readSiteSecurityFile(cfg.Paths.WWWRoot, filepath.Join(site.WebRoot, "wp-config.php"), 1024*1024)
		if err != nil {
			return "", false
		}
	}
	h := sha256.New()
	data, _ := json.Marshal(site)
	h.Write(data)
	h.Write(vhost)
	h.Write(wpConfig)
	for _, path := range []string{site.OLSVHostConfigPath, filepath.Join(site.WebRoot, "wp-config.php")} {
		if info, err := os.Lstat(path); err == nil {
			uid, gid, known := wpInventoryFileOwner(info)
			fmt.Fprintf(h, "|%d|%d|%s|%d|%d|%t", info.Size(), info.ModTime().UnixNano(), info.Mode(), uid, gid, known)
		}
	}
	block, ban := GetSQLiProtectionSettings()
	fmt.Fprintf(h, "|%t|%t", block, ban)
	for _, path := range []string{site.SSLCertPath, site.SSLKeyPath} {
		if info, err := os.Lstat(path); err == nil {
			fmt.Fprintf(h, "|%s|%d|%d|%s", path, info.Size(), info.ModTime().UnixNano(), info.Mode())
		}
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

func applyCachedWebsiteSecurityVerification(site *models.Website, report *models.WebsiteSecurityStatus) {
	fingerprint, ok := websiteSecurityFingerprint(site)
	if !ok {
		return
	}
	websiteSecurityVerificationCache.Lock()
	defer websiteSecurityVerificationCache.Unlock()
	for i := range report.Checks {
		key := strconv.Itoa(site.ID) + ":" + report.Checks[i].Key
		cached, exists := websiteSecurityVerificationCache.entries[key]
		if !exists {
			continue
		}
		if cached.fingerprint != fingerprint || !time.Now().Before(cached.expires) {
			delete(websiteSecurityVerificationCache.entries, key)
			continue
		}
		// Event-derived observations are newer than a component-only verification.
		if report.Checks[i].RecentEventAt == "" {
			report.Checks[i] = cached.check
		}
	}
}

func rememberWebsiteSecurityVerification(site *models.Website, check models.WebsiteSecurityCheck, expected string) {
	current, ok := websiteSecurityFingerprint(site)
	if !ok || current != expected {
		return
	}
	websiteSecurityVerificationCache.Lock()
	defer websiteSecurityVerificationCache.Unlock()
	now := time.Now()
	for key, cached := range websiteSecurityVerificationCache.entries {
		if !now.Before(cached.expires) {
			delete(websiteSecurityVerificationCache.entries, key)
		}
	}
	if len(websiteSecurityVerificationCache.entries) >= 1024 {
		return
	}
	expires := now.Add(10 * time.Minute)
	if check.Key == "https" && check.State == "effective" {
		certificateExpiry, err := time.Parse(time.RFC3339, check.Details["expires_at"])
		if err != nil || !now.Before(certificateExpiry) {
			return
		}
		if certificateExpiry.Before(expires) {
			expires = certificateExpiry
		}
	}
	websiteSecurityVerificationCache.entries[strconv.Itoa(site.ID)+":"+check.Key] = websiteSecurityCachedVerification{fingerprint: current, expires: expires, check: check}
}

var verifyWebsiteSecurityTLS = verifySiteTLS
var verifyWebsiteSecurityCore = runSiteSecurityCorePolicy

// Verification never submits credentials, creates an attack request, changes a
// firewall or follows a redirect. Core checks run separately from request checks.
func VerifyWebsiteSecurityStatus(ctx context.Context, site *models.Website, key string) (models.WebsiteSecurityStatus, error) {
	if site == nil || !WebsiteSecurityCheckVerifiable(key) {
		return models.WebsiteSecurityStatus{}, errors.New("unsupported verification key")
	}
	report := CollectWebsiteSecurityStatus(ctx, site)
	if site.Status != models.StatusActive {
		setWebsiteSecurityEvidence(&report, key, "site_not_active", "saved_configuration", report.CheckedAt, nil)
		return report, nil
	}
	fingerprint, safe := websiteSecurityFingerprint(site)
	if !safe {
		setWebsiteSecurityEvidence(&report, key, "configuration_check_failed", "saved_configuration", report.CheckedAt, nil)
		return report, nil
	}
	for i := range report.Checks {
		check := &report.Checks[i]
		if check.Key != key || check.State == "unsupported" || check.State == "disabled" || check.Configured == nil || !*check.Configured {
			continue
		}
		switch key {
		case "https":
			reason, details := verifyWebsiteSecurityTLS(ctx, site.Domain)
			if reason == "tls_verified" {
				*check = newWebsiteSecurityCheck(key, "effective", securityBool(true), securityBool(true), report.CheckedAt)
			} else {
				*check = newWebsiteSecurityCheck(key, "configured", securityBool(true), nil, report.CheckedAt)
			}
			setWebsiteSecurityEvidence(&report, key, reason, "loopback_tls", time.Now().UTC().Format(time.RFC3339), details)
		case "application_passwords", "file_editing", "debug_display", "wp_updates":
			*check = newWebsiteSecurityCheck(key, "configured", securityBool(true), nil, report.CheckedAt)
			values, err := verifyWebsiteSecurityCore(ctx, site)
			if err != nil {
				setWebsiteSecurityEvidence(&report, key, "core_runtime_unavailable", "isolated_wp_core", time.Now().UTC().Format(time.RFC3339), nil)
			} else if verified, present := values[key]; present && verified {
				*check = newWebsiteSecurityCheck(key, "runtime_verified", securityBool(true), nil, report.CheckedAt)
				reason := map[string]string{"application_passwords": "core_application_passwords_disabled", "file_editing": "core_file_editor_disabled", "debug_display": "core_debug_display_disabled", "wp_updates": "core_updates_allowed"}[key]
				setWebsiteSecurityEvidence(&report, key, reason, "isolated_wp_core", time.Now().UTC().Format(time.RFC3339), nil)
			} else {
				setWebsiteSecurityEvidence(&report, key, "core_policy_not_enforced", "isolated_wp_core", time.Now().UTC().Format(time.RFC3339), nil)
			}
		}
		rememberWebsiteSecurityVerification(site, *check, fingerprint)
		break
	}
	return report, nil
}

func verifySiteTLS(ctx context.Context, domain string) (string, map[string]string) {
	if !validSiteSecurityHost(domain) {
		return "invalid_host", nil
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSHandshakeTimeout: 2 * time.Second, TLSClientConfig: &tls.Config{ServerName: domain, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", "127.0.0.1:443")
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return verifySiteTLSWithClient(ctx, domain, client)
}

func verifySiteTLSWithClient(ctx context.Context, domain string, client *http.Client) (string, map[string]string) {
	if !validSiteSecurityHost(domain) {
		return "invalid_host", nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+domain+"/", nil)
	if err != nil {
		return "invalid_host", nil
	}
	request.Header.Set("User-Agent", "OLS-WPanel-ReadOnly-Security-Check")
	response, err := client.Do(request)
	if err != nil {
		var nameErr x509.HostnameError
		var authorityErr x509.UnknownAuthorityError
		var certificateErr x509.CertificateInvalidError
		if errors.As(err, &nameErr) {
			return "tls_domain_mismatch", nil
		}
		if errors.As(err, &authorityErr) {
			return "tls_untrusted", nil
		}
		if errors.As(err, &certificateErr) {
			return "tls_certificate_invalid", nil
		}
		return "tls_connection_unavailable", nil
	}
	defer response.Body.Close()
	state := response.TLS
	if state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 || state.Version < tls.VersionTLS12 {
		return "tls_untrusted", nil
	}
	leaf := state.PeerCertificates[0]
	if leaf.VerifyHostname(domain) != nil {
		return "tls_domain_mismatch", nil
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return "tls_certificate_invalid", nil
	}
	return "tls_verified", map[string]string{"expires_at": leaf.NotAfter.UTC().Format(time.RFC3339), "http_status": strconv.Itoa(response.StatusCode)}
}
