package executor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/zangwp/OLS-WPanel/internal/models"
	"net"
	"net/http"
	"strconv"
	"time"
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
	if state == "configured" && !check.CanVerify {
		if reason := map[string]string{"file_lock": "file_lock_not_ready", "uptime_monitor": "uptime_check_pending", "anomaly_monitor": "anomaly_check_pending", "backup": "backup_schedule_enabled"}[key]; reason != "" {
			check.ReasonCode = reason
		}
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

var verifyWebsiteSecurityTLS = verifySiteTLS
var verifyWebsiteSecurityCore = runSiteSecurityCorePolicy
var collectWebsiteSecurityForVerification = CollectWebsiteSecurityStatus

// Verification never submits credentials, creates an attack request, changes a
// firewall or follows a redirect. Core checks run separately from request checks.
func VerifyWebsiteSecurityStatus(ctx context.Context, site *models.Website, key string) (models.WebsiteSecurityStatus, error) {
	if site == nil || !WebsiteSecurityCheckVerifiable(key) {
		return models.WebsiteSecurityStatus{}, errors.New("unsupported verification key")
	}
	report := collectWebsiteSecurityForVerification(ctx, site)
	if site.Status != models.StatusActive {
		setWebsiteSecurityEvidence(&report, key, "site_not_active", "saved_configuration", report.CheckedAt, nil)
		return report, nil
	}
	fingerprint, safe := websiteSecurityFingerprint(site, key)
	if !safe {
		SetWebsiteSecurityCheck(&report, key, "error", nil, nil)
		setWebsiteSecurityEvidence(&report, key, "configuration_check_failed", "saved_configuration", report.CheckedAt, nil)
		return report, errors.New("security verification configuration unavailable")
	}
	for i := range report.Checks {
		check := &report.Checks[i]
		if check.Key != key || !check.CanVerify || check.State == "unsupported" || check.State == "disabled" || check.Configured == nil || !*check.Configured {
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
		if err := rememberWebsiteSecurityVerification(ctx, site, check, fingerprint); err != nil {
			report.VerificationUnavailable = true
			return report, err
		}
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
