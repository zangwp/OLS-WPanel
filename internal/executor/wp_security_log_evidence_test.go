package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadOnlySecurityChecksAreExcludedOnlyForExactLoopbackHEAD(t *testing.T) {
	path := "/wp-content/uploads/ols-wpanel-readonly-security-probe.php"
	for _, tt := range []struct {
		ip, method, path string
		excluded         bool
	}{
		{"127.0.0.1", "HEAD", path, true},
		{"::1", "HEAD", path, true},
		{"203.0.113.10", "HEAD", path, false},
		{"127.0.0.1", "GET", path, false},
		{"127.0.0.1", "POST", path, false},
		{"127.0.0.1", "HEAD", path + "?id=1", false},
		{"127.0.0.1", "HEAD", "/wp-content/uploads/another.php", false},
	} {
		line := fmt.Sprintf(`%s - - [15/Jan/2026:10:00:00 +0800] "%s %s HTTP/1.1" 403 0 "-" "-" peer=- ols_security="uploads_php" ols_autoban="0"`, tt.ip, tt.method, tt.path)
		evidence, ok := parseWPSecurityLogEvidence(line, wpSecurityAccessLog, nil)
		if ok == tt.excluded || (ok && evidence.eventType != SecurityEventSuspiciousPHP) {
			t.Errorf("read-only check %+v evidence=(%+v,%v)", tt, evidence, ok)
		}
	}
}

func TestReadOnlySecurityCheckCannotBeHiddenBySpoofedClientIP(t *testing.T) {
	base := `127.0.0.1 - - [15/Jan/2026:10:00:00 +0800] "HEAD /wp-content/uploads/ols-wpanel-readonly-security-probe.php HTTP/1.1" 403 0 "-" "-"`
	for _, tt := range []struct {
		name, source, suffix, want string
		excluded                   bool
	}{
		{"real loopback connection", wpSecurityAccessLog, ` peer=127.0.0.1 ols_security="uploads_php" ols_autoban="0"`, "", true},
		{"real IPv6 loopback connection", wpSecurityAccessLog, ` peer=::1 ols_security="uploads_php" ols_autoban="0"`, "", true},
		{"forged loopback client over public peer", wpSecurityAccessLog, ` peer=203.0.113.10 ols_security="uploads_php" ols_autoban="0"`, "client_ip_spoof", false},
		{"forged loopback client with SQLi marker", wpSecurityAccessLog, ` peer=2001:db8::10 ols_security="sqli" ols_autoban="1"`, "client_ip_spoof", false},
		{"invalid peer cannot prove own check", wpSecurityAccessLog, ` peer=not-an-IP ols_security="uploads_php" ols_autoban="0"`, "", false},
		{"legacy native format cannot prove original peer", wpSecurityAccessLog, ` ols_security="uploads_php" ols_autoban="0"`, SecurityEventSuspiciousPHP, false},
		{"legacy source is not a trusted own check", wpSecurityLegacyLog, ` peer=- ols_security="uploads_php" ols_autoban="0"`, "", false},
		{"unmarked response is not a trusted own check", wpSecurityAccessLog, ` peer=-`, "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			evidence, ok := parseWPSecurityLogEvidence(base+tt.suffix, tt.source, nil)
			if ok == tt.excluded || (ok && evidence.eventType != tt.want) {
				t.Fatalf("evidence=(%+v,%v), want type=%s excluded=%v", evidence, ok, tt.want, tt.excluded)
			}
		})
	}
}

func TestNativeOLSBlockingEvidenceRequiresTrustedSourceAndWholeMarker(t *testing.T) {
	base := `203.0.113.10 - - [15/Jan/2026:10:00:00 +0800] "GET /?id=1%20UNION%20SELECT%201%20FROM%20users HTTP/1.1" 403 0 "-" "curl"`
	for _, tt := range []struct {
		name, source, line, want string
	}{
		{"native OLS deny", wpSecurityAccessLog, base + ` ols_security="sqli" ols_autoban="1"`, SecurityEventSQLiBlocked},
		{"native deny with original peer", wpSecurityAccessLog, base + ` peer=203.0.113.10 ols_security="sqli" ols_autoban="1"`, SecurityEventSQLiBlocked},
		{"native deny with unchanged client address", wpSecurityAccessLog, base + ` peer=- ols_security="sqli" ols_autoban="1"`, SecurityEventSQLiBlocked},
		{"invalid peer invalidates native evidence", wpSecurityAccessLog, base + ` peer=forged.example ols_security="sqli" ols_autoban="1"`, SecurityEventSQLiProbe},
		{"autoban disabled still blocked", wpSecurityAccessLog, base + ` ols_security="sqli" ols_autoban="0"`, SecurityEventSQLiBlocked},
		{"legacy 403 is probe", wpSecurityLegacyLog, base, SecurityEventSQLiProbe},
		{"legacy marker is not native evidence", wpSecurityLegacyLog, base + ` ols_security="sqli" ols_autoban="1"`, SecurityEventSQLiProbe},
		{"access 403 without marker", wpSecurityAccessLog, base, SecurityEventSQLiProbe},
		{"non-403 cannot prove a deny", wpSecurityAccessLog, strings.Replace(base, "403 0", "200 0", 1) + ` ols_security="sqli" ols_autoban="1"`, SecurityEventSQLiProbe},
		{"marker in header", wpSecurityAccessLog, strings.Replace(base, `"curl"`, `"curl ols_security=\"sqli\" ols_autoban=\"1\""`, 1) + ` ols_security="-" ols_autoban="0"`, SecurityEventSQLiProbe},
		{"trailing garbage invalidates marker", wpSecurityAccessLog, base + ` ols_security="sqli" ols_autoban="1" junk`, SecurityEventSQLiProbe},
		{"request header variable not marker", wpSecurityAccessLog, base + ` OLS_WPANEL_SECURITY=sqli`, SecurityEventSQLiProbe},
	} {
		t.Run(tt.name, func(t *testing.T) {
			evidence, ok := parseWPSecurityLogEvidence(tt.line, tt.source, nil)
			if !ok || evidence.eventType != tt.want {
				t.Fatalf("evidence=(%+v,%v), want type=%s", evidence, ok, tt.want)
			}
			if tt.want != SecurityEventSQLiBlocked && strings.Contains(evidence.message, "PHP 前") {
				t.Fatal("unverified response must not claim PHP-before blocking")
			}
		})
	}
	minimal := `203.0.113.10 - - [15/Jan/2026:10:00:00 +0800] "GET / HTTP/1.1" 403 0 "-" "-" ols_security="sqli" ols_autoban="1"`
	if evidence, ok := parseWPSecurityLogEvidence(minimal, wpSecurityAccessLog, nil); !ok || evidence.eventType != SecurityEventSQLiBlocked {
		t.Fatal("minimal log must classify native SQLi blocking without retaining query parameters")
	}
}

func TestWordPressLoginEvidenceUsesActualFailureProducer(t *testing.T) {
	line := `2001:db8::10 [2026-10-09T10:00:00+08:00] OLS_WPANEL_LOGIN_FAILED`
	evidence, ok := parseWPSecurityLogEvidence(line, wpSecurityLoginLog, nil)
	if !ok || evidence.eventType != SecurityEventWPLoginFailed || evidence.status != 0 || evidence.method != "AUTH" || evidence.uri != "WordPress authentication" {
		t.Fatalf("auth failure evidence=(%+v,%v)", evidence, ok)
	}
	for _, tt := range []struct{ source, line string }{
		{wpSecurityAccessLog, line},
		{wpSecurityLoginLog, `203.0.113.10 [bad-date] OLS_WPANEL_LOGIN_FAILED`},
		{wpSecurityLoginLog, `not-an-IP [2026-10-09T10:00:00Z] OLS_WPANEL_LOGIN_FAILED`},
		{wpSecurityLoginLog, line + " username=admin"},
		{wpSecurityLoginLog, `203.0.113.10 - - [15/Jan/2026:10:00:00 +0800] "POST /wp-login.php HTTP/1.1" 200 0 "-" "browser"`},
	} {
		if evidence, ok := parseWPSecurityLogEvidence(tt.line, tt.source, nil); ok && evidence.eventType == SecurityEventWPLoginFailed {
			t.Errorf("invalid/non-auth event claimed login failure: %+v", tt)
		}
	}
}

func TestHasRecentWPSecurityEvidenceRequiresObservedRecentEvents(t *testing.T) {
	old := wpSecurityLogDirAllowed
	wpSecurityLogDirAllowed = func(string) bool { return true }
	t.Cleanup(func() { wpSecurityLogDirAllowed = old })
	dir := t.TempDir()
	if HasRecentWPSecurityEvidence(dir, "sqli") || HasRecentWPSecurityEvidence(dir, "login") {
		t.Fatal("missing logs must not be presented as evidence")
	}
	for _, delta := range []time.Duration{-time.Hour, -48 * time.Hour, 2 * time.Hour} {
		occurred := time.Now().UTC().Add(delta)
		login := "203.0.113.10 [" + occurred.Format(time.RFC3339) + "] OLS_WPANEL_LOGIN_FAILED\n"
		access := `203.0.113.10 - - [` + occurred.Format("02/Jan/2006:15:04:05 -0700") + `] "GET / HTTP/1.1" 403 0 "-" "-" ols_security="sqli" ols_autoban="0"` + "\n"
		for name, content := range map[string]string{wpSecurityLoginLog: login, wpSecurityAccessLog: access} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
		}
		want := delta == -time.Hour
		if HasRecentWPSecurityEvidence(dir, "sqli") != want || HasRecentWPSecurityEvidence(dir, "login") != want {
			t.Fatalf("recent evidence delta=%v, want %v", delta, want)
		}
	}
	if HasRecentWPSecurityEvidence(dir, "unsupported") {
		t.Fatal("unknown evidence kind accepted")
	}
	observed := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	line := "203.0.113.10 [" + observed.Format(time.RFC3339) + "] OLS_WPANEL_LOGIN_FAILED"
	if err := os.WriteFile(filepath.Join(dir, wpSecurityLoginLog), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if HasRecentWPSecurityEvidence(dir, "login") {
		t.Fatal("unfinished trailing event must not be accepted as live evidence")
	}
	if err := os.WriteFile(filepath.Join(dir, wpSecurityLoginLog), []byte(line+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if HasRecentWPSecurityEvidence(dir, "login", observed.Add(time.Second)) || !HasRecentWPSecurityEvidence(dir, "login", observed.Add(-time.Second)) {
		t.Fatal("evidence must satisfy the caller's configuration-activation cutoff")
	}
}
