package executor

import (
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	wpSecurityLegacyLog = "wp-security.log"
	wpSecurityAccessLog = "access.log"
	wpSecurityLoginLog  = "wp-login-security.log"
)

var (
	// The entire record, including escaped request/header fields and the final
	// server environment markers, must match. A marker embedded in a User-Agent
	// or Referer cannot authenticate an application-generated 403.
	olsTrustedSecurityLogRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ((?:\\.|[^" ])+) [^"]*" ([0-9]{3}) \S+ "(?:\\.|[^"])*" "((?:\\.|[^"])*)"(?: peer=(\S+))? ols_security="(sqli|sensitive|uploads_php|xmlrpc|-)" ols_autoban="([01-])"$`)
	wpLoginFailureLogRe     = regexp.MustCompile(`^(\S+) \[([^\]]+)\] OLS_WPANEL_LOGIN_FAILED$`)
)

type wpSecurityLogEvidence struct {
	ip, method, uri, userAgent, peer string
	eventType, risk, message         string
	status                           int
	occurred                         time.Time
	trustedNative                    bool
}

func parseWPSecurityLogEvidence(line, source string, checker *searchBotIPChecker) (wpSecurityLogEvidence, bool) {
	var evidence wpSecurityLogEvidence
	if source == wpSecurityLoginLog {
		match := wpLoginFailureLogRe.FindStringSubmatch(line)
		if len(match) != 3 || net.ParseIP(match[1]) == nil {
			return evidence, false
		}
		occurred, err := time.Parse(time.RFC3339Nano, match[2])
		if err != nil {
			return evidence, false
		}
		evidence = wpSecurityLogEvidence{
			ip: match[1], method: "AUTH", uri: "WordPress authentication", occurred: occurred,
			eventType: SecurityEventWPLoginFailed, risk: "medium", message: "WordPress 认证钩子记录的真实登录失败",
		}
		return evidence, true
	}
	if source != wpSecurityAccessLog && source != wpSecurityLegacyLog {
		return evidence, false
	}
	match := combinedLogRe.FindStringSubmatch(line)
	if len(match) != 7 || net.ParseIP(strings.TrimSpace(match[1])) == nil {
		return evidence, false
	}
	evidence.ip, evidence.method = strings.TrimSpace(match[1]), match[3]
	evidence.uri, evidence.userAgent = normalizeLoggedURI(match[4]), strings.TrimSpace(match[6])
	evidence.status, _ = strconv.Atoi(match[5])
	evidence.occurred = parseWebAccessTime(match[2])
	if evidence.occurred.IsZero() {
		return wpSecurityLogEvidence{}, false
	}
	var trusted []string
	if source == wpSecurityAccessLog {
		trusted = olsTrustedSecurityLogRe.FindStringSubmatch(line)
		if len(trusted) == 10 && (trusted[7] == "" || trusted[7] == "-" || net.ParseIP(trusted[7]) != nil) {
			evidence.peer, evidence.trustedNative = trusted[7], true
		} else {
			trusted = nil
		}
	}
	if !evidence.trustedNative {
		evidence.peer = accessLogPeer(line)
	}
	// Preserve the original connection peer before trusting a rewritten client
	// IP, a denial marker, or one of the panel's loopback verification paths.
	if suspiciousClientIPAttribution(evidence.ip, evidence.peer) {
		evidence.eventType, evidence.risk, evidence.message = "client_ip_spoof", "high", "客户端 IP Header 归属异常"
		return evidence, true
	}
	if isWPSecurityReadOnlyProbe(evidence) {
		return wpSecurityLogEvidence{}, false
	}
	if evidence.trustedNative {
		if evidence.status == 403 {
			// Use the complete parser's escaped fields, not a prefix that may
			// stop inside a quoted client header.
			evidence.userAgent = strings.TrimSpace(trusted[6])
			switch trusted[8] {
			case "sqli":
				evidence.eventType, evidence.risk, evidence.message = SecurityEventSQLiBlocked, "high", "OpenLiteSpeed 规则标记确认 SQL 注入请求已在 PHP 前拒绝"
			case "sensitive":
				evidence.eventType, evidence.risk, evidence.message = SecurityEventSensitiveFileScan, "medium", "OpenLiteSpeed 已拒绝敏感文件访问"
			case "uploads_php":
				evidence.eventType, evidence.risk, evidence.message = SecurityEventSuspiciousPHP, "high", "OpenLiteSpeed 已拒绝上传目录中的 PHP 脚本访问"
			case "xmlrpc":
				evidence.eventType, evidence.risk, evidence.message = SecurityEventXMLRPCBlocked, "low", "OpenLiteSpeed 已按站点设置拒绝 XML-RPC 访问"
			}
			if evidence.eventType != "" {
				return evidence, true
			}
		}
	}
	evidence.eventType, evidence.risk, evidence.message = classifySecurityEvent(evidence.method, evidence.uri, evidence.userAgent, evidence.ip, evidence.status, checker)
	return evidence, true
}

func isWPSecurityReadOnlyProbe(evidence wpSecurityLogEvidence) bool {
	ip := net.ParseIP(evidence.ip)
	peer := net.ParseIP(evidence.peer)
	if !evidence.trustedNative || evidence.method != "HEAD" || ip == nil || !ip.IsLoopback() || (evidence.peer != "-" && (peer == nil || !peer.IsLoopback())) {
		return false
	}
	// These exact loopback HEAD paths are reserved for the panel's harmless
	// verification. No SQLi payload or authentication failure is generated.
	// Minimal security logs intentionally omit User-Agent, so it is not a gate.
	switch evidence.uri {
	case "/.git/ols-wpanel-readonly-security-probe",
		"/wp-content/uploads/ols-wpanel-readonly-security-probe.php",
		"/xmlrpc.php",
		"/.well-known/acme-challenge/ols-wpanel-readonly-security-probe",
		"/ols-wpanel-readonly-security-control-not-a-file":
		return true
	default:
		return false
	}
}

// HasRecentWPSecurityEvidence reports observed events, never enabled-state claims
// based on an empty file. SQLi evidence requires this panel's native OLS marker;
// login evidence requires the dedicated WordPress authentication-failure format.
func HasRecentWPSecurityEvidence(logDir, kind string, since ...time.Time) bool {
	if !wpSecurityLogDirAllowed(logDir) {
		return false
	}
	source, eventType := "", ""
	switch kind {
	case "sqli":
		source, eventType = wpSecurityAccessLog, SecurityEventSQLiBlocked
	case "login":
		source, eventType = wpSecurityLoginLog, SecurityEventWPLoginFailed
	default:
		return false
	}
	now := time.Now().UTC()
	earliest := now.Add(-24 * time.Hour)
	for _, minimum := range since {
		if minimum.After(earliest) {
			earliest = minimum
		}
	}
	for _, line := range tailCompleteWPSecurityEvidenceLines(filepath.Join(logDir, source), 1000) {
		evidence, ok := parseWPSecurityLogEvidence(line, source, nil)
		if ok && evidence.eventType == eventType && !evidence.occurred.Before(earliest) && !evidence.occurred.After(now.Add(time.Minute)) {
			return true
		}
	}
	return false
}

func tailCompleteWPSecurityEvidenceLines(path string, maxLines int) []string {
	lines := tailLogLines(path, maxLines+1)
	f, err := openSafeWPSecurityLog(path, wpSecurityLogDirAllowed)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() <= 0 {
		return nil
	}
	last := []byte{0}
	if _, err := f.ReadAt(last, info.Size()-1); err != nil {
		return nil
	}
	if last[0] != '\n' && len(lines) > 0 {
		lines = lines[:len(lines)-1]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return lines
}
