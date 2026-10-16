package executor

import (
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

// WordPress security event types. sqli_blocked means OpenLiteSpeed rejected the request
// before PHP; other types are investigative evidence, not proof of a vulnerability or successful attack.
const (
	SecurityEventSensitiveFileScan = "sensitive_file_scan"
	SecurityEventSQLiProbe         = "sqli_probe"
	SecurityEventSQLiBlocked       = "sqli_blocked"
	SecurityEventFakeSearchBot     = "fake_search_bot"
	SecurityEventSuspiciousPHP     = "suspicious_php"
	SecurityEventWPLoginFailed     = "wp_login_failed"
	SecurityEventXMLRPCBlocked     = "xmlrpc_blocked"
)

type WPSecurityReportItem struct {
	IPAddress      string   `json:"ip_address"`
	Domain         string   `json:"domain"`
	RiskLevel      string   `json:"risk_level"`
	Recommendation string   `json:"recommendation"`
	FirstSeen      string   `json:"first_seen"`
	LastSeen       string   `json:"last_seen"`
	EventCount     int      `json:"event_count"`
	SamplePaths    []string `json:"sample_paths"`
	Evidence       []string `json:"evidence"`
	Types          []string `json:"types"`
	CopyText       string   `json:"copy_text"`
}

type wpSecuritySite struct {
	ID     int
	Domain string
	LogDir string
}

type wpSecurityAggregate struct {
	ip         string
	domain     string
	firstSeen  time.Time
	lastSeen   time.Time
	events     int
	paths      map[string]int
	evidence   map[string]bool
	eventTypes map[string]bool
	riskLevel  string
}

type searchBotIPChecker struct {
	googlebot []string
	bingbot   []string
}

var (
	// Combined log format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
	combinedLogRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^" ]+) [^"]*" ([0-9]{3}) \S+ "[^"]*" "([^"]*)"`)
	webErrorRe    = regexp.MustCompile(`client: ([^,]+), server: ([^,]+), request: "([A-Z]+) ([^" ]+) [^"]*"`)

	// Conservative SQL injection detection: record without blocking, prioritizing fewer false positives.
	sqliProbePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)union\s+select`),
		regexp.MustCompile(`(?i)sleep\s*\(`),
		regexp.MustCompile(`(?i)benchmark\s*\(`),
		regexp.MustCompile(`(?i)information_schema`),
		regexp.MustCompile(`(?i)\bxp_cmdshell\b`),
		regexp.MustCompile(`(?i)\bwaitfor\s+delay\b`),
		regexp.MustCompile(`(?i)\bload_file\s*\(`),
		regexp.MustCompile(`(?i)\binto\s+outfile\b`),
		// Accept both ' OR 1=1 and the classic ' OR '1'='1 with quoted operands.
		regexp.MustCompile(`(?i)(?:'|%27)\s*or\s*(?:'|%27)?\s*[0-9]+\s*(?:'|%27)?\s*=\s*(?:'|%27)?\s*[0-9]+`),
		regexp.MustCompile(`(?i)0x[0-9a-f]{16,}`),
		regexp.MustCompile(`(?i)(?:;|%3b)\s*(?:drop|insert|update|delete)\s+`),
	}
	highConfidenceSQLiPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)union(?:\s|%20|\+|/\*.*?\*/)+select(?:\s|%20|\+|/\*.*?\*/)+.*(?:from|information_schema)`),
		regexp.MustCompile(`(?i)(?:sleep|pg_sleep)(?:\s|%20|\+)*(?:\(|%28)(?:\s|%20|\+)*[0-9]+(?:\s|%20|\+)*(?:\)|%29)`),
		regexp.MustCompile(`(?i)benchmark(?:\s|%20|\+)*(?:\(|%28)(?:\s|%20|\+)*[0-9]+(?:\s|%20|\+)*(?:,|%2c)`),
		regexp.MustCompile(`(?i)(?:union(?:\s|%20|\+)+select|select(?:\s|%20|\+)+).*information_schema`),
		regexp.MustCompile(`(?i)(?:load_file(?:\s|%20|\+)*(?:\(|%28).*(?:'|%27)|into(?:\s|%20|\+)+outfile(?:\s|%20|\+)+(?:'|%27))`),
		regexp.MustCompile(`(?i)(?:;|%3b)(?:\s|%20|\+)*(?:drop|alter|truncate)(?:\s|%20|\+)+(?:table|database)(?:\s|%20|\+)+`),
		regexp.MustCompile(`(?i)(?:'|%27)(?:\s|%20|\+)*or(?:\s|%20|\+)+(?:'|%27)?[0-9]+(?:'|%27)?(?:\s|%20|\+)*(?:=|%3d)(?:\s|%20|\+)*(?:'|%27)?[0-9]+(?:'|%27)?(?:\s|%20|\+)*(?:--|%2d%2d|#|%23)`),
	}

	// Sensitive-file scan patterns, kept consistent with the fail2ban filter.
	sensitiveFilePatterns = []string{
		".env", ".git", "config.bak", "wp-config.php", "secrets.json", "secrets.yaml", "secrets.yml",
		"settings.py", "application.properties", "config.toml", ".sql", ".tar", ".gz", ".zip",
		".old", ".swp", ".save", ".DS_Store",
	}

	wpSecurityReportCacheMu sync.Mutex
	wpSecurityReportCache   = map[int]wpSecurityReportCacheEntry{}
)

type wpSecurityReportCacheEntry struct {
	createdAt time.Time
	items     []WPSecurityReportItem
}

func BuildWPSecurityReport(limit int) ([]WPSecurityReportItem, error) {
	if limit <= 0 || limit > 100 {
		limit = 30
	}

	if items, ok := getWPSecurityReportCache(limit); ok {
		return items, nil
	}

	sites, err := listWordPressSecuritySites(database.GetDB())
	if err != nil {
		return nil, err
	}

	checker := newSearchBotIPChecker(database.GetDB())
	aggregates := map[string]*wpSecurityAggregate{}
	for _, site := range sites {
		if !wpSecurityLogDirAllowed(site.LogDir) {
			continue
		}
		for _, source := range []string{wpSecurityLegacyLog, wpSecurityAccessLog, wpSecurityLoginLog} {
			readWPSecurityLog(site, filepath.Join(site.LogDir, source), aggregates, checker)
		}
		readWebErrorLog(site, filepath.Join(site.LogDir, "error.log"), aggregates)
	}

	items := make([]WPSecurityReportItem, 0, len(aggregates))
	for _, agg := range aggregates {
		items = append(items, buildWPSecurityReportItem(agg))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].RiskLevel != items[j].RiskLevel {
			return riskWeight(items[i].RiskLevel) > riskWeight(items[j].RiskLevel)
		}
		if items[i].EventCount != items[j].EventCount {
			return items[i].EventCount > items[j].EventCount
		}
		return items[i].LastSeen > items[j].LastSeen
	})
	if len(items) > limit {
		items = items[:limit]
	}
	setWPSecurityReportCache(limit, items)
	return items, nil
}

func getWPSecurityReportCache(limit int) ([]WPSecurityReportItem, bool) {
	wpSecurityReportCacheMu.Lock()
	defer wpSecurityReportCacheMu.Unlock()

	entry, ok := wpSecurityReportCache[limit]
	if !ok || time.Since(entry.createdAt) > 30*time.Second {
		return nil, false
	}
	return cloneWPSecurityReportItems(entry.items), true
}

func setWPSecurityReportCache(limit int, items []WPSecurityReportItem) {
	wpSecurityReportCacheMu.Lock()
	defer wpSecurityReportCacheMu.Unlock()

	wpSecurityReportCache[limit] = wpSecurityReportCacheEntry{
		createdAt: time.Now(),
		items:     cloneWPSecurityReportItems(items),
	}
}

func cloneWPSecurityReportItems(items []WPSecurityReportItem) []WPSecurityReportItem {
	out := make([]WPSecurityReportItem, len(items))
	for i, item := range items {
		out[i] = item
		out[i].SamplePaths = append([]string(nil), item.SamplePaths...)
		out[i].Evidence = append([]string(nil), item.Evidence...)
		// append(nil, x...) returns nil for an empty slice, encoding as JSON null.
		// Unclassified IPs commonly have empty Types; preserve a non-nil empty slice so frontend
		// x-for iteration does not fail on null.
		out[i].Types = append([]string{}, item.Types...)
	}
	return out
}

func listWordPressSecuritySites(db *sql.DB) ([]wpSecuritySite, error) {
	rows, err := db.Query(`SELECT id, domain, log_dir FROM websites WHERE site_type = 'wordpress' ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sites []wpSecuritySite
	for rows.Next() {
		var site wpSecuritySite
		if err := rows.Scan(&site.ID, &site.Domain, &site.LogDir); err == nil {
			sites = append(sites, site)
		}
	}
	return sites, rows.Err()
}

func readWPSecurityLog(site wpSecuritySite, path string, aggregates map[string]*wpSecurityAggregate, checker *searchBotIPChecker) {
	for _, line := range tailLogLines(path, 1000) {
		evidence, ok := parseWPSecurityLogEvidence(line, filepath.Base(path), checker)
		if !ok {
			continue
		}
		// access.log also contains ordinary traffic; only classified security
		// events belong in this report. Preserve the legacy dedicated-log view.
		if filepath.Base(path) != wpSecurityLegacyLog && evidence.eventType == "" {
			continue
		}
		addWPSecurityEvent(aggregates, site.Domain, evidence.ip, evidence.occurred, evidence.method, evidence.uri, evidence.status, evidence.message, evidence.eventType, evidence.risk)
	}
}

func readWebErrorLog(site wpSecuritySite, path string, aggregates map[string]*wpSecurityAggregate) {
	for _, line := range tailLogLines(path, 1000) {
		m := webErrorRe.FindStringSubmatch(line)
		if len(m) != 5 {
			continue
		}
		reqPath := normalizeLoggedURI(m[4])
		reason := ""
		eventType := ""
		risk := "low"
		switch {
		case strings.Contains(line, "Primary script unknown"):
			// LSPHP reports a nonexistent PHP script, indicating PHP probing.
			// One occurrence retains the pre-classification high-risk behavior.
			reason = "Primary script unknown：不存在 PHP 文件进入 LSPHP"
			eventType = SecurityEventSuspiciousPHP
			risk = "high"
		case strings.Contains(line, "open()") && strings.Contains(line, "failed (2: No such file or directory)"):
			reason = "open() failed：不存在文件访问"
			// Most generic missing-file errors are harmless image/CSS/JS 404s. Classify only .php
			// requests as PHP probing; leave others unclassified so they reach medium risk only after
			// three events, preserving the previous threshold and avoiding noise from a single missing image.
			if strings.HasSuffix(strings.ToLower(reqPath), ".php") {
				eventType = SecurityEventSuspiciousPHP
				risk = "medium"
			}
		default:
			continue
		}
		addWPSecurityEvent(aggregates, site.Domain, strings.TrimSpace(m[1]), parseWebErrorTime(line), m[3], reqPath, 0, reason, eventType, risk)
	}
}

func addWPSecurityEvent(aggregates map[string]*wpSecurityAggregate, domain, ip string, seen time.Time, method, uri string, status int, reason, eventType, risk string) {
	if ip == "" || uri == "" {
		return
	}
	key := domain + "|" + ip
	agg := aggregates[key]
	if agg == nil {
		agg = &wpSecurityAggregate{
			ip:         ip,
			domain:     domain,
			paths:      map[string]int{},
			evidence:   map[string]bool{},
			eventTypes: map[string]bool{},
			riskLevel:  "low",
		}
		aggregates[key] = agg
	}
	agg.events++
	if !seen.IsZero() {
		if agg.firstSeen.IsZero() || seen.Before(agg.firstSeen) {
			agg.firstSeen = seen
		}
		if agg.lastSeen.IsZero() || seen.After(agg.lastSeen) {
			agg.lastSeen = seen
		}
	}
	agg.paths[method+" "+uri]++
	if status > 0 {
		agg.evidence[fmt.Sprintf("%s（HTTP %d）", reason, status)] = true
	} else {
		agg.evidence[reason] = true
	}
	if eventType != "" {
		agg.eventTypes[eventType] = true
		if eventRiskWeight(risk) > eventRiskWeight(agg.riskLevel) {
			agg.riskLevel = risk
		}
	}
}

// classifySecurityEvent uses request features and the actual response to identify event types.
func classifySecurityEvent(method, uri, ua, ip string, status int, checker *searchBotIPChecker) (eventType, riskLevel, message string) {
	lowerURI := strings.ToLower(uri)

	// Check SQL injection first because its query string may also match other patterns.
	// HTTP 403 alone may be generated by WordPress, a plugin or a CDN. Only
	// parseWPSecurityLogEvidence can confirm this panel's native blocking marker.
	if !isWordPressCoreSearchRequest(uri) && isSQLiProbe(uri) {
		return SecurityEventSQLiProbe, "high", "SQL 注入探测"
	}

	// Fake search engine bot.
	if isFakeSearchBot(ua, ip, checker) {
		return SecurityEventFakeSearchBot, "medium", "UA 声明为搜索引擎爬虫，但来源 IP 不在官方段"
	}

	// Check decoded sensitive paths too: OpenLiteSpeed decodes $uri before selecting the
	// security log, but the combined log keeps the original request URI, such as %2eenv.
	sensitiveURIs := []string{lowerURI}
	if decoded, err := url.QueryUnescape(uri); err == nil && decoded != uri {
		sensitiveURIs = append(sensitiveURIs, strings.ToLower(decoded))
	}
	for _, candidate := range sensitiveURIs {
		for _, pattern := range sensitiveFilePatterns {
			if strings.Contains(candidate, pattern) {
				return SecurityEventSensitiveFileScan, "medium", "敏感文件扫描"
			}
		}
	}

	// Nonexistent PHP file probe.
	if strings.HasSuffix(lowerURI, ".php") && status == 404 {
		return SecurityEventSuspiciousPHP, "low", "不存在 PHP 文件探测"
	}

	return "", "low", "WordPress 异常路径访问"
}

func isHighConfidenceSQLi(uri string) bool {
	if isWordPressCoreSearchRequest(uri) {
		return false
	}
	for _, re := range highConfidenceSQLiPatterns {
		if re.MatchString(uri) {
			return true
		}
	}
	return false
}

func isWordPressCoreSearchRequest(requestURI string) bool {
	parsed, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return false
	}
	values := parsed.Query()
	if len(values) != 1 {
		return false
	}
	switch parsed.Path {
	case "/", "/index.php":
		return len(values["s"]) == 1
	case "/wp-json/wp/v2/posts", "/wp-json/wp/v2/posts/", "/wp-json/wp/v2/pages", "/wp-json/wp/v2/pages/":
		return len(values["search"]) == 1
	default:
		return false
	}
}

// isSQLiProbe checks both raw and URL-decoded URIs. Logs preserve encoded spaces
// such as %20 or +, so raw matching alone would miss payloads such as UNION%20SELECT.
func isSQLiProbe(uri string) bool {
	candidates := []string{uri}
	if decoded, err := url.QueryUnescape(uri); err == nil && decoded != uri {
		candidates = append(candidates, decoded)
	}
	for _, candidate := range candidates {
		for _, re := range sqliProbePatterns {
			if re.MatchString(candidate) {
				return true
			}
		}
	}
	return false
}

func isFakeSearchBot(ua, ip string, checker *searchBotIPChecker) bool {
	lowerUA := strings.ToLower(ua)
	if checker == nil {
		return false
	}
	if strings.Contains(lowerUA, "googlebot") {
		if len(checker.googlebot) == 0 {
			return false
		}
		return !checker.containsGooglebot(ip)
	}
	if strings.Contains(lowerUA, "bingbot") {
		if len(checker.bingbot) == 0 {
			return false
		}
		return !checker.containsBingbot(ip)
	}
	return false
}

func newSearchBotIPChecker(db *sql.DB) *searchBotIPChecker {
	checker := &searchBotIPChecker{}
	if db == nil {
		return checker
	}
	var googleIPs, bingIPs string
	_ = db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'googlebot_ips'`).Scan(&googleIPs)
	_ = db.QueryRow(`SELECT svalue FROM security_settings WHERE skey = 'bingbot_ips'`).Scan(&bingIPs)
	checker.googlebot = parseIPRangeLines(googleIPs)
	checker.bingbot = parseIPRangeLines(bingIPs)
	return checker
}

func (c *searchBotIPChecker) containsGooglebot(ip string) bool {
	if c == nil {
		return false
	}
	return ipInRanges(ip, c.googlebot)
}

func (c *searchBotIPChecker) containsBingbot(ip string) bool {
	if c == nil {
		return false
	}
	return ipInRanges(ip, c.bingbot)
}

func parseIPRangeLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func ipInRanges(ip string, ranges []string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, r := range ranges {
		if strings.Contains(r, "/") {
			_, ipNet, err := net.ParseCIDR(r)
			if err == nil && ipNet.Contains(parsedIP) {
				return true
			}
		} else {
			if target := net.ParseIP(r); target != nil && target.Equal(parsedIP) {
				return true
			}
		}
	}
	return false
}

func sortedEventTypes(types map[string]bool) []string {
	out := make([]string, 0, len(types))
	for t := range types {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func buildWPSecurityReportItem(agg *wpSecurityAggregate) WPSecurityReportItem {
	paths := topSecurityPaths(agg.paths, 8)
	evidence := sortedEvidence(agg.evidence, 6)
	risk := classifyWPSecurityRisk(agg, paths, evidence)
	types := sortedEventTypes(agg.eventTypes)
	item := WPSecurityReportItem{
		IPAddress:      agg.ip,
		Domain:         agg.domain,
		RiskLevel:      risk,
		Recommendation: recommendationForRisk(risk),
		FirstSeen:      formatReportTime(agg.firstSeen),
		LastSeen:       formatReportTime(agg.lastSeen),
		EventCount:     agg.events,
		SamplePaths:    paths,
		Evidence:       evidence,
		Types:          types,
	}
	item.CopyText = buildWPSecurityCopyText(item)
	return item
}

func classifyWPSecurityRisk(agg *wpSecurityAggregate, paths, evidence []string) string {
	// Use a high-risk event classification directly.
	if agg.riskLevel == "high" || agg.events >= 10 || hasHighSignalPath(paths) || hasEvidence(evidence, "Primary script unknown") {
		return "高"
	}
	if agg.riskLevel == "medium" || agg.events >= 3 {
		return "中"
	}
	return "低"
}

func recommendationForRisk(risk string) string {
	switch risk {
	case "高":
		return "建议管理员结合 IP 来源确认后手动封禁"
	case "中":
		return "建议观察或结合 IP 信息判断"
	default:
		return "建议先观察"
	}
}

func buildWPSecurityCopyText(item WPSecurityReportItem) string {
	return fmt.Sprintf(`IP: %s
站点: %s
时间: %s - %s
事件次数: %d
风险等级: %s
访问路径样本:
%s
错误/证据:
%s
面板建议: %s
说明: 面板仅做本地日志统计，未自动封禁。请管理员结合 IP 来源、业务访问情况和 AI/IP 查询工具综合判断。`,
		item.IPAddress,
		item.Domain,
		defaultIfEmpty(item.FirstSeen, "未知"),
		defaultIfEmpty(item.LastSeen, "未知"),
		item.EventCount,
		item.RiskLevel,
		formatReportList(item.SamplePaths),
		formatReportList(item.Evidence),
		item.Recommendation,
	)
}

func topSecurityPaths(paths map[string]int, limit int) []string {
	type kv struct {
		Path  string
		Count int
	}
	items := make([]kv, 0, len(paths))
	for path, count := range paths {
		items = append(items, kv{Path: path, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count != items[j].Count {
			return items[i].Count > items[j].Count
		}
		return items[i].Path < items[j].Path
	})
	out := make([]string, 0, minInt(limit, len(items)))
	for i := 0; i < len(items) && i < limit; i++ {
		out = append(out, fmt.Sprintf("%s × %d", items[i].Path, items[i].Count))
	}
	return out
}

func sortedEvidence(evidence map[string]bool, limit int) []string {
	out := make([]string, 0, len(evidence))
	for e := range evidence {
		out = append(out, e)
	}
	sort.Strings(out)
	if len(out) > limit {
		return out[:limit]
	}
	return out
}

func hasHighSignalPath(paths []string) bool {
	needles := []string{"phpinfo", "config", "database", ".env", "test.php", "phptest.php", "settings.php", "wp-config"}
	for _, path := range paths {
		lower := strings.ToLower(path)
		for _, needle := range needles {
			if strings.Contains(lower, needle) {
				return true
			}
		}
	}
	return false
}

func hasEvidence(evidence []string, needle string) bool {
	for _, item := range evidence {
		if strings.Contains(item, needle) {
			return true
		}
	}
	return false
}

func normalizeLoggedURI(raw string) string {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Path == "" {
		return raw
	}
	return parsed.RequestURI()
}

func parseWebAccessTime(raw string) time.Time {
	t, _ := time.Parse("02/Jan/2006:15:04:05 -0700", raw)
	return t
}

func parseWebErrorTime(line string) time.Time {
	if len(line) < len("2006/01/02 15:04:05") {
		return time.Time{}
	}
	t, _ := time.ParseInLocation("2006/01/02 15:04:05", line[:19], time.Local)
	return t
}

func tailLogLines(path string, maxLines int, allowedDirs ...func(string) bool) []string {
	allowed := wpSecurityLogDirAllowed
	if len(allowedDirs) > 0 {
		allowed = allowedDirs[0]
	}
	f, err := openSafeWPSecurityLog(path, allowed)
	if err != nil {
		return nil
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil || info.Size() <= 0 {
		return nil
	}
	const maxBytes int64 = 512 * 1024
	start := int64(0)
	if info.Size() > maxBytes {
		start = info.Size() - maxBytes
	}
	buf := make([]byte, info.Size()-start)
	read, err := f.ReadAt(buf, start)
	if err != nil && read == 0 {
		return nil
	}
	buf = buf[:read]
	lines := strings.Split(string(buf), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func isAllowedSiteLogDir(logDir string) bool {
	root, err := fail2banWebsiteLogRoot()
	if err != nil || logDir == "" || logDir != strings.TrimSpace(logDir) || strings.ContainsAny(logDir, "\r\n\x00") {
		return false
	}
	clean := filepath.Clean(logDir)
	if !filepath.IsAbs(clean) {
		return false
	}
	rel, err := filepath.Rel(filepath.Clean(root), clean)
	return err == nil && rel != "." && rel != ".." && !strings.ContainsAny(rel, `/\`)
}

// wpSecurityLogDirAllowed defaults to isAllowedSiteLogDir and can be replaced in tests.
var wpSecurityLogDirAllowed = isAllowedSiteLogDir

func formatReportTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

func formatReportList(items []string) string {
	if len(items) == 0 {
		return "- 无"
	}
	return "- " + strings.Join(items, "\n- ")
}

func defaultIfEmpty(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func riskWeight(risk string) int {
	switch risk {
	case "高":
		return 3
	case "中":
		return 2
	default:
		return 1
	}
}

// eventRiskWeight uses the English high/medium/low values from classifySecurityEvent
// and readWebErrorLog, separately from riskWeight's localized labels to avoid mismatched comparisons.
func eventRiskWeight(risk string) int {
	switch risk {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
