package cloudflaresecurity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var operationMu sync.Mutex
var cycleMu sync.Mutex
var cycleCursor int
var ErrNotFound = errors.New("网站不存在")
var idPattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
var hostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$`)

type Service struct {
	DB     *sql.DB
	Client *Client
	seal   func(int, string) (string, error)
	open   func(int, string) (string, error)
}

func NewService(db *sql.DB) *Service {
	return &Service{DB: db, Client: NewClient(), seal: func(id int, token string) (string, error) { return sealToken(db, id, token) }, open: func(id int, text string) (string, error) { return openToken(db, id, text) }}
}

type Update struct {
	Enabled   bool   `json:"enabled"`
	AccountID string `json:"account_id"`
	ZoneID    string `json:"zone_id"`
	APIToken  string `json:"api_token"`
}
type Status struct {
	SiteID             int      `json:"site_id"`
	Hostname           string   `json:"hostname"`
	Enabled            bool     `json:"enabled"`
	AccountID          string   `json:"account_id"`
	ZoneID             string   `json:"zone_id"`
	ZoneName           string   `json:"zone_name"`
	WebsiteHostnames   []string `json:"website_hostnames"`
	CoveredHostnames   []string `json:"covered_hostnames"`
	CoverageError      string   `json:"coverage_error"`
	TokenConfigured    bool     `json:"token_configured"`
	RuleID             string   `json:"rule_id"`
	SyncStatus         string   `json:"sync_status"`
	LastError          string   `json:"last_error"`
	LastSyncAt         string   `json:"last_sync_at"`
	Scope              string   `json:"scope"`
	ActiveIPCount      int      `json:"active_ip_count"`
	ActiveIPCountKnown bool     `json:"active_ip_count_known"`
	CleanupRequired    bool     `json:"cleanup_required"`
}
type storedConfig struct {
	Status
	Ciphertext  string
	Ref         string
	RulesetID   string
	AppliedHash string
	PendingHash string
}

func (s *Service) websiteHost(ctx context.Context, id int) (string, error) {
	if s.DB == nil {
		return "", errors.New("网站数据库暂不可用")
	}
	var host string
	err := s.DB.QueryRowContext(ctx, `SELECT domain FROM websites WHERE id=?`, id).Scan(&host)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", errors.New("读取网站信息失败")
	}
	return canonicalHost(host)
}
func (s *Service) load(ctx context.Context, id int) (storedConfig, error) {
	if s.DB == nil {
		return storedConfig{}, errors.New("网站数据库暂不可用")
	}
	cfg := storedConfig{Status: Status{SiteID: id, Scope: "shared_web_bans", SyncStatus: "disabled", WebsiteHostnames: []string{}, CoveredHostnames: []string{}}}
	var enabled int
	var covered string
	err := s.DB.QueryRowContext(ctx, `SELECT hostname,enabled,account_id,zone_id,zone_name,covered_hostnames,coverage_error,token_ciphertext,rule_ref,ruleset_id,rule_id,applied_hash,pending_hash,sync_status,last_error,last_sync_at FROM website_cloudflare_security WHERE site_id=?`, id).Scan(&cfg.Hostname, &enabled, &cfg.AccountID, &cfg.ZoneID, &cfg.ZoneName, &covered, &cfg.CoverageError, &cfg.Ciphertext, &cfg.Ref, &cfg.RulesetID, &cfg.RuleID, &cfg.AppliedHash, &cfg.PendingHash, &cfg.SyncStatus, &cfg.LastError, &cfg.LastSyncAt)
	if errors.Is(err, sql.ErrNoRows) {
		return cfg, nil
	}
	if err != nil {
		return cfg, errors.New("读取 Cloudflare 网站设置失败")
	}
	cfg.Enabled = enabled == 1
	cfg.TokenConfigured = cfg.Ciphertext != ""
	cfg.CleanupRequired = cfg.RuleID != "" || cfg.PendingHash != ""
	if json.Unmarshal([]byte(covered), &cfg.CoveredHostnames) != nil {
		return cfg, errors.New("读取 Cloudflare 已同步域名失败")
	}
	if cfg.CoveredHostnames == nil {
		cfg.CoveredHostnames = []string{}
	}
	return cfg, nil
}
func (s *Service) Get(ctx context.Context, id int) (Status, error) {
	host, err := s.websiteHost(ctx, id)
	if err != nil {
		return Status{}, err
	}
	cfg, err := s.load(ctx, id)
	if err != nil {
		return Status{}, err
	}
	if cfg.Hostname == "" {
		cfg.Hostname = host
	}
	s.populateWebsiteStatus(ctx, &cfg)
	if ips, err := s.activeIPs(ctx); err == nil {
		cfg.ActiveIPCount = len(ips)
		cfg.ActiveIPCountKnown = true
	}
	return cfg.Status, nil
}
func (s *Service) populateWebsiteStatus(ctx context.Context, cfg *storedConfig) {
	hosts, err := s.websiteHosts(ctx, cfg.SiteID)
	if err != nil {
		cfg.CoverageError = err.Error()
		if cfg.Enabled && cfg.SyncStatus == "synced" {
			cfg.SyncStatus = "pending"
		}
		return
	}
	cfg.WebsiteHostnames = hosts
	if cfg.ZoneName != "" {
		if err := checkHostSuffixes(hosts, cfg.ZoneName); err != nil {
			cfg.CoverageError = err.Error()
			if cfg.Enabled && cfg.SyncStatus == "synced" {
				cfg.SyncStatus = "pending"
			}
		}
	}
	if cfg.Enabled && cfg.RuleID != "" && cfg.SyncStatus == "synced" && !sameHosts(hosts, cfg.CoveredHostnames) {
		cfg.SyncStatus = "pending"
	}
}
func sameHosts(a, b []string) bool { return strings.Join(a, "\x00") == strings.Join(b, "\x00") }
func (s *Service) Save(ctx context.Context, id int, input Update) (Status, error) {
	operationMu.Lock()
	defer operationMu.Unlock()
	host, err := s.websiteHost(ctx, id)
	if err != nil {
		return Status{}, err
	}
	if deleting, err := s.websiteDeleting(ctx, id); err != nil {
		return Status{}, err
	} else if deleting && input.Enabled {
		return Status{}, errors.New("网站正在删除，不能启用 Cloudflare 同步；已有规则仍可停用并清理")
	}
	cfg, err := s.load(ctx, id)
	if err != nil {
		return Status{}, err
	}
	if !input.Enabled && (cfg.RuleID != "" || cfg.PendingHash != "") {
		host = cfg.Hostname
	}
	account, zoneID := strings.TrimSpace(input.AccountID), strings.TrimSpace(input.ZoneID)
	if account != "" && !idPattern.MatchString(account) || zoneID != "" && !idPattern.MatchString(zoneID) {
		return Status{}, errors.New("Account ID 与 Zone ID 应为 32 位十六进制标识")
	}
	account = strings.ToLower(account)
	zoneID = strings.ToLower(zoneID)
	token := strings.TrimSpace(input.APIToken)
	if token != "" {
		if len(token) < 20 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
			return Status{}, errors.New("Cloudflare API Token 格式错误")
		}
		for _, r := range token {
			if r < 33 || r > 126 {
				return Status{}, errors.New("Cloudflare API Token 格式错误")
			}
		}
	}
	bound := cfg.RuleID != "" || cfg.PendingHash != ""
	if zoneID == "" && cfg.ZoneID != "" && account == cfg.AccountID && host == cfg.Hostname && (bound || !input.Enabled) {
		zoneID = cfg.ZoneID
	}
	changed := cfg.AccountID != account || cfg.ZoneID != zoneID || cfg.Hostname != "" && cfg.Hostname != host
	// A pending create can have reached Cloudflare even if its response was lost.
	// Require explicit disabled cleanup before scope replacement. Token rotation
	// within the same binding must remain available when the previous token has
	// expired/revoked. Never require decrypting that old token to replace it; the
	// next read-only test/sync still checks account/zone and owned rule hashes.
	if changed && bound {
		return Status{}, errors.New("请先关闭同步并执行同步清理已有规则，再更换账户、Zone ID 或域名；同一绑定可直接更新 API Token")
	}
	zoneName := cfg.ZoneName
	if changed {
		zoneName = ""
	}
	// UI sends only account/token. Initial identification is read-only and must
	// finish before a credential/configuration is committed. Existing ownership
	// keeps its exact binding even when the old token is no longer decryptable.
	if input.Enabled && zoneID == "" {
		if account == "" {
			return Status{}, errors.New("启用前请填写 Account ID 与 API Token")
		}
		candidateToken := token
		if candidateToken == "" {
			if cfg.Ciphertext == "" {
				return Status{}, errors.New("启用前请填写 Account ID 与 API Token")
			}
			candidateToken, err = s.open(id, cfg.Ciphertext)
			if err != nil {
				return Status{}, err
			}
		}
		hosts, err := s.websiteHosts(ctx, id)
		if err != nil {
			return Status{}, err
		}
		if hosts[0] != host {
			return Status{}, errors.New("网站主域名在读取期间发生变化，请刷新后重新保存")
		}
		z, err := s.Client.resolveCoverage(ctx, account, candidateToken, hosts, nil)
		if err != nil {
			return Status{}, err
		}
		zoneID, zoneName = z.ID, z.Name
	} else if input.Enabled {
		hosts, err := s.websiteHosts(ctx, id)
		if err != nil {
			return Status{}, err
		}
		if zoneName != "" {
			if err = checkHostSuffixes(hosts, zoneName); err != nil {
				return Status{}, err
			}
		}
	}
	ciphertext := cfg.Ciphertext
	if token != "" {
		ciphertext, err = s.seal(id, token)
		if err != nil {
			return Status{}, err
		}
	}
	if input.Enabled && (account == "" || zoneID == "" || ciphertext == "") {
		return Status{}, errors.New("启用前请填写 Account ID 与 API Token，并识别网站 Zone")
	}
	ref := cfg.Ref
	if ref == "" {
		data := make([]byte, 16)
		if _, err := rand.Read(data); err != nil {
			return Status{}, errors.New("生成 Cloudflare 规则标识失败")
		}
		ref = "olswp_" + hex.EncodeToString(data) + fmt.Sprintf("_%d", id)
	}
	state := "pending"
	if !input.Enabled {
		state = "disabled"
		if cfg.RuleID != "" || cfg.PendingHash != "" {
			state = "removal_required"
		}
	}
	// A direct final DELETE transaction may complete while read-only Zone
	// discovery is in flight. Recheck existence/deletion state in the write itself.
	result, err := s.DB.ExecContext(ctx, `INSERT INTO website_cloudflare_security(site_id,hostname,enabled,account_id,zone_id,zone_name,token_ciphertext,rule_ref,sync_status) SELECT ?,?,?,?,?,?,?,?,? FROM websites WHERE id=? AND (status<>'deleting' OR ?=0) ON CONFLICT(site_id) DO UPDATE SET hostname=excluded.hostname,enabled=excluded.enabled,account_id=excluded.account_id,zone_id=excluded.zone_id,zone_name=excluded.zone_name,token_ciphertext=excluded.token_ciphertext,sync_status=excluded.sync_status,last_error='',updated_at=CURRENT_TIMESTAMP`, id, host, input.Enabled, account, zoneID, zoneName, ciphertext, ref, state, id, input.Enabled)
	if err != nil {
		return Status{}, errors.New("保存 Cloudflare 网站设置失败")
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		return Status{}, errors.New("网站已删除或正在删除，Cloudflare 设置未保存")
	}
	return s.Get(ctx, id)
}

func (s *Service) activeIPs(ctx context.Context) ([]string, error) {
	// UNION by IP rather than the latest ticket: one jail's expiry/unban cannot
	// remove an IP while another explicitly website-scoped jail still requires it.
	rows, err := s.DB.QueryContext(ctx, `SELECT DISTINCT ip_address FROM firewall_bans WHERE unbanned_at IS NULL AND source_jail IN ('olswpanel','olswpanel-404','olswpanel-login','olswpanel-sqli') AND (expires_at IS NULL OR datetime(expires_at)>datetime('now'))`)
	if err != nil {
		return nil, errors.New("读取网站自动封禁记录失败")
	}
	defer rows.Close()
	unique := map[string]bool{}
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) != nil {
			return nil, errors.New("读取网站自动封禁记录失败")
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(ip))
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLoopback() {
			return nil, errors.New("网站封禁记录包含无效 IP，Cloudflare 未同步")
		}
		unique[addr.Unmap().String()] = true
	}
	if rows.Err() != nil {
		return nil, errors.New("读取网站自动封禁记录失败")
	}
	ips := make([]string, 0, len(unique))
	for ip := range unique {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return ips, nil
}
func expression(host string, ips []string) (string, error) {
	return expressionForHosts([]string{host}, ips)
}
func canonicalJSON(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var decoded any
	if json.Unmarshal(data, &decoded) != nil {
		return string(data)
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return string(data)
	}
	return string(encoded)
}
func ruleHash(r rule) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%t\x00%s\x00%s\x00%s\x00%s", r.Ref, r.Action, r.Enabled, r.Expression, r.Description, canonicalJSON(r.ActionParameters), canonicalJSON(r.Logging))))
	return hex.EncodeToString(sum[:])
}
func desiredRule(cfg storedConfig, text string) rule {
	return rule{Ref: cfg.Ref, Action: "block", Expression: text, Enabled: true, Description: "OLS WPanel website automatic bans: " + cfg.Hostname}
}
func ownedRule(cfg storedConfig, r rule) bool {
	hosts, ok := hostsFromExpression(r.Expression)
	contains := false
	for _, host := range hosts {
		if host == cfg.Hostname {
			contains = true
		}
	}
	return ok && contains && r.Ref == cfg.Ref && r.Action == "block" && (ruleHash(r) == cfg.AppliedHash || ruleHash(r) == cfg.PendingHash)
}

func (s *Service) Test(ctx context.Context, id int) (Status, error) {
	return s.TestUpdate(ctx, id, nil)
}
func (s *Service) TestUpdate(ctx context.Context, id int, input *Update) (Status, error) {
	operationMu.Lock()
	defer operationMu.Unlock()
	host, err := s.websiteHost(ctx, id)
	if err != nil {
		return Status{}, err
	}
	cfg, err := s.load(ctx, id)
	if err != nil {
		return Status{}, err
	}
	oldAccount, oldHost, oldZone := cfg.AccountID, cfg.Hostname, cfg.ZoneID
	cfg.Hostname = host
	token := ""
	if input != nil {
		cfg.AccountID = strings.ToLower(strings.TrimSpace(input.AccountID))
		cfg.ZoneID = strings.ToLower(strings.TrimSpace(input.ZoneID))
		token = strings.TrimSpace(input.APIToken)
	}
	if cfg.ZoneID == "" && cfg.AccountID == oldAccount && host == oldHost && cfg.CleanupRequired {
		cfg.ZoneID = oldZone
	}
	if !idPattern.MatchString(cfg.AccountID) || cfg.ZoneID != "" && !idPattern.MatchString(cfg.ZoneID) {
		return Status{}, errors.New("请填写有效的 Account ID")
	}
	if token == "" {
		if cfg.Ciphertext == "" {
			return Status{}, errors.New("请填写 Cloudflare API Token")
		}
		token, err = s.open(id, cfg.Ciphertext)
		if err != nil {
			return Status{}, err
		}
	}
	if len(token) < 20 || len(token) > 512 || strings.ContainsAny(token, " \t\r\n") {
		return Status{}, errors.New("Cloudflare API Token 格式错误")
	}
	hosts, err := s.websiteHosts(ctx, id)
	if err != nil {
		return Status{}, err
	}
	if hosts[0] != host {
		return Status{}, errors.New("网站主域名在读取期间发生变化，请刷新后重新测试")
	}
	var bound *zone
	if cfg.ZoneID != "" {
		z, err := s.Client.readZone(ctx, cfg, token)
		if err != nil {
			return Status{}, err
		}
		bound = &z
	}
	z, err := s.Client.resolveCoverage(ctx, cfg.AccountID, token, hosts, bound)
	if err != nil {
		return Status{}, err
	}
	cfg.ZoneID, cfg.ZoneName = z.ID, z.Name
	if bound == nil {
		if _, err = s.Client.readZone(ctx, cfg, token); err != nil {
			return Status{}, err
		}
	}
	_, err = s.Client.entrypoint(ctx, cfg, token)
	if err != nil && !errors.Is(err, ErrAPIAbsent) {
		return Status{}, err
	}
	status, err := s.Get(ctx, id)
	status.AccountID = cfg.AccountID
	status.ZoneID = cfg.ZoneID
	status.ZoneName = cfg.ZoneName
	status.WebsiteHostnames = hosts
	status.CoverageError = ""
	status.Hostname = host
	status.TokenConfigured = true
	return status, err
}

func (s *Service) Sync(ctx context.Context, id int) (Status, error) {
	operationMu.Lock()
	defer operationMu.Unlock()
	cfg, err := s.load(ctx, id)
	if err != nil {
		return Status{}, err
	}
	if cfg.Ref == "" {
		return Status{}, errors.New("请先保存 Cloudflare 网站设置")
	}
	host, hostErr := s.websiteHost(ctx, id)
	deleting, deletionErr := s.websiteDeleting(ctx, id)
	if deletionErr != nil && !errors.Is(deletionErr, ErrNotFound) {
		return Status{}, s.fail(ctx, id, deletionErr)
	}
	if errors.Is(hostErr, ErrNotFound) || deleting {
		cfg.Enabled = false
		if _, err = s.DB.ExecContext(ctx, `UPDATE website_cloudflare_security SET enabled=0 WHERE site_id=?`, id); err != nil {
			return Status{}, s.fail(ctx, id, errors.New("保存已删除网站的 Cloudflare 停用状态失败"))
		}
	}
	if !cfg.Enabled && cfg.RuleID == "" && cfg.PendingHash == "" {
		return s.finish(ctx, cfg, "disabled", "", "", "")
	}
	var ips []string
	if cfg.Enabled {
		ips, err = s.activeIPs(ctx)
		if err != nil {
			return Status{}, s.fail(ctx, id, err)
		}
		// An empty blacklist must release the old owned rule even if a newly
		// configured hostname/alias is invalid. Cleanup uses only its saved binding.
		if len(ips) > 0 {
			if hostErr != nil {
				return Status{}, s.coverageFail(ctx, id, hostErr)
			}
			if cfg.Hostname != host {
				return Status{}, s.fail(ctx, id, errors.New("网站域名已变更，请关闭并清理原域名规则后重新配置"))
			}
		}
	}
	token, err := s.open(id, cfg.Ciphertext)
	if err != nil {
		return Status{}, s.fail(ctx, id, err)
	}
	z, err := s.Client.readZone(ctx, cfg, token)
	if err != nil {
		return Status{}, s.fail(ctx, id, err)
	}
	cfg.ZoneName = z.Name
	text := ""
	if cfg.Enabled && len(ips) > 0 {
		hosts, err := s.websiteHosts(ctx, id)
		if err != nil {
			return Status{}, s.coverageFail(ctx, id, err)
		}
		if hosts[0] != cfg.Hostname {
			return Status{}, s.coverageFail(ctx, id, errors.New("网站主域名在读取期间发生变化，请关闭并清理原域名规则后重新配置"))
		}
		if _, err = s.Client.resolveCoverage(ctx, cfg.AccountID, token, hosts, &z); err != nil {
			return Status{}, s.coverageFail(ctx, id, err)
		}
		cfg.WebsiteHostnames = hosts
		_, _ = s.DB.ExecContext(ctx, `UPDATE website_cloudflare_security SET zone_name=?,coverage_error='' WHERE site_id=?`, z.Name, id)
		text, err = expressionForHosts(hosts, ips)
		if err != nil {
			return Status{}, s.fail(ctx, id, err)
		}
	}
	wanted := desiredRule(cfg, text)
	if cfg.Enabled && text != "" {
		cfg.CoveredHostnames = cfg.WebsiteHostnames
	} else {
		cfg.CoveredHostnames = []string{}
	}
	rs, err := s.Client.entrypoint(ctx, cfg, token)
	if err != nil && !errors.Is(err, ErrAPIAbsent) {
		return Status{}, s.fail(ctx, id, err)
	}
	if errors.Is(err, ErrAPIAbsent) {
		if !cfg.Enabled || len(ips) == 0 {
			return s.finish(ctx, cfg, "disabled_or_empty", "", "", "")
		}
		if err = s.pending(ctx, id, ruleHash(wanted), "", nil); err != nil {
			return Status{}, err
		}
		cfg.PendingHash = ruleHash(wanted)
		body := map[string]any{"name": "OLS WPanel website security", "description": "Owned website automatic ban rules", "kind": "zone", "phase": phase, "rules": []rule{wanted}}
		if err = s.Client.request(ctx, token, http.MethodPost, "/zones/"+cfg.ZoneID+"/rulesets", body, &rs); err != nil {
			return Status{}, s.fail(ctx, id, err)
		}
		if !idPattern.MatchString(rs.ID) || rs.Kind != "zone" || rs.Phase != phase {
			return Status{}, s.fail(ctx, id, errors.New("Cloudflare 新规则集响应不匹配，稍后将核对"))
		}
		found := false
		for _, r := range rs.Rules {
			if r.Ref == cfg.Ref && ownedRule(cfg, r) && idPattern.MatchString(r.ID) {
				wanted.ID = r.ID
				found = true
			}
		}
		if !found {
			return Status{}, s.fail(ctx, id, errors.New("Cloudflare 新规则响应不匹配，稍后将核对"))
		}
		return s.finish(ctx, cfg, "synced", rs.ID, wanted.ID, ruleHash(wanted))
	}
	var current *rule
	for i := range rs.Rules {
		r := rs.Rules[i]
		if r.Ref == cfg.Ref || cfg.RuleID != "" && r.ID == cfg.RuleID {
			if current != nil || !ownedRule(cfg, r) || !idPattern.MatchString(r.ID) {
				return Status{}, s.fail(ctx, id, errors.New("Cloudflare 受管规则被外部修改或所有权不匹配，请人工核对"))
			}
			current = &rs.Rules[i]
		}
	}
	if !cfg.Enabled || len(ips) == 0 {
		if current != nil {
			if err = s.Client.request(ctx, token, http.MethodDelete, "/zones/"+cfg.ZoneID+"/rulesets/"+rs.ID+"/rules/"+current.ID, nil, nil); err != nil && !errors.Is(err, ErrAPIAbsent) {
				return Status{}, s.fail(ctx, id, err)
			}
		}
		state := "synced"
		if !cfg.Enabled {
			state = "disabled"
		}
		return s.finish(ctx, cfg, state, "", "", "")
	}
	if current != nil && ruleHash(*current) == ruleHash(wanted) {
		return s.finish(ctx, cfg, "synced", rs.ID, current.ID, ruleHash(wanted))
	}
	if err = s.pending(ctx, id, ruleHash(wanted), rs.ID, current); err != nil {
		return Status{}, err
	}
	var result ruleset
	method, path := http.MethodPost, "/zones/"+cfg.ZoneID+"/rulesets/"+rs.ID+"/rules"
	if current != nil {
		method = http.MethodPatch
		path += "/" + current.ID
	}
	if err = s.Client.request(ctx, token, method, path, wanted, &result); err != nil {
		return Status{}, s.fail(ctx, id, err)
	}
	if result.ID != rs.ID {
		return Status{}, s.fail(ctx, id, errors.New("Cloudflare 规则响应不匹配，稍后将核对"))
	}
	var matched *rule
	for i := range result.Rules {
		r := &result.Rules[i]
		if r.Ref == cfg.Ref {
			if matched != nil || !idPattern.MatchString(r.ID) || current != nil && r.ID != current.ID || ruleHash(*r) != ruleHash(wanted) {
				return Status{}, s.fail(ctx, id, errors.New("Cloudflare 规则响应不匹配，稍后将核对"))
			}
			matched = r
		}
	}
	if matched == nil {
		return Status{}, s.fail(ctx, id, errors.New("Cloudflare 规则响应不匹配，稍后将核对"))
	}
	return s.finish(ctx, cfg, "synced", rs.ID, matched.ID, ruleHash(wanted))
}
func (s *Service) pending(ctx context.Context, id int, hash, rulesetID string, current *rule) error {
	var err error
	if current != nil {
		// A previous uncertain write may already be present remotely. Preserve
		// this verified baseline before replacing pending with a newer target.
		hosts, _ := hostsFromExpression(current.Expression)
		covered, _ := json.Marshal(hosts)
		_, err = s.DB.ExecContext(ctx, `UPDATE website_cloudflare_security SET ruleset_id=?,rule_id=?,applied_hash=?,pending_hash=?,covered_hostnames=?,sync_status='pending',updated_at=CURRENT_TIMESTAMP WHERE site_id=?`, rulesetID, current.ID, ruleHash(*current), hash, string(covered), id)
	} else {
		_, err = s.DB.ExecContext(ctx, `UPDATE website_cloudflare_security SET pending_hash=?,sync_status='pending',updated_at=CURRENT_TIMESTAMP WHERE site_id=?`, hash, id)
	}
	if err != nil {
		return errors.New("保存 Cloudflare 同步计划失败")
	}
	return nil
}
func (s *Service) fail(ctx context.Context, id int, err error) error {
	_, _ = s.DB.ExecContext(ctx, `UPDATE website_cloudflare_security SET sync_status='error',last_error=?,updated_at=CURRENT_TIMESTAMP WHERE site_id=?`, err.Error(), id)
	return err
}
func (s *Service) coverageFail(ctx context.Context, id int, err error) error {
	_, _ = s.DB.ExecContext(ctx, `UPDATE website_cloudflare_security SET coverage_error=? WHERE site_id=?`, err.Error(), id)
	return s.fail(ctx, id, err)
}
func (s *Service) finish(ctx context.Context, cfg storedConfig, state, rulesetID, ruleID, hash string) (Status, error) {
	if state == "disabled_or_empty" {
		state = "synced"
		if !cfg.Enabled {
			state = "disabled"
		}
	}
	if ruleID == "" {
		cfg.CoveredHostnames = []string{}
	}
	covered, _ := json.Marshal(cfg.CoveredHostnames)
	_, err := s.DB.ExecContext(ctx, `UPDATE website_cloudflare_security SET ruleset_id=?,rule_id=?,applied_hash=?,pending_hash='',zone_name=?,covered_hostnames=?,coverage_error='',sync_status=?,last_error='',last_sync_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE site_id=?`, rulesetID, ruleID, hash, cfg.ZoneName, string(covered), state, cfg.SiteID)
	if err != nil {
		return Status{}, errors.New("保存 Cloudflare 同步结果失败；稍后将重新核对")
	}
	result, err := s.load(ctx, cfg.SiteID)
	if err != nil {
		return Status{}, err
	}
	s.populateWebsiteStatus(ctx, &result)
	if ips, err := s.activeIPs(ctx); err == nil {
		result.ActiveIPCount = len(ips)
		result.ActiveIPCountKnown = true
	}
	return result.Status, nil
}
func (s *Service) SyncAll(ctx context.Context) error {
	cycleMu.Lock()
	defer cycleMu.Unlock()
	if s.DB == nil {
		return errors.New("网站数据库暂不可用")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT c.site_id FROM website_cloudflare_security c WHERE enabled=1 OR ((rule_id<>'' OR pending_hash<>'') AND (NOT EXISTS(SELECT 1 FROM websites w WHERE w.id=c.site_id) OR EXISTS(SELECT 1 FROM websites w WHERE w.id=c.site_id AND w.status='deleting'))) ORDER BY c.site_id`)
	if err != nil {
		return errors.New("读取 Cloudflare 待同步网站失败")
	}
	var ids []int
	for rows.Next() {
		var id int
		if rows.Scan(&id) != nil {
			rows.Close()
			return errors.New("读取 Cloudflare 待同步网站失败")
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return errors.New("读取 Cloudflare 待同步网站失败")
	}
	if len(ids) > 0 {
		start := sort.SearchInts(ids, cycleCursor+1)
		if start == len(ids) {
			start = 0
		}
		ids = append(append([]int{}, ids[start:]...), ids[:start]...)
	}
	var failures []error
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Advance before the attempt: a consistently failing site cannot starve
		// higher IDs when the enclosing cycle budget is exhausted.
		cycleCursor = id
		siteCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		_, err := s.Sync(siteCtx, id)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Errorf("网站 %d: %w", id, err))
		}
	}
	return errors.Join(failures...)
}
