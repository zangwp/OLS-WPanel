// Package cloudflaresecurity manages one explicitly enabled website's owned WAF
// rule. It never changes administrator rules or sends SSH/panel bans upstream.
package cloudflaresecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"
const phase = "http_request_firewall_custom"

var ErrAPIAbsent = errors.New("Cloudflare 自定义规则集尚未创建")

type Client struct{ HTTP *http.Client }

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

type rule struct {
	ID               string          `json:"id,omitempty"`
	Ref              string          `json:"ref"`
	Action           string          `json:"action"`
	Expression       string          `json:"expression"`
	Enabled          bool            `json:"enabled"`
	Description      string          `json:"description"`
	ActionParameters json.RawMessage `json:"action_parameters,omitempty"`
	Logging          json.RawMessage `json:"logging,omitempty"`
}
type ruleset struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Phase string `json:"phase"`
	Rules []rule `json:"rules"`
}
type zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Account struct {
		ID string `json:"id"`
	} `json:"account"`
}
type resultInfo struct {
	Page       int `json:"page"`
	TotalPages int `json:"total_pages"`
}

func (c *Client) request(ctx context.Context, token, method, path string, body any, result any) error {
	return c.requestInfo(ctx, token, method, path, body, result, nil)
}
func (c *Client) requestInfo(ctx context.Context, token, method, path string, body any, result any, info *resultInfo) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return errors.New("Cloudflare 请求格式错误")
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, reader)
	if err != nil {
		return errors.New("Cloudflare 请求创建失败")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "OLS-WPanel/Cloudflare-Security")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New("Cloudflare 连接失败或超时，稍后将重试")
	}
	defer resp.Body.Close()
	// Neither response bodies nor transport errors are propagated: a proxy or
	// API can echo the bearer credential into either of them.
	if resp.StatusCode == http.StatusNotFound {
		return ErrAPIAbsent
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		switch resp.StatusCode {
		case 401, 403:
			return errors.New("Cloudflare API Token 无效或权限不足，请检查 Zone Read 与 Zone WAF Edit 权限")
		case 429:
			return errors.New("Cloudflare API 请求过于频繁，稍后将重试")
		default:
			return fmt.Errorf("Cloudflare API 返回 HTTP %d，稍后将重试", resp.StatusCode)
		}
	}
	var envelope struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Info    resultInfo      `json:"result_info"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&envelope); err != nil || !envelope.Success {
		return errors.New("Cloudflare API 响应无效或操作失败")
	}
	if result != nil && json.Unmarshal(envelope.Result, result) != nil {
		return errors.New("Cloudflare API 响应格式错误")
	}
	if info != nil {
		*info = envelope.Info
	}
	return nil
}

func (c *Client) readZone(ctx context.Context, cfg storedConfig, token string) (zone, error) {
	var z zone
	if err := c.request(ctx, token, http.MethodGet, "/zones/"+cfg.ZoneID, nil, &z); err != nil {
		if errors.Is(err, ErrAPIAbsent) {
			return zone{}, errors.New("Cloudflare Zone ID 不存在或当前 Token 无权读取")
		}
		return zone{}, err
	}
	name, err := canonicalHost(z.Name)
	if err != nil || z.ID != cfg.ZoneID || z.Account.ID != cfg.AccountID || !hostInZone(cfg.Hostname, name) {
		return zone{}, errors.New("Cloudflare 账户、Zone ID 与当前网站域名不匹配")
	}
	z.Name = name
	return z, nil
}

// Query only the requested account and exact candidate. Never enumerate an
// unrelated account or rely on a zone-name substring match.
func (c *Client) zonesNamed(ctx context.Context, account, token, name string) ([]zone, error) {
	var found []zone
	seen := map[string]bool{}
	for page := 1; page <= 20; page++ {
		q := url.Values{"account.id": {account}, "name": {name}, "match": {"all"}, "per_page": {"50"}, "page": {fmt.Sprint(page)}}
		var result []zone
		var info resultInfo
		if err := c.requestInfo(ctx, token, http.MethodGet, "/zones?"+q.Encode(), nil, &result, &info); err != nil {
			return nil, err
		}
		if info.Page != 0 && info.Page != page || info.TotalPages < 0 || info.TotalPages > 20 {
			return nil, errors.New("Cloudflare Zone 分页结果不完整，无法安全识别网站 Zone")
		}
		for _, z := range result {
			canonical, err := canonicalHost(z.Name)
			if err != nil || canonical != name || !idPattern.MatchString(z.ID) || z.Account.ID != account {
				return nil, errors.New("Cloudflare Zone 查询结果与指定账户或域名不匹配")
			}
			if seen[z.ID] {
				return nil, errors.New("Cloudflare Zone 分页结果重复，无法安全识别网站 Zone")
			}
			seen[z.ID] = true
			z.Name = canonical
			found = append(found, z)
		}
		if info.TotalPages > 0 {
			if page >= info.TotalPages {
				return found, nil
			}
		} else if len(result) < 50 {
			return found, nil
		} else {
			return nil, errors.New("Cloudflare Zone 分页信息缺失，无法安全识别网站 Zone")
		}
	}
	return nil, errors.New("Cloudflare Zone 分页超过安全上限，无法识别网站 Zone")
}
func (c *Client) resolveHost(ctx context.Context, account, token, host string, cache map[string][]zone) (zone, error) {
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		matches, ok := cache[name]
		if !ok {
			var err error
			matches, err = c.zonesNamed(ctx, account, token, name)
			if err != nil {
				return zone{}, err
			}
			cache[name] = matches
		}
		if len(matches) > 1 {
			return zone{}, errors.New("Cloudflare 返回多个同名 Zone，无法唯一识别网站 Zone")
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
	}
	return zone{}, fmt.Errorf("未能在指定 Cloudflare 账户与 Token 可见范围内识别域名 %s 的 Zone，请检查 Account ID 与 Zone Read 权限", host)
}
func (c *Client) resolveCoverage(ctx context.Context, account, token string, hosts []string, bound *zone) (zone, error) {
	if len(hosts) == 0 {
		return zone{}, errors.New("网站缺少可用域名")
	}
	cache := map[string][]zone{}
	var selected zone
	if bound != nil {
		selected = *bound
		if err := checkHostSuffixes(hosts, selected.Name); err != nil {
			return zone{}, err
		}
	}
	for _, host := range hosts {
		z, err := c.resolveHost(ctx, account, token, host, cache)
		if err != nil {
			return zone{}, err
		}
		if selected.ID == "" {
			selected = z
		}
		if z.ID != selected.ID || z.Account.ID != selected.Account.ID {
			return zone{}, fmt.Errorf("域名 %s 属于不同的 Cloudflare Zone，整组域名尚未覆盖；请将不同 Zone 或账户的网站分别配置", host)
		}
	}
	return selected, nil
}
func (c *Client) entrypoint(ctx context.Context, cfg storedConfig, token string) (ruleset, error) {
	var rs ruleset
	err := c.request(ctx, token, http.MethodGet, "/zones/"+cfg.ZoneID+"/rulesets/phases/"+phase+"/entrypoint", nil, &rs)
	if err == nil && (!idPattern.MatchString(rs.ID) || rs.Kind != "zone" || rs.Phase != phase) {
		err = errors.New("Cloudflare 自定义规则集信息不匹配")
	}
	return rs, err
}
