package cloudflaresecurity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

func canonicalHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil || len(ascii) > 253 || !hostPattern.MatchString(ascii) || strings.Contains(ascii, "..") || !strings.Contains(ascii, ".") {
		return "", errors.New("网站或别名域名格式不支持 Cloudflare 同步")
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", errors.New("网站或别名域名格式不支持 Cloudflare 同步")
		}
	}
	return ascii, nil
}
func (s *Service) websiteHosts(ctx context.Context, id int) ([]string, error) {
	if s.DB == nil {
		return nil, errors.New("网站数据库暂不可用")
	}
	var primary, aliases string
	err := s.DB.QueryRowContext(ctx, `SELECT domain,COALESCE(aliases,'') FROM websites WHERE id=?`, id).Scan(&primary, &aliases)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, errors.New("读取网站域名与别名失败")
	}
	host, err := canonicalHost(primary)
	if err != nil {
		return nil, err
	}
	unique := map[string]bool{host: true}
	var additional []string
	for _, raw := range strings.Split(aliases, "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		alias, err := canonicalHost(raw)
		if err != nil {
			return nil, err
		}
		if !unique[alias] {
			unique[alias] = true
			additional = append(additional, alias)
		}
	}
	sort.Strings(additional)
	return append([]string{host}, additional...), nil
}
func hostInZone(host, name string) bool {
	return name != "" && (host == name || strings.HasSuffix(host, "."+name))
}
func checkHostSuffixes(hosts []string, name string) error {
	for _, host := range hosts {
		if !hostInZone(host, name) {
			return fmt.Errorf("域名 %s 不属于当前 Cloudflare Zone %s，尚未覆盖；请将不同 Zone 或账户的网站分别配置", host, name)
		}
	}
	return nil
}
func expressionForHosts(hosts, ips []string) (string, error) {
	if len(ips) == 0 {
		return "", nil
	}
	if len(hosts) == 0 {
		return "", errors.New("Cloudflare 规则缺少网站域名")
	}
	predicate := fmt.Sprintf(`http.host eq %q`, hosts[0])
	if len(hosts) > 1 {
		quoted := make([]string, len(hosts))
		for i, host := range hosts {
			quoted[i] = strconv.Quote(host)
		}
		predicate = "http.host in {" + strings.Join(quoted, " ") + "}"
	}
	text := "(" + predicate + ") and ip.src in {" + strings.Join(ips, " ") + "}"
	if len(text) > 4096 {
		return "", errors.New("Cloudflare 规则表达式超过 4096 字节；所有 IP 与域名均未截断，请改用可用的 IP List 方案")
	}
	return text, nil
}
func hostsFromExpression(text string) ([]string, bool) {
	const single = "(http.host eq "
	const multiple = "(http.host in {"
	var raw string
	var tokens []string
	if strings.HasPrefix(text, single) {
		end := strings.Index(text, ") and ip.src in {")
		if end < 0 {
			return nil, false
		}
		raw = text[len(single):end]
		tokens = []string{raw}
	} else if strings.HasPrefix(text, multiple) {
		end := strings.Index(text, "}) and ip.src in {")
		if end < 0 {
			return nil, false
		}
		raw = text[len(multiple):end]
		tokens = strings.Fields(raw)
	} else {
		return nil, false
	}
	var hosts []string
	seen := map[string]bool{}
	for _, token := range tokens {
		host, err := strconv.Unquote(token)
		if err != nil {
			return nil, false
		}
		canonical, err := canonicalHost(host)
		if err != nil || canonical != host || seen[host] {
			return nil, false
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts, len(hosts) > 0
}
