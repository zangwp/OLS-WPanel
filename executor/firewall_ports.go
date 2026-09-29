package executor

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/database"
)

const (
	managedPortCommentPrefix = "ols-wpanel-port:"
	portRuleMaxDescription   = 80
)

type FirewallPortRule struct {
	ID          int64      `json:"id"`
	Protocol    string     `json:"protocol"`
	Port        int        `json:"port"`
	Source      string     `json:"source"`
	Description string     `json:"description"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	Applied     bool       `json:"applied"`
}

type FirewallListener struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Process  string `json:"process"`
}

type FirewallPortStatus struct {
	Backend     string             `json:"backend"`
	Writable    bool               `json:"writable"`
	Warning     string             `json:"warning"`
	InputPolicy string             `json:"input_policy"`
	SSHPort     int                `json:"ssh_port"`
	PanelPort   int                `json:"panel_port"`
	Listeners   []FirewallListener `json:"listeners"`
	Rules       []FirewallPortRule `json:"rules"`
}

type FirewallPortRuleRequest struct {
	Protocol       string `json:"protocol"`
	Port           int    `json:"port"`
	Source         string `json:"source"`
	Description    string `json:"description"`
	DurationMinute int    `json:"duration_minutes"`
}

var (
	portRulesMu sync.Mutex
	portCommand = func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	managedRuleRE = regexp.MustCompile(`comment\s+"?` + regexp.QuoteMeta(managedPortCommentPrefix) + `([a-z]+):(\d+):([A-Za-z0-9_-]+)"?.*# handle (\d+)`)
	policyRE      = regexp.MustCompile(`policy\s+(accept|drop|reject)\s*;`)
)

func normalizeFirewallPortRule(req FirewallPortRuleRequest) (FirewallPortRuleRequest, error) {
	req.Protocol = strings.ToLower(strings.TrimSpace(req.Protocol))
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		return req, errors.New("协议只能是 TCP 或 UDP")
	}
	if req.Port < 1 || req.Port > 65535 {
		return req, errors.New("端口必须在 1 到 65535 之间")
	}
	req.Source = strings.TrimSpace(req.Source)
	if req.Source == "0.0.0.0/0" || req.Source == "::/0" {
		req.Source = ""
	}
	if req.Source != "" {
		if ip := net.ParseIP(req.Source); ip != nil {
			if ip.To4() != nil {
				req.Source = ip.String() + "/32"
			} else {
				req.Source = ip.String() + "/128"
			}
		} else if _, network, err := net.ParseCIDR(req.Source); err != nil {
			return req, errors.New("来源必须是有效的 IP 或 CIDR")
		} else {
			req.Source = network.String()
		}
	}
	req.Description = strings.TrimSpace(req.Description)
	if len([]rune(req.Description)) > portRuleMaxDescription || strings.ContainsAny(req.Description, "\r\n\x00") {
		return req, errors.New("备注不能超过 80 个字符或包含换行")
	}
	if req.DurationMinute < 0 || req.DurationMinute > 10080 {
		return req, errors.New("临时放行时长必须在 1 分钟到 7 天之间")
	}
	// OpenLiteSpeed WebAdmin must never be exposed to the whole Internet.
	if req.Port == 7080 && req.Source == "" {
		return req, errors.New("OpenLiteSpeed WebAdmin 7080 只能向指定管理 IP/CIDR 开放")
	}
	return req, nil
}

func firewallPortTarget(ctx context.Context) (family, table, chain, policy, warning string, writable bool) {
	if _, err := portCommand(ctx, "nft", "--version"); err != nil {
		return "", "", "", "unknown", "nftables 不可用", false
	}
	if out, err := portCommand(ctx, "ufw", "status"); err == nil && strings.Contains(strings.ToLower(out), "status: active") {
		return "", "", "", "unknown", "检测到 UFW 正在运行。为避免两套防火墙互相覆盖，端口写入已禁用。", false
	}
	if _, err := portCommand(ctx, "systemctl", "is-active", "--quiet", "firewalld"); err == nil {
		return "", "", "", "unknown", "检测到 firewalld 正在运行。为避免规则冲突，端口写入已禁用。", false
	}
	out, err := portCommand(ctx, "nft", "-a", "list", "chain", "inet", "filter", "input")
	if err != nil {
		return "", "", "", "unknown", "未找到唯一可安全管理的 inet filter input 链；当前仅提供端口查看。", false
	}
	policy = "accept"
	if match := policyRE.FindStringSubmatch(out); len(match) == 2 {
		policy = match[1]
	}
	return "inet", "filter", "input", policy, "", true
}

func managedPortTag(protocol string, port int, source string) string {
	scope := "any"
	if source != "" {
		digest := sha256.Sum256([]byte(source))
		scope = fmt.Sprintf("src%x", digest[:6])
	}
	return managedPortCommentPrefix + protocol + ":" + strconv.Itoa(port) + ":" + scope
}

func nftRuleArgs(action, family, table, chain string, rule FirewallPortRuleRequest) []string {
	args := []string{action, "rule", family, table, chain}
	if rule.Source != "" {
		if strings.Contains(rule.Source, ":") {
			args = append(args, "ip6", "saddr", rule.Source)
		} else {
			args = append(args, "ip", "saddr", rule.Source)
		}
	}
	args = append(args, rule.Protocol, "dport", strconv.Itoa(rule.Port), "ct", "state", "new", "accept", "comment", managedPortTag(rule.Protocol, rule.Port, rule.Source))
	return args
}

func listManagedHandles(ctx context.Context, family, table, chain string) (map[string][]string, string, error) {
	out, err := portCommand(ctx, "nft", "-a", "list", "chain", family, table, chain)
	if err != nil {
		return nil, out, err
	}
	handles := make(map[string][]string)
	for _, line := range strings.Split(out, "\n") {
		match := managedRuleRE.FindStringSubmatch(line)
		if len(match) != 5 {
			continue
		}
		tag := managedPortCommentPrefix + match[1] + ":" + match[2] + ":" + match[3]
		handles[tag] = append(handles[tag], match[4])
	}
	return handles, out, nil
}

func detectListeners(ctx context.Context) []FirewallListener {
	out, err := portCommand(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return []FirewallListener{}
	}
	seen := make(map[string]FirewallListener)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if strings.HasPrefix(proto, "tcp") {
			proto = "tcp"
		} else if strings.HasPrefix(proto, "udp") {
			proto = "udp"
		} else {
			continue
		}
		address := fields[4]
		idx := strings.LastIndex(address, ":")
		if idx < 0 {
			continue
		}
		port, err := strconv.Atoi(strings.TrimSuffix(address[idx+1:], "]"))
		if err != nil || port < 1 {
			continue
		}
		process := ""
		if pos := strings.Index(line, "users:(("); pos >= 0 {
			process = strings.Trim(line[pos+7:], "()\"")
			if comma := strings.Index(process, ","); comma >= 0 {
				process = process[:comma]
			}
		}
		key := proto + ":" + strconv.Itoa(port)
		seen[key] = FirewallListener{Protocol: proto, Port: port, Process: process}
	}
	items := make([]FirewallListener, 0, len(seen))
	for _, item := range seen {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Port == items[j].Port {
			return items[i].Protocol < items[j].Protocol
		}
		return items[i].Port < items[j].Port
	})
	return items
}

func detectSSHPort(ctx context.Context, listeners []FirewallListener) int {
	out, err := portCommand(ctx, "sshd", "-T")
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 2 && fields[0] == "port" {
				if port, convErr := strconv.Atoi(fields[1]); convErr == nil && port > 0 && port <= 65535 {
					return port
				}
			}
		}
	}
	for _, listener := range listeners {
		if listener.Protocol == "tcp" && strings.Contains(strings.ToLower(listener.Process), "sshd") {
			return listener.Port
		}
	}
	return 22
}

func loadFirewallPortRules(db *sql.DB) ([]FirewallPortRule, error) {
	rows, err := db.Query(`SELECT id,protocol,port,source,description,expires_at,created_at
		FROM firewall_port_rules ORDER BY port,protocol,source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []FirewallPortRule
	for rows.Next() {
		var item FirewallPortRule
		if err := rows.Scan(&item.ID, &item.Protocol, &item.Port, &item.Source, &item.Description, &item.ExpiresAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if items == nil {
		items = []FirewallPortRule{}
	}
	return items, rows.Err()
}

func GetFirewallPortStatus() (FirewallPortStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	family, table, chain, policy, warning, writable := firewallPortTarget(ctx)
	listeners := detectListeners(ctx)
	rules, err := loadFirewallPortRules(database.GetDB())
	if err != nil {
		return FirewallPortStatus{}, err
	}
	handles := map[string][]string{}
	if writable {
		handles, _, _ = listManagedHandles(ctx, family, table, chain)
	}
	for i := range rules {
		tag := managedPortTag(rules[i].Protocol, rules[i].Port, rules[i].Source)
		rules[i].Applied = len(handles[tag]) > 0
	}
	return FirewallPortStatus{
		Backend: "nftables", Writable: writable, Warning: warning, InputPolicy: policy,
		SSHPort: detectSSHPort(ctx, listeners), PanelPort: 8443, Listeners: listeners, Rules: rules,
	}, nil
}

func AddFirewallPortRule(req FirewallPortRuleRequest) (FirewallPortRule, error) {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	normalized, err := normalizeFirewallPortRule(req)
	if err != nil {
		return FirewallPortRule{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	family, table, chain, _, warning, writable := firewallPortTarget(ctx)
	if !writable {
		return FirewallPortRule{}, errors.New(warning)
	}
	handles, _, err := listManagedHandles(ctx, family, table, chain)
	if err != nil {
		return FirewallPortRule{}, errors.New("无法读取当前 nftables 规则")
	}
	tag := managedPortTag(normalized.Protocol, normalized.Port, normalized.Source)
	if len(handles[tag]) == 0 {
		checkArgs := append([]string{"-c"}, nftRuleArgs("insert", family, table, chain, normalized)...)
		if out, checkErr := portCommand(ctx, "nft", checkArgs...); checkErr != nil {
			return FirewallPortRule{}, fmt.Errorf("nftables 规则验证失败: %s", strings.TrimSpace(out))
		}
		if out, applyErr := portCommand(ctx, "nft", nftRuleArgs("insert", family, table, chain, normalized)...); applyErr != nil {
			return FirewallPortRule{}, fmt.Errorf("nftables 规则应用失败: %s", strings.TrimSpace(out))
		}
	}
	var expires interface{}
	if normalized.DurationMinute > 0 {
		expires = time.Now().UTC().Add(time.Duration(normalized.DurationMinute) * time.Minute)
	}
	result, err := database.GetDB().Exec(`INSERT INTO firewall_port_rules(protocol,port,source,description,expires_at)
		VALUES(?,?,?,?,?) ON CONFLICT(protocol,port,source) DO UPDATE SET description=excluded.description,expires_at=excluded.expires_at`,
		normalized.Protocol, normalized.Port, normalized.Source, normalized.Description, expires)
	if err != nil {
		if rollbackHandles, _, listErr := listManagedHandles(ctx, family, table, chain); listErr == nil {
			for _, handle := range rollbackHandles[tag] {
				_, _ = portCommand(ctx, "nft", "delete", "rule", family, table, chain, "handle", handle)
			}
		}
		return FirewallPortRule{}, err
	}
	id, _ := result.LastInsertId()
	if id <= 0 {
		_ = database.GetDB().QueryRow(`SELECT id FROM firewall_port_rules WHERE protocol=? AND port=? AND source=?`, normalized.Protocol, normalized.Port, normalized.Source).Scan(&id)
	}
	recordOperationLog("firewall_port_open", fmt.Sprintf("%s/%d", normalized.Protocol, normalized.Port), "success", "source="+displayFirewallSource(normalized.Source))
	return FirewallPortRule{ID: id, Protocol: normalized.Protocol, Port: normalized.Port, Source: normalized.Source, Description: normalized.Description, Applied: true}, nil
}

func DeleteFirewallPortRule(id int64) error {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	if id <= 0 {
		return errors.New("无效的规则 ID")
	}
	var rule FirewallPortRule
	if err := database.GetDB().QueryRow(`SELECT id,protocol,port,source,description,expires_at,created_at FROM firewall_port_rules WHERE id=?`, id).
		Scan(&rule.ID, &rule.Protocol, &rule.Port, &rule.Source, &rule.Description, &rule.ExpiresAt, &rule.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("端口规则不存在")
		}
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	family, table, chain, _, warning, writable := firewallPortTarget(ctx)
	if !writable {
		return errors.New(warning)
	}
	handles, _, err := listManagedHandles(ctx, family, table, chain)
	if err != nil {
		return errors.New("无法读取当前 nftables 规则")
	}
	for _, handle := range handles[managedPortTag(rule.Protocol, rule.Port, rule.Source)] {
		if out, deleteErr := portCommand(ctx, "nft", "delete", "rule", family, table, chain, "handle", handle); deleteErr != nil {
			return fmt.Errorf("删除 nftables 规则失败: %s", strings.TrimSpace(out))
		}
	}
	if _, err := database.GetDB().Exec(`DELETE FROM firewall_port_rules WHERE id=?`, id); err != nil {
		return err
	}
	recordOperationLog("firewall_port_close", fmt.Sprintf("%s/%d", rule.Protocol, rule.Port), "success", "source="+displayFirewallSource(rule.Source))
	return nil
}

func displayFirewallSource(source string) string {
	if source == "" {
		return "any"
	}
	return source
}

func ReconcileFirewallPortRules() error {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	db := database.GetDB()
	if db == nil {
		return nil
	}
	now := time.Now().UTC()
	expiredRows, err := db.Query(`SELECT id FROM firewall_port_rules WHERE expires_at IS NOT NULL AND expires_at <= ?`, now)
	if err != nil {
		return err
	}
	var expired []int64
	for expiredRows.Next() {
		var id int64
		if scanErr := expiredRows.Scan(&id); scanErr == nil {
			expired = append(expired, id)
		}
	}
	expiredRows.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	family, table, chain, _, warning, writable := firewallPortTarget(ctx)
	if !writable {
		return errors.New(warning)
	}
	handles, _, err := listManagedHandles(ctx, family, table, chain)
	if err != nil {
		return err
	}
	for _, id := range expired {
		var protocol, source string
		var port int
		deleteSucceeded := true
		if db.QueryRow(`SELECT protocol,port,source FROM firewall_port_rules WHERE id=?`, id).Scan(&protocol, &port, &source) == nil {
			for _, handle := range handles[managedPortTag(protocol, port, source)] {
				if _, deleteErr := portCommand(ctx, "nft", "delete", "rule", family, table, chain, "handle", handle); deleteErr != nil {
					deleteSucceeded = false
				}
			}
		}
		if deleteSucceeded {
			_, _ = db.Exec(`DELETE FROM firewall_port_rules WHERE id=?`, id)
		}
	}
	rules, err := loadFirewallPortRules(db)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		tag := managedPortTag(rule.Protocol, rule.Port, rule.Source)
		if len(handles[tag]) > 0 {
			continue
		}
		req := FirewallPortRuleRequest{Protocol: rule.Protocol, Port: rule.Port, Source: rule.Source, Description: rule.Description}
		checkArgs := append([]string{"-c"}, nftRuleArgs("insert", family, table, chain, req)...)
		if _, err := portCommand(ctx, "nft", checkArgs...); err != nil {
			return err
		}
		if _, err := portCommand(ctx, "nft", nftRuleArgs("insert", family, table, chain, req)...); err != nil {
			return err
		}
	}
	return nil
}

func StartFirewallPortRuleManager() {
	GoSafe(func() {
		_ = ReconcileFirewallPortRules()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			_ = ReconcileFirewallPortRules()
		}
	})
}
