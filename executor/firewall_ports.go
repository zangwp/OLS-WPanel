package executor

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/config"
	"github.com/zangwp/OLS-WPanel/database"
)

const (
	managedPortCommentPrefix = "ols-wpanel-port:"
	managedCoreCommentPrefix = "ols-wpanel-core:"
	portRuleMaxDescription   = 80
	firewallRollbackUnit     = "ols-wpanel-firewall-rollback"
	firewallRollbackDelay    = 90 * time.Second
	nftablesConfigPath       = "/etc/nftables.conf"
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
	HitPackets  *uint64    `json:"hit_packets,omitempty"`
	HitBytes    *uint64    `json:"hit_bytes,omitempty"`
}

type FirewallListener struct {
	Protocol     string `json:"protocol"`
	Port         int    `json:"port"`
	Address      string `json:"address"`
	Process      string `json:"process"`
	BindScope    string `json:"bind_scope"`
	HostExposure string `json:"host_exposure"`
}

type FirewallPortStatus struct {
	Backend                string             `json:"backend"`
	Writable               bool               `json:"writable"`
	Warning                string             `json:"warning"`
	InputPolicy            string             `json:"input_policy"`
	RecommendedPolicy      string             `json:"recommended_policy"`
	SSHPort                int                `json:"ssh_port"`
	PanelPort              int                `json:"panel_port"`
	CurrentManagementIP    string             `json:"current_management_ip,omitempty"`
	ManagedRuleCount       int                `json:"managed_rule_count"`
	AnomalyCount           int                `json:"anomaly_count"`
	ListenerCount          int                `json:"listener_count"`
	NetworkListenerCount   int                `json:"network_listener_count"`
	LocalListenerCount     int                `json:"local_listener_count"`
	DangerousListenerCount int                `json:"dangerous_listener_count"`
	CanEnableProtection    bool               `json:"can_enable_protection"`
	ProtectionPending      bool               `json:"protection_pending"`
	ProtectionDeadline     *time.Time         `json:"protection_deadline,omitempty"`
	Listeners              []FirewallListener `json:"listeners"`
	Rules                  []FirewallPortRule `json:"rules"`
}

type FirewallPortRuleRequest struct {
	Protocol       string `json:"protocol"`
	Port           int    `json:"port"`
	Source         string `json:"source"`
	SourceMode     string `json:"source_mode"`
	Description    string `json:"description"`
	DurationMode   string `json:"duration_mode"`
	DurationMinute int    `json:"duration_minutes"`
	ConfirmPublic  bool   `json:"confirm_public"`
}

type FirewallProtectionResult struct {
	ConfirmationToken string    `json:"confirmation_token"`
	Deadline          time.Time `json:"deadline"`
}

type managedRuleRuntime struct {
	Handles    []string
	HitPackets *uint64
	HitBytes   *uint64
}

var (
	portRulesMu               sync.Mutex
	protectionMu              sync.Mutex
	pendingProtectionToken    string
	pendingProtectionDeadline time.Time
	portCommand               = func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	managedRuleRE = regexp.MustCompile(`comment\s+"?` + regexp.QuoteMeta(managedPortCommentPrefix) + `([a-z]+):(\d+):([A-Za-z0-9_-]+)"?`)
	handleRE      = regexp.MustCompile(`# handle (\d+)`)
	counterRE     = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)
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
	req.SourceMode = strings.ToLower(strings.TrimSpace(req.SourceMode))
	if req.SourceMode == "" {
		if strings.TrimSpace(req.Source) == "" {
			req.SourceMode = "any"
		} else {
			req.SourceMode = "specific"
		}
	}
	if req.SourceMode != "current" && req.SourceMode != "specific" && req.SourceMode != "any" {
		return req, errors.New("访问范围不正确")
	}
	req.Source = strings.TrimSpace(req.Source)
	if req.SourceMode == "specific" && req.Source == "" {
		return req, errors.New("指定 IP/CIDR 不能为空")
	}
	if req.SourceMode == "current" && req.Source == "" {
		return req, errors.New("无法识别当前管理 IP")
	}
	// OpenLiteSpeed WebAdmin must never be exposed to the whole Internet.
	// Reject this before the generic public-access confirmation so callers get
	// the non-overridable 7080 restriction instead of a misleading prompt.
	if req.Port == 7080 && (req.SourceMode == "any" || req.Source == "0.0.0.0/0" || req.Source == "::/0") {
		return req, errors.New("OpenLiteSpeed WebAdmin 7080 只能向指定管理 IP/CIDR 开放")
	}
	if req.SourceMode == "any" {
		req.Source = ""
		if !req.ConfirmPublic {
			return req, errors.New("向所有来源开放前必须确认公网访问风险")
		}
	}
	if req.Source == "0.0.0.0/0" || req.Source == "::/0" {
		req.Source = ""
		req.SourceMode = "any"
		if !req.ConfirmPublic {
			return req, errors.New("向所有来源开放前必须确认公网访问风险")
		}
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
	req.DurationMode = strings.ToLower(strings.TrimSpace(req.DurationMode))
	if req.DurationMode == "" {
		if req.DurationMinute > 0 {
			req.DurationMode = "temporary"
		} else {
			req.DurationMode = "permanent"
		}
	}
	if req.DurationMode != "permanent" && req.DurationMode != "temporary" {
		return req, errors.New("有效期类型不正确")
	}
	if req.DurationMode == "permanent" {
		req.DurationMinute = 0
	}
	if req.DurationMode == "temporary" && req.DurationMinute < 1 {
		return req, errors.New("临时放行时长必须至少为 1 分钟")
	}
	if req.DurationMinute < 0 || req.DurationMinute > 10080 {
		return req, errors.New("临时放行时长必须在 1 分钟到 7 天之间")
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
	args = append(args, rule.Protocol, "dport", strconv.Itoa(rule.Port), "ct", "state", "new", "counter", "accept", "comment", managedPortTag(rule.Protocol, rule.Port, rule.Source))
	return args
}

func listManagedRuntime(ctx context.Context, family, table, chain string) (map[string]managedRuleRuntime, string, error) {
	out, err := portCommand(ctx, "nft", "-a", "list", "chain", family, table, chain)
	if err != nil {
		return nil, out, err
	}
	runtimeByTag := make(map[string]managedRuleRuntime)
	for _, line := range strings.Split(out, "\n") {
		match := managedRuleRE.FindStringSubmatch(line)
		if len(match) != 4 {
			continue
		}
		tag := managedPortCommentPrefix + match[1] + ":" + match[2] + ":" + match[3]
		item := runtimeByTag[tag]
		if handle := handleRE.FindStringSubmatch(line); len(handle) == 2 {
			item.Handles = append(item.Handles, handle[1])
		}
		if counter := counterRE.FindStringSubmatch(line); len(counter) == 3 {
			packets, packetErr := strconv.ParseUint(counter[1], 10, 64)
			bytes, byteErr := strconv.ParseUint(counter[2], 10, 64)
			if packetErr == nil && byteErr == nil {
				item.HitPackets = &packets
				item.HitBytes = &bytes
			}
		}
		runtimeByTag[tag] = item
	}
	return runtimeByTag, out, nil
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
		bindAddress := normalizeListenerAddress(address[:idx])
		bindScope := listenerBindScope(bindAddress)
		key := proto + ":" + strconv.Itoa(port) + ":" + bindAddress
		seen[key] = FirewallListener{Protocol: proto, Port: port, Address: bindAddress, Process: process, BindScope: bindScope}
	}
	items := make([]FirewallListener, 0, len(seen))
	for _, item := range seen {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Port == items[j].Port {
			if items[i].Protocol == items[j].Protocol {
				return items[i].Address < items[j].Address
			}
			return items[i].Protocol < items[j].Protocol
		}
		return items[i].Port < items[j].Port
	})
	return items
}

func normalizeListenerAddress(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if zone := strings.LastIndex(value, "%"); zone > 0 {
		value = value[:zone]
	}
	if value == "" {
		return "*"
	}
	return value
}

func listenerBindScope(address string) string {
	if address == "*" || address == "0.0.0.0" || address == "::" {
		return "network"
	}
	ip := net.ParseIP(address)
	if ip != nil && ip.IsLoopback() {
		return "local"
	}
	return "network"
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
	runtimeByTag := map[string]managedRuleRuntime{}
	if writable {
		runtimeByTag, _, _ = listManagedRuntime(ctx, family, table, chain)
	}
	anomalies := 0
	for i := range rules {
		tag := managedPortTag(rules[i].Protocol, rules[i].Port, rules[i].Source)
		runtimeRule := runtimeByTag[tag]
		rules[i].Applied = len(runtimeRule.Handles) > 0
		rules[i].HitPackets = runtimeRule.HitPackets
		rules[i].HitBytes = runtimeRule.HitBytes
		if !rules[i].Applied || len(runtimeRule.Handles) > 1 {
			anomalies++
		}
	}
	localListeners, networkListeners, dangerousListeners := 0, 0, 0
	for i := range listeners {
		if listeners[i].BindScope == "local" {
			listeners[i].HostExposure = "local_only"
			localListeners++
			continue
		}
		networkListeners++
		if policy == "accept" {
			listeners[i].HostExposure = "allowed_by_default"
		} else {
			listeners[i].HostExposure = "rule_dependent"
		}
		if listeners[i].Port == 3306 || listeners[i].Port == 6379 {
			dangerousListeners++
		}
	}
	anomalies += dangerousListeners
	panelPort := 8443
	if config.AppConfig != nil && config.AppConfig.Panel.TLSPort > 0 {
		panelPort = config.AppConfig.Panel.TLSPort
	}
	pending, deadline := firewallProtectionPending()
	canProtect := runtime.GOOS == "linux" && writable && policy == "accept" && systemdRunAvailable()
	return FirewallPortStatus{
		Backend: "nftables", Writable: writable, Warning: warning, InputPolicy: policy, RecommendedPolicy: "drop",
		SSHPort: detectSSHPort(ctx, listeners), PanelPort: panelPort,
		ManagedRuleCount: len(rules), AnomalyCount: anomalies,
		ListenerCount: len(listeners), NetworkListenerCount: networkListeners, LocalListenerCount: localListeners,
		DangerousListenerCount: dangerousListeners, CanEnableProtection: canProtect,
		ProtectionPending: pending, ProtectionDeadline: deadline, Listeners: listeners, Rules: rules,
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
	runtimeByTag, _, err := listManagedRuntime(ctx, family, table, chain)
	if err != nil {
		return FirewallPortRule{}, errors.New("无法读取当前 nftables 规则")
	}
	tag := managedPortTag(normalized.Protocol, normalized.Port, normalized.Source)
	if len(runtimeByTag[tag].Handles) == 0 {
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
		if rollbackRuntime, _, listErr := listManagedRuntime(ctx, family, table, chain); listErr == nil {
			for _, handle := range rollbackRuntime[tag].Handles {
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
	runtimeByTag, _, err := listManagedRuntime(ctx, family, table, chain)
	if err != nil {
		return errors.New("无法读取当前 nftables 规则")
	}
	for _, handle := range runtimeByTag[managedPortTag(rule.Protocol, rule.Port, rule.Source)].Handles {
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

func systemdRunAvailable() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, nftErr := exec.LookPath("nft")
	_, systemdRunErr := exec.LookPath("systemd-run")
	return nftErr == nil && systemdRunErr == nil
}

func firewallProtectionPending() (bool, *time.Time) {
	protectionMu.Lock()
	defer protectionMu.Unlock()
	if pendingProtectionToken == "" || pendingProtectionDeadline.IsZero() || time.Now().After(pendingProtectionDeadline) {
		pendingProtectionToken = ""
		pendingProtectionDeadline = time.Time{}
		return false, nil
	}
	deadline := pendingProtectionDeadline
	return true, &deadline
}

func setInputPolicy(ctx context.Context, family, table, chain, policy string) error {
	if policy != "accept" && policy != "drop" {
		return errors.New("不支持的防火墙默认策略")
	}
	args := []string{"chain", family, table, chain, "{", "policy", policy, ";", "}"}
	if out, err := portCommand(ctx, "nft", args...); err != nil {
		return fmt.Errorf("切换 nftables 入站策略失败: %s", strings.TrimSpace(out))
	}
	return nil
}

func coreRuleArgs(family, table, chain, name string, expressions ...string) []string {
	args := []string{"insert", "rule", family, table, chain}
	args = append(args, expressions...)
	args = append(args, "counter", "accept", "comment", managedCoreCommentPrefix+name)
	return args
}

func sourceExpression(source string) []string {
	if strings.Contains(source, ":") {
		return []string{"ip6", "saddr", source}
	}
	return []string{"ip", "saddr", source}
}

func addCoreRuleIfMissing(ctx context.Context, family, table, chain, chainOutput, name string, expressions ...string) error {
	tag := managedCoreCommentPrefix + name
	if strings.Contains(chainOutput, tag) {
		return nil
	}
	args := coreRuleArgs(family, table, chain, name, expressions...)
	checkArgs := append([]string{"-c"}, args...)
	if out, err := portCommand(ctx, "nft", checkArgs...); err != nil {
		return fmt.Errorf("核心放行规则验证失败 (%s): %s", name, strings.TrimSpace(out))
	}
	if out, err := portCommand(ctx, "nft", args...); err != nil {
		return fmt.Errorf("核心放行规则应用失败 (%s): %s", name, strings.TrimSpace(out))
	}
	return nil
}

func hasTCPListener(listeners []FirewallListener, port int) bool {
	for _, listener := range listeners {
		if listener.Protocol == "tcp" && listener.Port == port {
			return true
		}
	}
	return false
}

func scheduleFirewallRollback(ctx context.Context, family, table, chain string) error {
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		return errors.New("找不到 nftables 可执行文件")
	}
	_, _ = portCommand(ctx, "systemctl", "stop", firewallRollbackUnit+".timer")
	_, _ = portCommand(ctx, "systemctl", "reset-failed", firewallRollbackUnit+".service")
	args := []string{
		"--unit=" + firewallRollbackUnit,
		"--on-active=" + strconv.Itoa(int(firewallRollbackDelay.Seconds())) + "s",
		"--timer-property=AccuracySec=1s",
		"--property=Type=oneshot",
		nftPath, "chain", family, table, chain, "{", "policy", "accept", ";", "}",
	}
	if out, runErr := portCommand(ctx, "systemd-run", args...); runErr != nil {
		return fmt.Errorf("无法创建防锁死回退任务: %s", strings.TrimSpace(out))
	}
	return nil
}

func cancelFirewallRollback(ctx context.Context) error {
	if out, err := portCommand(ctx, "systemctl", "stop", firewallRollbackUnit+".timer"); err != nil && !strings.Contains(strings.ToLower(out), "not loaded") {
		return fmt.Errorf("停止防火墙回退任务失败: %s", strings.TrimSpace(out))
	}
	_, _ = portCommand(ctx, "systemctl", "reset-failed", firewallRollbackUnit+".service")
	return nil
}

func randomConfirmationToken() (string, error) {
	value := make([]byte, 24)
	if _, err := cryptorand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

// EnableFirewallProtection switches only the existing inet/filter/input chain
// after installing the minimum rules needed to keep the current administrator,
// SSH, web traffic, loopback, established connections, and ICMP reachable. A
// systemd timer restores policy accept unless the browser confirms the change.
func EnableFirewallProtection(managementIP string) (FirewallProtectionResult, error) {
	portRulesMu.Lock()
	defer portRulesMu.Unlock()
	if !systemdRunAvailable() {
		return FirewallProtectionResult{}, errors.New("当前系统缺少 nftables 或 systemd-run，无法启用带自动回退的保护模式")
	}
	ip := net.ParseIP(strings.TrimSpace(managementIP))
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return FirewallProtectionResult{}, errors.New("无法确认直接连接的管理 IP，请勿切换默认入站策略")
	}
	managementSource := ip.String() + "/128"
	if ip.To4() != nil {
		managementSource = ip.String() + "/32"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	family, table, chain, policy, warning, writable := firewallPortTarget(ctx)
	if !writable {
		return FirewallProtectionResult{}, errors.New(warning)
	}
	if policy != "accept" {
		return FirewallProtectionResult{}, errors.New("仅能从 accept 策略启用保护模式")
	}
	listeners := detectListeners(ctx)
	sshPort := detectSSHPort(ctx, listeners)
	panelPort := 8443
	if config.AppConfig != nil && config.AppConfig.Panel.TLSPort > 0 {
		panelPort = config.AppConfig.Panel.TLSPort
	}
	if !hasTCPListener(listeners, sshPort) || !hasTCPListener(listeners, panelPort) {
		return FirewallProtectionResult{}, errors.New("SSH 或面板监听状态未通过预检，未修改防火墙")
	}
	_, chainOutput, err := listManagedRuntime(ctx, family, table, chain)
	if err != nil {
		return FirewallProtectionResult{}, errors.New("无法读取当前 nftables input 链")
	}
	if err := scheduleFirewallRollback(ctx, family, table, chain); err != nil {
		return FirewallProtectionResult{}, err
	}
	rollback := true
	defer func() {
		if rollback {
			_ = setInputPolicy(context.Background(), family, table, chain, "accept")
		}
	}()
	coreRules := []struct {
		name string
		expr []string
	}{
		{name: "established", expr: []string{"ct", "state", "established,related"}},
		{name: "loopback", expr: []string{"iifname", "lo"}},
		{name: "icmp4", expr: []string{"ip", "protocol", "icmp"}},
		{name: "icmp6", expr: []string{"meta", "l4proto", "ipv6-icmp"}},
		{name: "http", expr: []string{"tcp", "dport", "80", "ct", "state", "new"}},
		{name: "https", expr: []string{"tcp", "dport", "443", "ct", "state", "new"}},
		{name: "http3", expr: []string{"udp", "dport", "443", "ct", "state", "new"}},
	}
	sshExpr := append(sourceExpression(managementSource), "tcp", "dport", strconv.Itoa(sshPort), "ct", "state", "new")
	panelExpr := append(sourceExpression(managementSource), "tcp", "dport", strconv.Itoa(panelPort), "ct", "state", "new")
	coreRules = append(coreRules,
		struct {
			name string
			expr []string
		}{name: "ssh", expr: sshExpr},
		struct {
			name string
			expr []string
		}{name: "panel", expr: panelExpr},
	)
	for _, rule := range coreRules {
		if err := addCoreRuleIfMissing(ctx, family, table, chain, chainOutput, rule.name, rule.expr...); err != nil {
			return FirewallProtectionResult{}, err
		}
	}
	if err := setInputPolicy(ctx, family, table, chain, "drop"); err != nil {
		return FirewallProtectionResult{}, err
	}
	_, _, _, verifiedPolicy, _, verifiedWritable := firewallPortTarget(ctx)
	if !verifiedWritable || verifiedPolicy != "drop" {
		return FirewallProtectionResult{}, errors.New("保护模式验证失败，已恢复 accept 策略")
	}
	token, err := randomConfirmationToken()
	if err != nil {
		return FirewallProtectionResult{}, errors.New("无法生成保护模式确认令牌")
	}
	deadline := time.Now().Add(firewallRollbackDelay)
	protectionMu.Lock()
	pendingProtectionToken = token
	pendingProtectionDeadline = deadline
	protectionMu.Unlock()
	rollback = false
	recordOperationLog("firewall_protection_enable", "inet/filter/input", "pending", "rollback_deadline="+deadline.UTC().Format(time.RFC3339))
	return FirewallProtectionResult{ConfirmationToken: token, Deadline: deadline}, nil
}

func persistCurrentNftablesRules(ctx context.Context) error {
	ruleset, err := portCommand(ctx, "nft", "list", "ruleset")
	if err != nil || strings.TrimSpace(ruleset) == "" {
		return errors.New("无法导出当前 nftables 规则")
	}
	dir := filepath.Dir(nftablesConfigPath)
	tmp, err := os.CreateTemp(dir, ".nftables.conf.ols-wpanel-*")
	if err != nil {
		return fmt.Errorf("创建 nftables 临时配置失败: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	content := "flush ruleset\n" + strings.TrimSpace(ruleset) + "\n"
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("写入 nftables 临时配置失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("同步 nftables 临时配置失败: %w", err)
	}
	if err := tmp.Chmod(0640); err != nil {
		tmp.Close()
		return fmt.Errorf("设置 nftables 临时配置权限失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("关闭 nftables 临时配置失败: %w", err)
	}
	if out, err := portCommand(ctx, "nft", "--check", "--file", tmpPath); err != nil {
		return fmt.Errorf("持久化前验证 nftables 配置失败: %s", strings.TrimSpace(out))
	}
	if err := os.Rename(tmpPath, nftablesConfigPath); err != nil {
		return fmt.Errorf("原子替换 nftables 配置失败: %w", err)
	}
	return nil
}

func ConfirmFirewallProtection(token string) error {
	protectionMu.Lock()
	defer protectionMu.Unlock()
	if pendingProtectionToken == "" || time.Now().After(pendingProtectionDeadline) {
		return errors.New("保护模式确认已过期；系统将自动恢复 accept 策略")
	}
	if token == "" || token != pendingProtectionToken {
		return errors.New("保护模式确认令牌无效")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := persistCurrentNftablesRules(ctx); err != nil {
		return err
	}
	if err := cancelFirewallRollback(ctx); err != nil {
		return err
	}
	pendingProtectionToken = ""
	pendingProtectionDeadline = time.Time{}
	recordOperationLog("firewall_protection_confirm", "inet/filter/input", "success", "policy=drop")
	return nil
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
	runtimeByTag, _, err := listManagedRuntime(ctx, family, table, chain)
	if err != nil {
		return err
	}
	for _, id := range expired {
		var protocol, source string
		var port int
		deleteSucceeded := true
		if db.QueryRow(`SELECT protocol,port,source FROM firewall_port_rules WHERE id=?`, id).Scan(&protocol, &port, &source) == nil {
			for _, handle := range runtimeByTag[managedPortTag(protocol, port, source)].Handles {
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
		if len(runtimeByTag[tag].Handles) > 0 {
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
