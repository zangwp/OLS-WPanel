package executor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

const accessTable = "ols_wpanel_access"

// An additional input hook restricts access even when an older chain accepts it.
// Accepting here never bypasses a drop in another administrator-owned chain.
type FirewallAccessRule struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Source   string `json:"source"` // empty means public, for both address families
}

type FirewallAccessRequest struct {
	Rules         []FirewallAccessRule `json:"rules"`
	Fingerprint   string               `json:"fingerprint"`
	ConfirmPublic bool                 `json:"confirm_public"`
}

func normalizeAccessRules(rules []FirewallAccessRule, managementIP string, sshPort, panelPort int) ([]FirewallAccessRule, error) {
	ip := net.ParseIP(managementIP)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		return nil, fmt.Errorf("无法识别直接连接的管理 IP")
	}
	if len(rules) == 0 || len(rules) > 64 {
		return nil, fmt.Errorf("请选择 1 至 64 条放行规则")
	}
	result := make([]FirewallAccessRule, 0, len(rules))
	seen := map[string]bool{}
	sshOK, panelOK := false, false
	for _, r := range rules {
		r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
		if (r.Protocol != "tcp" && r.Protocol != "udp") || r.Port < 1 || r.Port > 65535 {
			return nil, fmt.Errorf("端口或协议无效")
		}
		r.Source = strings.TrimSpace(r.Source)
		contains := r.Source == ""
		if r.Source != "" {
			if sourceIP := net.ParseIP(r.Source); sourceIP != nil {
				bits := 128
				if sourceIP.To4() != nil {
					bits = 32
				}
				r.Source = fmt.Sprintf("%s/%d", sourceIP.String(), bits)
			}
			_, network, err := net.ParseCIDR(r.Source)
			if err != nil {
				return nil, fmt.Errorf("来源必须是 IPv4、IPv6 或 CIDR")
			}
			ones, _ := network.Mask.Size()
			if ones == 0 {
				return nil, fmt.Errorf("全网开放请使用公开访问选项")
			}
			r.Source = network.String()
			contains = network.Contains(ip)
		}
		if r.Protocol == "tcp" && contains {
			if r.Port == sshPort {
				sshOK = true
			}
			if r.Port == panelPort {
				panelOK = true
			}
		}
		key := fmt.Sprintf("%s:%d:%s", r.Protocol, r.Port, r.Source)
		if !seen[key] {
			result = append(result, r)
			seen[key] = true
		}
	}
	if !sshOK || !panelOK {
		return nil, fmt.Errorf("SSH 和面板端口必须保留当前管理 IP 的访问权限")
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Source < b.Source
	})
	return result, nil
}

func accessPublicExposure(previous, next []FirewallAccessRule, previousManaged bool) []FirewallAccessRule {
	previousPublic := make(map[FirewallAccessRule]bool)
	if previousManaged {
		for _, rule := range previous {
			if rule.Source == "" {
				previousPublic[rule] = true
			}
		}
	}
	exposure := []FirewallAccessRule{}
	seen := make(map[FirewallAccessRule]bool)
	for _, rule := range next {
		if rule.Source != "" || (rule.Port != 7080 && rule.Port != 3306 && rule.Port != 6379) || previousPublic[rule] || seen[rule] {
			continue
		}
		exposure = append(exposure, rule)
		seen[rule] = true
	}
	return exposure
}

func accessRulesScript(rules []FirewallAccessRule, replace bool) string {
	var b strings.Builder
	if replace {
		fmt.Fprintf(&b, "delete table inet %s\n", accessTable)
	}
	fmt.Fprintf(&b, "table inet %s {\n chain input {\n type filter hook input priority -5; policy drop;\n", accessTable)
	b.WriteString("iifname \"lo\" accept\nct state established,related accept\nmeta l4proto icmp accept\nmeta l4proto ipv6-icmp accept\n")
	b.WriteString("udp sport 67 udp dport 68 accept\nip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n")
	for _, r := range rules {
		if r.Source != "" {
			family := "ip"
			if strings.Contains(r.Source, ":") {
				family = "ip6"
			}
			fmt.Fprintf(&b, "%s saddr %s ", family, r.Source)
		}
		fmt.Fprintf(&b, "%s dport %d counter accept comment \"ols-access:%s:%d:%s\"\n", r.Protocol, r.Port, r.Protocol, r.Port, r.Source)
	}
	b.WriteString("}\n}\n")
	return b.String()
}

func accessFingerprint(previousTable string, rules []FirewallAccessRule, sshPort, panelPort int) string {
	data, _ := json.Marshal(rules)
	// Only this table is replaced. Traffic-updated sets and independent bans in
	// other tables must not invalidate an otherwise unchanged access selection.
	// A previously checked selection must not become valid after a management
	// endpoint changes, even if it happened to include both old and new ports.
	endpoints := fmt.Sprintf("\nssh=%d;panel=%d\n", sshPort, panelPort)
	return fmt.Sprintf("%x", sha256.Sum256(append([]byte(previousTable+endpoints), data...)))
}

// accessSourceCovers proves that every address admitted by previous remains
// admitted by next. Public access spans both families, so a single CIDR cannot
// replace it even if it contains the current administrator.
func accessSourceCovers(next, previous string) bool {
	if next == "" {
		return true
	}
	if previous == "" {
		return false
	}
	_, nextNetwork, nextErr := net.ParseCIDR(next)
	_, previousNetwork, previousErr := net.ParseCIDR(previous)
	if nextErr != nil || previousErr != nil {
		return false
	}
	nextBits, nextSize := nextNetwork.Mask.Size()
	previousBits, previousSize := previousNetwork.Mask.Size()
	return nextSize == previousSize && nextBits <= previousBits && nextNetwork.Contains(previousNetwork.IP)
}

func accessManagementPreserved(previous, next []FirewallAccessRule, sshPort, panelPort int) bool {
	sshPresent, panelPresent := false, false
	for _, old := range previous {
		if old.Protocol != "tcp" || (old.Port != sshPort && old.Port != panelPort) {
			continue
		}
		sshPresent = sshPresent || old.Port == sshPort
		panelPresent = panelPresent || old.Port == panelPort
		covered := false
		for _, candidate := range next {
			if candidate.Protocol == old.Protocol && candidate.Port == old.Port && accessSourceCovers(candidate.Source, old.Source) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return sshPresent && panelPresent
}

// Only an exact panel-owned table can use the fast save path. Tagged comments
// alone do not prove rule semantics: a manual rule or forged comment must keep
// the rollback workflow instead of silently losing management access.
func accessTableMatchesManagedPolicy(table string, rules []FirewallAccessRule) bool {
	current, currentOK := canonicalManagedAccessTable(table)
	expected, expectedOK := canonicalManagedAccessTable(accessRulesScript(rules, false))
	return currentOK && expectedOK && current == expected
}

var accessPolicySourceRE = regexp.MustCompile(`\b(ip|ip6) saddr ([0-9a-fA-F:./]+)`)
var accessPolicyCounterRE = regexp.MustCompile(`\bcounter packets [0-9]+ bytes [0-9]+\b`)

func canonicalManagedAccessTable(table string) (string, bool) {
	value := strings.Join(strings.Fields(table), " ")
	quoted := strings.Split(value, `"`)
	if len(quoted)%2 == 0 {
		return value, false
	}
	valid := true
	for i := 0; i < len(quoted); i += 2 {
		segment := strings.ReplaceAll(quoted[i], "priority filter - 5;", "priority -5;")
		segment = strings.ReplaceAll(segment, "ct state { established, related }", "ct state established,related")
		segment = accessPolicyCounterRE.ReplaceAllString(segment, "counter")
		quoted[i] = accessPolicySourceRE.ReplaceAllStringFunc(segment, func(source string) string {
			parts := strings.Fields(source)
			address := parts[2]
			if ip := net.ParseIP(address); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				address = fmt.Sprintf("%s/%d", ip.String(), bits)
			}
			_, network, err := net.ParseCIDR(address)
			if err != nil || (parts[0] == "ip") != (network.IP.To4() != nil) {
				valid = false
				return source
			}
			return parts[0] + " saddr " + network.String()
		})
	}
	return strings.Join(quoted, `"`), valid
}
