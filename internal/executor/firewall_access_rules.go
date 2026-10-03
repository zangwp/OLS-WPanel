package executor

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
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
	Rules       []FirewallAccessRule `json:"rules"`
	Fingerprint string               `json:"fingerprint"`
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
		if r.Source == "" && (r.Port == 7080 || r.Port == 3306 || r.Port == 6379) {
			return nil, fmt.Errorf("WebAdmin 和数据服务端口必须指定来源 IP/CIDR")
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

func accessFingerprint(ruleset string, rules []FirewallAccessRule) string {
	data, _ := json.Marshal(rules)
	return fmt.Sprintf("%x", sha256.Sum256(append([]byte(ruleset+"\n"), data...)))
}
