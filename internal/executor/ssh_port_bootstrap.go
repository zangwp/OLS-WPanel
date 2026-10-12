package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

var sshBootstrapCounterRE = regexp.MustCompile(`\bcounter(?: packets [0-9]+ bytes [0-9]+)?\b`)
var sshBootstrapCommentRE = regexp.MustCompile(`\s+comment "[^"\r\n]*"$`)
var sshBootstrapPortRE = regexp.MustCompile(`^(?:(ip|ip6) saddr ([0-9a-fA-F:./]+) )?(tcp|udp) dport ([0-9]+)(?: ct state new)? accept$`)

// A fresh installer already supplies a strict base allowlist. SSH migration can
// copy that known policy into its transaction without requiring a separate UI
// policy toggle. Unbounded or custom rules cannot be safely reconstructed.
func sshMigrationAccessState(ctx context.Context, sshPort int) (bool, []FirewallAccessRule, error) {
	exists, rules, err := readAccessState(ctx)
	if err != nil || exists {
		return exists, rules, err
	}
	output, err := portCommand(ctx, "nft", "--stateless", "list", "chain", "inet", "filter", "input")
	if err != nil {
		return false, nil, errors.New("无法读取现有防火墙放行来源，暂不支持自动迁移 SSH")
	}
	panelPort, _ := PanelListenEndpoint(config.AppConfig)
	rules, err = sshBootstrapAccessRules(output, sshPort, panelPort)
	if err != nil {
		return false, nil, err
	}
	return false, rules, nil
}

func sshBootstrapAccessRules(chain string, sshPort, panelPort int) ([]FirewallAccessRule, error) {
	fail := func() ([]FirewallAccessRule, error) {
		return nil, errors.New("现有防火墙不是可完整识别的严格放行策略，请先在端口设置中预览并应用策略")
	}
	rules := []FirewallAccessRule{}
	seen := map[string]bool{}
	tableSeen, chainSeen, policySeen := false, false, false
	closed := 0
	for _, raw := range strings.Split(chain, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if line == "table inet filter {" && !tableSeen && !chainSeen {
			tableSeen = true
			continue
		}
		if line == "chain input {" && tableSeen && !chainSeen {
			chainSeen = true
			continue
		}
		if line == "}" && chainSeen {
			closed++
			continue
		}
		if !chainSeen || closed != 0 {
			return fail()
		}
		if line == "type filter hook input priority filter; policy drop;" || line == "type filter hook input priority 0; policy drop;" {
			if policySeen {
				return fail()
			}
			policySeen = true
			continue
		}
		line = sshBootstrapCommentRE.ReplaceAllString(line, "")
		line = strings.Join(strings.Fields(sshBootstrapCounterRE.ReplaceAllString(line, "")), " ")
		switch line {
		case `iifname "lo" accept`, "ct state established,related accept", "ct state { established, related } accept", "ct state invalid drop",
			"ip protocol icmp accept", "meta l4proto icmp accept", "meta l4proto ipv6-icmp accept", "ip6 nexthdr ipv6-icmp accept",
			"udp sport 67 udp dport 68 accept", "ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept":
			continue
		}
		match := sshBootstrapPortRE.FindStringSubmatch(line)
		if match == nil {
			return fail()
		}
		port, err := strconv.Atoi(match[4])
		if err != nil || port < 1 || port > 65535 {
			return fail()
		}
		source := match[2]
		if source != "" {
			if address := net.ParseIP(source); address != nil {
				bits := 128
				if address.To4() != nil {
					bits = 32
				}
				source = fmt.Sprintf("%s/%d", address.String(), bits)
			}
			_, network, err := net.ParseCIDR(source)
			if err != nil || (match[1] == "ip") != (network.IP.To4() != nil) {
				return fail()
			}
			ones, _ := network.Mask.Size()
			if ones == 0 {
				return fail()
			}
			source = network.String()
		}
		rule := FirewallAccessRule{Protocol: match[3], Port: port, Source: source}
		key := fmt.Sprintf("%s:%d:%s", rule.Protocol, rule.Port, rule.Source)
		if !seen[key] {
			rules = append(rules, rule)
			seen[key] = true
		}
	}
	if !tableSeen || !chainSeen || !policySeen || closed != 2 || len(rules) == 0 || len(rules) > 64 ||
		!accessManagementPreserved(rules, rules, sshPort, panelPort) {
		return fail()
	}
	return rules, nil
}
