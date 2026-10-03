package executor

import (
	"fmt"
	"strconv"
	"strings"
)

// Change only global Port directives; authentication and Match sections remain intact.
// sshd -T validates included files separately and rejects conflicting effective ports.
func sshPortConfig(original string, ports ...int) (string, error) {
	var b strings.Builder
	b.WriteString("# OLS WPanel managed SSH listening ports\n")
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return "", fmt.Errorf("SSH 端口必须在 1 至 65535 之间")
		}
		fmt.Fprintf(&b, "Port %d\n", p)
	}
	matched := false
	for _, line := range strings.Split(original, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.EqualFold(f[0], "Match") {
			matched = true
		}
		if !matched && len(f) > 0 && strings.EqualFold(f[0], "Port") {
			continue
		}
		if line == "# OLS WPanel managed SSH listening ports" {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func validateSSHPorts(output string, ports ...int) error {
	wanted := map[int]bool{}
	found := map[int]bool{}
	listened := map[int]bool{}
	for _, p := range ports {
		wanted[p] = true
	}
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if f[0] == "port" {
			p, _ := strconv.Atoi(f[1])
			if !wanted[p] {
				return fmt.Errorf("Include 或启动配置仍指定其他 SSH 端口，请先手动整理")
			}
			found[p] = true
		}
		if f[0] == "listenaddress" {
			i := strings.LastIndex(f[1], ":")
			if i < 0 {
				return fmt.Errorf("无法识别 ListenAddress")
			}
			p, _ := strconv.Atoi(f[1][i+1:])
			if !wanted[p] {
				return fmt.Errorf("ListenAddress 固定了其他端口，暂不支持自动修改")
			}
			listened[p] = true
		}
	}
	if len(found) != len(wanted) || len(listened) != len(wanted) {
		return fmt.Errorf("SSH 有效监听端口与预期不一致")
	}
	return nil
}

func migrateSSHAccess(rules []FirewallAccessRule, oldPort, newPort int, keepOld bool) ([]FirewallAccessRule, error) {
	out := []FirewallAccessRule{}
	found := false
	for _, r := range rules {
		if r.Protocol == "tcp" && r.Port == newPort {
			return nil, fmt.Errorf("新端口已有访问策略，请选择未使用端口")
		}
		if r.Protocol == "tcp" && r.Port == oldPort {
			found = true
			if keepOld {
				out = append(out, r)
			}
			r.Port = newPort
		}
		out = append(out, r)
	}
	if !found {
		return nil, fmt.Errorf("当前 SSH 端口没有放行来源，请先配置端口访问策略")
	}
	return out, nil
}

func shellLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
