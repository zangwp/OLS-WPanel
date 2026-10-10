package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	olsIPv6Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).Output()
	}
	olsIPv6Listen           = net.Listen
	olsIPv6Available        = detectOLSIPv6
	olsListenerProcessIsOLS = func(pid string) bool {
		return olsProcessUsesBinary(pid, currentOLSRuntimePaths().binary, os.Stat)
	}
)

type olsIPv6Address struct {
	Family            string          `json:"family"`
	Local             string          `json:"local"`
	Scope             string          `json:"scope"`
	Flags             []string        `json:"flags"`
	Tentative         bool            `json:"tentative"`
	DADFailed         bool            `json:"dadfailed"`
	Deprecated        bool            `json:"deprecated"`
	PreferredLifeTime json.RawMessage `json:"preferred_life_time"`
	ValidLifeTime     json.RawMessage `json:"valid_life_time"`
}

type olsIPv6Interface struct {
	Name      string           `json:"ifname"`
	Flags     []string         `json:"flags"`
	Addresses []olsIPv6Address `json:"addr_info"`
}

type olsIPv6Route struct {
	Destination string   `json:"dst"`
	Device      string   `json:"dev"`
	Type        string   `json:"type"`
	Flags       []string `json:"flags"`
}

// detectOLSIPv6 checks the VPS network itself, without DNS or a remote probe.
// Missing iproute2, an unreadable route, or disabled IPv6 simply keeps IPv4.
func detectOLSIPv6() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return probeOLSIPv6(ctx)
}

func probeOLSIPv6(ctx context.Context) bool {
	addresses, err := olsIPv6Command(ctx, "ip", "-6", "-j", "addr", "show", "up", "scope", "global")
	if err != nil {
		return false
	}
	routes, err := olsIPv6Command(ctx, "ip", "-6", "-j", "route", "show", "default")
	if err != nil || !olsIPv6NetworkReady(addresses, routes) {
		return false
	}
	listener, err := olsIPv6Listen("tcp6", "[::]:0")
	if err != nil {
		return false
	}
	return listener.Close() == nil
}

func olsIPv6HasFlag(flags []string, expected string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, expected) {
			return true
		}
	}
	return false
}

func olsIPv6NetworkReady(addressJSON, routeJSON []byte) bool {
	var interfaces []olsIPv6Interface
	var routes []olsIPv6Route
	if json.Unmarshal(addressJSON, &interfaces) != nil || json.Unmarshal(routeJSON, &routes) != nil {
		return false
	}
	publicIPv6 := netip.MustParsePrefix("2000::/3")
	documentationIPv6 := netip.MustParsePrefix("2001:db8::/32")
	devices := map[string]bool{}
	for _, iface := range interfaces {
		if iface.Name == "" || !olsIPv6HasFlag(iface.Flags, "UP") || olsIPv6HasFlag(iface.Flags, "LOOPBACK") {
			continue
		}
		for _, address := range iface.Addresses {
			ip, err := netip.ParseAddr(address.Local)
			if err != nil || address.Family != "inet6" || address.Scope != "global" || !publicIPv6.Contains(ip) || documentationIPv6.Contains(ip) ||
				address.Tentative || address.DADFailed || address.Deprecated || olsIPv6HasFlag(address.Flags, "tentative") || olsIPv6HasFlag(address.Flags, "dadfailed") || olsIPv6HasFlag(address.Flags, "deprecated") ||
				string(address.PreferredLifeTime) == "0" || string(address.ValidLifeTime) == "0" {
				continue
			}
			devices[iface.Name] = true
		}
	}
	for _, route := range routes {
		if route.Destination != "default" && route.Destination != "::/0" {
			continue
		}
		if route.Type != "" && route.Type != "unicast" {
			continue
		}
		if devices[route.Device] && !olsIPv6HasFlag(route.Flags, "linkdown") && !olsIPv6HasFlag(route.Flags, "dead") {
			return true
		}
	}
	return false
}

// A successful OLS restart does not guarantee that every listener bound.
// Query each address family separately so ss's wildcard "*" cannot cause an
// IPv4 socket to satisfy the IPv6 check. This reads only local kernel state.
func verifyOLSIPv6Listeners() error {
	return verifyOLSWebListeners(true)
}

// An IPv4 fallback must still prove that the retained public listeners bound;
// it deliberately does not require the optional IPv6 listeners to exist.
func verifyOLSWebListeners(requireIPv6 bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	families := []string{"-4"}
	if requireIPv6 {
		families = append(families, "-6")
	}
	for {
		var missing error
		for _, family := range families {
			output, err := olsIPv6Command(ctx, "ss", "-H", "-l", "-t", "-n", "-p", family)
			if err != nil {
				return fmt.Errorf("读取 OpenLiteSpeed %s 监听失败: %w", family, err)
			}
			if !olsWildcardWebListenersReady(output, family == "-6") {
				missing = fmt.Errorf("OpenLiteSpeed %s 通配监听尚未确认由实际 OLS 进程绑定 80 和 443", family)
			}
		}
		if missing == nil {
			return nil
		}
		// Allow a brief local startup delay after the service reports success.
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return missing
		case <-timer.C:
		}
	}
}

func olsWildcardWebListenersReady(output []byte, ipv6 bool) bool {
	ports := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "LISTEN" {
			continue
		}
		host, port, err := net.SplitHostPort(fields[3])
		if ipv6 && (fields[3] == ":::80" || fields[3] == ":::443") {
			// Some ss versions print the IPv6 wildcard without brackets.
			host, port, err = "::", strings.TrimPrefix(fields[3], ":::"), nil
		}
		if err != nil || (port != "80" && port != "443") {
			continue
		}
		wildcard := host == "*"
		if ip, err := netip.ParseAddr(host); err == nil {
			wildcard = ip.IsUnspecified() && ip.Is6() == ipv6 && !ip.Is4In6()
		}
		if wildcard && olsListenerOwnedByOLS(line) {
			ports[port] = true
		}
	}
	return ports["80"] && ports["443"]
}

// Ignore quoted process names entirely: comm is not proof of executable
// ownership, and a name containing "pid=" must not become a second owner.
func olsListenerOwnedByOLS(line string) bool {
	start := strings.Index(line, "users:(")
	if start < 0 {
		return false
	}
	owners, quoted := 0, false
	users := line[start:]
	for i := 0; i < len(users); i++ {
		if quoted {
			if users[i] == '\\' {
				i++
			} else if users[i] == '"' {
				quoted = false
			}
			continue
		}
		if users[i] == '"' {
			quoted = true
			continue
		}
		if !strings.HasPrefix(users[i:], ",pid=") {
			continue
		}
		begin, end := i+5, i+5
		for end < len(users) && users[end] >= '0' && users[end] <= '9' {
			end++
		}
		if end == begin || end >= len(users) || users[end] != ',' && users[end] != ')' || !olsListenerProcessIsOLS(users[begin:end]) {
			return false
		}
		owners++
		i = end - 1
	}
	return owners > 0 && !quoted
}

func olsProcessUsesBinary(pid, binary string, stat func(string) (os.FileInfo, error)) bool {
	number, err := strconv.ParseUint(pid, 10, 32)
	if err != nil || number == 0 {
		return false
	}
	expected, err := stat(binary)
	if err != nil || !expected.Mode().IsRegular() {
		return false
	}
	actual, err := stat("/proc/" + pid + "/exe")
	return err == nil && actual.Mode().IsRegular() && os.SameFile(expected, actual)
}
