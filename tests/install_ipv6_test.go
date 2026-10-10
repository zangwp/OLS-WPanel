package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestInstallIPv6DetectionUsesLocalBoundedProbes(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	helper := extractShellFunction(t, script, "ols_ipv6_available", "append_ols_ipv6_listeners")
	for _, required := range []string{
		"timeout 2s ip -6 -j addr show up scope global",
		"timeout 2s ip -6 -j route show default",
		"${#ipv6_addresses} -le 65536",
		"${#ipv6_routes} -le 65536",
		`timeout 2s "$php_cli" -n -r`,
		`stream_socket_server("tcp://[::]:0"`,
		"fclose($socket)",
	} {
		if !strings.Contains(helper, required) {
			t.Errorf("IPv6 probe missing %q", required)
		}
	}
	for _, forbidden := range []string{"curl", "wget", "ping", "gethost", "dns_get_record", "stream_socket_client", "socket_connect", "sysctl -w"} {
		if strings.Contains(helper, forbidden) {
			t.Errorf("IPv6 probe must not make external requests or change network state: %q", forbidden)
		}
	}
}

func TestInstallIPv6DetectionRequiresUsableAddressDefaultRouteAndKernel(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		if os.Getenv("OLS_WPANEL_REQUIRE_PHP_TESTS") == "1" {
			t.Fatal("PHP runtime required for IPv6 installer regression")
		}
		t.Skip("PHP runtime unavailable")
	}
	script := readInstallScript(t, installScriptPath)
	helper := extractShellFunction(t, script, "ols_ipv6_available", "append_ols_ipv6_listeners")
	helper = strings.Replace(helper, `local php_cli="/usr/local/lsws/lsphp85/bin/php"`, "local php_cli="+strconv.Quote(filepath.ToSlash(php)), 1)
	address := func(flags []string, local string, extra map[string]any) string {
		entry := map[string]any{"family": "inet6", "scope": "global", "local": local, "preferred_life_time": "forever", "valid_life_time": "forever"}
		for key, value := range extra {
			entry[key] = value
		}
		data, err := json.Marshal([]any{map[string]any{"ifname": "eth0", "flags": flags, "addr_info": []any{entry}}})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	valid := address([]string{"UP", "LOWER_UP"}, "2001:4860:1234::10", nil)
	route := `[{"dst":"default","gateway":"fe80::1","dev":"eth0","flags":[]}]`
	for _, tc := range []struct {
		name, addresses, routes, failure string
		wantEnabled, wantKernel          bool
	}{
		{name: "dual stack", addresses: valid, routes: route, wantEnabled: true, wantKernel: true},
		{name: "on-link default", addresses: valid, routes: `[{"dst":"::/0","dev":"eth0","type":"unicast","flags":["onlink"]}]`, wantEnabled: true, wantKernel: true},
		{name: "no IPv6", addresses: "[]", routes: route},
		{name: "no default route", addresses: valid, routes: "[]"},
		{name: "nondefault route", addresses: valid, routes: `[{"dst":"2000::/3","dev":"eth0"}]`},
		{name: "route on other interface", addresses: valid, routes: `[{"dst":"default","dev":"eth1"}]`},
		{name: "blackhole route", addresses: valid, routes: `[{"dst":"default","dev":"eth0","type":"blackhole"}]`},
		{name: "dead route", addresses: valid, routes: `[{"dst":"default","dev":"eth0","flags":["dead"]}]`},
		{name: "linkdown route", addresses: valid, routes: `[{"dst":"default","dev":"eth0","flags":["linkdown"]}]`},
		{name: "down interface", addresses: address([]string{"LOWER_UP"}, "2001:4860:1234::10", nil), routes: route},
		{name: "loopback interface", addresses: address([]string{"UP", "LOOPBACK"}, "2001:4860:1234::10", nil), routes: route},
		{name: "loopback address", addresses: address([]string{"UP"}, "::1", nil), routes: route},
		{name: "link-local address", addresses: address([]string{"UP"}, "fe80::10", nil), routes: route},
		{name: "private address", addresses: address([]string{"UP"}, "fd00::10", nil), routes: route},
		{name: "documentation address", addresses: address([]string{"UP"}, "2001:db8::10", nil), routes: route},
		{name: "IPv4 address", addresses: address([]string{"UP"}, "192.0.2.10", nil), routes: route},
		{name: "wrong family", addresses: address([]string{"UP"}, "2001:4860:1234::10", map[string]any{"family": "inet"}), routes: route},
		{name: "wrong scope", addresses: address([]string{"UP"}, "2001:4860:1234::10", map[string]any{"scope": "link"}), routes: route},
		{name: "tentative", addresses: address([]string{"UP"}, "2001:4860:1234::10", map[string]any{"tentative": true}), routes: route},
		{name: "dad failed", addresses: address([]string{"UP"}, "2001:4860:1234::10", map[string]any{"dadfailed": true}), routes: route},
		{name: "deprecated flag", addresses: address([]string{"UP"}, "2001:4860:1234::10", map[string]any{"flags": []string{"deprecated"}}), routes: route},
		{name: "zero preferred lifetime", addresses: address([]string{"UP"}, "2001:4860:1234::10", map[string]any{"preferred_life_time": 0}), routes: route},
		{name: "zero valid lifetime", addresses: address([]string{"UP"}, "2001:4860:1234::10", map[string]any{"valid_life_time": 0}), routes: route},
		{name: "malformed address JSON", addresses: "[", routes: route},
		{name: "malformed route JSON", addresses: valid, routes: "["},
		{name: "oversized inventory", addresses: strings.Repeat(" ", 65537), routes: route},
		{name: "address command failure", addresses: valid, routes: route, failure: "addr"},
		{name: "route command failure", addresses: valid, routes: route, failure: "route"},
		{name: "kernel disabled", addresses: valid, routes: route, failure: "kernel", wantKernel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probeLog := filepath.ToSlash(filepath.Join(t.TempDir(), "probes.log"))
			addressValue := strconv.Quote(tc.addresses)
			if len(tc.addresses) > 65536 {
				addressValue = `"$(printf '%65537s' '')"`
			}
			fixture := fmt.Sprintf(`addresses=%s
routes=%s
failure=%s
probe_log=%s
ip() {
    case "$*" in
        '-6 -j addr show up scope global') [[ "$failure" != addr ]] || return 1; printf '%%s' "$addresses" ;;
        '-6 -j route show default') [[ "$failure" != route ]] || return 1; printf '%%s' "$routes" ;;
        *) echo unexpected-ip >&2; return 1 ;;
    esac
}
timeout() {
    [[ "$1" == 2s ]] || return 1
    shift
    if [[ "$*" == *stream_socket_server* ]]; then
        printf 'kernel\n' >> "$probe_log"
        [[ "$failure" != kernel ]]
    else
        "$@"
    fi
}
%s
if ols_ipv6_available; then echo DUAL_STACK; else echo IPV4_ONLY; fi
`, addressValue, strconv.Quote(tc.routes), strconv.Quote(tc.failure), strconv.Quote(probeLog), helper)
			out, err := lifecycleBash(t, fixture)
			if err != nil || strings.Contains(string(out), "DUAL_STACK") != tc.wantEnabled {
				t.Fatalf("enabled=%t err=%v output=%s", tc.wantEnabled, err, out)
			}
			_, probeErr := os.Stat(probeLog)
			if (probeErr == nil) != tc.wantKernel {
				t.Fatalf("kernel probe=%t, want=%t", probeErr == nil, tc.wantKernel)
			}
		})
	}
}

func TestInstallIPv6RegistryPreservesIPv4MappingsAndCertificates(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	appendHelper := extractShellFunction(t, script, "append_ols_ipv6_listeners", "require_ols_listeners")
	start := requiredIndex(t, script, `cat > "$OLS_MANAGED_CONF" << 'OLSMANAGEDEOF'`)
	end := strings.Index(script[start:], `chmod 0640 "$OLS_MANAGED_CONF"`)
	if end < 0 {
		t.Fatal("managed registry block is incomplete")
	}
	registry := script[start : start+end]
	heredocStart := strings.Index(registry, "\n") + 1
	heredocEnd := strings.Index(registry, "\nOLSMANAGEDEOF")
	ipv4Original := registry[heredocStart:heredocEnd] + "\n"
	guard := requiredLastIndexBefore(t, script, "if ! $REPAIR_MODE; then", start)
	repairMessage := requiredIndex(t, script, `log_info "repair模式不改写或重载 OpenLiteSpeed 配置"`)
	if guard >= start || repairMessage <= start {
		t.Fatal("registry configuration must preserve the fresh-install/repair boundary")
	}
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			conf := filepath.ToSlash(filepath.Join(t.TempDir(), "sites.conf"))
			fixture := fmt.Sprintf("OLS_MANAGED_CONF=%s\nINSTALL_WORKDIR=%s\nOLS_CONF_DIR=/managed/certs\nlog_info() { :; }\nols_ipv6_available() { %t; }\n", strconv.Quote(conf), strconv.Quote(filepath.ToSlash(filepath.Dir(conf))), enabled) + appendHelper + "\n" + registry
			out, err := lifecycleBash(t, fixture)
			if err != nil {
				t.Fatalf("registry render failed: %v %s", err, out)
			}
			data, err := os.ReadFile(conf)
			if err != nil {
				t.Fatal(err)
			}
			got := string(data)
			if !strings.HasPrefix(got, ipv4Original) {
				t.Fatal("original IPv4 registry changed")
			}
			wantTLSListeners := 1
			if enabled {
				wantTLSListeners = 2
			}
			if strings.Count(got, "sslProtocol             24\n") != wantTLSListeners || strings.Contains(got, "sslProtocol             30") {
				t.Fatal("all HTTPS listener families must allow only TLS 1.2 and TLS 1.3")
			}
			if !enabled {
				if got != ipv4Original {
					t.Fatal("IPv4-only install must emit its original registry unchanged")
				}
				return
			}
			for _, required := range []string{"listener OLSWPanelHTTPIPv6 {", "address                 [ANY]:80", "listener OLSWPanelHTTPSIPv6 {", "address                 [ANY]:443", "keyFile                 /managed/certs/default.key", "certFile                /managed/certs/default.crt"} {
				if strings.Count(got, required) != 1 {
					t.Errorf("IPv6 registry requires one %q", required)
				}
			}
			if strings.Count(got, "map                     olsw_default *") != 4 {
				t.Fatal("both IPv4 and IPv6 listeners must map the same safe default vhost")
			}
		})
	}
	probeCall := `append_ols_ipv6_listeners /usr/local/lsws/conf/httpd_config.conf 8080 8443 olsw_example example.test "$OLS_CHECK_ROOT"`
	probeStart := requiredIndex(t, script, "if $CHECK_OLS_PACKAGES_ONLY; then")
	probeEnd := requiredIndex(t, script[probeStart:], "    exit 0\nfi") + probeStart
	if !strings.Contains(script[probeStart:probeEnd], probeCall+"\n    /usr/local/lsws/bin/openlitespeed -t") {
		t.Fatal("isolated package probe must parse the same IPv6 listener syntax before reporting success")
	}
	if strings.Count(script[probeStart:probeEnd], "sslProtocol            24\n") != 2 {
		t.Fatal("isolated package probe must use modern TLS for both its SNI vhost and HTTPS listener")
	}
}

func TestInstallIPv6ListenerReadinessChecksBothFamilies(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	helper := extractShellFunction(t, script, "ols_listener_pid_is_ols", "apply_system_tuning")
	for _, tc := range []struct {
		name, ipv4, ipv6 string
		enabled, ready   bool
	}{
		{"IPv4-only unchanged", "0.0.0.0:80 0.0.0.0:443", "", false, true},
		{"IPv4-only rejects specific host address", "192.0.2.10:80 192.0.2.10:443", "", false, false},
		{"IPv4-only rejects loopback sockets", "127.0.0.1:80 127.0.0.1:443", "", false, false},
		{"both families", "0.0.0.0:80 0.0.0.0:443", "[::]:80 [::]:443", true, true},
		{"family-specific star wildcards", "*:80 *:443", "*:80 *:443", true, true},
		{"unbracketed IPv6 wildcards", "0.0.0.0:80 0.0.0.0:443", ":::80 :::443", true, true},
		{"missing IPv6 HTTPS", "0.0.0.0:80 0.0.0.0:443", "[::]:80", true, false},
		{"missing IPv4 HTTP", "0.0.0.0:443", "[::]:80 [::]:443", true, false},
		{"IPv6 loopback only", "0.0.0.0:80 0.0.0.0:443", "[::1]:80 [::1]:443", true, false},
		{"IPv4 loopback only", "127.0.0.1:80 127.0.0.1:443", "[::]:80 [::]:443", true, false},
		{"IPv6 host address only", "0.0.0.0:80 0.0.0.0:443", "[2001:4860:1234::10]:80 [2001:4860:1234::10]:443", true, false},
		{"IPv4 address in IPv6 result", "0.0.0.0:80 0.0.0.0:443", "0.0.0.0:80 0.0.0.0:443", true, false},
		{"IPv6 address in IPv4 result", "[::]:80 [::]:443", "[::]:80 [::]:443", true, false},
		{"wrong port suffix", "0.0.0.0:8080 0.0.0.0:8443", "[::]:80 [::]:443", true, false},
		{"IPv4 query fails with partial sockets", "query-failure", "[::]:80 [::]:443", true, false},
		{"IPv6 query fails with partial sockets", "0.0.0.0:80 0.0.0.0:443", "query-failure", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"fatal", "return"} {
				t.Run(mode, func(t *testing.T) {
					fixture := fmt.Sprintf(`OLS_IPV6_ENABLED=%t
ipv4=%s
ipv6=%s
mode=%s
ss() {
    case "$*" in
        '-H -l -t -n -p -4') addresses="$ipv4" ;;
        '-H -l -t -n -p -6') addresses="$ipv6" ;;
        *) echo unexpected-ss >&2; return 1 ;;
    esac
    failed=false
    if [[ "$addresses" == query-failure ]]; then
        failed=true
        if [[ "$*" == *-4 ]]; then addresses='0.0.0.0:80 0.0.0.0:443'; else addresses='[::]:80 [::]:443'; fi
    fi
    for address in $addresses; do printf 'LISTEN 0 511 %%s *:* users:(("test-only-owner",pid=4242,fd=7))\n' "$address"; done
    ! $failed
}
timeout() { [[ "$1" == 2s ]] || return 1; shift; "$@"; }
sleep() { :; }
log_error() { echo ERROR; exit 1; }
%s
# Test-only /proc identity boundary; the production helper is separately checked.
ols_listener_pid_is_ols() { [[ "$1" == 4242 ]]; }
if [[ "$mode" == return ]]; then
    if require_ols_listeners return; then echo READY; else echo RETURNED; fi
else
    require_ols_listeners
    echo READY
fi
`, tc.enabled, strconv.Quote(tc.ipv4), strconv.Quote(tc.ipv6), strconv.Quote(mode), helper)
					out, err := lifecycleBash(t, fixture)
					if (err == nil) != (tc.ready || mode == "return") || strings.Contains(string(out), "READY") != tc.ready {
						t.Fatalf("ready=%t err=%v output=%s", tc.ready, err, out)
					}
					if !tc.ready && mode == "fatal" && !strings.Contains(string(out), "ERROR") {
						t.Fatalf("listener rejection must reach its own fatal guard, not a missing runtime tool: %v %s", err, out)
					}
					if !tc.ready && mode == "return" && (!strings.Contains(string(out), "RETURNED") || strings.Contains(string(out), "ERROR")) {
						t.Fatalf("optional IPv6 startup must return to its fallback instead of terminating installation: %v %s", err, out)
					}
				})
			}
		})
	}
}

func TestInstallIPv6ListenerOwnershipIgnoresProcessNames(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	helper := extractShellFunction(t, script, "ols_listener_pid_is_ols", "require_ols_listeners")
	for _, tc := range []struct {
		name, owners string
		ready        bool
	}{
		{"different comm same executable", `users:(("nginx",pid=4242,fd=7))`, true},
		{"OLS comm different executable", `users:(("openlitespeed",pid=9898,fd=7))`, false},
		{"missing ownership", "", false},
		{"unavailable proc permission", `users:(("openlitespeed",pid=9999,fd=7))`, false},
		{"pid inside quoted comm ignored", `users:((",pid=4242,",pid=9898,fd=7))`, false},
		{"escaped quote inside comm", `users:(("fake\",pid=9898,",pid=4242,fd=7))`, true},
		{"two genuine OLS owners", `users:(("one",pid=4242,fd=7),("two",pid=4242,fd=9))`, true},
		{"additional foreign owner", `users:(("one",pid=4242,fd=7),("two",pid=9898,fd=9))`, false},
		{"malformed pid", `users:(("one",pid=4242x,fd=7))`, false},
		{"unterminated comm", `users:(("one,pid=4242,fd=7))`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := helper + `
# Test-only process identity boundary: 9898 is another binary; 9999 is unreadable.
ols_listener_pid_is_ols() { [[ "$1" == 4242 ]]; }
line=` + strconv.Quote("LISTEN 0 511 [::]:443 *:* "+tc.owners) + `
if ols_listener_owned_by_ols "$line"; then echo READY; else echo REJECTED; fi
`
			out, err := lifecycleBash(t, fixture)
			if err != nil || strings.Contains(string(out), "READY") != tc.ready {
				t.Fatalf("ready=%t err=%v output=%s", tc.ready, err, out)
			}
		})
	}
}

func TestInstallIPv6ListenerOwnershipUsesExecutableFileIdentity(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	helper := extractShellFunction(t, script, "ols_listener_pid_is_ols", "ols_listener_owned_by_ols")
	if !strings.Contains(helper, `"/proc/$pid/exe" -ef /usr/local/lsws/bin/openlitespeed`) {
		t.Fatal("installer must compare the actual kernel executable with the installed OLS binary")
	}
	// Relocate only the /proc and installed binary paths to writable fixtures.
	// The actual Bash -f/-ef validation remains unchanged and touches no service.
	helper = strings.ReplaceAll(helper, "/usr/local/lsws/bin/openlitespeed", `"$OLS_TEST_BINARY"`)
	helper = strings.ReplaceAll(helper, `"/proc/$pid/exe"`, `"$OLS_TEST_PROCESS_EXE"`)
	root := t.TempDir()
	binary, same, other, missing := filepath.Join(root, "openlitespeed"), filepath.Join(root, "proc-exe"), filepath.Join(root, "other-server"), filepath.Join(root, "missing")
	for _, file := range []string{binary, other} {
		if err := os.WriteFile(file, []byte("test fixture only; never executed"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(binary, same); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, binary, process, pid string
		ready                      bool
	}{
		{"same inode different path", binary, same, "4242", true},
		{"other server binary", binary, other, "4242", false},
		{"missing proc exe", binary, missing, "4242", false},
		{"missing installed binary", missing, same, "4242", false},
		{"invalid pid", binary, same, "bad", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := "OLS_TEST_BINARY=" + strconv.Quote(filepath.ToSlash(tc.binary)) + "\nOLS_TEST_PROCESS_EXE=" + strconv.Quote(filepath.ToSlash(tc.process)) + "\n" + helper +
				"\nif ols_listener_pid_is_ols " + strconv.Quote(tc.pid) + "; then echo READY; else echo REJECTED; fi\n"
			out, err := lifecycleBash(t, fixture)
			if err != nil || strings.Contains(string(out), "READY") != tc.ready {
				t.Fatalf("ready=%t err=%v output=%s", tc.ready, err, out)
			}
		})
	}
}

func TestInstallIPv6StartupFallsBackOnlyToSavedIPv4Registry(t *testing.T) {
	script := readInstallScript(t, installScriptPath)
	start := requiredIndex(t, script, "OLS_READY=false\n")
	end := requiredIndex(t, script[start:], `log_info "OpenLiteSpeed 基础配置完成`) + start
	startup := strings.ReplaceAll(script[start:end], "/usr/local/lsws/bin/openlitespeed", "ols_config_check")
	for _, tc := range []struct {
		name, failure                    string
		ipv6, missingSnapshot, recovered bool
		wantFailure                      bool
	}{
		{name: "IPv4-only original flow"},
		{name: "dual-stack succeeds", ipv6: true},
		{name: "IPv6 syntax fails", ipv6: true, failure: "config6", recovered: true},
		{name: "IPv6 restart fails", ipv6: true, failure: "restart6", recovered: true},
		{name: "IPv6 listener missing", ipv6: true, failure: "listeners6", recovered: true},
		{name: "IPv6 service inactive", ipv6: true, failure: "active6", recovered: true},
		{name: "snapshot missing", ipv6: true, failure: "listeners6", missingSnapshot: true, wantFailure: true},
		{name: "snapshot copy fails", ipv6: true, failure: "restore", wantFailure: true},
		{name: "IPv4 syntax also fails", ipv6: true, failure: "config4", recovered: true, wantFailure: true},
		{name: "IPv4 restart also fails", ipv6: true, failure: "restart4", recovered: true, wantFailure: true},
		{name: "IPv4 service also inactive", ipv6: true, failure: "active4", recovered: true, wantFailure: true},
		{name: "IPv4 listeners also fail", ipv6: true, failure: "listeners4", recovered: true, wantFailure: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			conf := filepath.ToSlash(filepath.Join(root, "sites.conf"))
			snapshot := filepath.ToSlash(filepath.Join(root, "saved-ipv4.conf"))
			const original = "original managed IPv4 registry\n"
			current := original
			if tc.ipv6 {
				current += "new IPv6 listeners\n"
			}
			if err := os.WriteFile(conf, []byte(current), 0600); err != nil {
				t.Fatal(err)
			}
			if !tc.missingSnapshot {
				if err := os.WriteFile(snapshot, []byte(original), 0600); err != nil {
					t.Fatal(err)
				}
			}
			fixture := fmt.Sprintf(`OLS_IPV6_ENABLED=%t
OLS_MANAGED_CONF=%s
OLS_IPV4_REGISTRY=%s
failure=%s
log_error() { echo ERROR; exit 1; }
log_warn() { echo FALLBACK; }
ols_config_check() {
    if $OLS_IPV6_ENABLED; then echo CHECK6; [[ "$failure" != config6 ]]; else echo CHECK4; [[ "$failure" != config4 ]]; fi
}
systemctl() {
    if [[ "$1" == restart ]]; then
        if $OLS_IPV6_ENABLED; then echo RESTART6; [[ "$failure" != restart6 ]]; else echo RESTART4; [[ "$failure" != restart4 ]]; fi
    elif [[ "$1" == is-active ]]; then
        [[ "$failure" != active6 ]]
    fi
}
require_ols_listeners() {
    if $OLS_IPV6_ENABLED; then
        echo LISTEN6
        [[ "$failure" != listeners6 && "$failure" != restore && "$failure" != config4 && "$failure" != restart4 && "$failure" != active4 && "$failure" != listeners4 ]]
    else
        echo LISTEN4
        [[ "$failure" != listeners4 ]] || log_error
    fi
}
systemctl_wait_active_required() { echo WAIT4; [[ "$failure" != active4 ]] || log_error; }
cp() { [[ "$failure" != restore ]] && command cp "$@"; }
chown() { :; }
chmod() { :; }
%s
echo READY
`, tc.ipv6, strconv.Quote(conf), strconv.Quote(snapshot), strconv.Quote(tc.failure), startup)
			out, err := lifecycleBash(t, fixture)
			if (err != nil) != tc.wantFailure {
				t.Fatalf("failure=%t err=%v output=%s", tc.wantFailure, err, out)
			}
			if tc.wantFailure && !strings.Contains(string(out), "ERROR") {
				t.Fatalf("startup failure must reach its own fatal guard: %v %s", err, out)
			}
			got, err := os.ReadFile(conf)
			if err != nil {
				t.Fatal(err)
			}
			if tc.recovered && (string(got) != original || !strings.Contains(string(out), "CHECK4") || !strings.Contains(string(out), "FALLBACK")) {
				t.Fatalf("fallback did not restore and recheck its exact original registry: %s %s", got, out)
			}
			if !tc.recovered && string(got) != current {
				t.Fatalf("startup changed a registry without a valid rollback: %s", got)
			}
			if !tc.ipv6 && strings.Contains(string(out), "CHECK6") {
				t.Fatal("IPv4-only startup must not run the new dual-stack branch")
			}
			if tc.ipv6 && tc.failure == "" && strings.Contains(string(out), "CHECK4") {
				t.Fatal("successful dual-stack startup must not restart OpenLiteSpeed twice")
			}
		})
	}
}
