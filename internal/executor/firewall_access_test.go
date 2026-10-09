package executor

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestAccessStateDistinguishesReadFailure(t *testing.T) {
	old := portCommand
	defer func() { portCommand = old }()
	portCommand = func(context.Context, string, ...string) (string, error) { return "", errors.New("permission denied") }
	if _, _, err := readAccessState(context.Background()); err == nil {
		t.Fatal("read failure treated as absent policy")
	}
	portCommand = func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Join(args, " ") == "--stateless list tables" {
			return "table inet ols_wpanel_access", nil
		}
		return `tcp dport 22 counter accept comment "ols-access:tcp:22:2001:db8::1/128"`, nil
	}
	enabled, rules, err := readAccessState(context.Background())
	if err != nil || !enabled || len(rules) != 1 || rules[0].Source != "2001:db8::1/128" {
		t.Fatalf("bad state: %v %+v %v", enabled, rules, err)
	}
}

func TestAccessConfirmationFailureRestoresRuntimeAndBoot(t *testing.T) {
	oldCmd, oldPersist, oldPending := portCommand, persistAccessRules, pendingAccess
	oldConfig := config.AppConfig
	defer func() {
		portCommand = oldCmd
		persistAccessRules = oldPersist
		pendingAccess = oldPending
		config.AppConfig = oldConfig
	}()
	config.AppConfig = &config.Config{Panel: config.PanelConfig{Port: 8080, TLSPort: 8443, TLSCertPath: "cert.pem", TLSKeyPath: "key.pem"}}
	pendingAccess.token = "test-token"
	pendingAccess.expected = "expected table"
	pendingAccess.rollback = "/test/rollback.nft"
	pendingAccess.deadline = time.Now().Add(time.Minute)
	pendingAccess.sshPort = 22
	pendingAccess.panelPort = 8443
	var calls []string
	portCommand = func(_ context.Context, name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		calls = append(calls, cmd)
		if name == "ss" {
			return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\ntcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:* users:((\"ols-wpanel\",pid=2,fd=4))", nil
		}
		if name == "sshd" {
			return "port 22", nil
		}
		if strings.Contains(cmd, "is-active") {
			return "inactive", errors.New("inactive")
		}
		if strings.Contains(cmd, "is-enabled") {
			return "disabled", errors.New("disabled")
		}
		if strings.Contains(cmd, "list table") {
			return "expected table", nil
		}
		return "", nil
	}
	persistAccessRules = func(context.Context) error { calls = append(calls, "persist"); return errors.New("disk full") }
	if err := ConfirmFirewallAccess("test-token"); err == nil {
		t.Fatal("save failure ignored")
	}
	all := strings.Join(calls, "\n")
	stop := strings.Index(all, "systemctl stop")
	save := strings.Index(all, "persist")
	restore := strings.Index(all, "nft --file /test/rollback.nft")
	if stop < 0 || save < stop || restore < save || !strings.Contains(all, "systemctl disable nftables") {
		t.Fatalf("unsafe failure ordering: %s", all)
	}
	if pendingAccess.token != "" {
		t.Fatal("failed transaction remains confirmable")
	}
}

func TestAccessExpiredConfirmationDoesNotMutate(t *testing.T) {
	oldCmd, oldPending := portCommand, pendingAccess
	defer func() { portCommand = oldCmd; pendingAccess = oldPending }()
	pendingAccess.token = "expired"
	pendingAccess.deadline = time.Now().Add(5 * time.Second)
	portCommand = func(context.Context, string, ...string) (string, error) {
		t.Fatal("expired confirmation ran a command")
		return "", nil
	}
	if err := ConfirmFirewallAccess("expired"); err == nil {
		t.Fatal("late confirmation accepted")
	}
}

func TestAccessPreviewUsesActualPanelEndpointAndPreservesSources(t *testing.T) {
	oldCmd, oldConfig := portCommand, config.AppConfig
	defer func() { portCommand = oldCmd; config.AppConfig = oldConfig }()
	for _, tc := range []struct {
		name string
		cfg  config.PanelConfig
		port int
	}{
		{name: "HTTP fallback", cfg: config.PanelConfig{Port: 8080, TLSPort: 8443}, port: 8080},
		{name: "custom HTTPS", cfg: config.PanelConfig{Port: 8080, TLSPort: 49173, TLSCertPath: "cert.pem", TLSKeyPath: "key.pem"}, port: 49173},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.AppConfig = &config.Config{Panel: tc.cfg}
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				command := name + " " + strings.Join(args, " ")
				switch command {
				case "nft --version":
					return "nftables v1.1.1", nil
				case "nft -a list chain inet filter input":
					return "type filter hook input priority filter; policy accept;", nil
				case "systemctl show nftables --property=ExecStart --value":
					return "/usr/sbin/nft -f /etc/nftables.conf", nil
				case "ss -H -lntup":
					return "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:" + strconv.Itoa(tc.port) + " 0.0.0.0:*", nil
				case "sshd -T":
					return "port 22", nil
				case "nft --stateless list tables":
					return "table inet filter", nil
				case "nft --stateless list ruleset":
					return "table inet filter { chain input { policy accept; } }", nil
				}
				return "", errors.New("unavailable: " + command)
			}
			req := FirewallAccessRequest{Rules: []FirewallAccessRule{
				{Protocol: "tcp", Port: 22, Source: "203.0.113.5"},
				{Protocol: "tcp", Port: tc.port, Source: "203.0.113.0/24"},
				// Old port remains a custom rule without extending its sources.
				{Protocol: "tcp", Port: 8443, Source: "2001:db8::/64"},
			}}
			preview, err := previewAccess(context.Background(), req, "203.0.113.5")
			if err != nil {
				t.Fatal(err)
			}
			if preview.PanelPort != tc.port || preview.SSHPort != 22 {
				t.Fatalf("incorrect endpoint snapshot: %+v", preview)
			}
			if !strings.Contains(preview.Script, "ip saddr 203.0.113.0/24 tcp dport "+strconv.Itoa(tc.port)) ||
				!strings.Contains(preview.Script, "ip6 saddr 2001:db8::/64 tcp dport 8443") {
				t.Fatalf("source restriction was not preserved: %s", preview.Script)
			}
			for _, rule := range preview.Rules {
				if rule.Source == "" {
					t.Fatalf("private rule became public: %+v", rule)
				}
			}
		})
	}
}

func TestAccessConfirmationRejectsChangedManagementEndpoints(t *testing.T) {
	oldCmd, oldPersist, oldPending, oldConfig := portCommand, persistAccessRules, pendingAccess, config.AppConfig
	defer func() {
		portCommand = oldCmd
		persistAccessRules = oldPersist
		pendingAccess = oldPending
		config.AppConfig = oldConfig
	}()
	for _, tc := range []struct {
		name         string
		panelPort    int
		sshPort      int
		panelPresent bool
	}{
		{name: "panel configuration changed", panelPort: 9443, sshPort: 22, panelPresent: true},
		{name: "SSH configuration changed", panelPort: 8443, sshPort: 2222, panelPresent: true},
		{name: "panel listener disappeared", panelPort: 8443, sshPort: 22},
		{name: "invalid panel configuration", sshPort: 22, panelPresent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.AppConfig = &config.Config{Panel: config.PanelConfig{Port: tc.panelPort}}
			pendingAccess.token = "pending-token"
			pendingAccess.deadline = time.Now().Add(time.Minute)
			pendingAccess.sshPort, pendingAccess.panelPort = 22, 8443
			pendingAccess.expected = "unchanged rules"
			persistAccessRules = func(context.Context) error { t.Fatal("changed endpoint persisted"); return nil }
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				command := name + " " + strings.Join(args, " ")
				if name == "systemctl" && len(args) > 0 && args[0] == "is-active" {
					return "inactive", errors.New("inactive")
				}
				if name == "ss" {
					out := "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
					if tc.panelPresent {
						out += "\ntcp LISTEN 0 128 0.0.0.0:8443 0.0.0.0:*"
					}
					return out, nil
				}
				if name == "sshd" {
					return "port " + strconv.Itoa(tc.sshPort), nil
				}
				t.Fatalf("changed endpoint executed unexpected command: %s", command)
				return "", errors.New("unexpected command")
			}
			if err := ConfirmFirewallAccess("pending-token"); err == nil || !strings.Contains(err.Error(), "入口已变化") {
				t.Fatalf("changed endpoint accepted: %v", err)
			}
			if pendingAccess.token != "pending-token" {
				t.Fatal("endpoint failure removed rollback transaction")
			}
		})
	}
}
