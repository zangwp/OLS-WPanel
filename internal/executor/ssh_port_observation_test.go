package executor

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestObservedSSHPortPrefersUniqueLiveEndpoint(t *testing.T) {
	oldCommand := portCommand
	t.Cleanup(func() { portCommand = oldCommand })
	for _, sample := range []struct {
		name       string
		listeners  []FirewallListener
		configured string
		want       int
		fallback   bool
	}{
		{name: "external change before configuration reload", configured: "port 22", want: 2222,
			listeners: []FirewallListener{{Protocol: "tcp", Port: 2222, Process: "sshd"}}},
		{name: "IPv4 and IPv6 share one port", configured: "port 22", want: 2222,
			listeners: []FirewallListener{{Protocol: "tcp", Port: 2222, Address: "0.0.0.0", Process: "sshd"}, {Protocol: "tcp", Port: 2222, Address: "::", Process: "sshd"}}},
		{name: "multiple SSH ports retain configured observation", configured: "port 22", want: 22, fallback: true,
			listeners: []FirewallListener{{Protocol: "tcp", Port: 2222, Process: "sshd"}, {Protocol: "tcp", Port: 22, Process: "sshd"}}},
		{name: "unidentified owner uses configuration", configured: "port 2222", want: 2222, fallback: true,
			listeners: []FirewallListener{{Protocol: "tcp", Port: 22}, {Protocol: "udp", Port: 53, Process: "sshd"}}},
		{name: "unavailable listeners retain configuration fallback", configured: "port 2222", want: 2222, fallback: true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			called := false
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				if name != "sshd" || strings.Join(args, " ") != "-T" {
					t.Fatalf("observation executed an unexpected command: %s %v", name, args)
				}
				called = true
				return sample.configured, nil
			}
			if got := observedSSHPort(context.Background(), sample.listeners); got != sample.want || called != sample.fallback {
				t.Fatalf("observed port=%d, configuration read=%t; want %d, %t", got, called, sample.want, sample.fallback)
			}
		})
	}
}

func TestSSHPortObservationKeepsConfigurationGuard(t *testing.T) {
	oldCommand := portCommand
	t.Cleanup(func() { portCommand = oldCommand })
	portCommand = func(_ context.Context, name string, args ...string) (string, error) {
		if name != "sshd" || strings.Join(args, " ") != "-T" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return "port 22", nil
	}
	listeners := []FirewallListener{{Protocol: "tcp", Port: 2222, Process: "sshd"}}
	if observedSSHPort(context.Background(), listeners) != 2222 || detectSSHPort(context.Background(), listeners) != 22 {
		t.Fatal("read-only observation changed the configuration guard used by access transactions")
	}
}

func TestSSHMigrationRequiresCompleteUniqueListenerInspection(t *testing.T) {
	oldCommand, oldAvailable, oldDefaults := portCommand, sshSystemdAvailable, sshDefaultsPath
	t.Cleanup(func() { portCommand, sshSystemdAvailable, sshDefaultsPath = oldCommand, oldAvailable, oldDefaults })
	sshSystemdAvailable = func() bool { return true }
	sshDefaultsPath = filepath.Join(t.TempDir(), "missing-defaults")
	listener := func(address string) string {
		return "tcp LISTEN 0 128 " + address + " 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))"
	}
	for _, sample := range []struct {
		name, output, reason string
		readErr              error
	}{
		{name: "unique dual stack", output: listener("0.0.0.0:22") + "\n" + listener("[::]:22")},
		{name: "multiple live ports", output: listener("0.0.0.0:22") + "\n" + listener("0.0.0.0:2222"), reason: "多个 SSH 监听端口"},
		{name: "configuration differs from live port", output: listener("0.0.0.0:2222"), reason: "配置端口与实际 SSH 监听不一致"},
		{name: "listener read failure", output: listener("0.0.0.0:22"), readErr: errors.New("fixture permission denied"), reason: "无法完整核对 SSH 监听"},
		{name: "partially parsed listeners", output: listener("0.0.0.0:22") + "\ntcp LISTEN 0", reason: "无法完整核对 SSH 监听"},
		{name: "owner unavailable", output: "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*", reason: "配置端口与实际 SSH 监听不一致"},
	} {
		t.Run(sample.name, func(t *testing.T) {
			portCommand = func(_ context.Context, name string, args ...string) (string, error) {
				joined := strings.Join(args, " ")
				switch name {
				case "ss":
					return sample.output, sample.readErr
				case "sshd", "/usr/sbin/sshd":
					return "port 22\nlistenaddress 0.0.0.0:22", nil
				case "getenforce":
					return "Disabled", nil
				case "ufw":
					return "inactive", nil
				case "systemctl":
					if strings.HasPrefix(joined, "is-active") {
						if strings.HasSuffix(joined, "ssh.service") {
							return "active", nil
						}
						return "inactive", errors.New("inactive")
					}
					if joined == "is-enabled nftables" {
						return "enabled", nil
					}
					if strings.HasPrefix(joined, "is-enabled") {
						return "disabled", errors.New("disabled")
					}
					if strings.Contains(joined, "--property=ExecStart") {
						if strings.Contains(joined, "nftables") {
							return "/usr/sbin/nft -f " + nftablesConfigPath, nil
						}
						return "/usr/sbin/sshd -D", nil
					}
					if strings.Contains(joined, "--property=Environment") {
						return "", nil
					}
				case "nft":
					switch joined {
					case "--version":
						return "nftables", nil
					case "--stateless list tables":
						return "table inet " + accessTable, nil
					case "--stateless list table inet " + accessTable:
						return accessRulesScript([]FirewallAccessRule{{Protocol: "tcp", Port: 22}}, false), nil
					case "-a list chain inet filter input":
						return "chain input { policy drop; }", nil
					}
				}
				t.Fatalf("SSH inspection executed an unexpected command: %s %s", name, joined)
				return "", errors.New("unexpected")
			}
			status := GetSSHPortStatus()
			if sample.reason == "" {
				if !status.Available || status.Port != 22 {
					t.Fatalf("unique live endpoint was not available: %+v", status)
				}
			} else if status.Available || !strings.Contains(status.Reason, sample.reason) {
				t.Fatalf("unsafe listener observation accepted or misreported: %+v, want %q", status, sample.reason)
			}
		})
	}
}
