package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestVPSMaintenanceCLIRejectsUntrustedParameters(t *testing.T) {
	for _, sample := range []struct{ action, value string }{
		{"ports-status", "--apply"}, {"services-status", "restart"}, {"service-log", "ssh; reboot"},
		{"service-log", "--all"}, {"ssh-port-start", "2222:bad"}, {"ssh-port-start", "0:203.0.113.9"},
		{"ssh-port-start", "65536:203.0.113.9"}, {"ssh-port-start", "+2222:203.0.113.9"},
		{"ssh-port-confirm", "bad-token"}, {"service-restart", "panel"},
	} {
		if err := ValidateVPSMaintenanceCLI(sample.action, sample.value, nil); err == nil {
			t.Errorf("accepted %#v", sample)
		}
	}
	if port, ip, err := parseVPSCLISSHStart("2222:2001:db8::9"); err != nil || port != 2222 || ip != "2001:db8::9" {
		t.Fatalf("IPv6 client rejected: %d %q %v", port, ip, err)
	}
	cfg := &config.Config{}
	cfg.Systemd.ServiceName = "--dangerous"
	if err := ValidateVPSMaintenanceCLI("service-log", "panel", cfg); err == nil {
		t.Fatal("unsafe configured service accepted")
	}
}

func TestVPSCLIServicesUseOnlyReadOnlyAllowlistedCommands(t *testing.T) {
	calls := 0
	result := inspectVPSCLIServices(context.Background(), nil, func(_ context.Context, command string, args ...string) (string, error) {
		calls++
		if command != "systemctl" || len(args) != 3 || args[0] != "show" || !strings.HasSuffix(args[1], ".service") || args[2] != "--property=LoadState,ActiveState,SubState,UnitFileState" {
			t.Fatalf("unexpected diagnostic command: %s %q", command, args)
		}
		if args[1] == "redis-server.service" {
			return "LoadState=not-found\nActiveState=inactive", errors.New("not installed")
		}
		return "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled", nil
	})
	items := result.(struct {
		Services []vpsCLIServiceState `json:"services"`
	}).Services
	if calls != 6 || len(items) != 6 || items[0].ActiveState != "active" || items[3].LoadState != "not-found" || items[3].Error == "" {
		t.Fatalf("lost service facts or failure: %#v", items)
	}
}

func TestVPSCLIBBRSeparatesCurrentAndPersistentConfiguration(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sysctl.d"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"sysctl.conf":               "# manual configuration\nnet.ipv4.tcp_congestion_control = bbr\n",
		"sysctl.d/99-ols.conf":      "# OLS WPanel — 网络与内核优化\nnet.core.default_qdisc = fq # owned setting\n",
		"sysctl.d/98-external.conf": "# external\n#net.core.default_qdisc = fq\nnet.core.default_qdisc = fq_codel\n",
	}
	for path, data := range files {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	status := inspectVPSCLIBBR(context.Background(), dir, func(_ context.Context, command string, args ...string) (string, error) {
		if command != "sysctl" || len(args) != 2 || args[0] != "-n" {
			t.Fatal("BBR status attempted mutation")
		}
		return map[string]string{"net.ipv4.tcp_congestion_control": "cubic", "net.core.default_qdisc": "fq_codel", "net.ipv4.tcp_available_congestion_control": "reno cubic bbr"}[args[1]], nil
	})
	if status.Algorithm != "cubic" || status.QueueDiscipline != "fq_codel" || len(status.AvailableAlgorithms) != 3 || len(status.Persistent) != 3 {
		t.Fatalf("bad BBR facts: %#v", status)
	}
	owned, external := 0, 0
	for _, entry := range status.Persistent {
		if entry.Managed {
			owned++
		} else {
			external++
		}
	}
	if owned != 1 || external != 2 {
		t.Fatalf("incorrect ownership: %#v", status.Persistent)
	}
}

func TestVPSCLIPortsWithoutDatabaseRemainsReadOnly(t *testing.T) {
	oldCommand := portCommand
	defer func() { portCommand = oldCommand }()
	portCommand = func(_ context.Context, command string, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch command {
		case "ss":
			if joined != "-H -lntup" {
				t.Fatalf("unexpected ss command: %q", args)
			}
			return "tcp LISTEN 0 128 127.0.0.1:3306 0.0.0.0:* users:((\"mariadbd\",pid=2,fd=3))\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=3,fd=3))", nil
		case "nft":
			if args[0] != "--version" && !strings.Contains(joined, "list") {
				t.Fatalf("nft diagnostic attempted mutation: %q", args)
			}
			if strings.Contains(joined, "list chain") {
				return "chain input { policy accept; }", nil
			}
			return "", nil
		case "ufw":
			if joined != "status" {
				t.Fatal("unexpected ufw command")
			}
			return "inactive", nil
		case "systemctl":
			if strings.HasPrefix(joined, "is-active") {
				return "inactive", errors.New("inactive")
			}
		case "/usr/sbin/sshd", "sshd":
			if joined != "-T" {
				t.Fatal("unexpected SSH diagnostic")
			}
			return "port 22", nil
		}
		return "", fmt.Errorf("unhandled fixture command %s %s", command, joined)
	}
	status := inspectVPSCLIPortsWithoutDatabase(context.Background(), nil)
	if len(status.Listeners) != 2 || status.LocalListenerCount != 1 || status.NetworkListenerCount != 1 || !strings.Contains(status.Warning, "未读取面板数据库") {
		t.Fatalf("lost listener diagnostic without database: %#v", status)
	}
	if _, err := loadFirewallPortRules(nil); err == nil {
		t.Fatal("nil database must return an error rather than panic")
	}
}

func TestVPSCLISSHConfirmationRequiresNewConnection(t *testing.T) {
	for _, connection := range []string{"", "203.0.113.9 1234 192.0.2.10 22", "203.0.113.9 invalid 192.0.2.10 2222", "bogus 1234 192.0.2.10 2222"} {
		if err := validateVPSCLISSHConnection(connection, 2222); err == nil {
			t.Fatalf("accepted old or invalid SSH session %q", connection)
		}
	}
	if err := validateVPSCLISSHConnection("2001:db8::9 1234 2001:db8::10 2222", 2222); err != nil {
		t.Fatal(err)
	}
}

func TestVPSCLISSHSnapshotRejectsExpiryAndUnexpectedPaths(t *testing.T) {
	token := strings.Repeat("a", 48)
	now := time.Now()
	state := vpsCLISSHState{Change: SSHPortChange{Token: token, OldPort: 22, NewPort: 2222, Deadline: now.Add(time.Minute)}, Directory: filepath.Join(sshMoveRunDirectory, "ols-ssh-port-fixture"), Service: "ssh.service", ExpectedConfig: "dual", ExpectedTable: "expected nft policy"}
	connection := "203.0.113.9 1234 192.0.2.10 2222"
	if err := validateVPSCLISSHState(state, token, connection, now); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*vpsCLISSHState){
		func(s *vpsCLISSHState) { s.Change.Deadline = now.Add(-time.Second) },
		func(s *vpsCLISSHState) { s.Change.Deadline = now.Add(time.Hour) },
		func(s *vpsCLISSHState) { s.Change.Token = strings.Repeat("b", 48) },
		func(s *vpsCLISSHState) { s.Directory = filepath.Join(sshMoveRunDirectory, "unrelated-directory") },
		func(s *vpsCLISSHState) {
			s.Directory = filepath.Join(sshMoveRunDirectory, "other", "ols-ssh-port-fixture")
		},
		func(s *vpsCLISSHState) { s.Service = "arbitrary.service" },
		func(s *vpsCLISSHState) { s.ExpectedTable = "" },
	} {
		bad := state
		alter(&bad)
		if err := validateVPSCLISSHState(bad, token, connection, now); err == nil {
			t.Fatalf("unsafe snapshot accepted: %#v", bad)
		}
	}
}
