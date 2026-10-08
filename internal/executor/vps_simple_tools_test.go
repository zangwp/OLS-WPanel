package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestQueueMigrationRestoreAndVerificationRollback(t *testing.T) {
	for _, failVerification := range []bool{false, true} {
		t.Run(map[bool]string{false: "restore", true: "rollback"}[failVerification], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "queue.conf")
			baseline := filepath.Join(dir, "baseline.json")
			installer := filepath.Join(dir, "installer.conf")
			legacy := "# OLS WPanel — 网络与内核优化\nnet.core.somaxconn = 65535\nnet.ipv4.tcp_max_syn_backlog = 8192\nnet.core.default_qdisc = fq\n"
			if err := os.WriteFile(installer, []byte(legacy), 0644); err != nil {
				t.Fatal(err)
			}
			live := map[string]string{vpsTuningKeys[0]: "65535", vpsTuningKeys[1]: "8192"}
			applied := false
			run := func(_ context.Context, _ string, args ...string) (string, error) {
				switch args[0] {
				case "-n":
					if failVerification && applied {
						return "123", nil
					}
					return live[args[1]], nil
				case "-p":
					data, err := os.ReadFile(args[1])
					if err != nil {
						return "", err
					}
					for _, line := range strings.Split(string(data), "\n") {
						if k, v, ok := strings.Cut(line, " = "); ok {
							live[k] = v
						}
					}
					applied = true
				case "-w":
					k, v, _ := strings.Cut(args[1], "=")
					live[k] = v
				default:
					t.Fatalf("unexpected args: %v", args)
				}
				return "", nil
			}
			_, err := setVPSTuningAt(context.Background(), "balanced", path, baseline, installer, run)
			data, readErr := os.ReadFile(installer)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if failVerification {
				if err == nil || string(data) != legacy || live[vpsTuningKeys[0]] != "65535" || live[vpsTuningKeys[1]] != "8192" {
					t.Fatalf("rollback failed: %v %s %v", err, data, live)
				}
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("failed config persisted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "somaxconn") || !strings.Contains(string(data), "default_qdisc = fq") {
				t.Fatalf("bad migration: %s", data)
			}
			if _, err = setVPSTuningAt(context.Background(), "default", path, baseline, installer, run); err != nil {
				t.Fatal(err)
			}
			data, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), "somaxconn = 65535") || live[vpsTuningKeys[0]] != "65535" {
				t.Fatal("restore did not persist original values")
			}
			if _, err = os.Stat(baseline); !os.IsNotExist(err) {
				t.Fatal("restore left stale baseline")
			}
		})
	}
}

func TestQueueRollbackHasIndependentContextAndVerifiesRuntime(t *testing.T) {
	for _, failRestore := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled operation restores", true: "failed rollback reported"}[failRestore], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			dir := t.TempDir()
			path, baseline, installer := filepath.Join(dir, "queue.conf"), filepath.Join(dir, "baseline.json"), filepath.Join(dir, "installer.conf")
			live := map[string]string{vpsTuningKeys[0]: "128", vpsTuningKeys[1]: "256"}
			restored := 0
			run := func(commandCtx context.Context, _ string, args ...string) (string, error) {
				if commandCtx.Err() != nil {
					return "", commandCtx.Err()
				}
				switch args[0] {
				case "-n":
					return live[args[1]], nil
				case "-p":
					live[vpsTuningKeys[0]] = "4096"
					cancel()
					return "", ctx.Err()
				case "-w":
					restored++
					if _, ok := commandCtx.Deadline(); !ok {
						t.Fatal("rollback must have its own deadline")
					}
					key, value, _ := strings.Cut(args[1], "=")
					if failRestore && key == vpsTuningKeys[0] {
						return "", errors.New("injected restoration failure")
					}
					live[key] = value
				}
				return "", nil
			}
			_, err := setVPSTuningAt(ctx, "balanced", path, baseline, installer, run)
			if !errors.Is(err, context.Canceled) || restored != 2 {
				t.Fatalf("err=%v restore attempts=%d", err, restored)
			}
			if failRestore {
				if !strings.Contains(err.Error(), "回滚验证失败") || !strings.Contains(err.Error(), "运行值回滚失败") {
					t.Fatalf("lost rollback failure: %v", err)
				}
			} else if live[vpsTuningKeys[0]] != "128" || live[vpsTuningKeys[1]] != "256" {
				t.Fatalf("runtime not restored: %v", live)
			}
		})
	}
}

func TestVPSTimezoneUsesSystemDatabaseAndRejectsPaths(t *testing.T) {
	for _, zone := range []string{"America/New_York", "Europe/Berlin", "UTC", "../etc/passwd", "/etc/localtime", "--help", "Asia/Shanghai;reboot", "Asia/../Shanghai", "Unknown/City"} {
		t.Run(zone, func(t *testing.T) {
			var calls []string
			run := func(_ context.Context, command string, args ...string) (string, error) {
				calls = append(calls, command+" "+strings.Join(args, " "))
				if args[0] == "list-timezones" {
					return "America/New_York\nEurope/Berlin\nAsia/Shanghai\n", nil
				}
				if args[0] == "show" {
					return zone, nil
				}
				return "", nil
			}
			_, err := setVPSTimezone(context.Background(), zone, run)
			valid := zone == "America/New_York" || zone == "Europe/Berlin" || zone == "UTC"
			if (err == nil) != valid {
				t.Fatalf("zone=%q err=%v", zone, err)
			}
			for _, call := range calls {
				if !valid && strings.Contains(call, "set-timezone") {
					t.Fatalf("invalid zone submitted: %v", calls)
				}
			}
		})
	}
}

func TestVPSHostnameStrictValidationAndRuntimeCheck(t *testing.T) {
	for _, name := range []string{"web-01", "Node.Example.com", "x", "-bad", "bad-", "bad..host", "bad host", "服务器", "$(reboot)", strings.Repeat("a", 64), "bad/host"} {
		t.Run(name, func(t *testing.T) {
			var calls []string
			run := func(_ context.Context, command string, args ...string) (string, error) {
				calls = append(calls, command+" "+strings.Join(args, " "))
				return strings.ToLower(name), nil
			}
			_, err := setVPSHostname(context.Background(), name, run)
			valid := name == "web-01" || name == "Node.Example.com" || name == "x"
			if (err == nil) != valid || (!valid && len(calls) != 0) {
				t.Fatalf("name=%q err=%v calls=%v", name, err, calls)
			}
			if valid && calls[0] != "hostnamectl set-hostname --static "+strings.ToLower(name) {
				t.Fatalf("wrong command: %v", calls)
			}
		})
	}
	if _, err := setVPSHostname(context.Background(), "web-01", func(context.Context, string, ...string) (string, error) { return "different-host", nil }); err == nil {
		t.Fatal("accepted hostname verification mismatch")
	}
}

func TestVPSLocaleInstallIsExplicitAndBounded(t *testing.T) {
	var calls [][]string
	run := func(_ context.Context, command string, args ...string) (string, error) {
		calls = append(calls, append([]string{command}, args...))
		return "", nil
	}
	if _, err := installVPSLocale(context.Background(), "arbitrary-package", run); err == nil || len(calls) != 0 {
		t.Fatal("accepted package parameter")
	}
	if _, err := installVPSLocale(context.Background(), "", run); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"apt-get", "install", "-y", "--no-install-recommends", "locales"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls=%v", calls)
	}
}

func TestQueueMigrationRejectsUnownedFile(t *testing.T) {
	if _, err := stripInstallerQueues([]byte("# administrator\nnet.core.somaxconn = 100\n")); err == nil {
		t.Fatal("accepted administrator config")
	}
}

func TestVPSIPPriorityRoundTripPreservesAdministratorSettings(t *testing.T) {
	original := "# administrator comment\nlabel ::1/128 0\n"
	ipv4, err := buildVPSIPPriority(original, "ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ipv4, "precedence ::ffff:0:0/96 100") {
		t.Fatal("missing IPv4 priority")
	}
	ipv6, err := buildVPSIPPriority(ipv4, "ipv6")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ipv6, ipPriorityBegin) != 1 || !strings.Contains(ipv6, "precedence ::/0 100") {
		t.Fatal("duplicated priority or missing IPv6 rule")
	}
	restored, err := buildVPSIPPriority(ipv6, "default")
	if err != nil || restored != original {
		t.Fatalf("restored %q, %v", restored, err)
	}
}
func TestVPSIPPriorityRejectsCustomRulesAndInvalidModes(t *testing.T) {
	if _, err := buildVPSIPPriority("precedence ::/0 80\n", "ipv4"); err == nil {
		t.Fatal("overrode administrator rule")
	}
	if _, err := buildVPSIPPriority("", "ipv4; reboot"); err == nil {
		t.Fatal("accepted command input")
	}
	if _, err := buildVPSIPPriority(ipPriorityBegin+"\nbroken", "default"); err == nil {
		t.Fatal("accepted incomplete managed block")
	}
	block := ipPriorityBegin + "\nprecedence ::ffff:0:0/96 100\n" + ipPriorityEnd + "\n"
	for _, content := range []string{block + block, ipPriorityBegin + "\n" + block} {
		for _, mode := range []string{"default", "ipv4", "ipv6"} {
			if _, err := buildVPSIPPriority(content, mode); err == nil {
				t.Fatalf("accepted duplicate/nested ownership markers for %s", mode)
			}
		}
	}
	original := "precedence ::/0 40\n" + block
	restored, err := buildVPSIPPriority(original, "default")
	if err != nil || restored != "precedence ::/0 40\n" {
		t.Fatalf("removing panel rules changed administrator rules: %q, %v", restored, err)
	}
}
