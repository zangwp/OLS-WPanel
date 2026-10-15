//go:build linux

package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// CI explicitly opts in and runs this test as root on its native systemd host.
// Only unique, transient CI units are changed; no firewall or SSH commands run.
func TestFirewallRollbackSystemd(t *testing.T) {
	if os.Getenv("OLS_WPANEL_SYSTEMD_TEST") != "1" {
		t.Skip("set OLS_WPANEL_SYSTEMD_TEST=1 to require real systemd acceptance")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real systemd acceptance requires root; refusing to skip an opted-in test")
	}
	pidOne, err := os.ReadFile("/proc/1/comm")
	if err != nil || strings.TrimSpace(string(pidOne)) != "systemd" {
		t.Fatalf("opted-in acceptance requires systemd as PID 1: %q, %v", pidOne, err)
	}
	for _, name := range []string{"systemctl", "systemd-run", "true", "sleep"} {
		if info, err := os.Stat("/usr/bin/" + name); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			t.Fatalf("required real command /usr/bin/%s is unavailable: %v", name, err)
		}
	}
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("ols-wpanel-ci-rollback-%d-%s-", os.Getpid(), hex.EncodeToString(nonce[:]))
	allowed := map[string]bool{}
	oldCommand := portCommand
	// Keep the production command seam, but execute real programs and reject
	// every mutation that does not address a unit created by this test.
	portCommand = func(ctx context.Context, name string, args ...string) (string, error) {
		valid := false
		switch name {
		case "systemctl":
			if len(args) == 4 && strings.Join(args, " ") == "list-jobs --all --no-legend --no-pager" {
				valid = true // Read-only, independent queued-job verification.
			} else if len(args) >= 2 && args[0] == "show" {
				valid = allowed[args[1]]
			} else if len(args) >= 2 && (args[0] == "stop" || args[0] == "reset-failed") {
				valid = true
				for _, unit := range args[1:] {
					valid = valid && allowed[unit]
				}
			}
		case "systemd-run":
			for _, arg := range args {
				if base, ok := strings.CutPrefix(arg, "--unit="); ok {
					valid = allowed[base+".timer"] && allowed[base+".service"]
					break
				}
			}
		}
		if !valid {
			return "", fmt.Errorf("integration test refused unrelated command: %s %v", name, args)
		}
		output, err := exec.CommandContext(ctx, "/usr/bin/"+name, args...).CombinedOutput()
		return strings.TrimSpace(string(output)), err
	}
	t.Cleanup(func() { portCommand = oldCommand })

	run := func(t *testing.T, name string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output, err := portCommand(ctx, name, args...)
		if err != nil {
			t.Fatalf("real %s %v failed: %v\n%s", name, args, err, output)
		}
		return output
	}
	query := func(t *testing.T, unit string) map[string]string {
		t.Helper()
		output := run(t, "systemctl", "show", unit, "--property=LoadState", "--property=ActiveState", "--property=Result", "--property=Job", "--property=MainPID", "--property=ExecMainPID")
		properties := map[string]string{}
		for _, line := range strings.Split(output, "\n") {
			if key, value, ok := strings.Cut(line, "="); ok {
				properties[key] = value
			}
		}
		return properties
	}
	waitFor := func(t *testing.T, unit, description string, ready func(map[string]string) bool) map[string]string {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for {
			properties := query(t, unit)
			if ready(properties) {
				return properties
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s did not %s: %v", unit, description, properties)
			}
			time.Sleep(40 * time.Millisecond)
		}
	}
	assertStopped := func(t *testing.T, units ...string) {
		t.Helper()
		for _, unit := range units {
			properties := query(t, unit)
			job, hasJob := properties["Job"]
			if (properties["LoadState"] != "loaded" && properties["LoadState"] != "not-found") || properties["ActiveState"] != "inactive" || !hasJob || (job != "" && job != "0") {
				t.Fatalf("real unit is not safely inactive without a job: %s %v", unit, properties)
			}
			if result := properties["Result"]; result != "" && result != "success" {
				t.Fatalf("real unit has an unsuccessful result: %s %v", unit, properties)
			}
			if pid := properties["MainPID"]; pid != "" && pid != "0" {
				t.Fatalf("real service still has a main process: %s %v", unit, properties)
			}
			t.Logf("real-systemd %s LoadState=%s ActiveState=%s Result=%q Job=%q", unit, properties["LoadState"], properties["ActiveState"], properties["Result"], job)
		}
		for _, line := range strings.Split(run(t, "systemctl", "list-jobs", "--all", "--no-legend", "--no-pager"), "\n") {
			for _, field := range strings.Fields(line) {
				for _, unit := range units {
					if field == unit {
						t.Fatalf("real systemd still has a queued job for %s: %s", unit, line)
					}
				}
			}
		}
	}
	newUnits := func(t *testing.T, suffix string) (string, []string) {
		t.Helper()
		base := prefix + suffix
		units := []string{base + ".timer", base + ".service"}
		for _, unit := range units {
			allowed[unit] = true
		}
		t.Cleanup(func() {
			for _, unit := range units {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				_, _ = portCommand(ctx, "systemctl", "stop", unit)
				_, _ = portCommand(ctx, "systemctl", "reset-failed", unit)
				cancel()
			}
			assertStopped(t, units...)
		})
		return base, units
	}
	stop := func(t *testing.T, units []string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := stopFirewallRollbackUnits(ctx, units...); err != nil {
			t.Fatalf("production cancellation helper rejected real systemd state: %v", err)
		}
		assertStopped(t, units...)
	}

	t.Run("cancel_waiting_timer", func(t *testing.T) {
		base, units := newUnits(t, "waiting")
		run(t, "systemd-run", "--unit="+base, "--on-active=120s", "--timer-property=AccuracySec=1s", "--property=Type=oneshot", "/usr/bin/true")
		waitFor(t, units[0], "become a waiting timer", func(p map[string]string) bool { return p["LoadState"] == "loaded" && p["ActiveState"] == "active" })
		stop(t, units)
	})
	t.Run("accept_collected_and_missing_units", func(t *testing.T) {
		base, units := newUnits(t, "collected")
		run(t, "systemd-run", "--unit="+base, "--collect", "--wait", "--property=Type=oneshot", "/usr/bin/true")
		waitFor(t, units[1], "be garbage-collected", func(p map[string]string) bool { return p["LoadState"] == "not-found" && p["ActiveState"] == "inactive" })
		stop(t, units)
	})
	t.Run("stop_triggered_service", func(t *testing.T) {
		base, units := newUnits(t, "triggered")
		run(t, "systemd-run", "--unit="+base, "--on-active=100ms", "--timer-property=AccuracySec=10ms", "--property=Type=oneshot", "/usr/bin/sleep", "20")
		waitFor(t, units[1], "start its controlled sleep process", func(p map[string]string) bool {
			pid, err := strconv.ParseUint(p["ExecMainPID"], 10, 64)
			return err == nil && pid > 0 && (p["ActiveState"] == "active" || p["ActiveState"] == "activating")
		})
		stop(t, units)
	})
	if !t.Failed() {
		t.Log("SYSTEMD_FIREWALL_ROLLBACK_OK: waiting timer, collected units, triggered service; no remaining jobs")
	}
}
