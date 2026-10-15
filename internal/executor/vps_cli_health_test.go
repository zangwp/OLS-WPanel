package executor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func fixtureVPSCLIHealthOperations(t *testing.T) vpsCLIHealthOperations {
	t.Helper()
	return vpsCLIHealthOperations{
		now:          func() time.Time { return time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC) },
		totalTimeout: time.Second, commandTimeout: 100 * time.Millisecond,
		run: func(ctx context.Context, command string, args ...string) (string, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("health command has no deadline")
			}
			switch command {
			case "systemctl":
				if len(args) != 3 || args[0] != "show" || !strings.HasSuffix(args[1], ".service") || args[2] != "--property=LoadState,ActiveState,SubState,UnitFileState" {
					t.Fatal("unexpected service command", args)
				}
				return "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n", nil
			case "df":
				if len(args) != 3 || args[1] != "--" || (args[0] != "--output=pcent" && args[0] != "--output=ipcent") {
					t.Fatal("unexpected disk command", args)
				}
				return "Use%\n 25%\n", nil
			case "dpkg":
				if strings.Join(args, " ") != "--audit" {
					t.Fatal("unexpected package mutation", args)
				}
				return "", nil
			case "ip":
				if len(args) != 4 || (args[0] != "-4" && args[0] != "-6") || strings.Join(args[1:], " ") != "route show default" {
					t.Fatal("unexpected route command", args)
				}
				if args[0] == "-4" {
					return "default via 192.0.2.1 dev eth0\n", nil
				}
				return "", nil // IPv4-only is a valid configuration.
			default:
				t.Fatal("non-allowlisted command", command, args)
				return "", errors.New("unexpected command")
			}
		},
		read: func(ctx context.Context, path string, limit int64) ([]byte, error) {
			if path != "/etc/resolv.conf" || limit != vpsCLIHealthResolverLimit {
				t.Fatal("unexpected file read", path, limit)
			}
			return []byte("# local systemd stub\nnameserver 127.0.0.53\n"), ctx.Err()
		},
	}
}

func vpsCLIHealthCheckByID(t *testing.T, report vpsCLIHealthStatus, id string) vpsCLIHealthCheck {
	t.Helper()
	for _, check := range report.Checks {
		if check.ID == id {
			return check
		}
	}
	t.Fatal("missing check", id)
	return vpsCLIHealthCheck{}
}

func TestVPSCLIHealthReadOnlyChecksAndJSONContract(t *testing.T) {
	ops := fixtureVPSCLIHealthOperations(t)
	report := inspectVPSCLIHealthWith(context.Background(), nil, ops)
	if report.Status != "ok" || len(report.Checks) != 11 || len(report.Limitations) < 2 {
		t.Fatal("missing health evidence", report)
	}
	data, err := json.Marshal(report)
	if err != nil || !strings.Contains(string(data), `"checked_at":"2026-10-15T08:00:00Z"`) || !strings.Contains(string(data), `"next_step":`) {
		t.Fatal("unstable CLI contract", string(data), err)
	}
	for _, check := range report.Checks {
		if check.Status != "ok" || check.Name == "" || check.Summary == "" || check.NextStep == "" {
			t.Fatal("incomplete check", check)
		}
	}
}

func TestVPSCLIHealthUnknownAndWarningsNeverBecomeOK(t *testing.T) {
	for _, scenario := range []string{"service_missing", "service_partial", "service_failed", "service_oneshot", "disk_full", "disk_partial", "disk_all_failed", "inode_unknown", "packages_pending", "packages_failed", "route_missing", "route_partial", "dns_missing", "dns_invalid", "invalid_path"} {
		t.Run(scenario, func(t *testing.T) {
			ops := fixtureVPSCLIHealthOperations(t)
			original := ops.run
			ops.run = func(ctx context.Context, command string, args ...string) (string, error) {
				if command == "systemctl" && args[1] == "nftables.service" {
					switch scenario {
					case "service_missing":
						return "LoadState=not-found\nActiveState=inactive", errors.New("missing")
					case "service_partial":
						return "LoadState=loaded\nActiveState=active", nil
					case "service_failed":
						return "LoadState=loaded\nActiveState=failed\nSubState=failed", nil
					case "service_oneshot":
						return "LoadState=loaded\nActiveState=active\nSubState=exited", nil
					}
				}
				if command == "df" {
					if scenario == "disk_all_failed" {
						return "", errors.New("disk statistics unavailable")
					}
					if scenario == "disk_full" && args[0] == "--output=pcent" && args[2] == "/" {
						return "Use%\n95%", nil
					}
					if scenario == "disk_partial" && args[2] != "/" {
						return "", errors.New("directory missing")
					}
					if scenario == "inode_unknown" && args[0] == "--output=ipcent" {
						return "IUse%\n-", nil
					}
				}
				if command == "dpkg" && scenario == "packages_pending" {
					return "package awaiting configuration", nil
				}
				if command == "dpkg" && scenario == "packages_failed" {
					return "", errors.New("cannot read package database")
				}
				if command == "ip" && scenario == "route_missing" {
					return "", nil
				}
				if command == "ip" && scenario == "route_partial" && args[0] == "-6" {
					return "", errors.New("read error")
				}
				return original(ctx, command, args...)
			}
			if scenario == "dns_missing" || scenario == "dns_invalid" {
				ops.read = func(context.Context, string, int64) ([]byte, error) {
					if scenario == "dns_missing" {
						return nil, os.ErrNotExist
					}
					return []byte("nameserver invalid.example\n"), nil
				}
			}
			var cfg *config.Config
			if scenario == "invalid_path" {
				cfg = &config.Config{}
				cfg.Panel.BackupDir = "--not-an-absolute-path"
			}
			report := inspectVPSCLIHealthWith(context.Background(), cfg, ops)
			want := "unknown"
			if scenario == "service_failed" || scenario == "disk_full" || scenario == "packages_pending" || scenario == "route_missing" || scenario == "dns_invalid" {
				want = "warning"
			} else if scenario == "service_oneshot" {
				want = "ok" // oneshot nftables can be active/exited.
			}
			if report.Status != want {
				t.Fatalf("%s status=%s want=%s checks=%+v", scenario, report.Status, want, report.Checks)
			}
			if scenario == "disk_all_failed" {
				for _, id := range []string{"disk_space", "inodes"} {
					check := vpsCLIHealthCheckByID(t, report, id)
					if strings.Contains(check.Summary, "%") || check.Status != "unknown" {
						t.Fatal("unreadable disks were presented as a measured percentage", check)
					}
				}
			}
		})
	}
}

func TestVPSCLIHealthLimitsTotalTimeAndKeepsUnknownChecks(t *testing.T) {
	ops := fixtureVPSCLIHealthOperations(t)
	ops.totalTimeout, ops.commandTimeout = 35*time.Millisecond, 10*time.Millisecond
	calls := 0
	ops.run = func(ctx context.Context, _ string, _ ...string) (string, error) {
		calls++
		<-ctx.Done()
		return "", ctx.Err()
	}
	start := time.Now()
	report := inspectVPSCLIHealthWith(context.Background(), nil, ops)
	if time.Since(start) > time.Second || report.Status != "unknown" || calls > 6 || len(report.Checks) != 11 {
		t.Fatal("deadline was lost or missing checks became normal", time.Since(start), calls, report)
	}
	for _, check := range report.Checks {
		if check.Status != "unknown" {
			t.Fatal("expired collection reported normal", check)
		}
	}
}

func TestVPSCLIHealthRunnerRejectsMutatingAndUnboundedCommandsBeforeExecution(t *testing.T) {
	for _, sample := range [][]string{{"systemctl", "restart", "ssh.service"}, {"dpkg", "--configure", "-a"}, {"apt-get", "update"}, {"ip", "route", "add", "default"}, {"df", "--output=pcent", "relative"}, {"sh", "-c", "true"}} {
		if _, err := runVPSCLIHealthCommand(context.Background(), sample[0], sample[1:]...); err == nil {
			t.Fatal("accepted non-readonly command", sample)
		}
	}
}

func TestVPSCLIHealthProcessBoundsCombinedOutputAndHonorsCancellation(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := runVPSCLIHealthProcess(context.Background(), binary, "-test.run=^TestVPSCLIHealthProcessHelper$", "--", "health-output-flood"); !errors.Is(err, errVPSCLIHealthOutputLimit) || out != "" {
		t.Fatal("oversized partial output was returned as evidence", len(out), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := runVPSCLIHealthProcess(ctx, binary, "-test.run=^TestVPSCLIHealthProcessHelper$", "--", "health-wait"); err == nil || time.Since(start) > 2*time.Second {
		t.Fatal("process deadline was not enforced", time.Since(start), err)
	}
}

func TestVPSCLIHealthProcessHelper(t *testing.T) {
	switch os.Args[len(os.Args)-1] {
	case "health-output-flood":
		_, _ = io.WriteString(os.Stdout, strings.Repeat("a", vpsCLIHealthOutputLimit/2))
		_, _ = io.WriteString(os.Stderr, strings.Repeat("b", vpsCLIHealthOutputLimit/2+1))
		os.Exit(0)
	case "health-wait":
		time.Sleep(time.Hour)
		os.Exit(0)
	}
}

func TestVPSCLIHealthFileReadIsBoundedAndCancellationAware(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 127.0.0.53\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := readVPSCLIHealthFile(context.Background(), path, 100); err != nil || !strings.Contains(string(data), "127.0.0.53") {
		t.Fatal("lost valid local resolver config", string(data), err)
	}
	if _, err := readVPSCLIHealthFile(context.Background(), path, 5); err == nil {
		t.Fatal("oversized config was read")
	}
	if _, err := readVPSCLIHealthFile(context.Background(), filepath.Dir(path), 100); err == nil {
		t.Fatal("directory accepted as resolver config")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readVPSCLIHealthFile(ctx, path, 100); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled read continued", err)
	}
}
