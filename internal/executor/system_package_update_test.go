package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRunSystemPackageUpdatePlanCompletesAllChecks(t *testing.T) {
	tempDir := t.TempDir()
	planPath := filepath.Join(tempDir, "plan.json")
	statusPath := filepath.Join(tempDir, "status.json")
	plan := systemPackageUpdatePlan{ID: "test", StatusPath: statusPath, PlanPath: planPath}
	if err := writePanelDBRestoreJSON(planPath, plan); err != nil {
		t.Fatal(err)
	}

	oldCommand := systemPackageUpdateCommand
	oldLockPath := systemPackageUpdateLockPath
	oldSleep := systemPackageUpdateSleep
	oldRemaining := systemPackageUpdateRemaining
	systemPackageUpdateRemaining = func(context.Context) ([]string, error) { return nil, nil }
	t.Cleanup(func() {
		systemPackageUpdateCommand = oldCommand
		systemPackageUpdateLockPath = oldLockPath
		systemPackageUpdateSleep = oldSleep
		systemPackageUpdateRemaining = oldRemaining
	})
	systemPackageUpdateSleep = func(time.Duration) {}
	systemPackageUpdateLockPath = filepath.Join(tempDir, "update.lock")
	var calls []string
	systemPackageUpdateCommand = func(_ context.Context, name string, args ...string) error {
		calls = append(calls, name+" "+joinSystemPackageUpdateArgs(args))
		return nil
	}

	if err := RunSystemPackageUpdatePlan(planPath); err != nil {
		t.Fatal(err)
	}
	status := readSystemPackageUpdateStatusFile(t, statusPath)
	if status.Status != "success" || status.Stage != "complete" {
		t.Fatalf("unexpected status: %+v", status)
	}
	want := []string{
		"systemctl is-active --quiet lshttpd",
		"systemctl is-active --quiet mariadb",
		"systemctl is-active --quiet redis-server",
		"systemctl is-active --quiet ols-wpanel",
		"/usr/local/lsws/bin/openlitespeed -t",
		"apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=300 update",
		"apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=300 --with-new-pkgs --no-remove -s upgrade",
		"env DEBIAN_FRONTEND=noninteractive apt-get -y -o Acquire::Retries=3 -o DPkg::Lock::Timeout=300 --with-new-pkgs --no-remove -o Dpkg::Options::=--force-confold upgrade",
		"apt-get check",
		"dpkg --audit",
		"systemctl is-active --quiet lshttpd",
		"systemctl is-active --quiet mariadb",
		"systemctl is-active --quiet redis-server",
		"systemctl is-active --quiet ols-wpanel",
		"/usr/local/lsws/bin/openlitespeed -t",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("unexpected commands:\n got: %#v\nwant: %#v", calls, want)
	}
}

func TestRunSystemPackageUpdatePlanStopsBeforeUpgradeWhenPreflightFails(t *testing.T) {
	tempDir := t.TempDir()
	planPath := filepath.Join(tempDir, "plan.json")
	statusPath := filepath.Join(tempDir, "status.json")
	if err := writePanelDBRestoreJSON(planPath, systemPackageUpdatePlan{ID: "test", StatusPath: statusPath, PlanPath: planPath}); err != nil {
		t.Fatal(err)
	}

	oldCommand := systemPackageUpdateCommand
	oldLockPath := systemPackageUpdateLockPath
	oldSleep := systemPackageUpdateSleep
	oldRemaining := systemPackageUpdateRemaining
	systemPackageUpdateRemaining = func(context.Context) ([]string, error) { return nil, nil }
	t.Cleanup(func() {
		systemPackageUpdateCommand = oldCommand
		systemPackageUpdateLockPath = oldLockPath
		systemPackageUpdateSleep = oldSleep
		systemPackageUpdateRemaining = oldRemaining
	})
	systemPackageUpdateSleep = func(time.Duration) {}
	systemPackageUpdateLockPath = filepath.Join(tempDir, "update.lock")
	var calls []string
	systemPackageUpdateCommand = func(_ context.Context, name string, args ...string) error {
		call := name + " " + joinSystemPackageUpdateArgs(args)
		calls = append(calls, call)
		if call == "apt-get -o Acquire::Retries=3 -o DPkg::Lock::Timeout=300 --with-new-pkgs --no-remove -s upgrade" {
			return errors.New("dependency failure")
		}
		return nil
	}

	if err := RunSystemPackageUpdatePlan(planPath); err == nil {
		t.Fatal("expected failure")
	}
	status := readSystemPackageUpdateStatusFile(t, statusPath)
	if status.Status != "failed" || status.Stage != "preflight" || status.MessageKey != "settings.system_update_status_failed" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if len(calls) != 7 {
		t.Fatalf("upgrade should not run after failed preflight: %#v", calls)
	}
}

func TestRunSystemPackageUpdatePlanReportsPostUpdateHealthFailure(t *testing.T) {
	tempDir := t.TempDir()
	planPath := filepath.Join(tempDir, "plan.json")
	statusPath := filepath.Join(tempDir, "status.json")
	if err := writePanelDBRestoreJSON(planPath, systemPackageUpdatePlan{ID: "test", StatusPath: statusPath, PlanPath: planPath}); err != nil {
		t.Fatal(err)
	}

	oldCommand := systemPackageUpdateCommand
	oldLockPath := systemPackageUpdateLockPath
	oldSleep := systemPackageUpdateSleep
	oldRemaining := systemPackageUpdateRemaining
	systemPackageUpdateRemaining = func(context.Context) ([]string, error) { return nil, nil }
	t.Cleanup(func() {
		systemPackageUpdateCommand = oldCommand
		systemPackageUpdateLockPath = oldLockPath
		systemPackageUpdateSleep = oldSleep
		systemPackageUpdateRemaining = oldRemaining
	})
	systemPackageUpdateSleep = func(time.Duration) {}
	systemPackageUpdateLockPath = filepath.Join(tempDir, "update.lock")
	mariaChecks := 0
	systemPackageUpdateCommand = func(_ context.Context, name string, args ...string) error {
		if name == "systemctl" && len(args) == 3 && args[2] == "mariadb" {
			mariaChecks++
		}
		if mariaChecks > 1 && name == "systemctl" && len(args) == 3 && args[2] == "mariadb" {
			return errors.New("inactive")
		}
		return nil
	}

	if err := RunSystemPackageUpdatePlan(planPath); err == nil {
		t.Fatal("expected failure")
	}
	status := readSystemPackageUpdateStatusFile(t, statusPath)
	if status.Status != "failed" || status.Stage != "services" || status.MessageKey != "settings.system_update_status_health_failed" {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestSystemPackageUpdateErrorDetailRedactsURLCredentialsAndControlsLength(t *testing.T) {
	detail := systemPackageUpdateErrorDetail(errors.New("apt failed: https://user:secret@example.com/repo\x00\n" + strings.Repeat("x", 4096)))
	if strings.Contains(detail, "user:secret") || !strings.Contains(detail, "https://[redacted]@example.com/repo") {
		t.Fatalf("credentials were not redacted: %q", detail)
	}
	if len(detail) > 2051 || strings.ContainsRune(detail, '\x00') {
		t.Fatalf("detail was not bounded/sanitized: len=%d", len(detail))
	}
}

func TestSystemUpdateRechecksRemainingPackages(t *testing.T) {
	for _, tc := range []struct {
		name      string
		remaining []string
		err       error
		wantKey   string
	}{
		{"complete", nil, nil, "settings.system_update_status_success"},
		{"held back", []string{"linux-image-amd64 → 6.12.111-1"}, nil, "settings.system_update_status_remaining"},
		{"inventory failure", nil, errors.New("apt inventory unavailable"), "settings.system_update_status_remaining_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			planPath, statusPath := filepath.Join(dir, "plan.json"), filepath.Join(dir, "status.json")
			if err := writePanelDBRestoreJSON(planPath, systemPackageUpdatePlan{ID: "remaining", StatusPath: statusPath, PlanPath: planPath}); err != nil {
				t.Fatal(err)
			}
			oldCommand, oldRemaining, oldLock := systemPackageUpdateCommand, systemPackageUpdateRemaining, systemPackageUpdateLockPath
			t.Cleanup(func() {
				systemPackageUpdateCommand, systemPackageUpdateRemaining, systemPackageUpdateLockPath = oldCommand, oldRemaining, oldLock
			})
			systemPackageUpdateLockPath = filepath.Join(dir, "lock")
			systemPackageUpdateCommand = func(context.Context, string, ...string) error { return nil }
			checked := false
			systemPackageUpdateRemaining = func(context.Context) ([]string, error) { checked = true; return tc.remaining, tc.err }
			err := RunSystemPackageUpdatePlan(planPath)
			if (err != nil) != (tc.err != nil) {
				t.Fatalf("unexpected result: %v", err)
			}
			status := readSystemPackageUpdateStatusFile(t, statusPath)
			if !checked || status.MessageKey != tc.wantKey || status.RemainingCount != len(tc.remaining) {
				t.Fatalf("unexpected status: %+v, checked=%v", status, checked)
			}
			if len(tc.remaining) > 0 && status.Detail != strings.Join(tc.remaining, "\n") {
				t.Fatalf("missing pending package detail: %+v", status)
			}
			if tc.err != nil && status.Status != "failed" {
				t.Fatalf("inventory failure reported as success: %+v", status)
			}
		})
	}
}

func readSystemPackageUpdateStatusFile(t *testing.T, path string) SystemPackageUpdateStatus {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status SystemPackageUpdateStatus
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal(err)
	}
	return status
}

func joinSystemPackageUpdateArgs(args []string) string {
	return strings.Join(args, " ")
}
