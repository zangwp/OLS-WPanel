package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zangwp/OLS-WPanel/config"
)

const systemPackageUpdateStatusFile = "system-package-update-status.json"

type SystemPackageUpdateStatus struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Stage      string `json:"stage"`
	MessageKey string `json:"message_key"`
	Detail     string `json:"detail,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	UpdatedAt  string `json:"updated_at"`
}

type systemPackageUpdatePlan struct {
	ID         string `json:"id"`
	StatusPath string `json:"status_path"`
	PlanPath   string `json:"plan_path"`
}

var (
	systemPackageUpdateCommand  = runSystemPackageUpdateCommand
	systemPackageUpdateUnitLive = func(id string) bool {
		return exec.Command("systemctl", "is-active", "--quiet", "ols-wpanel-system-update-"+id).Run() == nil
	}
	systemPackageUpdateLockPath = "/run/lock/ols-wpanel-system-update.lock"
	systemPackageUpdateStartMu  sync.Mutex
	systemPackageUpdateSleep    = time.Sleep
)

var systemPackageUpdateURLCredentialsRE = regexp.MustCompile(`(?i)(https?://)[^/@\s]+@`)

func SystemPackageUpdateStatusPath(cfg *config.Config) string {
	return filepath.Join(cfg.Panel.DataDir, systemPackageUpdateStatusFile)
}

func ReadSystemPackageUpdateStatus(cfg *config.Config) SystemPackageUpdateStatus {
	status := SystemPackageUpdateStatus{Status: "idle"}
	if cfg == nil {
		return status
	}
	data, err := os.ReadFile(SystemPackageUpdateStatusPath(cfg))
	if err == nil {
		_ = json.Unmarshal(data, &status)
	}
	return status
}

// ReconcileSystemPackageUpdateStatus converts a stale running state left by an
// interrupted detached process into an explicit failure visible to the UI.
func ReconcileSystemPackageUpdateStatus(cfg *config.Config) SystemPackageUpdateStatus {
	status := ReadSystemPackageUpdateStatus(cfg)
	if status.Status != "running" || status.ID == "" || systemPackageUpdateUnitLive(status.ID) {
		return status
	}
	startedAt, err := time.Parse(time.RFC3339, status.StartedAt)
	if err == nil && time.Since(startedAt) < 10*time.Second {
		return status
	}
	status.Status = "failed"
	status.Stage = "interrupted"
	status.MessageKey = "settings.system_update_status_interrupted"
	status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = writePanelDBRestoreJSON(SystemPackageUpdateStatusPath(cfg), status)
	return status
}

func StartSystemPackageUpdate(cfg *config.Config) (SystemPackageUpdateStatus, error) {
	systemPackageUpdateStartMu.Lock()
	defer systemPackageUpdateStartMu.Unlock()

	if cfg == nil {
		return SystemPackageUpdateStatus{}, errors.New("panel config unavailable")
	}
	current := ReconcileSystemPackageUpdateStatus(cfg)
	if current.Status == "running" {
		return SystemPackageUpdateStatus{}, errors.New("系统更新正在执行")
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		return SystemPackageUpdateStatus{}, errors.New("systemd-run unavailable")
	}
	executable, err := os.Executable()
	if err != nil {
		return SystemPackageUpdateStatus{}, err
	}
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	planPath := filepath.Join(cfg.Panel.DataDir, "system-package-update-"+id+".json")
	plan := systemPackageUpdatePlan{ID: id, StatusPath: SystemPackageUpdateStatusPath(cfg), PlanPath: planPath}
	now := time.Now().UTC().Format(time.RFC3339)
	status := SystemPackageUpdateStatus{ID: id, Status: "running", Stage: "queued", MessageKey: "settings.system_update_status_queued", StartedAt: now, UpdatedAt: now}
	if err := writePanelDBRestoreJSON(planPath, plan); err != nil {
		return SystemPackageUpdateStatus{}, err
	}
	if err := writePanelDBRestoreJSON(plan.StatusPath, status); err != nil {
		_ = os.Remove(planPath)
		return SystemPackageUpdateStatus{}, err
	}
	out, err := exec.Command("systemd-run", "--unit", "ols-wpanel-system-update-"+id, "--collect", "--property", "Type=exec", executable, "--system-package-update-plan", planPath).CombinedOutput()
	if err != nil {
		status.Status, status.Stage, status.MessageKey, status.UpdatedAt = "failed", "start", "settings.system_update_status_start_failed", time.Now().UTC().Format(time.RFC3339)
		status.Detail = systemPackageUpdateErrorDetail(fmt.Errorf("systemd-run failed: %w: %s", err, strings.TrimSpace(string(out))))
		_ = writePanelDBRestoreJSON(plan.StatusPath, status)
		_ = os.Remove(planPath)
		return SystemPackageUpdateStatus{}, fmt.Errorf("启动系统更新失败: %s", strings.TrimSpace(string(out)))
	}
	return status, nil
}

func RunSystemPackageUpdatePlan(planPath string) error {
	data, err := os.ReadFile(planPath)
	if err != nil {
		return err
	}
	var plan systemPackageUpdatePlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return err
	}
	defer os.Remove(plan.PlanPath)
	lock, err := os.OpenFile(systemPackageUpdateLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another system update is running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	started := time.Now().UTC().Format(time.RFC3339)
	writeStatus := func(status, stage, messageKey, detail string) {
		_ = writePanelDBRestoreJSON(plan.StatusPath, SystemPackageUpdateStatus{ID: plan.ID, Status: status, Stage: stage, MessageKey: messageKey, Detail: detail, StartedAt: started, UpdatedAt: time.Now().UTC().Format(time.RFC3339)})
	}
	fail := func(stage, messageKey string, cause error) error {
		writeStatus("failed", stage, messageKey, systemPackageUpdateErrorDetail(cause))
		if cause != nil {
			return cause
		}
		return errors.New(messageKey)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	writeStatus("running", "services_preflight", "settings.system_update_status_checking_services", "")
	if err := checkSystemPackageUpdateHealth(ctx); err != nil {
		return fail("services_preflight", "settings.system_update_status_health_failed", err)
	}
	aptOptions := []string{"-o", "Acquire::Retries=3", "-o", "DPkg::Lock::Timeout=300"}
	for _, step := range []struct {
		stage, messageKey, name string
		args                    []string
	}{
		{"refresh", "settings.system_update_status_refresh", "apt-get", append(append([]string{}, aptOptions...), "update")},
		{"preflight", "settings.system_update_status_preflight", "apt-get", append(append([]string{}, aptOptions...), "-s", "upgrade")},
		{"upgrade", "settings.system_update_status_upgrading", "env", append([]string{"DEBIAN_FRONTEND=noninteractive", "apt-get", "-y"}, append(append([]string{}, aptOptions...), "-o", "Dpkg::Options::=--force-confold", "upgrade")...)},
		{"packages", "settings.system_update_status_checking_packages", "apt-get", []string{"check"}},
		{"packages", "settings.system_update_status_checking_packages", "dpkg", []string{"--audit"}},
	} {
		writeStatus("running", step.stage, step.messageKey, "")
		if err := systemPackageUpdateCommand(ctx, step.name, step.args...); err != nil {
			return fail(step.stage, "settings.system_update_status_failed", err)
		}
	}
	writeStatus("running", "services", "settings.system_update_status_checking_services", "")
	if err := checkSystemPackageUpdateHealth(ctx); err != nil {
		return fail("services", "settings.system_update_status_health_failed", err)
	}
	status := SystemPackageUpdateStatus{ID: plan.ID, Status: "success", Stage: "complete", MessageKey: "settings.system_update_status_success", StartedAt: started, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
	return writePanelDBRestoreJSON(plan.StatusPath, status)
}

func checkSystemPackageUpdateHealth(ctx context.Context) error {
	for _, service := range []string{"lshttpd", "mariadb", "redis-server", "ols-wpanel"} {
		if err := waitForSystemPackageUpdateService(ctx, service); err != nil {
			return err
		}
	}
	if err := systemPackageUpdateCommand(ctx, "/usr/local/lsws/bin/openlitespeed", "-t"); err != nil {
		return err
	}
	return nil
}

func waitForSystemPackageUpdateService(ctx context.Context, service string) error {
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		if err := systemPackageUpdateCommand(ctx, "systemctl", "is-active", "--quiet", service); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if attempt < 5 {
			systemPackageUpdateSleep(5 * time.Second)
		}
	}
	return fmt.Errorf("service %s did not become active: %w", service, lastErr)
}

func systemPackageUpdateErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	detail := systemPackageUpdateURLCredentialsRE.ReplaceAllString(strings.TrimSpace(err.Error()), `${1}[redacted]@`)
	detail = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 32 {
			return r
		}
		return -1
	}, detail)
	const maximum = 2048
	if len(detail) > maximum {
		detail = detail[:maximum] + "..."
	}
	return detail
}

func runSystemPackageUpdateCommand(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	if name == "dpkg" && strings.TrimSpace(string(out)) != "" {
		return errors.New("dpkg reports unfinished packages")
	}
	return nil
}
