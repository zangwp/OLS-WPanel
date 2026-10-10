package executor

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var websiteSecurityMaintenanceState = readWebsiteSecurityMaintenanceState

func readWebsiteSecurityMaintenanceState(ctx context.Context, id int) (string, error) {
	db := database.GetDB()
	if db == nil {
		return "unknown", errors.New("maintenance database unavailable")
	}
	var raw string
	if err := db.QueryRowContext(ctx, "SELECT maintenance_security FROM websites WHERE id=?", id).Scan(&raw); err != nil {
		return "unknown", err
	}
	if trimmed := strings.TrimSpace(raw); trimmed == "" || trimmed[0] != '{' {
		return "unknown", errors.New("invalid maintenance record")
	}
	// Inspect only lifecycle state; never copy private passwords/hashes into the
	// security report. An uncertain transition must not claim inherited coverage.
	var state struct {
		Window *struct {
			State string `json:"state"`
		} `json:"window"`
	}
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return "unknown", err
	}
	if DefaultMaintenanceManager().isUncertain(id) {
		return "unknown", nil
	}
	if state.Window != nil {
		return state.Window.State, nil
	}
	return "locked", nil
}

func applyWebsiteFileLockSecurityStatus(report *models.WebsiteSecurityStatus, site *models.Website, policyPresent bool, maintenanceState string, readErr error) {
	if !site.FileLockEnabled && site.FileLockApplyStatus == "" && maintenanceState == "locked" && readErr == nil {
		SetWebsiteSecurityCheck(report, "file_lock", "disabled", securityBool(false), nil)
		return
	}
	state, reason := "error", "file_lock_not_ready"
	switch {
	case readErr != nil || maintenanceState == "unknown":
		state, reason = "unknown", "file_lock_state_unknown"
	case maintenanceState == "unlocked" || maintenanceState == "unlocking" || maintenanceState == "relocking":
		state, reason = "configured", "file_lock_temporarily_unlocked"
	case maintenanceState != "locked" || !site.FileLockEnabled || site.FileLockApplyStatus != FileLockApplyStatusReady:
	case !policyPresent:
		reason = "file_lock_policy_not_confirmed"
	default:
		state, reason = "ready", "file_lock_applied"
	}
	SetWebsiteSecurityCheck(report, "file_lock", state, securityBool(true), nil)
	setWebsiteSecurityEvidence(report, "file_lock", reason, "file_lock_apply", report.CheckedAt, nil)
	if state != "ready" {
		return
	}
	// Ready records a successful lock-transition verification plus the current
	// DISALLOW_FILE_MODS policy. It is not a fresh whole-tree permission audit or
	// an isolated WordPress core verification.
	SetWebsiteSecurityCheck(report, "file_editing", "ready", securityBool(true), nil)
	setWebsiteSecurityEvidence(report, "file_editing", "file_editing_managed_by_file_lock", "file_lock_apply", report.CheckedAt, map[string]string{"protected_by": "file_lock"})
	for i := range report.Checks {
		if report.Checks[i].Key == "file_editing" {
			report.Checks[i].CanVerify = false
		}
	}
}

type websiteAvailabilityObservation struct {
	domain     string
	ssl        bool
	interval   int
	statusCode int
	failures   int
	checkedAt  time.Time
}

var websiteAvailabilityObservations = struct {
	sync.RWMutex
	entries map[string]websiteAvailabilityObservation
}{entries: make(map[string]websiteAvailabilityObservation)}

func recordWebsiteAvailabilityObservation(id, domain string, ssl bool, interval, statusCode, failures int, checkedAt time.Time) {
	websiteAvailabilityObservations.Lock()
	defer websiteAvailabilityObservations.Unlock()
	// Bounded, process-local evidence. Restarting loses observations and shows
	// pending until the existing scheduler checks the site again.
	if _, exists := websiteAvailabilityObservations.entries[id]; !exists && len(websiteAvailabilityObservations.entries) >= 1024 {
		oldestID, oldest := "", checkedAt
		for key, observation := range websiteAvailabilityObservations.entries {
			if oldestID == "" || observation.checkedAt.Before(oldest) {
				oldestID, oldest = key, observation.checkedAt
			}
		}
		delete(websiteAvailabilityObservations.entries, oldestID)
	}
	websiteAvailabilityObservations.entries[id] = websiteAvailabilityObservation{domain, ssl, interval, statusCode, failures, checkedAt}
}

// ApplyWebsiteAvailabilitySecurityStatus consumes observations from the existing
// alert checker. Reading a security summary never starts a new HTTP check.
func ApplyWebsiteAvailabilitySecurityStatus(report *models.WebsiteSecurityStatus, site *models.Website, alertsEnabled bool, now time.Time) {
	if !site.MonitoringEnabled {
		return
	}
	reason := "uptime_check_pending"
	if !alertsEnabled {
		reason = "uptime_alert_disabled"
	} else if site.Status != models.StatusActive {
		reason = "site_not_active"
	}
	SetWebsiteSecurityCheck(report, "uptime_monitor", "configured", securityBool(true), nil)
	setWebsiteSecurityEvidence(report, "uptime_monitor", reason, "saved_configuration", report.CheckedAt, nil)
	if !alertsEnabled || site.Status != models.StatusActive {
		return
	}
	websiteAvailabilityObservations.RLock()
	observation, ok := websiteAvailabilityObservations.entries[strconv.Itoa(site.ID)]
	websiteAvailabilityObservations.RUnlock()
	interval := site.MonitoringInterval
	if interval < 1 {
		interval = 5
	}
	if !ok || observation.domain != site.Domain || observation.ssl != site.SSLEnabled || observation.interval != interval {
		return
	}
	if observation.checkedAt.IsZero() || observation.checkedAt.After(now.Add(time.Minute)) || now.Sub(observation.checkedAt) > time.Duration(interval)*time.Minute+2*time.Minute {
		setWebsiteSecurityEvidence(report, "uptime_monitor", "uptime_check_stale", "website_http", observation.checkedAt.UTC().Format(time.RFC3339), nil)
		return
	}
	state, reason := "ready", "uptime_check_succeeded"
	if observation.statusCode < 200 || observation.statusCode >= 400 || observation.failures > 0 {
		state, reason = "error", "uptime_check_failed"
	}
	SetWebsiteSecurityCheck(report, "uptime_monitor", state, securityBool(true), nil)
	setWebsiteSecurityEvidence(report, "uptime_monitor", reason, "website_http", observation.checkedAt.UTC().Format(time.RFC3339), map[string]string{"status_code": strconv.Itoa(observation.statusCode), "failure_count": strconv.Itoa(observation.failures)})
}

func ApplyWebsiteAnomalySecurityStatus(report *models.WebsiteSecurityStatus, enabled bool, lastSuccess, nextCheck int64, lastError string, now time.Time) {
	if !enabled {
		SetWebsiteSecurityCheck(report, "anomaly_monitor", "disabled", securityBool(false), nil)
		return
	}
	state, reason, source, at := "configured", "anomaly_check_pending", "saved_configuration", report.CheckedAt
	details := map[string]string{"next_check": strconv.FormatInt(nextCheck, 10)}
	switch {
	case lastError != "":
		state, reason, source, at = "error", "anomaly_check_failed", "wordpress_inventory", ""
		details["error_code"] = lastError
	case lastSuccess < 0 || lastSuccess > now.Add(time.Minute).Unix() || nextCheck < 0:
		state, reason, source, at = "unknown", "anomaly_state_unknown", "wordpress_inventory", ""
	case lastSuccess > 0:
		state, reason, source, at = "ready", "anomaly_check_succeeded", "wordpress_inventory", time.Unix(lastSuccess, 0).UTC().Format(time.RFC3339)
		if now.Unix()-lastSuccess > 3900 || (nextCheck > 0 && now.Unix() > nextCheck+300) {
			state, reason = "configured", "anomaly_check_stale"
		}
	}
	SetWebsiteSecurityCheck(report, "anomaly_monitor", state, securityBool(true), nil)
	setWebsiteSecurityEvidence(report, "anomaly_monitor", reason, source, at, details)
}
