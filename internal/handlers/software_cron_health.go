package handlers

import (
	"context"
	"errors"
	"strings"
)

// Cron health is deliberately separate from the process guard: inspecting a
// scheduled-task dependency must never register it for automatic restarts or
// grant arbitrary service mutations.
type softwareCronHealth struct {
	Unit          string `json:"unit"`
	State         string `json:"state"`
	Enabled       string `json:"enabled"`
	LoadState     string `json:"load_state"`
	ActiveState   string `json:"active_state"`
	SubState      string `json:"sub_state"`
	UnitFileState string `json:"unit_file_state"`
	ErrorCode     string `json:"error_code,omitempty"`
}

func getCronHealth(ctx context.Context, fresh bool) softwareCronHealth {
	health := softwareCronHealth{Unit: "cron.service", State: "error", Enabled: "unknown"}
	output, err := softwareReadCache.read(ctx, fresh, "systemctl", "show", health.Unit,
		"--property=LoadState,ActiveState,SubState,UnitFileState")
	if err != nil {
		health.ErrorCode = "probe_failed"
		if errors.Is(err, context.DeadlineExceeded) {
			health.ErrorCode = "deadline_exceeded"
		} else if errors.Is(err, context.Canceled) {
			health.ErrorCode = "canceled"
		}
		return health
	}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "LoadState":
			health.LoadState = value
		case "ActiveState":
			health.ActiveState = value
		case "SubState":
			health.SubState = value
		case "UnitFileState":
			health.UnitFileState = value
		}
	}
	// Only persistent enablement is called enabled. Runtime enablement, aliases,
	// masked units and unfamiliar values stay unknown and retain the raw value.
	switch health.UnitFileState {
	case "enabled", "disabled", "static":
		health.Enabled = health.UnitFileState
	}
	if health.LoadState == "not-found" {
		health.State, health.Enabled = "missing", "unknown"
		return health
	}
	if health.LoadState != "loaded" {
		health.ErrorCode = "unit_unavailable"
		return health
	}
	switch health.ActiveState {
	case "active":
		// A cron daemon must have a live process. An active (exited) unit is
		// not evidence that scheduled jobs can run.
		if health.SubState == "running" {
			health.State = "running"
		} else {
			health.ErrorCode = "unknown_state"
		}
	case "inactive":
		health.State = "stopped"
	case "failed":
		health.ErrorCode = "service_failed"
	default:
		// Activating, deactivating, reloading and incomplete replies are not
		// stable running/stopped states; the raw fields show what was observed.
		health.ErrorCode = "unknown_state"
	}
	return health
}
