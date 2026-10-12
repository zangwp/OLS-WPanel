package handlers

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
)

func TestSoftwareCronHealthUsesFixedCachedReadOnlyProbe(t *testing.T) {
	var calls atomic.Int32
	previous := softwareReadCache
	softwareReadCache = newSoftwareProbeCache(func(_ context.Context, command string, args ...string) ([]byte, error) {
		calls.Add(1)
		want := []string{"show", "cron.service", "--property=LoadState,ActiveState,SubState,UnitFileState"}
		if command != "systemctl" || !reflect.DeepEqual(args, want) {
			t.Errorf("unexpected cron command: %s %v", command, args)
		}
		return []byte("LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\n"), nil
	})
	t.Cleanup(func() { softwareReadCache = previous })
	for range 2 {
		health := getCronHealth(context.Background(), false)
		if health.Unit != "cron.service" || health.State != "running" || health.Enabled != "enabled" || health.ErrorCode != "" {
			t.Fatalf("unexpected cron health: %+v", health)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("normal cron reads did not share cache: %d", calls.Load())
	}
	getCronHealth(context.Background(), true)
	if calls.Load() != 2 {
		t.Fatalf("manual refresh did not issue fresh probe: %d", calls.Load())
	}
}

func TestSoftwareCronHealthPreservesUnavailableAndUncertainStates(t *testing.T) {
	tests := []struct {
		name, output, state, enabled, errorCode string
		err                                     error
	}{
		{name: "stopped", output: "LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=disabled", state: "stopped", enabled: "disabled"},
		{name: "static running", output: "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=static", state: "running", enabled: "static"},
		{name: "missing", output: "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=", state: "missing", enabled: "unknown"},
		{name: "failed", output: "LoadState=loaded\nActiveState=failed\nSubState=failed\nUnitFileState=enabled", state: "error", enabled: "enabled", errorCode: "service_failed"},
		{name: "active exited", output: "LoadState=loaded\nActiveState=active\nSubState=exited\nUnitFileState=enabled", state: "error", enabled: "enabled", errorCode: "unknown_state"},
		{name: "activating", output: "LoadState=loaded\nActiveState=activating\nSubState=start\nUnitFileState=disabled", state: "error", enabled: "disabled", errorCode: "unknown_state"},
		{name: "masked", output: "LoadState=masked\nActiveState=inactive\nSubState=dead\nUnitFileState=masked", state: "error", enabled: "unknown", errorCode: "unit_unavailable"},
		{name: "runtime enabled", output: "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled-runtime", state: "running", enabled: "unknown"},
		{name: "malformed", output: "systemd unavailable", state: "error", enabled: "unknown", errorCode: "unit_unavailable"},
		{name: "missing active property", output: "LoadState=loaded\nUnitFileState=static", state: "error", enabled: "static", errorCode: "unknown_state"},
		{name: "failed command cannot prove missing", output: "LoadState=not-found\nActiveState=inactive", err: errors.New("bus unavailable"), state: "error", enabled: "unknown", errorCode: "probe_failed"},
		{name: "deadline", err: context.DeadlineExceeded, state: "error", enabled: "unknown", errorCode: "deadline_exceeded"},
		{name: "cancellation", err: context.Canceled, state: "error", enabled: "unknown", errorCode: "canceled"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			previous := softwareReadCache
			softwareReadCache = newSoftwareProbeCache(func(context.Context, string, ...string) ([]byte, error) {
				return []byte(test.output), test.err
			})
			t.Cleanup(func() { softwareReadCache = previous })
			health := getCronHealth(context.Background(), false)
			if health.State != test.state || health.Enabled != test.enabled || health.ErrorCode != test.errorCode {
				t.Fatalf("health=%+v, want state=%s enabled=%s error=%s", health, test.state, test.enabled, test.errorCode)
			}
			if test.name == "runtime enabled" && health.UnitFileState != "enabled-runtime" {
				t.Fatal("raw runtime-only enablement was lost")
			}
			if test.err != nil && (health.LoadState != "" || health.ActiveState != "" || health.UnitFileState != "") {
				t.Fatal("failed command output became trusted service properties")
			}
		})
	}
}

func TestSoftwareCronHealthCanceledCallerDoesNotStartProbe(t *testing.T) {
	var calls atomic.Int32
	previous := softwareReadCache
	softwareReadCache = newSoftwareProbeCache(func(context.Context, string, ...string) ([]byte, error) {
		calls.Add(1)
		return nil, nil
	})
	t.Cleanup(func() { softwareReadCache = previous })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	health := getCronHealth(ctx, false)
	if health.State != "error" || health.Enabled != "unknown" || health.ErrorCode != "canceled" || calls.Load() != 0 {
		t.Fatalf("canceled cron read=%+v calls=%d", health, calls.Load())
	}
}
