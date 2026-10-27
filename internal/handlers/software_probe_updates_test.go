package handlers

import (
	"context"
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/executor"
)

func writeSoftwareSystemUpdateStatus(t *testing.T, cfg *config.Config, status executor.SystemPackageUpdateStatus) {
	t.Helper()
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executor.SystemPackageUpdateStatusPath(cfg), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSoftwareReadsObserveSystemUpdateCompletionWithoutSettingsPage(t *testing.T) {
	for _, endpoint := range []string{"/software", "/software/guard"} {
		for _, terminal := range []string{"success", "failed"} {
			t.Run(endpoint+"/"+terminal, func(t *testing.T) {
				cfg := &config.Config{Panel: config.PanelConfig{DataDir: t.TempDir()}}
				status := executor.SystemPackageUpdateStatus{ID: "update-1", Status: "running", UpdatedAt: "2026-01-01T00:00:00Z"}
				writeSoftwareSystemUpdateStatus(t, cfg, status)
				var redisCalls atomic.Int32
				router := softwareReadFixtureWithConfig(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
					if name == "redis-server" {
						redisCalls.Add(1)
					}
					return softwareVersionFixture(ctx, name, args...)
				}, cfg)
				read := func() { softwareReadRequest[json.RawMessage](t, router, endpoint) }
				read()
				read()
				if redisCalls.Load() != 1 {
					t.Fatal("running update repeatedly invalidated cached versions")
				}
				// The detached updater finishes after the user has left settings.
				status.Status, status.UpdatedAt = terminal, "2026-01-01T00:01:00Z"
				writeSoftwareSystemUpdateStatus(t, cfg, status)
				read()
				read()
				if redisCalls.Load() != 2 {
					t.Fatalf("terminal update was missed or invalidated twice: %d reads", redisCalls.Load())
				}
				status.UpdatedAt = "2026-01-01T00:02:00Z"
				writeSoftwareSystemUpdateStatus(t, cfg, status)
				read()
				if redisCalls.Load() != 3 {
					t.Fatalf("changed terminal status timestamp did not refresh versions: %d reads", redisCalls.Load())
				}
			})
		}
	}
}

func TestSoftwareSystemUpdateInvalidationSkipsIncompleteIdentity(t *testing.T) {
	softwareReadFixture(t, softwareVersionFixture)
	if _, err := softwareReadCache.read(t.Context(), false, "redis-server", "--version"); err != nil {
		t.Fatal(err)
	}
	for _, status := range []executor.SystemPackageUpdateStatus{
		{Status: "success"},
		{ID: "pending", Status: "running"},
		{ID: "idle", Status: "idle"},
	} {
		invalidateSoftwareProbesForSystemUpdate(status)
	}
	if softwareReadCache.generation != 0 || len(softwareReadCache.entries) != 1 {
		t.Fatal("incomplete or nonterminal update invalidated read cache")
	}
}
