package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
)

func softwareHealthHTTPFixture(t *testing.T, run softwareProbeRunner) *gin.Engine {
	t.Helper()
	oldList, oldRuntimeRead := softwareHealthRuntimeList, softwareHealthRuntimeRead
	oldBackupRead, oldInstall, oldCache := softwareHealthBackupRead, softwareHealthBackupInstall, softwareReadCache
	t.Cleanup(func() {
		softwareHealthRuntimeList, softwareHealthRuntimeRead = oldList, oldRuntimeRead
		softwareHealthBackupRead, softwareHealthBackupInstall, softwareReadCache = oldBackupRead, oldInstall, oldCache
	})
	softwareReadCache = newSoftwareProbeCache(run)
	softwareHealthRuntimeList = func(context.Context) []executor.LSPHPRuntime { return nil }
	softwareHealthBackupRead = func(context.Context) executor.BackupDependencyHealth {
		return executor.BackupDependencyHealth{Status: "installed", Ready: true, ConfigurationStatus: "ok", Dependencies: []executor.BackupDependency{}, MissingRequired: []string{}}
	}
	softwareHealthRuntimeRead = func(context.Context, executor.LSPHPRuntime, func(context.Context, string, ...string) ([]byte, error)) executor.LSPHPRuntimeHealth {
		t.Error("unexpected PHP runtime probe")
		return executor.LSPHPRuntimeHealth{}
	}
	softwareHealthBackupInstall = func(context.Context) (executor.BackupDependencyHealth, error) {
		t.Error("read-only health check attempted an installation")
		return executor.BackupDependencyHealth{}, errors.New("unexpected installation")
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := &SoftwareHandler{}
	router.GET("/software/health", handler.Health)
	router.POST("/software/backup-dependencies/install", handler.InstallBackupDependencies)
	return router
}

func decodeSoftwareHealthHTTP(t *testing.T, response *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()
	var envelope struct {
		Success bool                       `json:"success"`
		Data    map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || response.Code != http.StatusOK || !envelope.Success {
		t.Fatalf("health HTTP response: %d %s (%v)", response.Code, response.Body.String(), err)
	}
	return envelope.Data
}

func TestSoftwareHealthHTTPAggregatesReadOnlySectionsAndSharesProbeCache(t *testing.T) {
	var commands atomic.Int32
	router := softwareHealthHTTPFixture(t, func(_ context.Context, name string, args ...string) ([]byte, error) {
		commands.Add(1)
		if name == "systemctl" {
			return []byte("LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled"), nil
		}
		if name == "health-php-fixture" && len(args) == 1 {
			return []byte(args[0]), nil
		}
		t.Errorf("unexpected read-only command: %s %v", name, args)
		return nil, errors.New("unexpected probe")
	})
	softwareHealthRuntimeList = func(ctx context.Context) []executor.LSPHPRuntime {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Second {
			t.Error("health runtime metadata has no bounded request context")
		}
		return []executor.LSPHPRuntime{{Version: "8.5", Installed: true}, {Version: "8.4", Installed: true}}
	}
	softwareHealthRuntimeRead = func(ctx context.Context, runtime executor.LSPHPRuntime, probe func(context.Context, string, ...string) ([]byte, error)) executor.LSPHPRuntimeHealth {
		output, err := probe(ctx, "health-php-fixture", runtime.Version)
		if err != nil || string(output) != runtime.Version {
			t.Errorf("runtime probe=%q, %v", output, err)
		}
		return executor.LSPHPRuntimeHealth{Version: runtime.Version, State: "ok", Extensions: []executor.LSPHPExtensionHealth{},
			OPcache: executor.LSPHPOPCacheHealth{ConfigurationState: "unknown", MetricsState: "unavailable", MetricsReason: "web_worker_probe_unavailable"}}
	}
	for _, target := range []string{"/software/health", "/software/health", "/software/health?fresh=1"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
		data := decodeSoftwareHealthHTTP(t, response)
		if len(data) != 4 || data["php"] == nil || data["backup"] == nil || data["cron"] == nil || data["checked_at"] == nil {
			t.Fatalf("aggregate health JSON shape changed: %s", response.Body.String())
		}
		var runtimes []executor.LSPHPRuntimeHealth
		if err := json.Unmarshal(data["php"], &runtimes); err != nil || len(runtimes) != 2 || runtimes[0].Version != "8.5" || runtimes[1].Version != "8.4" {
			t.Fatalf("PHP runtime ordering/shape changed: %s (%v)", data["php"], err)
		}
		if !strings.Contains(string(data["php"]), `"memory_mb":null`) || !strings.Contains(string(data["php"]), `"metrics_state":"unavailable"`) {
			t.Fatalf("unmeasured OPcache information was represented as metrics: %s", data["php"])
		}
		var cron softwareCronHealth
		if err := json.Unmarshal(data["cron"], &cron); err != nil || cron.Unit != "cron.service" || cron.State != "running" || cron.Enabled != "enabled" {
			t.Fatalf("cron JSON contract: %s (%v)", data["cron"], err)
		}
		var backup executor.BackupDependencyHealth
		if err := json.Unmarshal(data["backup"], &backup); err != nil || !backup.Ready || backup.Status != "installed" {
			t.Fatalf("backup JSON contract: %s (%v)", data["backup"], err)
		}
		var checkedAt string
		if err := json.Unmarshal(data["checked_at"], &checkedAt); err != nil {
			t.Fatal(err)
		}
		if _, err := time.Parse(time.RFC3339, checkedAt); err != nil {
			t.Fatalf("invalid health timestamp: %q", checkedAt)
		}
		if target == "/software/health" && commands.Load() != 3 {
			t.Fatalf("ordinary aggregate reads did not share raw probes: %d", commands.Load())
		}
	}
	if commands.Load() != 6 {
		t.Fatalf("explicit refresh did not refresh each raw health probe: %d", commands.Load())
	}
}

func TestSoftwareHealthHTTPKeepsEmptyPHPArrayAndPartialFailures(t *testing.T) {
	router := softwareHealthHTTPFixture(t, func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("system service inspection unavailable")
	})
	softwareHealthBackupRead = func(context.Context) executor.BackupDependencyHealth {
		return executor.BackupDependencyHealth{Status: "error", ConfigurationStatus: "error"}
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/software/health", nil))
	data := decodeSoftwareHealthHTTP(t, response)
	if string(data["php"]) != "[]" || !strings.Contains(string(data["cron"]), `"state":"error"`) || !strings.Contains(string(data["backup"]), `"status":"error"`) {
		t.Fatalf("one unavailable section hid or misrepresented the aggregate: %s", response.Body.String())
	}
}

func TestSoftwareHealthHTTPCancellationReachesReadBoundariesWithoutLaunchingCommands(t *testing.T) {
	var commands, reads atomic.Int32
	router := softwareHealthHTTPFixture(t, func(context.Context, string, ...string) ([]byte, error) {
		commands.Add(1)
		return nil, nil
	})
	check := func(ctx context.Context) {
		reads.Add(1)
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Errorf("read boundary did not inherit browser cancellation: %v", ctx.Err())
		}
	}
	softwareHealthRuntimeList = func(ctx context.Context) []executor.LSPHPRuntime {
		check(ctx)
		return []executor.LSPHPRuntime{{Version: "8.5", Installed: true}}
	}
	softwareHealthRuntimeRead = func(ctx context.Context, runtime executor.LSPHPRuntime, _ func(context.Context, string, ...string) ([]byte, error)) executor.LSPHPRuntimeHealth {
		check(ctx)
		return executor.LSPHPRuntimeHealth{Version: runtime.Version, State: "unknown", Reason: "probe_canceled"}
	}
	softwareHealthBackupRead = func(ctx context.Context) executor.BackupDependencyHealth {
		check(ctx)
		return executor.BackupDependencyHealth{Status: "error"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/software/health", nil).WithContext(ctx))
	data := decodeSoftwareHealthHTTP(t, response)
	if commands.Load() != 0 || reads.Load() != 3 || !strings.Contains(string(data["cron"]), `"error_code":"canceled"`) {
		t.Fatalf("canceled aggregate launched commands or lost uncertainty: %s commands=%d reads=%d", response.Body.String(), commands.Load(), reads.Load())
	}
}

func TestSoftwareBackupInstallHTTPOwnsContextBeyondBrowserCancellation(t *testing.T) {
	var commands atomic.Int32
	router := softwareHealthHTTPFixture(t, func(context.Context, string, ...string) ([]byte, error) {
		commands.Add(1)
		return []byte("before installation"), nil
	})
	if _, err := softwareReadCache.read(context.Background(), false, "prime-cache-fixture"); err != nil {
		t.Fatal(err)
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var installerCanceled error
	softwareHealthBackupInstall = func(ctx context.Context) (executor.BackupDependencyHealth, error) {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 10*time.Minute || time.Until(deadline) < 9*time.Minute {
			t.Error("installation does not have its bounded server-owned context")
		}
		close(started)
		<-release
		installerCanceled = ctx.Err()
		return executor.BackupDependencyHealth{Status: "installed", Ready: true}, nil
	}
	browserCtx, cancelBrowser := context.WithCancel(context.Background())
	defer cancelBrowser()
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/software/backup-dependencies/install?lang=en-US", strings.NewReader(`{}`)).WithContext(browserCtx)
	go func() { defer close(done); router.ServeHTTP(response, request) }()
	<-started
	cancelBrowser()
	close(release)
	<-done
	data := decodeSoftwareHealthHTTP(t, response)
	if installerCanceled != nil {
		t.Fatalf("browser cancellation interrupted installation: %v", installerCanceled)
	}
	var message string
	if err := json.Unmarshal(data["message"], &message); err != nil || message != i18n.T("en-US", "software.backup_dependencies_installed") || !strings.Contains(string(data["backup"]), `"ready":true`) {
		t.Fatalf("installation success JSON contract: %s (%v)", response.Body.String(), err)
	}
	if _, err := softwareReadCache.read(context.Background(), false, "prime-cache-fixture"); err != nil || commands.Load() != 2 {
		t.Fatalf("installation did not invalidate cached health reads: calls=%d err=%v", commands.Load(), err)
	}
}

func TestSoftwareBackupInstallHTTPMapsBusyAndFailureWithoutLeakingDetails(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code int
		key  string
	}{
		{"busy", executor.ErrBackupDependencyInstallBusy, http.StatusConflict, "software.backup_dependencies_install_busy"},
		{"failed", errors.New("private APT source or credential detail"), http.StatusInternalServerError, "software.backup_dependencies_install_failed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var commands atomic.Int32
			router := softwareHealthHTTPFixture(t, func(context.Context, string, ...string) ([]byte, error) {
				commands.Add(1)
				return []byte("old"), nil
			})
			if _, err := softwareReadCache.read(context.Background(), false, "prime-cache-fixture"); err != nil {
				t.Fatal(err)
			}
			softwareHealthBackupInstall = func(context.Context) (executor.BackupDependencyHealth, error) {
				return executor.BackupDependencyHealth{}, test.err
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/software/backup-dependencies/install?lang=en-US", strings.NewReader(`{}`)))
			var envelope struct {
				Success bool   `json:"success"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || response.Code != test.code || envelope.Success || envelope.Message != i18n.T("en-US", test.key) {
				t.Fatalf("installation failure JSON contract: %d %s (%v)", response.Code, response.Body.String(), err)
			}
			if strings.Contains(response.Body.String(), "private") || strings.Contains(response.Body.String(), "credential") {
				t.Fatal("installation response leaked executor diagnostics")
			}
			if _, err := softwareReadCache.read(context.Background(), false, "prime-cache-fixture"); err != nil || commands.Load() != 2 {
				t.Fatalf("failed/partial installation retained stale health: %d %v", commands.Load(), err)
			}
		})
	}
}
