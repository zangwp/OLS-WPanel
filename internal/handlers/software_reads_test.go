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
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
)

func softwareReadFixture(t *testing.T, run softwareProbeRunner) *gin.Engine {
	return softwareReadFixtureWithConfig(t, run, nil)
}

func softwareReadFixtureWithConfig(t *testing.T, run softwareProbeRunner, cfg *config.Config) *gin.Engine {
	t.Helper()
	previousCache, previousGuard, previousAction := softwareReadCache, softwareGuardSnapshot, softwareSetServiceState
	softwareReadCache = newSoftwareProbeCache(run)
	softwareGuardSnapshot = func() []executor.GuardService {
		return []executor.GuardService{{Name: "Redis", ServiceName: "redis-server"}}
	}
	t.Cleanup(func() {
		softwareReadCache, softwareGuardSnapshot, softwareSetServiceState = previousCache, previousGuard, previousAction
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := &SoftwareHandler{Config: cfg}
	router.GET("/software", handler.List)
	router.GET("/software/guard", handler.GetGuardStatus)
	router.POST("/software/guard/action", handler.GuardAction)
	return router
}

func TestSoftwareListAndGuardShareFiveMinuteServiceVersions(t *testing.T) {
	var redisCalls atomic.Int32
	router := softwareReadFixture(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "redis-server" {
			redisCalls.Add(1)
		}
		return softwareVersionFixture(ctx, name, args...)
	})
	advance := softwareProbeClock(softwareReadCache)
	softwareReadRequest[[]softwareItem](t, router, "/software")
	advance(31 * time.Second)
	softwareReadRequest[[]guardResponse](t, router, "/software/guard")
	softwareReadRequest[[]softwareItem](t, router, "/software")
	if redisCalls.Load() != 1 {
		t.Fatalf("list/guard re-executed the same version command after 30s: %d", redisCalls.Load())
	}
	softwareReadRequest[[]guardResponse](t, router, "/software/guard?fresh=1")
	softwareReadRequest[[]softwareItem](t, router, "/software")
	if redisCalls.Load() != 2 {
		t.Fatalf("fresh guard version did not update the shared list cache: %d", redisCalls.Load())
	}
}

func softwareVersionFixture(_ context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "redis-server":
		return []byte("Redis server v=8.0.3 sha=00000000"), nil
	case "mariadb":
		return []byte("mariadb from 11.8.3-MariaDB, client 15.2"), nil
	case "nft":
		return []byte("nftables v1.1.1"), nil
	case "fail2ban-client":
		return []byte("Fail2Ban v1.1.0"), nil
	case "dpkg-query":
		return []byte("1.0"), nil
	case "apt-cache":
		return []byte("  Installed: 1.0\n  Candidate: 1.0\n"), nil
	}
	if name == executor.OpenLiteSpeedBinaryPath() {
		return []byte("LiteSpeed/1.9.3 Open"), nil
	}
	if name == executor.LSPHPBinaryPath() && len(args) == 1 {
		if args[0] == "-m" {
			return []byte("Core\njson\nmysqli\n"), nil
		}
		return []byte("PHP 8.5.11 (cli)"), nil
	}
	return nil, errors.New("unexpected read-only command: " + name)
}

func softwareReadRequest[T any](t *testing.T, router *gin.Engine, target string) T {
	t.Helper()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
	var result struct {
		Success bool `json:"success"`
		Data    T    `json:"data"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || !result.Success {
		t.Fatalf("read response=%d %s", response.Code, response.Body.String())
	}
	return result.Data
}

func TestSoftwareGuardKeepsRuntimeLiveWhileVersionsAreCached(t *testing.T) {
	var calls atomic.Int32
	router := softwareReadFixture(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls.Add(1)
		return softwareVersionFixture(ctx, name, args...)
	})
	snapshot := executor.GuardService{Name: "Redis", ServiceName: "redis-server", Paused: true, Restarts: 1, LastIncident: "old"}
	softwareGuardSnapshot = func() []executor.GuardService { return []executor.GuardService{snapshot} }
	first := softwareReadRequest[[]guardResponse](t, router, "/software/guard")[0]
	snapshot.Running, snapshot.Paused, snapshot.Restarts, snapshot.LastIncident = true, false, 4, "new"
	second := softwareReadRequest[[]guardResponse](t, router, "/software/guard")[0]
	if first.Running || !first.Paused || !second.Running || second.Paused || second.Restarts != 4 || second.LastIncident != "new" || second.Version != "8.0.3" || calls.Load() != 1 {
		t.Fatalf("runtime/version cache crossed: first=%+v second=%+v calls=%d", first, second, calls.Load())
	}
	softwareReadRequest[[]guardResponse](t, router, "/software/guard?fresh=1")
	if calls.Load() != 2 {
		t.Fatalf("manual guard refresh calls=%d", calls.Load())
	}
}

func TestSoftwareListSharesRawReadsWithoutCachingTranslations(t *testing.T) {
	var calls atomic.Int32
	router := softwareReadFixture(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls.Add(1)
		return softwareVersionFixture(ctx, name, args...)
	})
	english := softwareReadRequest[[]softwareItem](t, router, "/software?lang=en-US")
	firstCalls := calls.Load()
	chinese := softwareReadRequest[[]softwareItem](t, router, "/software?lang=zh-CN")
	if len(english) != 6 || len(chinese) != 6 || english[1].Status != i18n.T("en-US", "software.installed") || chinese[1].Status != i18n.T("zh-CN", "software.installed") || english[1].Status == chinese[1].Status || calls.Load() != firstCalls {
		t.Fatalf("translated List cache leaked across languages: en=%+v zh=%+v calls=%d/%d", english, chinese, firstCalls, calls.Load())
	}
	softwareReadRequest[[]softwareItem](t, router, "/software?fresh=1")
	if calls.Load() <= firstCalls {
		t.Fatal("manual List refresh used stale probes")
	}
}

func TestSoftwareFailedReadsCannotClaimInstalledOrOfferUpdate(t *testing.T) {
	softwareReadFixture(t, func(context.Context, string, ...string) ([]byte, error) {
		return []byte("misleading 1.0"), errors.New("probe failed")
	})
	for _, language := range []string{"en-US", "zh-CN"} {
		for _, item := range []softwareItem{getPHPInfo(context.Background(), language, false), getMariaDBInfo(context.Background(), language, false), getRedisInfo(context.Background(), language, false)} {
			if item.Version != "" || item.Status != i18n.T(language, "software.status_unavailable") || item.Status == "software.status_unavailable" {
				t.Fatalf("failed read claims availability: %+v", item)
			}
			applyPackageUpdateInfo(context.Background(), false, &item, "mariadb-server")
			if item.UpdateAvailable || item.CandidateVersion != "" {
				t.Fatalf("failed apt read offers update: %+v", item)
			}
		}
	}
}

func TestSoftwarePHPModuleFailureDoesNotInventExtensionCount(t *testing.T) {
	softwareReadFixture(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == executor.LSPHPBinaryPath() && len(args) == 1 && args[0] == "-m" {
			return []byte("Core"), errors.New("module read failed")
		}
		return softwareVersionFixture(ctx, name, args...)
	})
	item := getPHPInfo(context.Background(), "en-US", false)
	if item.Version != "8.5.11" || item.Status != i18n.T("en-US", "software.installed") {
		t.Fatalf("failed module read fabricated count: %+v", item)
	}
}

func TestSoftwareGuardMutationInvalidatesOnlyAfterSuccess(t *testing.T) {
	var calls atomic.Int32
	router := softwareReadFixture(t, func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls.Add(1)
		return softwareVersionFixture(ctx, name, args...)
	})
	softwareReadRequest[[]guardResponse](t, router, "/software/guard")
	softwareSetServiceState = func(string, string) error { return errors.New("restart failed") }
	performAction := func() int {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/software/guard/action", strings.NewReader(`{"service":"redis-server","action":"restart"}`)))
		return response.Code
	}
	if performAction() != http.StatusInternalServerError {
		t.Fatal("failed action reported success")
	}
	softwareReadRequest[[]guardResponse](t, router, "/software/guard")
	if calls.Load() != 1 {
		t.Fatal("failed action invalidated known read")
	}
	softwareSetServiceState = func(string, string) error { return nil }
	if performAction() != http.StatusOK {
		t.Fatal("successful action failed")
	}
	softwareReadRequest[[]guardResponse](t, router, "/software/guard")
	if calls.Load() != 2 {
		t.Fatalf("successful action retained stale probe: %d", calls.Load())
	}
}
