package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestLiteSpeedCacheStatusEndpointReportsIndependentLayers(t *testing.T) {
	setupWebsiteOptimizationsTestDB(t)
	oldObserve := observeLiteSpeedCacheStatus
	observeLiteSpeedCacheStatus = func(context.Context, *config.Config, *models.Website) executor.LiteSpeedCacheRuntimeStatus {
		configured := true
		return executor.LiteSpeedCacheRuntimeStatus{StatusKnown: true, PluginStatus: "active", PluginVersion: "7.9.1", PageCacheEnabled: true, ServerCacheState: "configured", ServerCacheReason: "module_ready", ServerCacheConfigured: &configured, RedisConnectionState: "not_checked", RedisObjectCacheConfigured: true, RedisHost: "localhost", RedisPort: 6379}
	}
	t.Cleanup(func() { observeLiteSpeedCacheStatus = oldObserve })

	router := gin.New()
	router.GET("/api/websites/:id/litespeed-cache/status", (&WebsiteHandler{}).LiteSpeedCacheStatus)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/websites/1/litespeed-cache/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("live cache status must not be cached")
	}
	for _, expected := range []string{`"status_known":true`, `"plugin_status":"active"`, `"page_cache_enabled":true`, `"server_cache_state":"configured"`, `"server_cache_configured":true`, `"server_cache_reason":"module_ready"`, `"redis_connection_state":"not_checked"`, `"redis_object_cache_configured":true`, `"redis_host":"localhost"`, `"redis_database":0`} {
		if !strings.Contains(rec.Body.String(), expected) {
			t.Fatalf("response missing %s: %s", expected, rec.Body.String())
		}
	}
	if strings.Contains(rec.Body.String(), "server_page_cache_enabled") {
		t.Fatal("old DB default policy must not masquerade as module capability")
	}
}

func TestVerifyLiteSpeedPageCacheEndpointKeepsMissAsObservedMiss(t *testing.T) {
	setupWebsiteOptimizationsTestDB(t)
	oldVerify := verifyLiteSpeedPageCache
	verifyLiteSpeedPageCache = func(ctx context.Context, _ *config.Config, site *models.Website) executor.LiteSpeedPageCacheVerification {
		if _, hasDeadline := ctx.Deadline(); !hasDeadline || site.Domain != "example.com" {
			t.Fatal("verification must be bounded and use the managed site")
		}
		return executor.LiteSpeedPageCacheVerification{State: "miss", Reason: "cache_miss_observed", URL: "https://example.com/", Source: "local_origin", Attempts: []executor.LiteSpeedPageCacheAttempt{{StatusCode: 200, CacheHeader: "miss"}}}
	}
	t.Cleanup(func() { verifyLiteSpeedPageCache = oldVerify })
	router := gin.New()
	router.POST("/api/websites/:id/litespeed-cache/verify", (&WebsiteHandler{}).VerifyLiteSpeedPageCache)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/websites/1/litespeed-cache/verify", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body)
	}
	for _, expected := range []string{`"state":"miss"`, `"reason":"cache_miss_observed"`, `"cache_header":"miss"`, `"source":"local_origin"`} {
		if !strings.Contains(rec.Body.String(), expected) {
			t.Fatalf("missing %s: %s", expected, rec.Body)
		}
	}
}

func TestApplyRecommendedLiteSpeedCacheConfiguresOfficialPluginAndBothCaches(t *testing.T) {
	setupWebsiteOptimizationsTestDB(t)
	oldEnsure, oldConfigure, oldUpdate := ensureLiteSpeedCachePlugin, configureLiteSpeedObjectCache, updateSiteLiteSpeedCache
	ensured, configured, updated := false, false, false
	ensureLiteSpeedCachePlugin = func(_, _ string) (bool, error) { ensured = true; return true, nil }
	configureLiteSpeedObjectCache = func(_, domain string) (func() error, error) {
		configured = domain == "example.com"
		return func() error { return nil }, nil
	}
	updateSiteLiteSpeedCache = func(id, enabled, ttl int) error {
		updated = id == 1 && enabled == 0 && ttl == 300
		return nil
	}
	t.Cleanup(func() {
		ensureLiteSpeedCachePlugin, configureLiteSpeedObjectCache, updateSiteLiteSpeedCache = oldEnsure, oldConfigure, oldUpdate
	})

	router := gin.New()
	router.POST("/api/websites/:id/litespeed-cache/recommended", (&WebsiteHandler{}).ApplyRecommendedLiteSpeedCache)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/websites/1/litespeed-cache/recommended", nil))
	if rec.Code != http.StatusOK || !ensured || !configured || !updated {
		t.Fatalf("status=%d ensured=%t configured=%t updated=%t body=%s", rec.Code, ensured, configured, updated, rec.Body.String())
	}
}
