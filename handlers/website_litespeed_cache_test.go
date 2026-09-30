package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/config"
	"github.com/zangwp/OLS-WPanel/executor"
	"github.com/zangwp/OLS-WPanel/models"
)

func TestLiteSpeedCacheStatusEndpointReportsIndependentLayers(t *testing.T) {
	setupWebsiteOptimizationsTestDB(t)
	oldObserve := observeLiteSpeedCacheStatus
	observeLiteSpeedCacheStatus = func(context.Context, *config.Config, *models.Website) executor.LiteSpeedCacheRuntimeStatus {
		return executor.LiteSpeedCacheRuntimeStatus{PluginStatus: "active", PluginVersion: "7.9.1", PageCacheEnabled: true, RedisObjectCacheConfigured: true, RedisHost: "127.0.0.1", RedisPort: 6379}
	}
	t.Cleanup(func() { observeLiteSpeedCacheStatus = oldObserve })

	router := gin.New()
	router.GET("/api/websites/:id/litespeed-cache/status", (&WebsiteHandler{}).LiteSpeedCacheStatus)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/websites/1/litespeed-cache/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	for _, expected := range []string{`"plugin_status":"active"`, `"page_cache_enabled":true`, `"redis_object_cache_configured":true`} {
		if !strings.Contains(rec.Body.String(), expected) {
			t.Fatalf("response missing %s: %s", expected, rec.Body.String())
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
		updated = id == 1 && enabled == 1 && ttl == 300
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
