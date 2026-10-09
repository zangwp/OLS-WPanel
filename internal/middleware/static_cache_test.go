package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
)

func TestVersionedStaticCacheExcludesPrivateAndUnversionedResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	files := fstest.MapFS{"js/app.js": {Data: []byte("public script")}}
	for _, tc := range []struct {
		method, url, version string
		cached               bool
	}{
		{http.MethodGet, "/panel/assets/js/app.js?v=v1.21.0", "v1.21.0", true},
		{http.MethodHead, "/panel/assets/js/app.js?v=v1.21.0", "v1.21.0", true},
		{http.MethodGet, "/panel/assets/js/app.js", "v1.21.0", false},
		{http.MethodGet, "/panel/assets/js/app.js?v=v1.20.0", "v1.21.0", false},
		{http.MethodGet, "/panel/assets/js/app.js?v=dev", "dev", false},
		{http.MethodGet, "/panel/assets/missing.js?v=v1.21.0", "v1.21.0", false},
		{http.MethodGet, "/panel/assets/js?v=v1.21.0", "v1.21.0", false},
		{http.MethodGet, "/panel/assets/js/../app.js?v=v1.21.0", "v1.21.0", false},
		{http.MethodGet, "/panel/settings?v=v1.21.0", "v1.21.0", false},
		{http.MethodGet, "/panel/api/auth?v=v1.21.0", "v1.21.0", false},
		{http.MethodPost, "/panel/assets/js/app.js?v=v1.21.0", "v1.21.0", false},
	} {
		t.Run(tc.method+tc.url, func(t *testing.T) {
			router := gin.New()
			router.Use(VersionedStaticCache("/panel/assets", tc.version, files))
			router.NoRoute(func(c *gin.Context) { c.Status(http.StatusOK) })
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(tc.method, tc.url, nil))
			if got := response.Header().Get("Cache-Control"); (got == "public, max-age=31536000, immutable") != tc.cached {
				t.Fatalf("cache policy=%q, expected public=%t", got, tc.cached)
			}
		})
	}
}
