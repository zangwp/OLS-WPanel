package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSiteSSLRenewalDefaultsAndManualGuard(t *testing.T) {
	setupBackupOverviewTestDB(t)
	insertBackupPolicySite(t, 1, "renew.example.com")
	if _, err := database.GetDB().Exec(`UPDATE websites SET ssl_enabled=1,ssl_cert_source='auto' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	call := func(method, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(method, "/api/websites/1/ssl/renewal", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "id", Value: "1"}}
		new(WebsiteHandler).SSLRenewal(c)
		return w
	}
	if r := call(http.MethodGet, ""); r.Code != 200 || !strings.Contains(r.Body.String(), `"enabled":true`) {
		t.Fatalf("default: %d %s", r.Code, r.Body.String())
	}
	if r := call(http.MethodPut, `{}`); r.Code != 400 {
		t.Fatalf("missing enabled: %d", r.Code)
	}
	if r := call(http.MethodPut, `{"enabled":false}`); r.Code != 200 {
		t.Fatalf("disable: %d %s", r.Code, r.Body.String())
	}
	if enabled, err := database.SiteSSLRenewalEnabled(1); err != nil || enabled {
		t.Fatalf("preference: %v %v", enabled, err)
	}
	if _, err := database.GetDB().Exec(`UPDATE websites SET ssl_cert_source='manual' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if r := call(http.MethodPut, `{"enabled":true}`); r.Code != 409 {
		t.Fatalf("manual certificate enabled: %d %s", r.Code, r.Body.String())
	}
}
