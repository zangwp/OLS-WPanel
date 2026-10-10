package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

func TestWebsiteCloudflareSecurityReadMasksCredentialAndDoesNotMutate(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	secret := "test-only-encrypted-opaque-token-value"
	if _, err := database.GetDB().Exec(`INSERT INTO website_cloudflare_security(site_id,hostname,account_id,zone_id,token_ciphertext,rule_ref) VALUES(1,'example.com','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',?,'owned-ref')`, secret); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/api/websites/:id/cloudflare-security", (&WebsiteHandler{}).GetCloudflareSecurity)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/websites/1/cloudflare-security", nil))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "token_ciphertext") {
		t.Fatal("read disclosed a secret or failed", response.Code)
	}
	var data struct {
		Data struct {
			TokenConfigured bool   `json:"token_configured"`
			Scope           string `json:"scope"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &data); err != nil || !data.Data.TokenConfigured || data.Data.Scope != "shared_web_bans" {
		t.Fatal("redacted status contract invalid")
	}
	var stored string
	if err := database.GetDB().QueryRow(`SELECT token_ciphertext FROM website_cloudflare_security WHERE site_id=1`).Scan(&stored); err != nil || stored != secret {
		t.Fatal("read mutated token")
	}
}
func TestWebsiteCloudflareSecurityRejectsInvalidIDBodyAndUnknownWebsite(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	router := gin.New()
	handler := &WebsiteHandler{}
	router.GET("/api/websites/:id/cloudflare-security", handler.GetCloudflareSecurity)
	router.PUT("/api/websites/:id/cloudflare-security", handler.SaveCloudflareSecurity)
	router.POST("/api/websites/:id/cloudflare-security/test", handler.TestCloudflareSecurity)
	for _, input := range []struct {
		method, path, body string
		code               int
	}{
		{http.MethodGet, "/api/websites/no/cloudflare-security", "", http.StatusBadRequest},
		{http.MethodGet, "/api/websites/99/cloudflare-security", "", http.StatusNotFound},
		{http.MethodPut, "/api/websites/1/cloudflare-security", `{"api_token":"DO_NOT_ECHO_SECRET",`, http.StatusBadRequest},
		{http.MethodPost, "/api/websites/1/cloudflare-security/test", `{"api_token":"DO_NOT_ECHO_SECRET",`, http.StatusBadRequest},
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(input.method, input.path, strings.NewReader(input.body))
		request.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(response, request)
		if response.Code != input.code || strings.Contains(response.Body.String(), "DO_NOT_ECHO_SECRET") {
			t.Fatalf("unsafe invalid input response %s: %d", input.path, response.Code)
		}
	}
}

func TestWebsiteCloudflareCoverageReadSeparatesCurrentAndConfirmedHosts(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	db := database.GetDB()
	if _, err := db.Exec(`UPDATE websites SET aliases='www.example.com' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO website_cloudflare_security(site_id,hostname,enabled,account_id,zone_id,zone_name,covered_hostnames,token_ciphertext,rule_ref,rule_id,sync_status) VALUES(1,'example.com',1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','example.com','["example.com"]','encrypted-placeholder','owned-ref','dddddddddddddddddddddddddddddddd','synced')`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/api/websites/:id/cloudflare-security", (&WebsiteHandler{}).GetCloudflareSecurity)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/websites/1/cloudflare-security", nil))
	var data struct {
		Data struct {
			ZoneName         string   `json:"zone_name"`
			WebsiteHostnames []string `json:"website_hostnames"`
			CoveredHostnames []string `json:"covered_hostnames"`
			SyncStatus       string   `json:"sync_status"`
			CoverageError    string   `json:"coverage_error"`
		} `json:"data"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &data) != nil || data.Data.ZoneName != "example.com" || strings.Join(data.Data.WebsiteHostnames, ",") != "example.com,www.example.com" || strings.Join(data.Data.CoveredHostnames, ",") != "example.com" || data.Data.SyncStatus != "pending" || data.Data.CoverageError != "" {
		t.Fatal("incorrect current/confirmed coverage response", response.Body.String())
	}
	if _, err := db.Exec(`UPDATE websites SET aliases='https://invalid.example.com' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/websites/1/cloudflare-security", nil))
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &data) != nil || data.Data.CoverageError == "" || strings.Join(data.Data.CoveredHostnames, ",") != "example.com" {
		t.Fatal("invalid alias blocked status needed for cleanup")
	}
}
