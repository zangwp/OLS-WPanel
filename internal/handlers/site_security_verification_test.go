package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func resetSiteVerificationLimiter(t *testing.T) {
	t.Helper()
	siteSecurityVerificationLimit.Lock()
	old := siteSecurityVerificationLimit.next
	siteSecurityVerificationLimit.next = make(map[int]time.Time)
	siteSecurityVerificationLimit.Unlock()
	t.Cleanup(func() {
		siteSecurityVerificationLimit.Lock()
		siteSecurityVerificationLimit.next = old
		siteSecurityVerificationLimit.Unlock()
	})
}

func requestSiteVerification(t *testing.T, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/api/websites/:id/security-verify", (&WebsiteHandler{}).VerifySecurityStatus)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/websites/"+id+"/security-verify", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("verification response may be cached")
	}
	return recorder
}

func TestSiteVerificationRejectsInvalidRequestsBeforeExecution(t *testing.T) {
	old := verifySiteSecurityForHandler
	verifySiteSecurityForHandler = func(context.Context, *models.Website, string) (models.WebsiteSecurityStatus, error) {
		t.Fatal("invalid request executed verification")
		return models.WebsiteSecurityStatus{}, nil
	}
	t.Cleanup(func() { verifySiteSecurityForHandler = old })
	for _, tc := range []struct{ id, body string }{
		{"0", `{"key":"https"}`}, {"bad", `{"key":"https"}`}, {"1", `{"key":"unknown"}`}, {"1", `{"key":"https","url":"https://attacker.example"}`}, {"1", `{"key":"https"} {"key":"https"}`}, {"1", strings.Repeat(" ", 1100) + `{"key":"https"}`},
	} {
		if response := requestSiteVerification(t, tc.id, tc.body); response.Code != http.StatusBadRequest {
			t.Fatalf("%s %s: %d %s", tc.id, tc.body, response.Code, response.Body)
		}
	}
}

func TestSiteVerificationRateLimiterBoundsAndRecovers(t *testing.T) {
	resetSiteVerificationLimiter(t)
	now := time.Now()
	if !allowSiteSecurityVerification(1, now) || allowSiteSecurityVerification(1, now.Add(time.Second)) || !allowSiteSecurityVerification(2, now) || !allowSiteSecurityVerification(1, now.Add(3*time.Second)) {
		t.Fatal("site cooldown incorrect")
	}
	resetSiteVerificationLimiter(t)
	for id := 1; id <= 1024; id++ {
		if !allowSiteSecurityVerification(id, now) {
			t.Fatal("unexpected capacity refusal")
		}
	}
	if allowSiteSecurityVerification(1025, now) {
		t.Fatal("unbounded limiter")
	}
	if !allowSiteSecurityVerification(1025, now.Add(3*time.Second)) {
		t.Fatal("expired slots not reclaimed")
	}
}

func TestSiteVerificationUsesCanonicalStatusAndLimitsRepeat(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	resetSiteVerificationLimiter(t)
	if _, err := database.GetDB().Exec("UPDATE websites SET status='active' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	old := verifySiteSecurityForHandler
	calls := 0
	verifySiteSecurityForHandler = func(ctx context.Context, site *models.Website, key string) (models.WebsiteSecurityStatus, error) {
		calls++
		if site.ID != 1 || key != "https" {
			t.Fatal("wrong verification target")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded execution")
		}
		return models.WebsiteSecurityStatus{SiteID: site.ID, CheckedAt: "2026-10-09T12:00:00Z", Checks: []models.WebsiteSecurityCheck{{Key: key, State: "configured", ReasonCode: "verification-report-preserved"}}}, nil
	}
	t.Cleanup(func() { verifySiteSecurityForHandler = old })
	first := requestSiteVerification(t, "1", `{"key":"https"}`)
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), `"site_id":1`) || !strings.Contains(first.Body.String(), `verification-report-preserved`) {
		t.Fatalf("canonical response=%d %s", first.Code, first.Body)
	}
	repeat := requestSiteVerification(t, "1", `{"key":"https"}`)
	if repeat.Code != http.StatusTooManyRequests || repeat.Header().Get("Retry-After") != "3" || calls != 1 {
		t.Fatalf("repeat=%d calls=%d", repeat.Code, calls)
	}
}

func TestSiteVerificationPausedAndBusySitesDoNotExecute(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	resetSiteVerificationLimiter(t)
	old := verifySiteSecurityForHandler
	verifySiteSecurityForHandler = func(context.Context, *models.Website, string) (models.WebsiteSecurityStatus, error) {
		t.Fatal("unavailable site executed")
		return models.WebsiteSecurityStatus{}, nil
	}
	t.Cleanup(func() { verifySiteSecurityForHandler = old })
	if response := requestSiteVerification(t, "1", `{"key":"https"}`); response.Code != http.StatusConflict {
		t.Fatalf("paused=%d", response.Code)
	}
	if _, err := database.GetDB().Exec("UPDATE websites SET status='active' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if !executor.TryAcquireSiteOpLock(1, "test-verification-busy") {
		t.Fatal("fixture cannot acquire lock")
	}
	defer executor.ReleaseSiteOpLock(1)
	if response := requestSiteVerification(t, "1", `{"key":"https"}`); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "site_busy") {
		t.Fatalf("busy=%d %s", response.Code, response.Body)
	}
}

func TestSiteVerificationDoesNotExposeExecutorErrors(t *testing.T) {
	setupWebsiteSecurityStatusDatabase(t, "wordpress")
	resetSiteVerificationLimiter(t)
	if _, err := database.GetDB().Exec("UPDATE websites SET status='active' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	old := verifySiteSecurityForHandler
	verifySiteSecurityForHandler = func(context.Context, *models.Website, string) (models.WebsiteSecurityStatus, error) {
		return models.WebsiteSecurityStatus{}, errors.New("never-include-sensitive-executor-detail")
	}
	t.Cleanup(func() { verifySiteSecurityForHandler = old })
	response := requestSiteVerification(t, "1", `{"key":"https"}`)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "never-include") {
		t.Fatalf("unsafe error response=%d %s", response.Code, response.Body)
	}
	if !executor.TryAcquireSiteOpLock(1, "test-released-verification") {
		t.Fatal("failed verifier leaked site lock")
	}
	executor.ReleaseSiteOpLock(1)
}

func TestSiteVerificationRequiresCSRFBeforeHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(middleware.CSRF())
	router.POST("/api/websites/:id/security-verify", (&WebsiteHandler{}).VerifySecurityStatus)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/websites/1/security-verify", strings.NewReader(`{"key":"https"}`)))
	if response.Code != http.StatusForbidden {
		t.Fatalf("CSRF-less POST=%d", response.Code)
	}
}
