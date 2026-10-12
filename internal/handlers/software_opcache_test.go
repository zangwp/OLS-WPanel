package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The HTTP contract is tested without restarting any host service. Worker
// restart ordering and the detached restart marker are tested in executor.
func TestClearOpcacheReturnsWellFormedResponse(t *testing.T) {
	previous := softwareClearOPcache
	defer func() { softwareClearOPcache = previous }()
	softwareClearOPcache = func() error { return errors.New("restart failed") }
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/software/opcache/clear", (&SoftwareHandler{}).ClearOpcache)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/software/opcache/clear", nil))

	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Data    struct {
			Message string `json:"message"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v; body=%s", err, rec.Body.String())
	}
	if resp.Success && resp.Data.Message == "" {
		t.Fatal("expected a non-empty success message")
	}
	if !resp.Success && resp.Message == "" {
		t.Fatal("expected a non-empty error message")
	}
	if rec.Code != http.StatusInternalServerError || resp.Success {
		t.Fatal("failed restart was reported as success")
	}
	softwareClearOPcache = func() error { return nil }
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/software/opcache/clear", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || rec.Code != http.StatusOK || !resp.Success || resp.Data.Message == "" {
		t.Fatalf("restart request response: %s %v", rec.Body.String(), err)
	}
}
