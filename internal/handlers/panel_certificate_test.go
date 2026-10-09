package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/executor"
	"github.com/zangwp/OLS-WPanel/internal/i18n"
)

func panelCertificateTestContext(t *testing.T, method, target, body string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, target, strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c, w
}

func TestPanelDomainCheckReturnsStableLocalizedDiagnosis(t *testing.T) {
	old := checkPanelDomainForSettings
	t.Cleanup(func() { checkPanelDomainForSettings = old })
	checkPanelDomainForSettings = func(context.Context, string) error {
		return &executor.PanelDomainError{Code: "panel_domain_http_status", Details: map[string]string{"address_family": "IPv6", "http_status": "403"}}
	}
	for _, lang := range []string{"zh-CN", "en-US"} {
		c, w := panelCertificateTestContext(t, http.MethodPost, "/api/settings/panel-domain/check?lang="+lang, `{"domain":"panel.example.com"}`)
		new(SettingsHandler).CheckPanelDomain(c)
		var got struct {
			Success   bool
			Message   string
			ErrorCode string `json:"error_code"`
			Details   map[string]string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if w.Code != 400 || got.Success || got.ErrorCode != "panel_domain_http_status" || got.Message != i18n.T(lang, "settings.panel_domain_http_status") || got.Details["http_status"] != "403" {
			t.Fatalf("bad diagnosis: %d %s", w.Code, w.Body.String())
		}
	}
	checkPanelDomainForSettings = func(context.Context, string) error { return errors.New("/private/account.key command-secret") }
	c, w := panelCertificateTestContext(t, http.MethodPost, "/check", `{"domain":"panel.example.com"}`)
	new(SettingsHandler).CheckPanelDomain(c)
	if strings.Contains(w.Body.String(), "private") || !strings.Contains(w.Body.String(), `"error_code":"panel_certificate_failed"`) {
		t.Fatalf("raw internal error exposed: %s", w.Body.String())
	}
}

func TestPanelCertificateStatusUsesActualListenerAndLocalizesJobError(t *testing.T) {
	oldCfg, oldRead := config.AppConfig, readPanelTLSStateForSettings
	panelCertificateJob.Lock()
	oldCode, oldDetails, oldError := panelCertificateJob.ErrorCode, panelCertificateJob.ErrorDetails, panelCertificateJob.Error
	panelCertificateJob.ErrorCode = "panel_domain_challenge_mismatch"
	panelCertificateJob.ErrorDetails = map[string]string{"address_family": "IPv4"}
	panelCertificateJob.Error = "raw internal error"
	panelCertificateJob.Unlock()
	t.Cleanup(func() {
		config.AppConfig, readPanelTLSStateForSettings = oldCfg, oldRead
		panelCertificateJob.Lock()
		panelCertificateJob.ErrorCode, panelCertificateJob.ErrorDetails, panelCertificateJob.Error = oldCode, oldDetails, oldError
		panelCertificateJob.Unlock()
	})
	readPanelTLSStateForSettings = func(string) (executor.PanelTLSState, error) {
		return executor.PanelTLSState{Domain: "panel.example.com"}, nil
	}
	for _, tc := range []struct {
		name, cert, key, url string
		tls                  bool
		port                 int
	}{
		{"HTTPS", "panel.crt", "panel.key", "https://panel.example.com:19443/secret-login", true, 19443},
		{"HTTP fallback", "", "", "http://panel.example.com:18080/secret-login", false, 18080},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.AppConfig = &config.Config{Panel: config.PanelConfig{Port: 18080, TLSPort: 19443, TLSCertPath: tc.cert, TLSKeyPath: tc.key, RandomSuffix: "secret-login"}}
			c, w := panelCertificateTestContext(t, http.MethodGet, "/status", "")
			new(SettingsHandler).PanelCertificateStatus(c)
			var got struct {
				Data struct {
					LoginURL         string `json:"login_url"`
					Port             int
					UsesTLS          bool `json:"uses_tls"`
					Error, ErrorCode string
				}
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || got.Data.Port != tc.port || got.Data.UsesTLS != tc.tls || got.Data.LoginURL != tc.url || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("listener mismatch: %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "raw internal error") || got.Data.Error != i18n.T(i18n.DefaultLang, "settings.panel_domain_challenge_mismatch") {
				t.Fatalf("raw job error: %s", w.Body.String())
			}
		})
	}
}

func TestPanelCertificateInvalidJSONAndConcurrentApplyReturnCodes(t *testing.T) {
	c, w := panelCertificateTestContext(t, http.MethodPost, "/check", `{`)
	new(SettingsHandler).CheckPanelDomain(c)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `"error_code":"panel_domain_invalid"`) {
		t.Fatalf("invalid JSON: %s", w.Body.String())
	}
	panelCertificateJob.Lock()
	oldRunning := panelCertificateJob.Running
	panelCertificateJob.Running = true
	panelCertificateJob.Unlock()
	t.Cleanup(func() {
		panelCertificateJob.Lock()
		panelCertificateJob.Running = oldRunning
		panelCertificateJob.Unlock()
	})
	c, w = panelCertificateTestContext(t, http.MethodPost, "/apply", `{"domain":"panel.example.com"}`)
	new(SettingsHandler).ApplyPanelCertificate(c)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"error_code":"panel_certificate_running"`) {
		t.Fatalf("concurrent apply: %s", w.Body.String())
	}
}
