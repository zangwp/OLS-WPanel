package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func setupSoftwareReloadTest(t *testing.T, content string) (string, *gin.Engine) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "olswpanel.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	oldPath := softwarePHPRuntimeConfigPath
	oldRegenerate := softwareRegenerateAllSitesOLSConfigs
	oldRunner := runSoftwareShellCommand
	softwarePHPRuntimeConfigPath = func() string { return path }
	softwareRegenerateAllSitesOLSConfigs = func() error { return nil }
	t.Cleanup(func() {
		softwarePHPRuntimeConfigPath = oldPath
		softwareRegenerateAllSitesOLSConfigs = oldRegenerate
		runSoftwareShellCommand = oldRunner
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/api/software/config", (&SoftwareHandler{}).SaveConfig)
	return path, router
}

func setupSoftwarePHPRebuildTest(t *testing.T, content string, regenerate func() error) (string, *gin.Engine) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "99-olswpanel.ini")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	oldPath := softwarePHPRuntimeConfigPath
	oldRegenerate := softwareRegenerateAllSitesOLSConfigs
	oldRunner := runSoftwareShellCommand
	softwarePHPRuntimeConfigPath = func() string { return path }
	softwareRegenerateAllSitesOLSConfigs = regenerate
	runSoftwareShellCommand = func(string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() {
		softwarePHPRuntimeConfigPath = oldPath
		softwareRegenerateAllSitesOLSConfigs = oldRegenerate
		runSoftwareShellCommand = oldRunner
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/api/software/config", (&SoftwareHandler{}).SaveConfig)
	return path, router
}

func performSoftwareConfigSave(router *gin.Engine, value string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	body := `{"name":"PHP","key":"opcache.memory_consumption","value":"` + value + `"}`
	req := httptest.NewRequest(http.MethodPut, "/api/software/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	return recorder
}

func performSoftwarePHPConfigSave(router *gin.Engine, value string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	body := `{"name":"PHP","key":"memory_limit","value":"` + value + `"}`
	req := httptest.NewRequest(http.MethodPut, "/api/software/config", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	return recorder
}

func softwareResponseMessage(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var response struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return response.Message
}

func TestSoftwareOpenLiteSpeedReloadFailureRestoresOldConfig(t *testing.T) {
	oldContent := "opcache.memory_consumption = 64\n"
	path, router := setupSoftwareReloadTest(t, oldContent)
	call := 0
	runSoftwareShellCommand = func(command string) ([]byte, error) {
		call++
		if call == 2 {
			return []byte("reload failed"), errors.New("reload failed")
		}
		return nil, nil
	}

	recorder := performSoftwareConfigSave(router, "128")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if message := softwareResponseMessage(t, recorder); !strings.Contains(message, "已自动恢复为原配置") {
		t.Fatalf("message=%q", message)
	}
	if got, _ := os.ReadFile(path); string(got) != oldContent {
		t.Fatalf("config=%q, want %q", got, oldContent)
	}
	if call != 4 {
		t.Fatalf("command calls=%d, want 4", call)
	}
}

func TestSoftwareOpenLiteSpeedRecoveryReloadFailureNeverReportsSuccess(t *testing.T) {
	oldContent := "opcache.memory_consumption = 64\n"
	path, router := setupSoftwareReloadTest(t, oldContent)
	call := 0
	runSoftwareShellCommand = func(command string) ([]byte, error) {
		call++
		if call == 2 || call == 4 {
			return []byte("reload failed"), errors.New("reload failed")
		}
		return nil, nil
	}

	recorder := performSoftwareConfigSave(router, "128")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if message := softwareResponseMessage(t, recorder); !strings.Contains(message, "自动恢复原配置也失败") {
		t.Fatalf("message=%q", message)
	}
	if got, _ := os.ReadFile(path); string(got) != oldContent {
		t.Fatalf("config=%q, want %q", got, oldContent)
	}
}

func TestSoftwareOpenLiteSpeedSuccessfulReloadKeepsNewConfig(t *testing.T) {
	path, router := setupSoftwareReloadTest(t, "opcache.memory_consumption = 64\n")
	runSoftwareShellCommand = func(command string) ([]byte, error) { return nil, nil }

	recorder := performSoftwareConfigSave(router, "128")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "opcache.memory_consumption = 128") {
		t.Fatalf("config=%q", got)
	}
}

func TestSoftwarePHPRebuildFailureRestoresOldConfigAndPools(t *testing.T) {
	oldContent := "memory_limit = 128M\n"
	calls := 0
	path, router := setupSoftwarePHPRebuildTest(t, oldContent, func() error {
		calls++
		if calls == 1 {
			return errors.New("first rebuild failed")
		}
		return nil
	})

	recorder := performSoftwarePHPConfigSave(router, "256M")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if message := softwareResponseMessage(t, recorder); !strings.Contains(message, "已自动恢复为原配置") {
		t.Fatalf("message=%q", message)
	}
	if got, _ := os.ReadFile(path); string(got) != oldContent {
		t.Fatalf("config=%q, want %q", got, oldContent)
	}
	if calls != 2 {
		t.Fatalf("regenerate calls=%d, want 2", calls)
	}
}

func TestSoftwarePHPRebuildRecoveryFailureIsExplicit(t *testing.T) {
	oldContent := "memory_limit = 128M\n"
	calls := 0
	path, router := setupSoftwarePHPRebuildTest(t, oldContent, func() error {
		calls++
		return errors.New("rebuild failed")
	})

	recorder := performSoftwarePHPConfigSave(router, "256M")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if message := softwareResponseMessage(t, recorder); !strings.Contains(message, "自动恢复原配置也失败") {
		t.Fatalf("message=%q", message)
	}
	if got, _ := os.ReadFile(path); string(got) != oldContent {
		t.Fatalf("config=%q, want %q", got, oldContent)
	}
	if calls != 2 {
		t.Fatalf("regenerate calls=%d, want 2", calls)
	}
}

func TestSoftwarePHPRebuildSuccessKeepsNewConfig(t *testing.T) {
	path, router := setupSoftwarePHPRebuildTest(t, "memory_limit = 128M\n", func() error { return nil })
	recorder := performSoftwarePHPConfigSave(router, "256M")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "memory_limit = 256M") {
		t.Fatalf("config=%q", got)
	}
}
