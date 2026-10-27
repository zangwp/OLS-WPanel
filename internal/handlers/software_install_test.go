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
	"github.com/zangwp/OLS-WPanel/internal/executor"
)

func TestSoftwareInstallationsRecordOutcomesAndOutliveBrowserCancellation(t *testing.T) {
	oldPHP, oldTool, oldRecord := softwareInstallPHPRuntime, softwareInstallDevelopmentTool, softwareRecordInstallOperation
	t.Cleanup(func() {
		softwareInstallPHPRuntime, softwareInstallDevelopmentTool, softwareRecordInstallOperation = oldPHP, oldTool, oldRecord
	})
	gin.SetMode(gin.TestMode)
	for _, kind := range []string{"php", "tool"} {
		for _, failed := range []bool{false, true} {
			name := kind + "/success"
			if failed {
				name = kind + "/failed"
			}
			t.Run(name, func(t *testing.T) {
				var records [][]string
				softwareRecordInstallOperation = func(operation, target, status, message string) {
					records = append(records, []string{operation, target, status, message})
				}
				failure := errors.New("download failed: https://user:secret@example.com/repo\x00 " + strings.Repeat("x", 4096))
				checkContext := func(ctx context.Context, maximum time.Duration) {
					t.Helper()
					if err := ctx.Err(); err != nil {
						t.Fatalf("browser cancellation interrupted installer: %v", err)
					}
					deadline, ok := ctx.Deadline()
					if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > maximum {
						t.Fatalf("installer context is not bounded: deadline=%v", deadline)
					}
				}
				softwareInstallPHPRuntime = func(ctx context.Context, version string) (executor.LSPHPRuntime, error) {
					checkContext(ctx, 30*time.Minute)
					if kind != "php" || version != "8.3" {
						t.Fatalf("unexpected runtime %s", version)
					}
					if failed {
						return executor.LSPHPRuntime{}, failure
					}
					return executor.LSPHPRuntime{Version: version, Installed: true}, nil
				}
				softwareInstallDevelopmentTool = func(ctx context.Context, id string) error {
					checkContext(ctx, 10*time.Minute)
					if kind != "tool" || id != "wp-cli" {
						t.Fatalf("unexpected tool %s", id)
					}
					if failed {
						return failure
					}
					return nil
				}
				router := gin.New()
				handler := &SoftwareHandler{}
				router.POST("/php", handler.InstallPHPRuntime)
				router.POST("/tool", handler.InstallDevelopmentTool)
				body, operation, target := `{"version":"8.3"}`, "php_runtime_install", "LSPHP 8.3"
				if kind == "tool" {
					body, operation, target = `{"id":"wp-cli"}`, "development_tool_install", "wp-cli"
				}
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				request := httptest.NewRequest(http.MethodPost, "/"+kind, strings.NewReader(body)).WithContext(ctx)
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				code, status := http.StatusOK, "success"
				if failed {
					code, status = http.StatusInternalServerError, "failed"
				}
				if response.Code != code || len(records) != 1 || records[0][0] != operation || records[0][1] != target || records[0][2] != status {
					t.Fatalf("response=%d records=%v", response.Code, records)
				}
				if failed && (len(records[0][3]) > 2051 || strings.Contains(records[0][3], "user:secret") || strings.ContainsRune(records[0][3], '\x00') || !strings.Contains(records[0][3], "[redacted]")) {
					t.Fatalf("unsafe operation diagnostic: %q", records[0][3])
				}
			})
		}
	}
}

func TestPHPInstallVersionIsValidatedBeforeInstallationAndLogging(t *testing.T) {
	oldPHP, oldRecord := softwareInstallPHPRuntime, softwareRecordInstallOperation
	t.Cleanup(func() {
		softwareInstallPHPRuntime, softwareRecordInstallOperation = oldPHP, oldRecord
	})
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name, body, version string
		code                int
	}{
		{"default", `{}`, executor.DefaultLSPHPVersion, http.StatusOK},
		{"trimmed", `{"version":" 8.3 "}`, "8.3", http.StatusOK},
		{"unsupported", `{"version":"8.2"}`, "", http.StatusBadRequest},
		{"control characters", `{"version":"8.3\nhttps://user:secret@example.com"}`, "", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installed, logged := 0, 0
			softwareInstallPHPRuntime = func(ctx context.Context, version string) (executor.LSPHPRuntime, error) {
				installed++
				if version != tc.version {
					t.Fatalf("installer received %q, want %q", version, tc.version)
				}
				return executor.LSPHPRuntime{Version: version, Installed: true}, nil
			}
			softwareRecordInstallOperation = func(operation, target, status, message string) {
				logged++
				if target != "LSPHP "+tc.version {
					t.Fatalf("unexpected log target: %q", target)
				}
			}
			router := gin.New()
			router.POST("/php", (&SoftwareHandler{}).InstallPHPRuntime)
			request := httptest.NewRequest(http.MethodPost, "/php", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			wantCalls := 0
			if tc.code == http.StatusOK {
				wantCalls = 1
			}
			if response.Code != tc.code || installed != wantCalls || logged != wantCalls {
				t.Fatalf("response=%d installed=%d logged=%d", response.Code, installed, logged)
			}
		})
	}
}
