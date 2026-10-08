package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

func TestCrossSiteCopyPermissionFailurePreservesExistingDestination(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "new-destination"
		if existing {
			name = "merged-existing-destination"
		}
		t.Run(name, func(t *testing.T) {
			setupCacheHelperTestDB(t)
			srcRoot, destRoot := t.TempDir(), t.TempDir()
			source, dest := filepath.Join(srcRoot, "assets"), filepath.Join(destRoot, "assets")
			if err := os.Mkdir(source, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(source, "new.txt"), []byte("copied content"), 0600); err != nil {
				t.Fatal(err)
			}
			if existing {
				if err := os.Mkdir(dest, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dest, "original.txt"), []byte("unrelated original content"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			db := database.GetDB()
			if _, err := db.Exec(`UPDATE websites SET site_type='static',web_root=? WHERE id=1`, srcRoot); err != nil {
				t.Fatal(err)
			}
			// An unavailable owner is a real permission-repair failure, reached
			// after copying. No external chown command or hook is needed.
			if _, err := db.Exec(`INSERT INTO websites(id,name,domain,status,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,site_type)
				VALUES(2,'destination','destination.example','active','',?,'','','','','','static')`, destRoot); err != nil {
				t.Fatal(err)
			}
			router := gin.New()
			router.POST("/copy", (&FileHandler{}).Copy)
			req := httptest.NewRequest(http.MethodPost, "/copy", strings.NewReader(`{"site_id":1,"dest_site_id":2,"src_path":"/","dest_path":"/","names":["assets"],"conflict_policy":"overwrite"}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			var response struct {
				Success bool   `json:"success"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusInternalServerError || response.Success || !strings.Contains(response.Message, "目标权限修复失败") {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if data, err := os.ReadFile(filepath.Join(source, "new.txt")); err != nil || string(data) != "copied content" {
				t.Fatalf("source changed: %q %v", data, err)
			}
			if !existing {
				if _, err := os.Stat(dest); !os.IsNotExist(err) {
					t.Fatalf("new failed copy should be cleaned up: %v", err)
				}
				return
			}
			for filename, want := range map[string]string{"original.txt": "unrelated original content", "new.txt": "copied content"} {
				if data, err := os.ReadFile(filepath.Join(dest, filename)); err != nil || string(data) != want {
					t.Fatalf("existing target content lost: %s=%q err=%v", filename, data, err)
				}
			}
			if !strings.Contains(response.Message, "目标已更新并保留") {
				t.Fatalf("partial mutation must be reported: %s", response.Message)
			}
		})
	}
}
