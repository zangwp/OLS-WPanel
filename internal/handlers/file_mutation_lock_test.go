package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/executor"
)

type fileMutationTestCloser struct {
	once  sync.Once
	close func()
}

func (c *fileMutationTestCloser) Close() error {
	c.once.Do(c.close)
	return nil
}

// Only the OS lock boundary is replaced: handlers, SQLite binding checks and
// the executor's real site slots run unchanged. CI must not touch /run.
func useFileMutationTestKernel(t *testing.T) *atomic.Int32 {
	t.Helper()
	old := acquireFileMutationKernel
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	closed := &atomic.Int32{}
	acquireFileMutationKernel = func(ctx context.Context) (io.Closer, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-gate:
			return &fileMutationTestCloser{close: func() { closed.Add(1); gate <- struct{}{} }}, nil
		}
	}
	t.Cleanup(func() { acquireFileMutationKernel = old })
	return closed
}

func setupFileMutationSites(t *testing.T) (string, string) {
	t.Helper()
	setupCacheHelperTestDB(t)
	root, other := t.TempDir(), t.TempDir()
	db := database.GetDB()
	if _, err := db.Exec(`UPDATE websites SET site_type='static',web_root=? WHERE id=1`, root); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO websites(id,name,domain,status,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path,site_type)
		VALUES(2,'other','other.example','active','',?,'','','','','','static')`, other); err != nil {
		t.Fatal(err)
	}
	return root, other
}

func TestFileMutationSlotsAreOrderedDeduplicatedAndReleased(t *testing.T) {
	root, other := setupFileMutationSites(t)
	closed := useFileMutationTestKernel(t)
	lease, err := acquireFileMutation(context.Background(), fileMutationTarget{2, other}, fileMutationTarget{1, root}, fileMutationTarget{2, other})
	if err != nil {
		t.Fatal(err)
	}
	if got := lease.(*fileMutationLease).sites; !reflect.DeepEqual(got, []int{1, 2}) {
		t.Fatalf("slots=%v", got)
	}
	if !executor.SiteOpLocked(1) || !executor.SiteOpLocked(2) {
		t.Fatal("site slots not held")
	}
	_ = lease.Close()
	_ = lease.Close()
	if executor.SiteOpLocked(1) || executor.SiteOpLocked(2) || closed.Load() != 1 {
		t.Fatal("lease did not release exactly once")
	}
	if !executor.TryAcquireSiteFileOpLock(2, "fixture_busy") {
		t.Fatal("slot unavailable")
	}
	t.Cleanup(func() { executor.ReleaseSiteOpLock(2) })
	if _, err := acquireFileMutation(context.Background(), fileMutationTarget{2, other}, fileMutationTarget{1, root}); err == nil {
		t.Fatal("busy transfer admitted")
	}
	if executor.SiteOpLocked(1) || !executor.SiteOpLocked(2) || closed.Load() != 2 {
		t.Fatal("partial acquisition leaked or released another owner")
	}
}

func TestFileMutationRechecksStateAfterKernelAcquisition(t *testing.T) {
	for _, change := range []string{"maintenance", "binding", "missing", "sql_failure", "backup_directory_attention"} {
		t.Run(change, func(t *testing.T) {
			root, _ := setupFileMutationSites(t)
			closed := useFileMutationTestKernel(t)
			original := acquireFileMutationKernel
			acquireFileMutationKernel = func(ctx context.Context) (io.Closer, error) {
				lock, err := original(ctx)
				if err != nil {
					return nil, err
				}
				db := database.GetDB()
				switch change {
				case "maintenance", "backup_directory_attention":
					_, err = db.Exec(`UPDATE websites SET status='backup_maintenance' WHERE id=1`)
				case "binding":
					_, err = db.Exec(`UPDATE websites SET web_root=? WHERE id=1`, t.TempDir())
				case "missing":
					_, err = db.Exec(`DELETE FROM websites WHERE id=1`)
				case "sql_failure":
					err = db.Close()
				}
				if err != nil {
					t.Fatal(err)
				}
				return lock, nil
			}
			target := fileMutationTarget{1, root}
			if change == "backup_directory_attention" {
				target = fileMutationTarget{0, t.TempDir()}
			}
			if lease, err := acquireFileMutation(context.Background(), target); err == nil {
				_ = lease.Close()
				t.Fatal("stale admission allowed")
			}
			if executor.SiteOpLocked(1) || closed.Load() != 1 {
				t.Fatal("failed admission leaked lease")
			}
		})
	}
}

func TestFileMutationAllowsAuthorizedTemporaryFileMaintenance(t *testing.T) {
	root, _ := setupFileMutationSites(t)
	useFileMutationTestKernel(t)
	if _, err := database.GetDB().Exec(`UPDATE websites SET site_type='wordpress',maintenance_security=json_object('window',json_object('id','window','state','unlocked','expires',?)) WHERE id=1`, time.Now().Unix()+600); err != nil {
		t.Fatal(err)
	}
	lease, err := acquireFileMutation(context.Background(), fileMutationTarget{1, root})
	if err != nil {
		t.Fatal("temporary authorized file edits must retain their file-specific slot:", err)
	}
	_ = lease.Close()
}

func TestFileMutationBackgroundOwnsLeaseAfterRequestEnds(t *testing.T) {
	root, _ := setupFileMutationSites(t)
	closed := useFileMutationTestKernel(t)
	request, cancel := context.WithCancel(context.Background())
	lease, err := acquireFileMutation(request, fileMutationTarget{1, root})
	if err != nil {
		t.Fatal(err)
	}
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	startFileMutationWorker(lease, func() { close(started); <-finish })
	<-started
	cancel()
	if !executor.SiteOpLocked(1) || closed.Load() != 0 {
		t.Fatal("request completion released a running import")
	}
	ctx, stop := context.WithCancel(context.Background())
	stop()
	if _, err := acquireFileMutation(ctx, fileMutationTarget{1, root}); err == nil {
		t.Fatal("backup/kernel writer could enter a running import")
	}
	go func() {
		close(finish)
		for executor.SiteOpLocked(1) || closed.Load() == 0 {
			time.Sleep(time.Millisecond)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("finished background worker did not release")
	}
	if closed.Load() != 1 {
		t.Fatal("kernel lease not released")
	}
	second, err := acquireFileMutation(context.Background(), fileMutationTarget{1, root})
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
}

func TestFileMutationLiveWriteHandlersRefuseFrozenSite(t *testing.T) {
	for _, name := range []string{"upload", "upload_complete", "remote_import", "delete", "rename", "batch_zip", "zip", "unzip", "move", "copy", "mkdir", "permissions"} {
		t.Run(name, func(t *testing.T) {
			root, _ := setupFileMutationSites(t)
			closed := useFileMutationTestKernel(t)
			oldConfig := config.AppConfig
			config.AppConfig = &config.Config{Panel: config.PanelConfig{DataDir: t.TempDir(), BackupDir: t.TempDir()}}
			t.Cleanup(func() { config.AppConfig = oldConfig })
			marker := filepath.Join(root, "keep.txt")
			if err := os.WriteFile(marker, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			z, err := os.Create(filepath.Join(root, "fixture.zip"))
			if err != nil {
				t.Fatal(err)
			}
			zw := zip.NewWriter(z)
			w, err := zw.Create("new.txt")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte("new"))
			_ = zw.Close()
			_ = z.Close()
			if _, err := database.GetDB().Exec(`UPDATE websites SET status='backup_maintenance' WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			h := &FileHandler{}
			method, route, body, fn := http.MethodPost, "/write?site_id=1&path=/", ``, h.CreateDir
			contentType := "application/json"
			remoteImportTasks.Lock()
			previousImports := len(remoteImportTasks.items)
			remoteImportTasks.Unlock()
			switch name {
			case "upload":
				var b bytes.Buffer
				mw := multipart.NewWriter(&b)
				fw, err := mw.CreateFormFile("file", "new.txt")
				if err != nil {
					t.Fatal(err)
				}
				_, _ = fw.Write([]byte("new"))
				_ = mw.Close()
				body = b.String()
				contentType = mw.FormDataContentType()
				fn = h.Upload
			case "upload_complete":
				s := uploadSession{Filename: "new.txt", SiteID: 1, Path: "/", TotalChunks: 1, CreatedAt: time.Now().Unix()}
				dir := uploadSessionDir("test-frozen")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := saveUploadSession(dir, s); err != nil {
					t.Fatal(err)
				}
				body = `{"upload_id":"test-frozen","site_id":1,"path":"/"}`
				fn = h.UploadComplete
			case "remote_import":
				// Literal documentation IP is parsed locally; the frozen gate
				// must reject before a task, DNS lookup or HTTP download starts.
				body = `{"site_id":1,"path":"/","url":"https://192.0.2.123/new.txt"}`
				fn = h.RemoteImport
			case "delete":
				method = http.MethodDelete
				route = "/write?site_id=1&path=/keep.txt"
				fn = h.Delete
			case "rename":
				method = http.MethodPut
				body = `{"site_id":1,"old_path":"/keep.txt","new_name":"moved.txt"}`
				fn = h.Rename
			case "batch_zip":
				body = `{"site_id":1,"path":"/","names":["keep.txt"],"archive_name":"new.zip"}`
				fn = h.BatchCompress
			case "zip":
				route = "/write?site_id=1&path=/keep.txt"
				fn = h.Compress
			case "unzip":
				route = "/write?site_id=1&path=/fixture.zip"
				fn = h.Decompress
			case "move", "copy":
				body = `{"site_id":1,"src_path":"/","dest_path":"/nested","names":["keep.txt"]}`
				if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
					t.Fatal(err)
				}
				fn = h.Copy
				if name == "move" {
					fn = h.Move
				}
			case "mkdir":
				body = `{"name":"new-dir"}`
			case "permissions":
				fn = h.FixPermissions
			}
			r := gin.New()
			r.Handle(method, "/write", fn)
			request := httptest.NewRequest(method, route, strings.NewReader(body))
			request.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, request)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if closed.Load() != 1 || executor.SiteOpLocked(1) {
				t.Fatal("failed handler leaked lease")
			}
			remoteImportTasks.Lock()
			imports := len(remoteImportTasks.items)
			remoteImportTasks.Unlock()
			if imports != previousImports {
				t.Fatal("frozen remote import launched a background task")
			}
			if data, err := os.ReadFile(marker); err != nil || string(data) != "original" {
				t.Fatal("frozen original changed")
			}
			for _, dest := range []string{"new.txt", "moved.txt", "new.zip", "keep.txt.zip", "new-dir", "nested/keep.txt"} {
				if _, err := os.Stat(filepath.Join(root, dest)); !os.IsNotExist(err) {
					t.Fatalf("frozen write created %s: %v", dest, err)
				}
			}
		})
	}
}

func TestFileMutationActiveSiteWritesCompleteAndRelease(t *testing.T) {
	root, _ := setupFileMutationSites(t)
	closed := useFileMutationTestKernel(t)
	if err := os.WriteFile(filepath.Join(root, "old.txt"), []byte("preserved bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	h := &FileHandler{}
	for _, tc := range []struct {
		method, url, body string
		handler           gin.HandlerFunc
	}{
		{http.MethodPost, "/write?site_id=1", `{"name":"new-dir"}`, h.CreateDir},
		{http.MethodPut, "/write", `{"site_id":1,"old_path":"/old.txt","new_name":"renamed.txt"}`, h.Rename},
		{http.MethodPost, "/write?site_id=1&path=/renamed.txt", "", h.Compress},
		{http.MethodPost, "/write?site_id=1&path=/renamed.txt.zip&overwrite=1", "", h.Decompress},
		{http.MethodDelete, "/write?site_id=1&path=/new-dir", "", h.Delete},
	} {
		r := gin.New()
		r.Handle(tc.method, "/write", tc.handler)
		req := httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: status=%d body=%s", tc.method, tc.url, rec.Code, rec.Body.String())
		}
		if executor.SiteOpLocked(1) {
			t.Fatal("successful writer retained its site slot")
		}
	}
	if closed.Load() != 5 {
		t.Fatalf("kernel closes=%d", closed.Load())
	}
	if data, err := os.ReadFile(filepath.Join(root, "renamed.txt")); err != nil || string(data) != "preserved bytes" {
		t.Fatalf("normal write chain lost original: %q %v", data, err)
	}
}

func TestFileMutationTransferCannotCrossFrozenDestination(t *testing.T) {
	for _, move := range []bool{false, true} {
		t.Run(map[bool]string{false: "copy", true: "move"}[move], func(t *testing.T) {
			root, other := setupFileMutationSites(t)
			useFileMutationTestKernel(t)
			if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := database.GetDB().Exec(`UPDATE websites SET status='backup_maintenance' WHERE id=2`); err != nil {
				t.Fatal(err)
			}
			h := &FileHandler{}
			fn := h.Copy
			if move {
				fn = h.Move
			}
			r := gin.New()
			r.POST("/write", fn)
			request := httptest.NewRequest(http.MethodPost, "/write", strings.NewReader(`{"site_id":1,"dest_site_id":2,"src_path":"/","dest_path":"/","names":["keep.txt"]}`))
			request.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, request)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if data, err := os.ReadFile(filepath.Join(root, "keep.txt")); err != nil || string(data) != "original" {
				t.Fatal("source lost")
			}
			if _, err := os.Stat(filepath.Join(other, "keep.txt")); !os.IsNotExist(err) {
				t.Fatal("frozen destination changed")
			}
		})
	}
}

func TestFileMutationKernelFailureNeverTouchesLiveTree(t *testing.T) {
	root, _ := setupFileMutationSites(t)
	old := acquireFileMutationKernel
	acquireFileMutationKernel = func(context.Context) (io.Closer, error) { return nil, errors.New("fixture kernel unavailable") }
	t.Cleanup(func() { acquireFileMutationKernel = old })
	r := gin.New()
	r.POST("/write", (&FileHandler{}).CreateDir)
	request := httptest.NewRequest(http.MethodPost, "/write?site_id=1", strings.NewReader(`{"name":"never"}`))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, request)
	if rec.Code != http.StatusConflict || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, "never")); !os.IsNotExist(err) {
		t.Fatal("mutation ran without kernel lease")
	}
}
