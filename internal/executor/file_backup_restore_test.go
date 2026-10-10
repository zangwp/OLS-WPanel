package executor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

type fullRestoreTarEntry struct {
	header tar.Header
	body   string
}

func fullRestoreTar(t *testing.T, entries []fullRestoreTarEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		hdr := entry.header
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			hdr.Size = int64(len(entry.body))
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func validFullRestoreTar(t *testing.T) []byte {
	entries := []fullRestoreTarEntry{}
	for _, name := range []string{"site/", "site/wp-admin/", "site/wp-includes/", "site/wp-content/", "site/wp-content/plugins/ols-wpanel-optimizer/", "site/wp-content/mu-plugins/"} {
		entries = append(entries, fullRestoreTarEntry{header: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 07777}})
	}
	for _, item := range []struct{ name, content string }{
		{"index.php", "restored-index"}, {"wp-load.php", "restored-load"}, {"wp-settings.php", "restored-settings"}, {"wp-config.php", "OLD database password and old domain"}, {"wp-includes/version.php", "restored-version"},
		{"wp-content/plugins/ols-wpanel-optimizer/old.php", "obsolete panel code"},
		{"wp-content/mu-plugins/ols-wpanel-access.php", "obsolete auth identity"},
		{"wp-content/mu-plugins/ols-wpanel-obsolete.php", "obsolete helper"},
		{"wp-content/mu-plugins/customer.php", "restored customer helper"}, {".maintenance", "stale maintenance"},
		{".lscache/old.page", "obsolete page cache"}, {"wp-content/litespeed/old.css", "obsolete generated CSS"},
	} {
		entries = append(entries, fullRestoreTarEntry{header: tar.Header{Name: "site/" + item.name, Typeflag: tar.TypeReg, Mode: 06777, Uid: 123, Gid: 456}, body: item.content})
	}
	return fullRestoreTar(t, entries)
}

func TestFullFileRestoreRejectsUnsafeArchiveBeforeAnyExchange(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []fullRestoreTarEntry
	}{
		{"parent traversal", []fullRestoreTarEntry{{header: tar.Header{Name: "site/../escape", Typeflag: tar.TypeReg}, body: "x"}}},
		{"absolute path", []fullRestoreTarEntry{{header: tar.Header{Name: "/site/escape", Typeflag: tar.TypeReg}, body: "x"}}},
		{"windows path", []fullRestoreTarEntry{{header: tar.Header{Name: "site/C:\\escape", Typeflag: tar.TypeReg}, body: "x"}}},
		{"another site", []fullRestoreTarEntry{{header: tar.Header{Name: "another/index.php", Typeflag: tar.TypeReg}, body: "x"}}},
		{"symlink", []fullRestoreTarEntry{{header: tar.Header{Name: "site/link", Typeflag: tar.TypeSymlink, Linkname: "../../secret"}}}},
		{"hardlink", []fullRestoreTarEntry{{header: tar.Header{Name: "site/link", Typeflag: tar.TypeLink, Linkname: "site/wp-config.php"}}}},
		{"device", []fullRestoreTarEntry{{header: tar.Header{Name: "site/device", Typeflag: tar.TypeChar}}}},
		{"fifo", []fullRestoreTarEntry{{header: tar.Header{Name: "site/fifo", Typeflag: tar.TypeFifo}}}},
		{"duplicate", []fullRestoreTarEntry{{header: tar.Header{Name: "site/one", Typeflag: tar.TypeReg}, body: "1"}, {header: tar.Header{Name: "site/one", Typeflag: tar.TypeReg}, body: "2"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			site := fullRestoreLiveFixture(t, false)
			ops, exchanges := fullRestoreTestOps(t)
			if _, err := restoreFullFileArchive(context.Background(), site, 1, "test", bytes.NewReader(fullRestoreTar(t, tc.entries)), ops); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if *exchanges != 0 {
				t.Fatal("unsafe archive reached exchange")
			}
			assertFullRestoreFile(t, filepath.Join(site.WebRoot, "index.php"), "current-index")
		})
	}
}

func TestFullFileRestoreRejectsOversizeChecksumAndTruncation(t *testing.T) {
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "site/huge", Typeflag: tar.TypeReg, Size: fileRestoreMaxBytes + 1}); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close() // Deliberately incomplete huge body: header must be rejected first.
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	valid := validFullRestoreTar(t)
	corrupt := append([]byte(nil), valid...)
	corrupt[len(corrupt)-8] ^= 1
	for name, data := range map[string][]byte{"size": buffer.Bytes(), "gzip checksum": corrupt, "truncation": valid[:len(valid)/2]} {
		t.Run(name, func(t *testing.T) {
			site := fullRestoreLiveFixture(t, false)
			ops, exchanges := fullRestoreTestOps(t)
			if _, err := restoreFullFileArchive(context.Background(), site, 1, "test", bytes.NewReader(data), ops); err == nil {
				t.Fatal("invalid archive accepted")
			}
			if *exchanges != 0 {
				t.Fatal("invalid archive reached exchange")
			}
		})
	}
}

func TestFullFileRestorePreservesCurrentConfigManagedCodeAndSafety(t *testing.T) {
	site := fullRestoreLiveFixture(t, true)
	ops, exchanges := fullRestoreTestOps(t)
	safety, err := restoreFullFileArchive(context.Background(), site, 11, "task", bytes.NewReader(validFullRestoreTar(t)), ops)
	if err != nil {
		t.Fatal(err)
	}
	if *exchanges != 1 {
		t.Fatalf("exchanges=%d", *exchanges)
	}
	assertFullRestoreFile(t, filepath.Join(site.WebRoot, "index.php"), "restored-index")
	assertFullRestoreFile(t, filepath.Join(site.WebRoot, "wp-config.php"), "CURRENT config database credentials and security policy")
	assertFullRestoreFile(t, filepath.Join(site.WebRoot, "wp-content/plugins/ols-wpanel-optimizer/current.php"), "current companion identity")
	assertFullRestoreFile(t, filepath.Join(site.WebRoot, "wp-content/mu-plugins/ols-wpanel-access.php"), "current auth identity")
	assertFullRestoreFile(t, filepath.Join(site.WebRoot, "wp-content/mu-plugins/customer.php"), "restored customer helper")
	for _, name := range []string{".maintenance", ".lscache", "wp-content/litespeed", "wp-content/plugins/ols-wpanel-optimizer/old.php", "wp-content/mu-plugins/ols-wpanel-obsolete.php"} {
		if _, err := os.Lstat(filepath.Join(site.WebRoot, name)); !os.IsNotExist(err) {
			t.Fatalf("obsolete %s retained: %v", name, err)
		}
	}
	assertFullRestoreFile(t, filepath.Join(safety, "index.php"), "current-index")
	journal, err := os.ReadFile(filepath.Join(filepath.Dir(safety), "journal.json"))
	if err != nil || !bytes.Contains(journal, []byte(`"state":"committed"`)) || !bytes.Contains(journal, []byte(`"database_restored":false`)) {
		t.Fatalf("journal=%s err=%v", journal, err)
	}
	if bytes.Contains(journal, []byte("credentials")) {
		t.Fatal("journal leaked config")
	}
	if info, err := os.Stat(filepath.Join(site.WebRoot, "index.php")); err != nil || info.Mode()&os.ModeSetuid != 0 {
		t.Fatal("tar permissions trusted")
	}
}

func TestFullFileRestoreDoesNotResurrectAbsentManagedPlugins(t *testing.T) {
	site := fullRestoreLiveFixture(t, false)
	ops, _ := fullRestoreTestOps(t)
	if _, err := restoreFullFileArchive(context.Background(), site, 1, "task", bytes.NewReader(validFullRestoreTar(t)), ops); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wp-content/plugins/ols-wpanel-optimizer", "wp-content/mu-plugins/ols-wpanel-access.php", "wp-content/mu-plugins/ols-wpanel-obsolete.php"} {
		if _, err := os.Lstat(filepath.Join(site.WebRoot, name)); !os.IsNotExist(err) {
			t.Fatalf("absent managed code resurrected: %s", name)
		}
	}
}

func TestFullFileRestorePreparationAndConflictFailuresKeepLiveTree(t *testing.T) {
	for _, stage := range []string{"permissions apply", "permissions verify", "persistent revalidation", "atomic exchange"} {
		t.Run(stage, func(t *testing.T) {
			site := fullRestoreLiveFixture(t, false)
			ops, exchanges := fullRestoreTestOps(t)
			failure := func(*models.Website) error { return errors.New("fixture failed") }
			switch stage {
			case "permissions apply":
				ops.prepare = failure
			case "permissions verify":
				ops.verify = failure
			case "persistent revalidation":
				ops.revalidate = func(context.Context) error { return errors.New("durable operation started") }
			case "atomic exchange":
				ops.exchange = func(string, string) error { return errors.New("RENAME_EXCHANGE unsupported") }
			}
			if _, err := restoreFullFileArchive(context.Background(), site, 1, "task", bytes.NewReader(validFullRestoreTar(t)), ops); err == nil {
				t.Fatal("failure accepted")
			}
			if *exchanges != 0 {
				t.Fatal("preparation failure changed live files")
			}
			assertFullRestoreFile(t, filepath.Join(site.WebRoot, "index.php"), "current-index")
		})
	}
}

func TestFullFileRestorePostExchangeFailuresRollbackAndRetainEvidence(t *testing.T) {
	for _, stage := range []string{"live permission check", "directory sync", "panic"} {
		t.Run(stage, func(t *testing.T) {
			site := fullRestoreLiveFixture(t, false)
			ops, exchanges := fullRestoreTestOps(t)
			if stage == "directory sync" {
				ops.syncDir = func(name string) error {
					if *exchanges == 1 && name == filepath.Dir(site.WebRoot) {
						return errors.New("sync failed")
					}
					return nil
				}
			} else {
				ops.verify = func(s *models.Website) error {
					if s.WebRoot == site.WebRoot {
						if stage == "panic" {
							panic("permission panic")
						}
						return errors.New("policy failed")
					}
					return nil
				}
			}
			_, err := restoreFullFileArchive(context.Background(), site, 1, "task", bytes.NewReader(validFullRestoreTar(t)), ops)
			if err == nil || !strings.Contains(err.Error(), "自动回滚") {
				t.Fatalf("err=%v", err)
			}
			if *exchanges != 2 {
				t.Fatalf("exchanges=%d", *exchanges)
			}
			assertFullRestoreFile(t, filepath.Join(site.WebRoot, "index.php"), "current-index")
			dirs, _ := filepath.Glob(filepath.Join(filepath.Dir(site.WebRoot), ".ols-wpanel-file-restore-*"))
			if len(dirs) != 1 {
				t.Fatalf("recovery directories=%v", dirs)
			}
			assertFullRestoreFile(t, filepath.Join(dirs[0], "before/index.php"), "restored-index")
		})
	}
}

func TestFullFileRestoreFailedRollbackNeverDeletesOnlyOriginalCopy(t *testing.T) {
	site := fullRestoreLiveFixture(t, false)
	ops, exchanges := fullRestoreTestOps(t)
	baseExchange := ops.exchange
	ops.exchange = func(live, staged string) error {
		if *exchanges == 1 {
			return errors.New("rollback unavailable")
		}
		return baseExchange(live, staged)
	}
	ops.verify = func(s *models.Website) error {
		if s.WebRoot == site.WebRoot {
			return errors.New("verify failed")
		}
		return nil
	}
	safety, err := restoreFullFileArchive(context.Background(), site, 1, "task", bytes.NewReader(validFullRestoreTar(t)), ops)
	if err == nil || !strings.Contains(err.Error(), "回滚失败") {
		t.Fatalf("err=%v", err)
	}
	var unresolved *fileRestoreUnresolvedError
	if !errors.As(err, &unresolved) || unresolved.safetyPath != safety {
		t.Fatalf("missing structured rollback outcome: %v", err)
	}
	assertFullRestoreFile(t, filepath.Join(safety, "index.php"), "current-index")
	assertFullRestoreFile(t, filepath.Join(site.WebRoot, "index.php"), "restored-index")
	journal, _ := os.ReadFile(filepath.Join(filepath.Dir(safety), "journal.json"))
	if !bytes.Contains(journal, []byte(`"state":"rollback_failed"`)) {
		t.Fatalf("journal=%s", journal)
	}
}

func TestFullFileRestoreUnresolvedLockedTreeClearsReadyStateAndEvidence(t *testing.T) {
	db := newFullRestoreSQLFixture(t)
	if _, err := db.Exec(`INSERT INTO websites(id,domain,web_root,system_user,site_type,status,file_lock_enabled,file_lock_mode,file_lock_apply_status,document_root_subdir) VALUES(1,'site.example','/www/site','wp_site','wordpress','active',1,'strict','ready','')`); err != nil {
		t.Fatal(err)
	}
	site := fullRestorePolicyFixture()
	site.FileLockEnabled = true
	websiteSecurityVerificationCache.Lock()
	oldEntries := websiteSecurityVerificationCache.entries
	websiteSecurityVerificationCache.entries = map[string]websiteSecurityCachedVerification{
		"1:file_editing": {}, "1:wp_updates": {}, "2:file_editing": {},
	}
	websiteSecurityVerificationCache.Unlock()
	t.Cleanup(func() {
		websiteSecurityVerificationCache.Lock()
		websiteSecurityVerificationCache.entries = oldEntries
		websiteSecurityVerificationCache.Unlock()
	})
	removed := false
	if err := markFileRestoreUnresolved(context.Background(), db, site, func(id int) error {
		if id != 1 {
			t.Fatal("wrong baseline")
		}
		removed = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := db.QueryRow(`SELECT file_lock_apply_status FROM websites WHERE id=1`).Scan(&status); err != nil || status != "failed" || !removed {
		t.Fatalf("status=%s removed=%v err=%v", status, removed, err)
	}
	websiteSecurityVerificationCache.Lock()
	defer websiteSecurityVerificationCache.Unlock()
	if len(websiteSecurityVerificationCache.entries) != 1 {
		t.Fatal("old restored-site runtime evidence retained")
	}
	if _, ok := websiteSecurityVerificationCache.entries["2:file_editing"]; !ok {
		t.Fatal("unrelated site evidence removed")
	}
}

func TestFullFileRestoreCancellationAndMalformedWordPressNeverSwap(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		site := fullRestoreLiveFixture(t, false)
		ops, exchanges := fullRestoreTestOps(t)
		ctx, cancel := context.WithCancel(context.Background())
		data := fullRestoreTar(t, []fullRestoreTarEntry{{header: tar.Header{Name: "site/not-wordpress.txt", Typeflag: tar.TypeReg}, body: "x"}})
		if cancelled {
			cancel()
			data = validFullRestoreTar(t)
		}
		_, err := restoreFullFileArchive(ctx, site, 1, "task", bytes.NewReader(data), ops)
		cancel()
		if err == nil || *exchanges != 0 {
			t.Fatal("cancelled or non WordPress restore accepted")
		}
	}
}

func TestFullFileRestoreRecordRequiresExactSiteAndFullMode(t *testing.T) {
	db := newFullRestoreSQLFixture(t)
	for _, query := range []string{
		`INSERT INTO file_backups VALUES(1,1,'file_full_ok.tar.gz',100,'full')`,
		`INSERT INTO file_backups VALUES(2,1,'file_inc_old.tar.gz',100,'inc')`,
		`INSERT INTO file_backups VALUES(3,1,'../file_full_unsafe.tar.gz',100,'full')`,
		`INSERT INTO file_backups VALUES(4,1,'file_full_empty.tar.gz',0,'full')`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if name, size, err := loadFullFileRestoreRecord(context.Background(), db, 1, 1); err != nil || name != "file_full_ok.tar.gz" || size != 100 {
		t.Fatalf("name=%s,size=%d,err=%v", name, size, err)
	}
	for _, pair := range [][2]int{{2, 1}, {1, 2}, {1, 3}, {1, 4}, {1, 99}} {
		if _, _, err := loadFullFileRestoreRecord(context.Background(), db, pair[0], pair[1]); err == nil {
			t.Fatalf("invalid pair accepted: %v", pair)
		}
	}
}

func TestFullFileRestorePersistentGuardsFailClosed(t *testing.T) {
	old := websiteSecurityMaintenanceState
	websiteSecurityMaintenanceState = func(context.Context, int) (string, error) { return "locked", nil }
	t.Cleanup(func() { websiteSecurityMaintenanceState = old })
	for _, tc := range []struct{ name, query string }{
		{"update preparing", `INSERT INTO wp_update_tasks VALUES(1,'preparing',0,'')`},
		{"update queued", `INSERT INTO wp_update_tasks VALUES(1,'queued',0,'')`},
		{"update running", `INSERT INTO wp_update_tasks VALUES(1,'running',0,'')`},
		{"update attention", `INSERT INTO wp_update_tasks VALUES(1,'failed',1,'')`},
		{"migration", `INSERT INTO site_migration_locks VALUES(1,'site.example','active')`},
		{"domain migration", `INSERT INTO site_migration_locks VALUES(0,'site.example','active')`},
		{"AI access", `INSERT INTO website_ai_development_access VALUES(1)`},
		{"image optimization", `INSERT INTO site_image_optimization_jobs VALUES(1,'running')`},
		{"SQL unknown", `DROP TABLE wp_update_tasks`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newFullRestoreSQLFixture(t)
			if _, err := db.Exec(tc.query); err != nil {
				t.Fatal(err)
			}
			if err := checkFileRestoreSite(context.Background(), db, fullRestorePolicyFixture()); err == nil {
				t.Fatal("busy/unknown durable state accepted")
			}
		})
	}
	db := newFullRestoreSQLFixture(t)
	if err := checkFileRestoreSite(context.Background(), db, fullRestorePolicyFixture()); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"unlocked", "relocking", "relock_failed", "unknown"} {
		websiteSecurityMaintenanceState = func(context.Context, int) (string, error) { return state, nil }
		if err := checkFileRestoreSite(context.Background(), db, fullRestorePolicyFixture()); err == nil {
			t.Fatalf("maintenance %s accepted", state)
		}
	}
}

func TestFullFileRestorePolicyGuardsAndCurrentSiteReload(t *testing.T) {
	db := newFullRestoreSQLFixture(t)
	old := websiteSecurityMaintenanceState
	websiteSecurityMaintenanceState = func(context.Context, int) (string, error) { return "locked", nil }
	t.Cleanup(func() { websiteSecurityMaintenanceState = old })
	for _, change := range []func(*models.Website){
		func(s *models.Website) { s.Status = "deleting" }, func(s *models.Website) { s.SiteType = "static" },
		func(s *models.Website) { s.DocumentRootSubdir = "public" }, func(s *models.Website) { s.FileLockApplyStatus = FileLockApplyStatusApplying },
		func(s *models.Website) { s.FileLockApplyStatus = FileLockApplyStatusFailed }, func(s *models.Website) {
			s.FileLockEnabled = true
			s.FileLockApplyStatus = FileLockApplyStatusReady
			s.FileLockMode = FileLockModeLegacy
		},
	} {
		s := fullRestorePolicyFixture()
		change(s)
		if err := checkFileRestoreSite(context.Background(), db, s); err == nil {
			t.Fatalf("policy accepted: %+v", s)
		}
	}
	if _, err := db.Exec(`INSERT INTO websites(id,domain,web_root,system_user,site_type,status,file_lock_enabled,file_lock_mode,file_lock_apply_status,document_root_subdir) VALUES(1,'site.example','/www/site','wp_site','wordpress','active',1,'strict','ready','')`); err != nil {
		t.Fatal(err)
	}
	s, err := loadFileRestoreSite(context.Background(), db, 1)
	if err != nil || s.Domain != "site.example" || s.FileLockMode != "strict" || !s.FileLockEnabled {
		t.Fatalf("site=%+v err=%v", s, err)
	}
}

func TestFullFileRestoreLocalArchiveSizeAndType(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file_full_test.tar.gz")
	if err := os.WriteFile(file, []byte("archive"), 0600); err != nil {
		t.Fatal(err)
	}
	opened, err := openFileRestoreArchive(file, 7)
	if err != nil {
		t.Fatal(err)
	}
	opened.Close()
	for _, size := range []int64{0, 6, 8} {
		if f, err := openFileRestoreArchive(file, size); err == nil {
			f.Close()
			t.Fatal("wrong size accepted")
		}
	}
	if f, err := openFileRestoreArchive(filepath.Dir(file), 7); err == nil {
		f.Close()
		t.Fatal("directory accepted")
	}
	if f, err := openFileRestoreArchive(file+"missing", 7); err == nil {
		f.Close()
		t.Fatal("remote-only accepted")
	}
}

func TestFullFileRestoreSpaceReserveDeclarationAndResampling(t *testing.T) {
	for _, scenario := range []string{"unknown available space", "initial low space", "declared body exceeds budget", "periodic space loss", "final space loss"} {
		t.Run(scenario, func(t *testing.T) {
			site := fullRestoreLiveFixture(t, false)
			ops, exchanges := fullRestoreTestOps(t)
			data := validFullRestoreTar(t)
			calls := 0
			switch scenario {
			case "unknown available space":
				ops.freeBytes = func(string) (int64, error) { return 0, errors.New("Statfs unavailable") }
			case "initial low space":
				ops.freeBytes = func(string) (int64, error) { return fileRestoreFreeReserve - 1, nil }
			case "declared body exceeds budget":
				ops.freeBytes = func(string) (int64, error) {
					return fileRestoreFreeReserve + fileRestoreManagedMaxBytes + (1 << 20) + 1, nil
				}
			case "periodic space loss":
				entries := []fullRestoreTarEntry{}
				for n := 0; n < 40; n++ {
					entries = append(entries, fullRestoreTarEntry{header: tar.Header{Name: fmt.Sprintf("site/d%d/", n), Typeflag: tar.TypeDir}})
				}
				data = fullRestoreTar(t, entries)
				ops.freeBytes = func(string) (int64, error) {
					calls++
					if calls > 1 {
						return 0, nil
					}
					return fileRestoreMaxBytes + fileRestoreFreeReserve, nil
				}
			case "final space loss":
				ops.freeBytes = func(string) (int64, error) {
					calls++
					if calls > 1 {
						return fileRestoreFreeReserve - 1, nil
					}
					return fileRestoreMaxBytes + fileRestoreFreeReserve, nil
				}
			}
			_, err := restoreFullFileArchive(context.Background(), site, 1, "task", bytes.NewReader(data), ops)
			if err == nil || !strings.Contains(err.Error(), "空间") {
				t.Fatalf("err=%v", err)
			}
			if *exchanges != 0 {
				t.Fatal("insufficient space changed live directory")
			}
			assertFullRestoreFile(t, filepath.Join(site.WebRoot, "index.php"), "current-index")
		})
	}
}

func newFullRestoreSQLFixture(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "restore.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, query := range []string{
		`CREATE TABLE websites(id INTEGER,domain TEXT,web_root TEXT,system_user TEXT,site_type TEXT,status TEXT,file_lock_enabled INTEGER,file_lock_mode TEXT,file_lock_apply_status TEXT,document_root_subdir TEXT,updated_at TEXT DEFAULT '')`,
		`CREATE TABLE file_backups(id INTEGER,site_id INTEGER,filename TEXT,file_size INTEGER,mode TEXT)`,
		`CREATE TABLE wp_update_tasks(site_id INTEGER,status TEXT,requires_attention INTEGER,manual_disposition TEXT)`,
		`CREATE TABLE site_migration_locks(site_id INTEGER,domain TEXT,status TEXT)`,
		`CREATE TABLE website_ai_development_access(site_id INTEGER)`,
		`CREATE TABLE site_image_optimization_jobs(site_id INTEGER,status TEXT)`,
	} {
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func fullRestorePolicyFixture() *models.Website {
	return &models.Website{ID: 1, Domain: "site.example", SystemUser: "wp_site", SiteType: "wordpress", Status: "active"}
}

func fullRestoreLiveFixture(t *testing.T, managed bool) *models.Website {
	t.Helper()
	site := fullRestorePolicyFixture()
	site.WebRoot = filepath.Join(t.TempDir(), "site")
	if err := os.Mkdir(site.WebRoot, 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"index.php": "current-index", "wp-config.php": "CURRENT config database credentials and security policy"}
	if managed {
		files["wp-content/plugins/ols-wpanel-optimizer/current.php"] = "current companion identity"
		files["wp-content/mu-plugins/ols-wpanel-access.php"] = "current auth identity"
	}
	for name, body := range files {
		file := filepath.Join(site.WebRoot, name)
		if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return site
}

// Native Windows fixtures substitute only the Linux atomic exchange and Unix
// UID/GID policy boundaries. Archive, current-content copy, persistent guards,
// journal, failure handling and rollback are the actual production functions.
func fullRestoreTestOps(t *testing.T) (fileRestoreOps, *int) {
	t.Helper()
	exchanges := new(int)
	return fileRestoreOps{
		prepare: func(*models.Website) error { return nil }, verify: func(*models.Website) error { return nil },
		syncDir: func(string) error { return nil }, revalidate: func(context.Context) error { return nil },
		syncFile:      func(*os.File) error { return nil },
		verifyPrivate: func(string) error { return nil },
		freeBytes:     func(string) (int64, error) { return fileRestoreMaxBytes + fileRestoreFreeReserve, nil },
		exchange: func(live, staged string) error {
			// Native Windows os.Root directory handles may prohibit renames.
			// Simulate the syscall's complete-tree outcome using fixture contents;
			// the Linux-only test independently calls the real atomic exchange.
			old := fullRestoreTreeFixtureSnapshot(t, live)
			incoming := fullRestoreTreeFixtureSnapshot(t, staged)
			fullRestoreTreeFixtureReplace(t, live, incoming)
			fullRestoreTreeFixtureReplace(t, staged, old)
			*exchanges++
			return nil
		},
	}, exchanges
}

func fullRestoreTreeFixtureSnapshot(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(name)
		result[rel] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func fullRestoreTreeFixtureReplace(t *testing.T, root string, files map[string][]byte) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		target := filepath.Join(root, entry.Name())
		rel, err := filepath.Rel(root, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			t.Fatal("fixture cleanup escaped root")
		}
		if err := os.RemoveAll(target); err != nil {
			t.Fatal(err)
		}
	}
	for rel, data := range files {
		target := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func assertFullRestoreFile(t *testing.T, name, want string) {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil || string(data) != want {
		t.Fatalf("%s=%q err=%v want=%q", name, data, err, want)
	}
}
