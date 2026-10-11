package executor

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

func TestSiteBackupRecoveryPhasesAreOperationSpecific(t *testing.T) {
	for _, tc := range []struct {
		operation, phase string
		safe             bool
	}{
		{"create", "backup_verified", true}, {"create", "building_artifacts", true},
		{"restore", "safety_verified", true}, {"restore", "rolled_back", true}, {"restore", "restore_committed", true},
		{"restore", "files_swap_intent", false}, {"restore", "files_restored", false}, {"restore", "database_restore_intent", false}, {"restore", "rollback_failed", false},
		{"create", "restore_committed", false}, {"create", "rolled_back", false}, {"restore", "backup_verified", false}, {"unknown", "frozen", false},
	} {
		if got := safeSiteBackupRecoveryPhase(tc.operation, tc.phase); got != tc.safe {
			t.Fatalf("%s/%s safe=%v", tc.operation, tc.phase, got)
		}
	}
}

func TestSiteBackupDurableMaintenanceBlocksOrdinaryAndBackgroundWriters(t *testing.T) {
	f, _, _ := siteBackupPairedFixture(t)
	for name, acquire := range map[string]func() bool{
		"ordinary":    func() bool { return TryAcquireSiteOpLock(f.site.ID, "ssl_renewal") },
		"companion":   func() bool { return TryAcquireCompanionDeployLock(f.site.ID) },
		"file":        func() bool { return TryAcquireSiteFileOpLock(f.site.ID, "upload") },
		"maintenance": func() bool { return tryAcquireMaintenanceOp(f.site.ID) },
	} {
		if acquire() {
			ReleaseSiteOpLock(f.site.ID)
			t.Fatalf("%s bypassed durable freeze", name)
		}
	}
	if !tryAcquireSiteBackupRecoveryOp(f.site.ID) {
		t.Fatal("special journal recovery cannot acquire")
	}
	ReleaseSiteOpLock(f.site.ID)
	if _, err := database.DB.Exec("UPDATE websites SET status='active' WHERE id=?", f.site.ID); err != nil {
		t.Fatal(err)
	}
	if tryAcquireSiteBackupRecoveryOp(f.site.ID) {
		ReleaseSiteOpLock(f.site.ID)
		t.Fatal("recovery admitted normal active site")
	}
	if !TryAcquireCompanionDeployLock(f.site.ID) {
		t.Fatal("normal active companion deployment blocked")
	}
	ReleaseSiteOpLock(f.site.ID)
	if _, err := database.DB.Exec("DROP TABLE websites"); err != nil {
		t.Fatal(err)
	}
	if TryAcquireSiteFileOpLock(f.site.ID, "upload") {
		ReleaseSiteOpLock(f.site.ID)
		t.Fatal("unknown durable status allowed writer")
	}
}

func TestSiteBackupDatabaseFreezeRejectsSharedAndUnsupportedObjects(t *testing.T) {
	old := siteBackupSQL
	defer func() { siteBackupSQL = old }()
	for _, tc := range []struct {
		name, account, count string
		fail                 bool
	}{
		{"dedicated local", "localhost\tfalse", "0", false}, {"locked", "localhost\ttrue", "0", true},
		{"multiple hosts", "localhost\tfalse\n%\tfalse", "0", true}, {"shared writer or database objects", "localhost\tfalse", "1", true},
		{"column-only writer", "localhost\tfalse", "1", true},
		{"unknown privilege result", "localhost\tfalse", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			siteBackupSQL = func(_ context.Context, _ string, q string) (string, error) {
				if strings.Contains(q, "mysql.global_priv") {
					return tc.account, nil
				}
				if !strings.Contains(q, "'mysql'@'localhost'") || !strings.Contains(q, "PRIVILEGE_TYPE IN") {
					t.Fatal("global read-only/admin permissions indiscriminately blocked")
				}
				if !strings.Contains(q, "information_schema.COLUMN_PRIVILEGES WHERE TABLE_SCHEMA='site_db'") {
					t.Fatal("column-level writer can bypass selected-database isolation")
				}
				return tc.count, nil
			}
			err := validateSiteBackupDatabase(context.Background(), &models.Website{DBName: "site_db", DBUser: "site_user"}, "test-not-secret")
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v fail=%v", err, tc.fail)
			}
		})
	}
}

func TestSiteBackupStaticMaintenanceHasAllRegisteredHostsAndNoLivePHP(t *testing.T) {
	root := filepath.Join(t.TempDir(), "maintenance")
	text, err := renderSiteBackupMaintenance(&models.Website{Domain: "example.com", Aliases: "www.example.com\nshop.example.com"}, root, "a31a9b36-2d77-4d82-8f55-b64fe66f4474")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"example.com,www.example.com,shop.example.com", "type NULL", "Cache-Control: no-store", "X-OLS-WPanel-Backup:", "[R=503,L]", "autoLoadHtaccess 0"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q", want)
		}
	}
	for _, bad := range []string{"scripthandler", "extprocessor", "module cache", "errorpage 503", "*.example.com"} {
		if strings.Contains(text, bad) {
			t.Fatalf("unsafe inherited setting %q", bad)
		}
	}
}

func TestSiteBackupArtifactFingerprintAndFixedNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "files.tar.gz")
	if err := os.WriteFile(path, []byte("valid payload"), 0600); err != nil {
		t.Fatal(err)
	}
	artifact, err := hashSiteBackupArtifact(context.Background(), path, "files.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if err = validSiteBackupArtifact(dir, artifact, "files.tar.gz", true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../secret", "/secret", "database.sql.gz"} {
		bad := artifact
		bad.Name = name
		if validSiteBackupArtifact(dir, bad, "files.tar.gz", false) == nil {
			t.Fatal("manifest path accepted")
		}
	}
	if err = os.WriteFile(path, []byte("bad!! payload"), 0600); err != nil {
		t.Fatal(err)
	}
	if validSiteBackupArtifact(dir, artifact, "files.tar.gz", true) == nil {
		t.Fatal("same-size tampering accepted")
	}
}

func TestSiteBackupMaintenanceOwnerNeverFallsBackToAnOlderJournal(t *testing.T) {
	base := t.TempDir()
	if err := verifySiteBackupParentDirectories(base); err != nil {
		t.Skip("requires root-owned private ancestor chain; native probe adapts Unix ownership boundary explicitly")
	}
	site := &models.Website{ID: 1, Domain: "example.com", WebRoot: filepath.Join(base, "site"), SystemUser: "wp_site", DBName: "site_db", DBUser: "site_user", TablePrefix: "wp_"}
	oldCfg := config.AppConfig
	config.AppConfig = &config.Config{Panel: config.PanelConfig{BackupDir: filepath.Join(base, "backups")}}
	defer func() { config.AppConfig = oldCfg }()
	root, err := siteBackupRoot(site)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	manifest := newSiteBackupManifest(site, "create")
	manifest.Marker = "a31a9b36-2d77-4d82-8f55-b64fe66f4474"
	manifest.OriginalVHost = "old-config"
	manifest.VHostPath = filepath.Join(base, "vhost.conf")
	manifest.Phase = "backup_verified"
	dir := filepath.Join(root, manifest.ID)
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = writeSiteBackupManifest(dir, manifest); err != nil {
		t.Fatal(err)
	}
	if err = writeSiteBackupMaintenanceOwner(site, manifest); err != nil {
		t.Fatal(err)
	}
	selected, selectedDir, err := readSiteBackupMaintenanceOwner(context.Background(), site)
	if err != nil || selected.ID != manifest.ID || selectedDir != dir {
		t.Fatalf("owner=%v dir=%s error=%v", selected, selectedDir, err)
	}
	latest := newSiteBackupManifest(site, "restore")
	latest.Marker = "873ce19d-5a87-4841-9cf1-a99a5c71148f"
	latest.OriginalVHost = "old-config"
	latest.VHostPath = manifest.VHostPath
	if err = writeSiteBackupMaintenanceOwner(site, latest); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readSiteBackupMaintenanceOwner(context.Background(), site); err == nil {
		t.Fatal("missing newest journal fell back to valid older backup")
	}
	operationDir := filepath.Join(filepath.Dir(root), "site-operations", latest.ID)
	if err = os.MkdirAll(operationDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(operationDir, "manifest.json"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readSiteBackupMaintenanceOwner(context.Background(), site); err == nil {
		t.Fatal("corrupt newest journal fell back")
	}
	if err = writeSiteBackupManifest(operationDir, latest); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readSiteBackupMaintenanceOwner(context.Background(), site); err != nil {
		t.Fatal(err)
	}
	latest.TablePrefix = "wrong_"
	if err = writeSiteBackupManifest(operationDir, latest); err != nil {
		t.Fatal(err)
	}
	if _, _, err = readSiteBackupMaintenanceOwner(context.Background(), site); err == nil {
		t.Fatal("new journal DB binding mismatch accepted")
	}
}

func TestSiteBackupArtifactPresenceIncludesUnknownAndRecoveryRecords(t *testing.T) {
	base := t.TempDir()
	if err := verifySiteBackupParentDirectories(base); err != nil {
		t.Skip("requires private root-owned storage")
	}
	site := &models.Website{ID: 1, Domain: "example.com"}
	oldCfg := config.AppConfig
	config.AppConfig = &config.Config{Panel: config.PanelConfig{BackupDir: filepath.Join(base, "backups")}}
	defer func() { config.AppConfig = oldCfg }()
	root, err := siteBackupRoot(site)
	if err != nil {
		t.Fatal(err)
	}
	if has, err := HasSiteBackupArtifacts(context.Background(), site); has || err != nil {
		t.Fatalf("missing storage has=%v error=%v", has, err)
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(root, "unknown-file")
	if err = os.WriteFile(unknown, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if has, err := HasSiteBackupArtifacts(context.Background(), site); !has || err != nil {
		t.Fatalf("unknown omitted has=%v error=%v", has, err)
	}
	if err = os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	operations := filepath.Join(filepath.Dir(root), "site-operations")
	if err = os.Mkdir(operations, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(operations, "recovery"), []byte("attention"), 0600); err != nil {
		t.Fatal(err)
	}
	if has, err := HasSiteBackupArtifacts(context.Background(), site); !has || err != nil {
		t.Fatalf("operation omitted has=%v error=%v", has, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = HasSiteBackupArtifacts(ctx, site); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

func TestSiteBackupDiskWriterResamplesAndRetainsFreeSpace(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "artifact")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	checks := 0
	writer := &siteBackupDiskWriter{ctx: context.Background(), file: file, free: func(string) (int64, error) {
		checks++
		if checks == 1 {
			return 4 << 30, nil
		}
		return fileRestoreFreeReserve, nil
	}}
	data := make([]byte, 1<<20)
	if _, err = writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write([]byte("next")); err == nil {
		t.Fatal("declining free space ignored")
	}
	if checks != 2 {
		t.Fatalf("space checks=%d", checks)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	writer.ctx = ctx
	if _, err = writer.Write(nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel=%v", err)
	}
}

type siteBackupFixtureReadLock struct{ closed bool }

func (l *siteBackupFixtureReadLock) Alive() error {
	if l.closed {
		return errors.New("READ lock closed")
	}
	return nil
}
func (l *siteBackupFixtureReadLock) Close() error { l.closed = true; return nil }

func siteBackupPairedFixture(t *testing.T) (*siteBackupFreeze, *models.SiteBackupManifest, string) {
	t.Helper()
	site := fullRestoreLiveFixture(t, true)
	site.Domain = "example.com"
	site.Aliases = "www.example.com"
	site.DBName = "site_db"
	site.DBUser = "site_user"
	site.SystemUser = "wp_site"
	site.TablePrefix = "wp_"
	site.Status = models.StatusBackupMaintenance
	configText := `<?php define('DB_NAME','site_db'); define('DB_USER','site_user'); define('DB_HOST','localhost'); $table_prefix = 'wp_';`
	if err := os.WriteFile(filepath.Join(site.WebRoot, "wp-config.php"), []byte(configText), 0644); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	oldDB := database.DB
	database.DB = db
	t.Cleanup(func() { database.DB = oldDB; db.Close() })
	_, err = db.Exec(`CREATE TABLE websites(id INTEGER PRIMARY KEY,domain TEXT,aliases TEXT,web_root TEXT,system_user TEXT,site_type TEXT,status TEXT,file_lock_enabled INTEGER,file_lock_mode TEXT,file_lock_apply_status TEXT,document_root_subdir TEXT,db_name TEXT,db_user TEXT,table_prefix TEXT,ols_vhost_config_path TEXT,ssl_enabled INTEGER,ssl_cert_path TEXT,ssl_key_path TEXT,updated_at TEXT);
INSERT INTO websites VALUES(1,'example.com','www.example.com',?, 'wp_site','wordpress','backup_maintenance',0,'','','','site_db','site_user','wp_','',0,'','','old')`, site.WebRoot)
	if err != nil {
		t.Fatal(err)
	}
	site.ID = 1
	manifest := newSiteBackupManifest(site, "restore")
	dir := filepath.Join(t.TempDir(), manifest.ID)
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	f := &siteBackupFreeze{site: site, manifest: manifest, dir: dir, password: "fixture-not-secret"}
	sourceDir := t.TempDir()
	source := newSiteBackupManifest(site, "create")
	if err = os.WriteFile(filepath.Join(sourceDir, "files.tar.gz"), validFullRestoreTar(t), 0600); err != nil {
		t.Fatal(err)
	}
	siteBackupWriteFixtureDatabase(t, filepath.Join(sourceDir, "database.sql.gz"), "backup-point")
	source.Files, err = hashSiteBackupArtifact(context.Background(), filepath.Join(sourceDir, "files.tar.gz"), "files.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	source.Database, err = hashSiteBackupArtifact(context.Background(), filepath.Join(sourceDir, "database.sql.gz"), "database.sql.gz")
	if err != nil {
		t.Fatal(err)
	}
	return f, source, sourceDir
}

func siteBackupWriteFixtureDatabase(t *testing.T, path, body string) {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	if _, err := gz.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSiteBackupRestoreKeepsReadOnlyUntilPreparedAndRollsBackBoth(t *testing.T) {
	for _, stage := range []string{"success", "database import failure", "child live verification failure", "preparation failure", "child rollback sync failure", "rollback directory sync failure", "rollback journal failure"} {
		t.Run(stage, func(t *testing.T) {
			f, source, sourceDir := siteBackupPairedFixture(t)
			oldDump, oldImport, oldOps, oldVerify, oldExchange := siteBackupDump, siteBackupImport, siteBackupFileOps, siteBackupVerifyRestoredFiles, siteBackupExchangeFiles
			oldSQL, oldLock, oldMount, oldUnmount, oldTraffic, oldUser := siteBackupSQL, siteBackupLockTables, siteBackupMountReadOnly, siteBackupUnmountReadOnly, siteBackupVerifyTraffic, siteBackupUserStopped
			oldPersist, oldSync, oldMark := siteBackupPersistManifest, siteBackupSyncDir, siteBackupMarkUnresolved
			defer func() {
				siteBackupDump, siteBackupImport, siteBackupFileOps, siteBackupVerifyRestoredFiles, siteBackupExchangeFiles = oldDump, oldImport, oldOps, oldVerify, oldExchange
				siteBackupSQL, siteBackupLockTables, siteBackupMountReadOnly, siteBackupUnmountReadOnly, siteBackupVerifyTraffic, siteBackupUserStopped = oldSQL, oldLock, oldMount, oldUnmount, oldTraffic, oldUser
				siteBackupPersistManifest, siteBackupSyncDir, siteBackupMarkUnresolved = oldPersist, oldSync, oldMark
			}()
			uncertain := strings.Contains(stage, "sync failure") || stage == "rollback journal failure"
			if uncertain {
				f.site.FileLockEnabled = true
				if _, err := database.DB.Exec("UPDATE websites SET file_lock_enabled=1,file_lock_apply_status='ready' WHERE id=1"); err != nil {
					t.Fatal(err)
				}
			}
			siteBackupMarkUnresolved = func(ctx context.Context, site *models.Website) error {
				return markFileRestoreUnresolved(ctx, database.DB, site, func(int) error { return nil })
			}
			siteBackupPersistManifest = func(dir string, m *models.SiteBackupManifest) error {
				if stage == "rollback journal failure" && m.Phase == "rolled_back" {
					return errors.New("parent rollback journal save failed")
				}
				return writeSiteBackupManifest(dir, m)
			}
			readOnly, prepared := false, false
			dbValue := "current-database"
			imports := 0
			siteBackupLockTables = func(context.Context, *models.Website, string) (siteBackupReadLocker, error) {
				return &siteBackupFixtureReadLock{}, nil
			}
			siteBackupMountReadOnly = func(string) (int, error) { readOnly = true; return 42, nil }
			siteBackupUnmountReadOnly = func(_ string, id int) error {
				if id != 42 || !prepared {
					t.Fatal("root released before complete staging")
				}
				readOnly = false
				return nil
			}
			siteBackupVerifyTraffic = func(context.Context, *models.Website, string, bool) error { return nil }
			siteBackupUserStopped = func(context.Context, *models.Website) error { return nil }
			siteBackupDump = func(_ context.Context, _ string, _ string, path string) error {
				if !readOnly {
					t.Fatal("safety dump outside readonly freeze")
				}
				siteBackupWriteFixtureDatabase(t, path, dbValue)
				return nil
			}
			siteBackupSQL = func(_ context.Context, _ string, q string) (string, error) {
				if strings.HasPrefix(q, "SELECT TABLE_NAME") {
					return "wp_posts", nil
				}
				if strings.Contains(q, "DROP TABLE") {
					dbValue = ""
				}
				return "", nil
			}
			siteBackupImport = func(path, _, _ string) TaskResult {
				imports++
				if strings.HasSuffix(path, "before.sql.gz") {
					dbValue = "current-database"
					return TaskResult{Success: true}
				}
				dbValue = "backup-point"
				return TaskResult{Success: stage != "database import failure" && !strings.HasPrefix(stage, "rollback "), Message: "fixture partial import"}
			}
			ops, exchanges := fullRestoreTestOps(t)
			baseExchange := ops.exchange
			siteBackupSyncDir = func(string) error {
				if stage == "rollback directory sync failure" && *exchanges == 2 {
					return errors.New("parent rollback fsync failed")
				}
				return nil
			}
			ops.syncDir = func(string) error {
				if stage == "child rollback sync failure" && *exchanges == 2 {
					return errors.New("child rollback fsync failed")
				}
				return nil
			}
			ops.prepare = func(*models.Website) error {
				if !readOnly {
					t.Fatal("live root writable during extraction/preparation")
				}
				if stage == "preparation failure" {
					return errors.New("fixture preparation failed")
				}
				return nil
			}
			ops.verify = func(s *models.Website) error {
				if s.WebRoot != f.site.WebRoot {
					if !readOnly {
						t.Fatal("staging verification after unmount")
					}
					prepared = true
					return nil
				}
				if readOnly {
					t.Fatal("exchange while still mounted")
				}
				if stage == "child live verification failure" || stage == "child rollback sync failure" {
					return errors.New("fixture live policy failed")
				}
				return nil
			}
			ops.exchange = func(live, staged string) error {
				if readOnly {
					t.Fatal("exchange precedes unmount")
				}
				return baseExchange(live, staged)
			}
			siteBackupFileOps = func(*siteBackupFreeze) fileRestoreOps { return ops }
			siteBackupExchangeFiles = ops.exchange
			siteBackupVerifyRestoredFiles = func(*models.Website) error { return nil }
			err := restoreSiteBackupComponents(context.Background(), f, source, sourceDir, "paired-task")
			if stage == "success" {
				if err != nil || f.manifest.Phase != "restore_committed" || dbValue != "backup-point" || *exchanges != 1 {
					t.Fatalf("success phase=%s db=%s exchanges=%d error=%v", f.manifest.Phase, dbValue, *exchanges, err)
				}
				assertFullRestoreFile(t, filepath.Join(f.site.WebRoot, "index.php"), "restored-index")
			} else {
				if err == nil {
					t.Fatal("failure reported success")
				}
				assertFullRestoreFile(t, filepath.Join(f.site.WebRoot, "index.php"), "current-index")
				if dbValue != "current-database" {
					t.Fatal("database safety rollback lost")
				}
				if stage == "preparation failure" {
					if f.manifest.Phase != "safety_verified" || *exchanges != 0 || !readOnly {
						t.Fatalf("preparation phase=%s exchange=%d RO=%v", f.manifest.Phase, *exchanges, readOnly)
					}
				} else if uncertain {
					if !f.manifest.RequiresAttention || safeSiteBackupRecoveryPhase("restore", f.manifest.Phase) || *exchanges != 2 {
						t.Fatalf("unsafe rollback phase=%s attention=%v exchanges=%d", f.manifest.Phase, f.manifest.RequiresAttention, *exchanges)
					}
					var lockStatus string
					if err = database.DB.QueryRow("SELECT file_lock_apply_status FROM websites WHERE id=1").Scan(&lockStatus); err != nil || lockStatus != "failed" {
						t.Fatalf("policy=%s error=%v", lockStatus, err)
					}
				} else if f.manifest.Phase != "rolled_back" || *exchanges != 2 {
					t.Fatalf("rollback phase=%s exchanges=%d", f.manifest.Phase, *exchanges)
				}
			}
			if stage == "database import failure" && imports != 2 {
				t.Fatalf("safety import count=%d", imports)
			}
			if (stage == "child live verification failure" || stage == "child rollback sync failure") && imports != 0 {
				t.Fatal("DB changed after child rollback")
			}
			if _, err = os.Stat(f.manifest.SafetyDatabase); err != nil {
				t.Fatal("database safety deleted")
			}
		})
	}
}

func TestSiteBackupFailedPhasePersistenceNeverPublishesSafePhase(t *testing.T) {
	manifest := &models.SiteBackupManifest{Phase: "database_restore_intent"}
	f := &siteBackupFreeze{manifest: manifest}
	old := siteBackupPersistManifest
	defer func() { siteBackupPersistManifest = old }()
	siteBackupPersistManifest = func(_ string, next *models.SiteBackupManifest) error {
		if next.Phase != "rolled_back" {
			t.Fatal("candidate phase missing")
		}
		return errors.New("journal write failed")
	}
	if err := f.save("rolled_back"); err == nil {
		t.Fatal("save failure ignored")
	}
	if manifest.Phase != "database_restore_intent" || safeSiteBackupRecoveryPhase("restore", manifest.Phase) {
		t.Fatalf("failed save published %s", manifest.Phase)
	}
}

func TestSiteBackupThawReLockIntentSurvivesPreLockFailureAndCanceledRequest(t *testing.T) {
	for _, stage := range []string{"OLS restart failure", "request canceled after restoring access"} {
		t.Run(stage, func(t *testing.T) {
			f, _, _ := siteBackupPairedFixture(t)
			f.manifest.Phase = "freeze_failed"
			f.manifest.OriginalVHost = "original vhost"
			f.manifest.VHostPath = filepath.Join(t.TempDir(), "site.conf")
			f.site.OLSVHostConfigPath = f.manifest.VHostPath
			f.manifest.MaintenanceRoot = t.TempDir()
			f.manifest.Marker = "a31a9b36-2d77-4d82-8f55-b64fe66f4474"
			f.manifest.DBAccountLocked = false
			maintenance, err := renderSiteBackupMaintenance(f.site, f.manifest.MaintenanceRoot, f.manifest.Marker)
			if err != nil {
				t.Fatal(err)
			}
			maintenanceHash := sha256.Sum256([]byte(maintenance))
			f.manifest.MaintenanceVHostSHA256 = hex.EncodeToString(maintenanceHash[:])
			if err = os.WriteFile(f.manifest.VHostPath, []byte(f.manifest.OriginalVHost), 0640); err != nil {
				t.Fatal(err)
			}
			if _, err = database.DB.Exec("UPDATE websites SET ols_vhost_config_path=? WHERE id=1", f.manifest.VHostPath); err != nil {
				t.Fatal(err)
			}
			oldSQL, oldRestart, oldWrite, oldTraffic, oldStop := siteBackupSQL, siteBackupRestartOLS, siteBackupWriteVHost, siteBackupVerifyTraffic, siteBackupStopUser
			defer func() {
				siteBackupSQL, siteBackupRestartOLS, siteBackupWriteVHost, siteBackupVerifyTraffic, siteBackupStopUser = oldSQL, oldRestart, oldWrite, oldTraffic, oldStop
			}()
			locked := false
			locks, unlocks, stops, restarts := 0, 0, 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			siteBackupSQL = func(runtime context.Context, _ string, query string) (string, error) {
				if runtime.Err() != nil {
					return "", runtime.Err()
				}
				if strings.HasSuffix(query, "ACCOUNT LOCK") {
					var durable models.SiteBackupManifest
					data, err := os.ReadFile(filepath.Join(f.dir, "manifest.json"))
					if err != nil {
						t.Fatal(err)
					}
					if err = json.Unmarshal(data, &durable); err != nil {
						t.Fatal(err)
					}
					if !durable.DBAccountLocked || !durable.RequiresAttention {
						t.Fatal("DB re-lock was not durably tracked before side effect")
					}
					locks++
					locked = true
				} else if strings.HasSuffix(query, "ACCOUNT UNLOCK") {
					unlocks++
					locked = false
				}
				if strings.Contains(query, "SELECT COUNT(*)") {
					return "0", nil
				}
				return "", nil
			}
			siteBackupWriteVHost = func(path string, data []byte, mode os.FileMode) error { return os.WriteFile(path, data, mode) }
			siteBackupRestartOLS = func() ([]byte, error) {
				restarts++
				if restarts == 1 && stage == "OLS restart failure" {
					return nil, errors.New("restart failed")
				}
				return nil, nil
			}
			siteBackupStopUser = func(runtime context.Context, _ *models.Website) error {
				if runtime.Err() != nil {
					t.Fatal("cleanup inherited canceled request")
				}
				stops++
				return nil
			}
			failedProbe := false
			siteBackupVerifyTraffic = func(runtime context.Context, _ *models.Website, _ string, inMaintenance bool) error {
				if !inMaintenance && stage == "request canceled after restoring access" && !failedProbe {
					failedProbe = true
					cancel()
					return runtime.Err()
				}
				if inMaintenance && runtime.Err() != nil {
					t.Fatal("maintenance recheck used canceled request")
				}
				return nil
			}
			if err = f.thaw(ctx); err == nil {
				t.Fatal("failed thaw returned success")
			}
			if !locked || locks != 1 || unlocks != 0 || stops != 1 || !f.manifest.DBAccountLocked || !f.manifest.RequiresAttention {
				t.Fatalf("cleanup locks=%d unlocks=%d stops=%d tracked=%v", locks, unlocks, stops, f.manifest.DBAccountLocked)
			}
			assertFullRestoreFile(t, f.manifest.VHostPath, maintenance)
			var durable models.SiteBackupManifest
			data, err := os.ReadFile(filepath.Join(f.dir, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(data, &durable); err != nil {
				t.Fatal(err)
			}
			// Explicit recovery reconstructs this same actual thaw protocol from the
			// durable owner journal; it must unlock even though initial freeze never did.
			f.manifest = &durable
			if err = f.thaw(context.Background()); err != nil {
				t.Fatal(err)
			}
			var status string
			if err = database.DB.QueryRow("SELECT status FROM websites WHERE id=1").Scan(&status); err != nil || status != "active" {
				t.Fatalf("status=%s error=%v", status, err)
			}
			if locked || unlocks != 1 || f.manifest.DBAccountLocked || f.manifest.RequiresAttention {
				t.Fatal("recovery resumed with the DB account still locked")
			}
			assertFullRestoreFile(t, f.manifest.VHostPath, "original vhost")
		})
	}
}
