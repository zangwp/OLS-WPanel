package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

var (
	siteBackupDump    = dumpSiteBackupDatabase
	siteBackupImport  = restoreDatabaseSnapshot
	siteBackupFileOps = func(f *siteBackupFreeze) fileRestoreOps {
		return fileRestoreOps{prepare: prepareFileRestorePermissions, verify: verifyFileRestorePermissions, exchange: exchangeFileRestoreDirectories, syncDir: syncDirectory, syncFile: func(file *os.File) error { return file.Sync() }, verifyPrivate: verifyFileRestorePrivateDirectory, freeBytes: availableFileRestoreBytes, revalidate: f.check}
	}
	siteBackupVerifyRestoredFiles = verifyFileRestorePermissions
	siteBackupExchangeFiles       = exchangeFileRestoreDirectories
	siteBackupSyncDir             = syncDirectory
	siteBackupPersistManifest     = writeSiteBackupManifest
	siteBackupMarkUnresolved      = func(ctx context.Context, site *models.Website) error {
		return markFileRestoreUnresolved(ctx, database.GetDB(), site, RemoveWPCodeIntegrityBaseline)
	}
)

func newSiteBackupManifest(site *models.Website, operation string) *models.SiteBackupManifest {
	return &models.SiteBackupManifest{Version: siteBackupManifestVersion, SiteBackup: models.SiteBackup{ID: uuid.NewString(), SiteID: site.ID, CreatedAt: time.Now().UTC(), State: "incomplete", Consistency: "controlled_quiescence"}, Domain: site.Domain, Aliases: site.Aliases, WebRoot: site.WebRoot, SystemUser: site.SystemUser, DBName: site.DBName, DBUser: site.DBUser, TablePrefix: site.TablePrefix, Operation: operation, Phase: "created", Atomic: false}
}

func createSiteBackupDirectory(site *models.Website, manifest *models.SiteBackupManifest) (string, error) {
	root, err := siteBackupRoot(site)
	if err != nil {
		return "", err
	}
	if manifest.Operation == "restore" {
		root = filepath.Join(filepath.Dir(root), "site-operations")
	}
	if err = os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	if err = verifySiteBackupParentDirectories(root); err != nil {
		return "", err
	}
	dir := filepath.Join(root, manifest.ID)
	if err = os.Mkdir(dir, 0700); err != nil {
		return "", err
	}
	if err = verifyFileRestorePrivateDirectory(dir); err != nil {
		return "", err
	}
	if err = writeSiteBackupManifest(dir, manifest); err != nil {
		return "", err
	}
	return dir, nil
}

func validateSiteBackupWPConfig(site *models.Website) error {
	path := filepath.Join(site.WebRoot, "wp-config.php")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("当前 wp-config.php 不安全或不能读取")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	prefix, ok := extractWPTablePrefix(string(content))
	if !ok || prefix != site.TablePrefix {
		return errors.New("wp-config.php 的实际表前缀与站点绑定不一致")
	}
	for name, want := range map[string]string{"DB_NAME": site.DBName, "DB_USER": site.DBUser} {
		pattern := regexp.MustCompile(`(?m)define\s*\(\s*['"]` + name + `['"]\s*,\s*['"]([^'"\r\n]+)['"]\s*\)\s*;`)
		matches := pattern.FindAllSubmatch(content, -1)
		if len(matches) != 1 || string(matches[0][1]) != want {
			return errors.New("wp-config.php 的数据库绑定不符合受管站点要求")
		}
	}
	pattern := regexp.MustCompile(`(?m)define\s*\(\s*['"]DB_HOST['"]\s*,\s*['"]([^'"\r\n]+)['"]\s*\)\s*;`)
	matches := pattern.FindAllSubmatch(content, -1)
	if len(matches) != 1 || (string(matches[0][1]) != "localhost" && string(matches[0][1]) != "127.0.0.1") {
		return errors.New("整站备份仅支持本机独占数据库，不支持外部数据库")
	}
	return nil
}

func checkSiteBackupSpace(ctx context.Context, site *models.Website, dir, password string) error {
	var files int64
	if err := filepath.WalkDir(site.WebRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 0 || info.Size() > fileRestoreMaxBytes-files {
			return errors.New("文件大小超过整站备份上限")
		}
		files += info.Size()
		return nil
	}); err != nil {
		return err
	}
	// The allowance is intentionally conservative: compressed output must fit
	// even for incompressible files, and MariaDB logical output needs headroom.
	databaseSize, err := siteBackupSQL(ctx, password, fmt.Sprintf("SELECT COALESCE(SUM(DATA_LENGTH+INDEX_LENGTH),0) FROM information_schema.TABLES WHERE TABLE_SCHEMA='%s'", site.DBName))
	if err != nil {
		return err
	}
	dbBytes, err := strconv.ParseInt(databaseSize, 10, 64)
	if err != nil || dbBytes < 0 || dbBytes > fileRestoreMaxBytes {
		return errors.New("数据库大小不能安全确认或超过备份上限")
	}
	free, err := availableFileRestoreBytes(dir)
	if err != nil {
		return err
	}
	if files > (free-fileRestoreFreeReserve)/2 || dbBytes > (free-fileRestoreFreeReserve-2*files)/3 || free < fileRestoreFreeReserve+128<<20 {
		return errors.New("整站备份磁盘余量不足，至少保留 1 GiB")
	}
	return nil
}

// This is intentionally lock-free. Only the coordinator holding the kernel
// backup lock, site slot and freeze may invoke it.
func buildSiteBackupArtifacts(ctx context.Context, f *siteBackupFreeze) error {
	var err error
	f.tables, err = siteBackupLockTables(ctx, f.site, f.password)
	if err != nil {
		return err
	}
	if err = f.readOnly(ctx); err != nil {
		return err
	}
	if err = f.check(ctx); err != nil {
		return err
	}
	if err = f.save("building_artifacts"); err != nil {
		return err
	}
	filePath := filepath.Join(f.dir, "files.tar.gz")
	if err = createSiteBackupFileArchive(ctx, f.site.WebRoot, filePath); err != nil {
		return err
	}
	if err = os.Chmod(filePath, 0600); err != nil {
		return err
	}
	if err = verifyFileBackupArchiveContext(ctx, filePath); err != nil {
		return err
	}
	if f.manifest.Files, err = hashSiteBackupArtifact(ctx, filePath, "files.tar.gz"); err != nil {
		return err
	}
	dbPath := filepath.Join(f.dir, "database.sql.gz")
	if err = dumpSiteBackupDatabase(ctx, f.site.DBName, f.password, dbPath); err != nil {
		return err
	}
	if err = verifyDatabaseSnapshot(dbPath); err != nil {
		return err
	}
	if f.manifest.Database, err = hashSiteBackupArtifact(ctx, dbPath, "database.sql.gz"); err != nil {
		return err
	}
	if err = f.check(ctx); err != nil {
		return err
	}
	return f.save("backup_verified")
}

func executeCreateSiteBackup(task *Task) (result TaskResult) {
	if task == nil {
		return TaskResult{Message: "整站备份任务无效"}
	}
	payload, ok := task.Payload.(*SiteBackupPayload)
	if !ok || payload == nil || payload.Site == nil || !payload.ConfirmExternalWritersStopped {
		return TaskResult{Message: "整站备份需要确认暂停网站及外部写入"}
	}
	ctx, cancel := withFileBackupCommandTimeout(context.Background())
	defer cancel()
	lock, err := AcquireFileBackupOperationLock(ctx)
	if err != nil {
		return taskFailure("取得备份锁失败", err)
	}
	defer lock.Close()
	if !TryAcquireSiteOpLock(payload.Site.ID, "site_backup") {
		return TaskResult{Message: "网站正在执行其他操作"}
	}
	defer ReleaseSiteOpLock(payload.Site.ID)
	site, err := loadSiteBackupWebsite(ctx, database.GetDB(), payload.Site.ID)
	if err != nil {
		return taskFailure("读取网站失败", err)
	}
	if err = validateSiteBackupWebsite(ctx, site); err != nil {
		return taskFailure("网站不能受控停写", err)
	}
	if err = validateSiteBackupWPConfig(site); err != nil {
		return taskFailure("当前数据库绑定核验失败", err)
	}
	password := readMariaDBPassword()
	if password == "" {
		return TaskResult{Message: "本地 MariaDB 管理凭据不可用"}
	}
	manifest := newSiteBackupManifest(site, "create")
	dir, err := createSiteBackupDirectory(site, manifest)
	if err != nil {
		return taskFailure("建立整站备份集合失败", err)
	}
	if err = checkSiteBackupSpace(ctx, site, dir, password); err != nil {
		manifest.Message = safeSiteBackupMessage(err)
		_ = writeSiteBackupManifest(dir, manifest)
		return taskFailure("磁盘检查失败", err)
	}
	f, err := beginSiteBackupFreeze(ctx, site, manifest, dir, password)
	if f != nil {
		defer f.close()
	}
	defer func() {
		if r := recover(); r != nil {
			manifest.RequiresAttention = f != nil
			manifest.Message = "整站备份中断，需核对维护现场"
			_ = writeSiteBackupManifest(dir, manifest)
			result = TaskResult{Message: manifest.Message, Data: map[string]interface{}{"backup_id": manifest.ID, "requires_attention": manifest.RequiresAttention}}
		}
	}()
	if err == nil {
		err = buildSiteBackupArtifacts(ctx, f)
	}
	if err == nil {
		err = f.thaw(ctx)
	}
	if err != nil {
		// A failed backup never changes live website content. Make a bounded
		// best effort to restore the original gates; keep attention only if
		// cleanup itself cannot be proven. Never label partial artifacts complete.
		if f != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			cleanupErr := f.thaw(cleanup)
			cancel()
			if cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
				manifest.RequiresAttention = true
			} else {
				manifest.RequiresAttention = false
				manifest.Phase = "backup_failed_cleaned"
			}
		}
		manifest.Message = safeSiteBackupMessage(err)
		_ = writeSiteBackupManifest(dir, manifest)
		return TaskResult{Message: "整站备份未完成；" + manifest.Message, Data: map[string]interface{}{"backup_id": manifest.ID, "requires_attention": manifest.RequiresAttention}}
	}
	manifest.State = "complete"
	manifest.Phase = "completed"
	manifest.LocalExists = true
	manifest.FileSize = manifest.Files.Size
	manifest.DBSize = manifest.Database.Size
	manifest.Message = "文件与数据库已在受控停写期间校验为同一备份集合；不是跨组件原子事务"
	if err = writeSiteBackupManifest(dir, manifest); err != nil {
		return taskFailure("备份组件已生成但完整状态保存失败", err)
	}
	return TaskResult{Success: true, Message: manifest.Message, Data: manifest.SiteBackup}
}

func executeCreateFileBackup(task *Task) TaskResult {
	if task == nil {
		return TaskResult{Message: "文件备份任务无效"}
	}
	payload, ok := task.Payload.(*CreateFileBackupPayload)
	if !ok || payload == nil || payload.Site == nil {
		return TaskResult{Message: "文件备份参数无效"}
	}
	ctx, cancel := withFileBackupCommandTimeout(context.Background())
	defer cancel()
	var status string
	if err := databaseStatusForSite(ctx, payload.Site.ID, &status); err != nil {
		return taskFailure("读取网站状态失败", err)
	}
	if status == string(models.StatusBackupMaintenance) {
		return TaskResult{Message: "网站正在整站维护中，不能另建文件备份"}
	}
	message, err := ExecuteFileBackupContext(ctx, payload.Site.ID, "full", 3)
	if err != nil {
		return taskFailure("全量文件备份失败", err)
	}
	return TaskResult{Success: true, Message: message}
}

func clearSiteBackupDatabase(ctx context.Context, site *models.Website, password string) error {
	current, err := loadSiteBackupWebsite(ctx, database.GetDB(), site.ID)
	if err != nil {
		return err
	}
	if current.Status != models.StatusBackupMaintenance || current.DBName != site.DBName || current.DBUser != site.DBUser || current.WebRoot != site.WebRoot {
		return errors.New("整站协调器不再持有此站点数据库绑定")
	}
	if !databaseRestoreNameAllowed(site.DBName) {
		return errors.New("不能安全清理未知数据库")
	}
	dropSQL, err := siteBackupSQL(ctx, password, databaseRestoreDropQuery(site.DBName))
	if err != nil {
		return err
	}
	// Drop routines/views/events as well as tables so a dump cannot CALL an
	// existing root-definer object to escape its schema-limited identity.
	_, err = siteBackupSQL(ctx, password, "SET FOREIGN_KEY_CHECKS=0;\n"+dropSQL+"\nSET FOREIGN_KEY_CHECKS=1;\n")
	return err
}

// Orchestrated restore retains both safety components until both are committed
// or both are rolled back. A partial failure remains in durable maintenance.
func restoreSiteBackupComponents(ctx context.Context, f *siteBackupFreeze, source *models.SiteBackupManifest, sourceDir, taskID string) (returnedErr error) {
	var err error
	if err = validSiteBackupArtifact(sourceDir, source.Files, "files.tar.gz", true); err != nil {
		return err
	}
	if err = validSiteBackupArtifact(sourceDir, source.Database, "database.sql.gz", true); err != nil {
		return err
	}
	if err = verifyDatabaseSnapshot(filepath.Join(sourceDir, "database.sql.gz")); err != nil {
		return err
	}
	f.tables, err = siteBackupLockTables(ctx, f.site, f.password)
	if err != nil {
		return err
	}
	if err = f.readOnly(ctx); err != nil {
		return err
	}
	f.manifest.SafetyDatabase = filepath.Join(f.dir, "before.sql.gz")
	if err = f.save("safety_database_intent"); err != nil {
		return err
	}
	if err = siteBackupDump(ctx, f.site.DBName, f.password, f.manifest.SafetyDatabase); err != nil {
		return err
	}
	if err = verifyDatabaseSnapshot(f.manifest.SafetyDatabase); err != nil {
		return err
	}
	if err = f.check(ctx); err != nil {
		return err
	}
	if err = f.save("safety_verified"); err != nil {
		return err
	}
	if err = f.tables.Close(); err != nil {
		return err
	}
	f.tables = nil
	archive, err := openFileRestoreArchive(filepath.Join(sourceDir, "files.tar.gz"), source.Files.Size)
	if err != nil {
		return err
	}
	defer archive.Close()
	filesChanged, dbChanged := false, false
	defer func() {
		if r := recover(); r != nil {
			returnedErr = fmt.Errorf("整站恢复过程异常: %v", r)
		}
		if returnedErr == nil {
			return
		}
		recovery, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		var rollbackErr error
		if dbChanged {
			rollbackErr = clearSiteBackupDatabase(recovery, f.site, f.password)
			if rollbackErr == nil {
				result := siteBackupImport(f.manifest.SafetyDatabase, f.site.DBName, f.password)
				if !result.Success {
					rollbackErr = errors.New(result.Message)
				}
			}
		}
		if filesChanged {
			rollbackErr = errors.Join(rollbackErr, siteBackupExchangeFiles(f.site.WebRoot, f.manifest.SafetyFiles))
			if rollbackErr == nil {
				rollbackErr = siteBackupVerifyRestoredFiles(f.site)
			}
		}
		if rollbackErr != nil {
			f.manifest.RequiresAttention = true
			_ = siteBackupMarkUnresolved(recovery, f.site)
			returnedErr = errors.Join(returnedErr, fmt.Errorf("跨组件自动回滚未完成: %w", rollbackErr))
			_ = f.save("rollback_failed")
			return
		}
		if filesChanged || dbChanged {
			rollbackErr = siteBackupSyncDir(filepath.Dir(f.site.WebRoot))
			if rollbackErr == nil {
				rollbackErr = siteBackupSyncDir(filepath.Dir(f.manifest.SafetyFiles))
			}
			if rollbackErr == nil {
				rollbackErr = f.save("rolled_back")
			}
			if rollbackErr != nil {
				f.manifest.RequiresAttention = true
				_ = siteBackupMarkUnresolved(recovery, f.site)
				returnedErr = errors.Join(returnedErr, fmt.Errorf("跨组件回滚持久化未确认: %w", rollbackErr))
				_ = f.save("rollback_failed")
			}
		}
	}()
	ops := siteBackupFileOps(f)
	ops.onPrepared = func(safety string) error {
		f.manifest.SafetyFiles = safety
		if err := f.save("files_swap_intent"); err != nil {
			return err
		}
		// Extraction can take hours. Keep the current root read-only until the
		// complete staged tree has passed validation and is ready to exchange.
		return f.releaseReadOnly()
	}
	safety, err := restoreFullFileArchive(ctx, f.site, 0, taskID, archive, ops)
	if err != nil {
		var unresolved *fileRestoreUnresolvedError
		if errors.As(err, &unresolved) {
			f.manifest.RequiresAttention = true
			_ = siteBackupMarkUnresolved(context.Background(), f.site)
			_ = f.save("rollback_failed")
		} else {
			var unchanged *fileRestoreUnchangedError
			var rolledBack *fileRestoreRolledBackError
			if errors.As(err, &rolledBack) {
				err = errors.Join(err, f.save("rolled_back"))
			} else if errors.As(err, &unchanged) {
				err = errors.Join(err, f.save("safety_verified"))
			}
		}
		return err
	}
	f.manifest.SafetyFiles = safety
	filesChanged = true
	if err = f.save("files_restored"); err != nil {
		return err
	}
	if err = f.check(ctx); err != nil {
		return err
	}
	if err = f.save("database_restore_intent"); err != nil {
		return err
	}
	dbChanged = true
	if err = clearSiteBackupDatabase(ctx, f.site, f.password); err != nil {
		return err
	}
	importResult := siteBackupImport(filepath.Join(sourceDir, "database.sql.gz"), f.site.DBName, f.password)
	if !importResult.Success {
		return errors.New(importResult.Message)
	}
	if err = validateSiteBackupWPConfig(f.site); err != nil {
		return err
	}
	if err = siteBackupVerifyRestoredFiles(f.site); err != nil {
		return err
	}
	if err = f.check(ctx); err != nil {
		return err
	}
	return f.save("restore_committed")
}

func executeRestoreSiteBackup(task *Task) (result TaskResult) {
	if task == nil {
		return TaskResult{Message: "整站恢复任务无效"}
	}
	payload, ok := task.Payload.(*RestoreSiteBackupPayload)
	if !ok || payload == nil || payload.Site == nil || !payload.ConfirmExternalWritersStopped {
		return TaskResult{Message: "整站恢复需要确认暂停网站和外部写入"}
	}
	ctx, cancel := withFileBackupCommandTimeout(context.Background())
	defer cancel()
	lock, err := AcquireFileBackupOperationLock(ctx)
	if err != nil {
		return taskFailure("取得备份锁失败", err)
	}
	defer lock.Close()
	if !TryAcquireSiteOpLock(payload.Site.ID, "site_restore") {
		return TaskResult{Message: "网站正在执行其他操作"}
	}
	defer ReleaseSiteOpLock(payload.Site.ID)
	site, err := loadSiteBackupWebsite(ctx, database.GetDB(), payload.Site.ID)
	if err != nil {
		return taskFailure("读取网站失败", err)
	}
	if err = validateSiteBackupWebsite(ctx, site); err != nil {
		return taskFailure("网站不能受控停写", err)
	}
	if err = validateSiteBackupWPConfig(site); err != nil {
		return taskFailure("当前数据库绑定不一致", err)
	}
	if err = ValidateSiteBackupRestore(ctx, site, payload.BackupID); err != nil {
		return taskFailure("整站备份不可恢复", err)
	}
	source, sourceDir, err := readSiteBackupManifest(ctx, site, payload.BackupID)
	if err != nil {
		return taskFailure("读取整站备份失败", err)
	}
	// Integrity failures precede any freeze or live mutation.
	if err = validSiteBackupArtifact(sourceDir, source.Files, "files.tar.gz", true); err == nil {
		err = validSiteBackupArtifact(sourceDir, source.Database, "database.sql.gz", true)
	}
	if err != nil {
		return taskFailure("整站备份指纹核验失败", err)
	}
	password := readMariaDBPassword()
	if password == "" {
		return TaskResult{Message: "本地 MariaDB 管理凭据不可用"}
	}
	manifest := newSiteBackupManifest(site, "restore")
	dir, err := createSiteBackupDirectory(site, manifest)
	if err != nil {
		return taskFailure("建立恢复日志失败", err)
	}
	f, err := beginSiteBackupFreeze(ctx, site, manifest, dir, password)
	if f != nil {
		defer f.close()
	}
	defer func() {
		if r := recover(); r != nil {
			manifest.RequiresAttention = f != nil
			manifest.Message = "整站恢复中断，维护现场需要人工核对"
			_ = writeSiteBackupManifest(dir, manifest)
			result = TaskResult{Message: manifest.Message}
		}
	}()
	if err == nil {
		err = restoreSiteBackupComponents(ctx, f, source, sourceDir, task.ID)
	}
	if err == nil {
		err = f.thaw(ctx)
	}
	if err != nil {
		manifest.RequiresAttention = f != nil
		// Before live mutation, or after explicitly verified rollback, failure
		// can return to the old website. Never thaw an ambiguous swap/import.
		if f != nil && safeSiteBackupRecoveryPhase(manifest.Operation, manifest.Phase) {
			recovery, stop := context.WithTimeout(context.Background(), 90*time.Second)
			cleanupErr := f.thaw(recovery)
			stop()
			if cleanupErr == nil {
				manifest.RequiresAttention = false
				manifest.Phase = "restore_failed_cleaned"
			} else {
				err = errors.Join(err, fmt.Errorf("恢复原访问状态失败: %w", cleanupErr))
			}
		}
		manifest.Message = safeSiteBackupMessage(err)
		_ = writeSiteBackupManifest(dir, manifest)
		state := "原网站状态已恢复或尚未修改；"
		if manifest.RequiresAttention {
			state = "网站保留维护状态，现场需要核对；"
		}
		return TaskResult{Message: "整站恢复未完成，" + state + manifest.Message, Data: map[string]interface{}{"requires_attention": manifest.RequiresAttention, "safety_files": manifest.SafetyFiles, "safety_database": manifest.SafetyDatabase}}
	}
	_ = RemoveWPCodeIntegrityBaseline(site.ID)
	warnings := ""
	if site.FileLockEnabled {
		if err = writeFileIntegrityBaseline(ctx, site); err != nil {
			warnings = "；文件保护基线刷新失败，请重新检查"
		}
	}
	manifest.Phase = "completed"
	manifest.Message = "文件与数据库已统一恢复并解除维护；当前 wp-config.php 和面板代码保留，恢复前双方安全副本保留；不是跨组件原子事务，PHP/页面/CDN/Redis缓存、组件清单及网站实际业务仍需检查" + warnings
	if err = writeSiteBackupManifest(dir, manifest); err != nil {
		return taskFailure("恢复已执行但最终日志保存失败", err)
	}
	return TaskResult{Success: true, Message: manifest.Message, Data: map[string]interface{}{"backup_id": payload.BackupID, "database_restored": true, "files_restored": true, "atomic": false, "safety_files": manifest.SafetyFiles, "safety_database": manifest.SafetyDatabase}}
}

// Recovery is deliberate, never a startup auto-resume. Partial/ambiguous
// cross-component states cannot be resumed through this endpoint.
func RecoverSiteBackupMaintenance(ctx context.Context, site *models.Website) error {
	if site == nil || site.ID <= 0 {
		return errors.New("网站无效")
	}
	lock, err := AcquireFileBackupOperationLock(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	if !tryAcquireSiteBackupRecoveryOp(site.ID) {
		return errors.New("网站仍有进行中的操作")
	}
	defer ReleaseSiteOpLock(site.ID)
	current, err := loadSiteBackupWebsite(ctx, database.GetDB(), site.ID)
	if err != nil {
		return err
	}
	if current.Status != models.StatusBackupMaintenance {
		return errors.New("网站不处于整站备份维护状态")
	}
	selected, selectedDir, err := readSiteBackupMaintenanceOwner(ctx, current)
	if err != nil {
		return err
	}
	if !safeSiteBackupRecoveryPhase(selected.Operation, selected.Phase) {
		return fmt.Errorf("此恢复阶段 %s 无法证明双方状态一致；请人工核对文件安全副本 %s 和数据库安全副本 %s，网站继续维护", selected.Phase, selected.SafetyFiles, selected.SafetyDatabase)
	}
	password := readMariaDBPassword()
	if password == "" {
		return errors.New("数据库管理凭据不可用")
	}
	f := &siteBackupFreeze{site: current, manifest: selected, dir: selectedDir, password: password}
	f.cronLocks, err = acquireSiteBackupCronLocks(ctx, current)
	if err != nil {
		return err
	}
	defer f.close()
	if err = siteBackupUserStopped(ctx, current); err != nil {
		return err
	}
	if err = f.thaw(ctx); err != nil {
		selected.RequiresAttention = true
		selected.Message = safeSiteBackupMessage(err)
		_ = writeSiteBackupManifest(selectedDir, selected)
		return err
	}
	if selected.Operation == "create" && selected.Phase == "backup_verified" {
		selected.State = "complete"
		selected.FileSize = selected.Files.Size
		selected.DBSize = selected.Database.Size
	}
	selected.Phase = "completed"
	selected.Message = "已按可确认日志解除整站维护；请检查网站与后台任务"
	return writeSiteBackupManifest(selectedDir, selected)
}

func safeSiteBackupRecoveryPhase(operation, phase string) bool {
	if operation == "restore" && (phase == "restore_committed" || phase == "rolled_back") {
		return true
	}
	if operation == "create" && phase == "backup_verified" {
		return true
	}
	preMutation := map[string]bool{"freeze_intent": true, "traffic_blocked": true, "db_lock_intent": true, "freeze_failed": true, "frozen": true, "readonly_mount_intent": true, "frozen_readonly": true}
	if operation == "create" {
		return preMutation[phase] || phase == "building_artifacts"
	}
	return operation == "restore" && (preMutation[phase] || phase == "safety_database_intent" || phase == "safety_verified")
}

func decodeSiteBackupRecoveryManifest(reader io.Reader, manifest *models.SiteBackupManifest) error {
	if err := json.NewDecoder(io.LimitReader(reader, 1<<20)).Decode(manifest); err != nil {
		return err
	}
	if manifest.Version != siteBackupManifestVersion || !validSiteBackupID(manifest.ID) || manifest.Atomic || manifest.OriginalVHost == "" || manifest.VHostPath == "" || manifest.Marker == "" {
		return errors.New("维护日志格式或版本无效")
	}
	return nil
}
