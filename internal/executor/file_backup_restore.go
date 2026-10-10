package executor

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

const (
	fileRestoreMaxEntries            = 250000
	fileRestoreMaxBytes        int64 = 64 << 30
	fileRestoreManagedMaxBytes int64 = 128 << 20
	fileRestoreFreeReserve     int64 = 1 << 30
)

type fileRestoreOps struct {
	prepare       func(*models.Website) error
	verify        func(*models.Website) error
	exchange      func(string, string) error
	syncDir       func(string) error
	syncFile      func(*os.File) error
	revalidate    func(context.Context) error
	verifyPrivate func(string) error
	freeBytes     func(string) (int64, error)
}

type fileRestoreUnresolvedError struct {
	cause      error
	safetyPath string
}

func (e *fileRestoreUnresolvedError) Error() string {
	return fmt.Sprintf("%v；自动回滚失败，恢复前原目录保留于 %s", e.cause, e.safetyPath)
}
func (e *fileRestoreUnresolvedError) Unwrap() error { return e.cause }

func executeRestoreFileBackup(task *Task) TaskResult {
	if task == nil {
		return TaskResult{Message: "文件恢复任务参数无效"}
	}
	payload, ok := task.Payload.(*RestoreFileBackupPayload)
	if !ok || payload == nil || payload.Site == nil || payload.Site.ID <= 0 || payload.BackupID <= 0 {
		return TaskResult{Message: "文件恢复任务参数无效"}
	}
	ctx, cancel := withFileBackupCommandTimeout(context.Background())
	defer cancel()
	// Backup deletion/rotation and cron processes use this same kernel lock.
	// The nonblocking site lock is acquired second, avoiding waiting for a
	// filesystem lock while unnecessarily occupying a website operation slot.
	lock, err := AcquireFileBackupOperationLock(ctx)
	if err != nil {
		return taskFailure("等待文件备份操作锁失败", err)
	}
	defer lock.Close()
	if !TryAcquireSiteOpLock(payload.Site.ID, "file_restore") {
		return TaskResult{Message: "网站正在维护或执行其他操作，请结束后重试"}
	}
	defer ReleaseSiteOpLock(payload.Site.ID)
	db := database.GetDB()
	site, err := loadFileRestoreSite(ctx, db, payload.Site.ID)
	if err != nil {
		return taskFailure("读取当前网站设置失败", err)
	}
	if err = checkFileRestoreSite(ctx, db, site); err != nil {
		return taskFailure("网站当前不能恢复文件", err)
	}
	if config.AppConfig == nil {
		return TaskResult{Message: "面板路径配置不可用"}
	}
	if _, err = validateFileRestoreRoot(config.AppConfig.Paths.WWWRoot, site.WebRoot); err != nil {
		return taskFailure("网站目录校验失败", err)
	}
	if site.FileLockEnabled {
		if err = VerifySiteFileLockMode(site, EffectiveFileLockMode(site)); err != nil {
			return taskFailure("当前网站文件保护未通过权限核验，请先修复", err)
		}
	}
	filename, size, err := loadFullFileRestoreRecord(ctx, db, site.ID, payload.BackupID)
	if err != nil {
		return taskFailure("读取全量文件备份失败", err)
	}
	if !IsValidDomain(site.Domain) {
		return TaskResult{Message: "全量文件备份记录无效"}
	}
	backupDir := filepath.Join(backupsRoot, site.Domain, "files")
	if err = fileRestoreNoSymlinkDirectories(backupDir); err != nil {
		return taskFailure("备份目录校验失败", err)
	}
	archive, err := openFileRestoreArchive(filepath.Join(backupDir, filename), size)
	if err != nil {
		return taskFailure("本地全量备份不可用；远端备份须先下载至本地", err)
	}
	defer archive.Close()
	policy := *site
	ops := fileRestoreOps{
		prepare:       prepareFileRestorePermissions,
		verify:        verifyFileRestorePermissions,
		exchange:      exchangeFileRestoreDirectories,
		syncDir:       syncDirectory,
		syncFile:      func(file *os.File) error { return file.Sync() },
		verifyPrivate: verifyFileRestorePrivateDirectory,
		freeBytes:     availableFileRestoreBytes,
		revalidate: func(ctx context.Context) error {
			current, err := loadFileRestoreSite(ctx, db, site.ID)
			if err != nil {
				return err
			}
			if current.Domain != policy.Domain || current.WebRoot != policy.WebRoot || current.SystemUser != policy.SystemUser || current.Status != policy.Status || current.FileLockEnabled != policy.FileLockEnabled || current.FileLockMode != policy.FileLockMode || current.FileLockApplyStatus != policy.FileLockApplyStatus {
				return errors.New("恢复准备期间网站配置已变化，请重新提交")
			}
			return checkFileRestoreSite(ctx, db, current)
		},
	}
	// Any attempt that changes files invalidates the old media timestamp. An
	// aborted restore may cause a conservative new full backup, never a broken
	// incremental chain. Failure to invalidate aborts before changing live files.
	if err = os.Remove(filepath.Join(backupDir, ".last_backup.stamp")); err != nil && !os.IsNotExist(err) {
		return taskFailure("清除增量备份基线失败，未修改网站文件", err)
	}
	safety, err := restoreFullFileArchive(ctx, site, payload.BackupID, task.ID, archive, ops)
	if err != nil {
		var unresolved *fileRestoreUnresolvedError
		if errors.As(err, &unresolved) {
			recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer recoveryCancel()
			if stateErr := markFileRestoreUnresolved(recoveryCtx, db, site, RemoveWPCodeIntegrityBaseline); stateErr != nil {
				err = fmt.Errorf("%w；保护状态未能完整保存: %v", err, stateErr)
			}
		}
		return taskFailure("全量文件恢复未完成", err)
	}
	// File restoration is complete independently of its optional component scan.
	// Never keep old runtime evidence or an integrity baseline for replaced code.
	// Existing cache helpers restart the shared OLS instance or invoke unbounded
	// redis-cli scans. Neither is an appropriate implicit per-site restore step.
	warnings := []string{"磁盘文件恢复已完成；运行中的 PHP OPcache、页面缓存、Redis 和 CDN 缓存仍需核对或手动清理，线上新代码执行尚未验证"}
	if _, err = db.ExecContext(ctx, `UPDATE websites SET updated_at=CURRENT_TIMESTAMP WHERE id=?`, site.ID); err != nil {
		warnings = append(warnings, "网站更新时间未保存")
	}
	invalidateFileRestoreSecurityCache(site.ID)
	if site.FileLockEnabled {
		if err = writeFileIntegrityBaseline(ctx, site); err != nil {
			_ = RemoveWPCodeIntegrityBaseline(site.ID)
			warnings = append(warnings, "代码完整性基线刷新失败，请重新检查文件保护")
		}
	} else if err = RemoveWPCodeIntegrityBaseline(site.ID); err != nil {
		warnings = append(warnings, "旧代码完整性基线清理失败")
	}
	refresh, err := NewWPInventoryService(db)
	if err == nil {
		_, err = refresh.Refresh(ctx, site.ID, time.Now().UTC())
	}
	if err != nil {
		warnings = append(warnings, "组件扫描未排队，请在 WordPress 维护中刷新")
	}
	message := "全量网站文件已恢复；保留当前 wp-config.php 和面板管理代码，数据库未恢复。恢复前副本: " + safety
	if len(warnings) != 0 {
		message += "；" + strings.Join(warnings, "；")
	}
	return TaskResult{Success: true, Message: message, Data: map[string]interface{}{
		"backup_id": payload.BackupID, "scope": "full_files", "safety_path": safety,
		"preserved_current_config": true, "preserved_panel_code": true,
		"database_restored": false, "warnings": warnings,
	}}
}

func loadFileRestoreSite(ctx context.Context, db *sql.DB, id int) (*models.Website, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	s := &models.Website{ID: id}
	err := db.QueryRowContext(ctx, `SELECT domain,web_root,system_user,site_type,status,file_lock_enabled,file_lock_mode,file_lock_apply_status,document_root_subdir FROM websites WHERE id=?`, id).Scan(&s.Domain, &s.WebRoot, &s.SystemUser, &s.SiteType, &s.Status, &s.FileLockEnabled, &s.FileLockMode, &s.FileLockApplyStatus, &s.DocumentRootSubdir)
	return s, err
}

func loadFullFileRestoreRecord(ctx context.Context, db *sql.DB, siteID, backupID int) (string, int64, error) {
	if db == nil || siteID <= 0 || backupID <= 0 {
		return "", 0, errors.New("文件备份参数无效")
	}
	var name, mode string
	var size int64
	if err := db.QueryRowContext(ctx, `SELECT filename,file_size,mode FROM file_backups WHERE id=? AND site_id=?`, backupID, siteID).Scan(&name, &size, &mode); err != nil {
		return "", 0, errors.New("文件备份不存在或不属于该网站")
	}
	if mode != "full" {
		return "", 0, errors.New("旧增量备份没有可验证的完整链，不能单独恢复；请选择全量文件备份")
	}
	if !validFullFileRestoreName(name) || size <= 0 {
		return "", 0, errors.New("全量文件备份记录无效")
	}
	return name, size, nil
}

func checkFileRestoreSite(ctx context.Context, db *sql.DB, site *models.Website) error {
	if site == nil || site.SiteType != "wordpress" || site.Status != "active" || site.DocumentRootSubdir != "" || strings.TrimSpace(site.SystemUser) == "" {
		return errors.New("仅支持当前运行中的根目录 WordPress 网站")
	}
	if site.FileLockApplyStatus == FileLockApplyStatusApplying || site.FileLockApplyStatus == FileLockApplyStatusFailed {
		return errors.New("文件保护正在应用或状态异常，请先处理")
	}
	if site.FileLockEnabled && (site.FileLockApplyStatus != FileLockApplyStatusReady || EffectiveFileLockMode(site) == FileLockModeLegacy) {
		return errors.New("请先将文件保护设置为已应用的标准或严格模式")
	}
	state, err := websiteSecurityMaintenanceState(ctx, site.ID)
	if err != nil || (state != "locked" && state != "unlocked_permanent") {
		return errors.New("临时维护或回锁状态尚未确认，请先结束维护")
	}
	queries := []string{
		`SELECT COUNT(*) FROM wp_update_tasks WHERE site_id=? AND (status IN ('preparing','queued','running') OR (requires_attention=1 AND manual_disposition=''))`,
		`SELECT COUNT(*) FROM site_migration_locks WHERE site_id=? AND status='active'`,
		`SELECT COUNT(*) FROM website_ai_development_access WHERE site_id=?`,
		`SELECT COUNT(*) FROM site_image_optimization_jobs WHERE site_id=? AND status IN ('queued','running')`,
	}
	for _, query := range queries {
		var n int
		if err = db.QueryRowContext(ctx, query, site.ID).Scan(&n); err != nil {
			return errors.New("无法确认网站持久操作状态")
		}
		if n != 0 {
			return errors.New("网站仍有更新、迁移、AI 访问或图片优化任务，请先结束")
		}
	}
	var migrating int
	if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM site_migration_locks WHERE domain=? AND status='active'`, site.Domain).Scan(&migrating); err != nil {
		return errors.New("无法确认域名迁移状态")
	}
	if migrating != 0 {
		return errors.New("该域名仍有迁移任务，请先结束")
	}
	return ctx.Err()
}

func validFullFileRestoreName(name string) bool {
	return filepath.Base(name) == name && !strings.ContainsAny(name, "/\\:\x00") && strings.HasPrefix(name, "file_full_") && strings.HasSuffix(name, ".tar.gz")
}

func fileRestoreNoSymlinkDirectories(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	for current := abs; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("目录缺失或包含符号链接")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

func validateFileRestoreRoot(wwwRoot, webRoot string) (string, error) {
	abs, err := managedSubpath(wwwRoot, webRoot, "file restore")
	if err != nil {
		return "", err
	}
	if err = fileRestoreNoSymlinkDirectories(abs); err != nil {
		return "", err
	}
	// A website user must not be able to replace its parent directory while
	// archive validation or the atomic exchange is underway.
	for parent := filepath.Dir(abs); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil {
			return "", err
		}
		uid, _, known := wpInventoryFileOwner(info)
		if !known || uid != 0 || info.Mode().Perm()&0022 != 0 {
			return "", errors.New("网站父目录必须由 root 管理且不可被普通用户写入")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return abs, nil
}

func openFileRestoreArchive(name string, size int64) (*os.File, error) {
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() != size || size <= 0 {
		return nil, errors.New("备份大小或文件类型与记录不一致")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != size {
		file.Close()
		return nil, errors.New("备份文件在打开时发生变化")
	}
	return file, nil
}

// Private incoming directory is also the final safety path. Atomic exchange
// installs the prepared tree and retains the previous tree in this one path.
func restoreFullFileArchive(ctx context.Context, site *models.Website, backupID int, taskID string, archive io.Reader, ops fileRestoreOps) (safety string, returnedErr error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	private, err := os.MkdirTemp(filepath.Dir(site.WebRoot), ".ols-wpanel-file-restore-")
	if err != nil {
		return "", err
	}
	if err = os.Chmod(private, 0700); err != nil {
		os.Remove(private)
		return "", err
	}
	if err = ops.verifyPrivate(private); err != nil {
		os.Remove(private)
		return "", err
	}
	safety = filepath.Join(private, "before")
	retained, exchanged := false, false
	defer func() {
		if r := recover(); r != nil {
			returnedErr = fmt.Errorf("恢复阶段异常: %v", r)
		}
		if exchanged && returnedErr != nil {
			// Recovery does not inherit an expired operation deadline.
			if err := ops.exchange(site.WebRoot, safety); err != nil {
				retained = true
				returnedErr = &fileRestoreUnresolvedError{cause: errors.Join(returnedErr, err), safetyPath: safety}
				_ = writeFileRestoreJournal(private, site, backupID, taskID, "rollback_failed", ops.syncDir)
			} else {
				retained = true
				_ = ops.syncDir(filepath.Dir(site.WebRoot))
				_ = ops.syncDir(private)
				_ = writeFileRestoreJournal(private, site, backupID, taskID, "rolled_back", ops.syncDir)
				returnedErr = fmt.Errorf("%w；原网站文件已自动回滚。失败的恢复目录保留于 %s", returnedErr, safety)
			}
		}
		if !retained {
			_ = os.RemoveAll(private)
		}
	}()
	if err = os.Mkdir(safety, 0700); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(safety)
	if err != nil {
		return "", err
	}
	if err = extractFullFileRestore(ctx, archive, root, filepath.Base(site.WebRoot), ops.freeBytes); err == nil {
		err = validateFileRestoreWordPress(root)
	}
	if err == nil {
		err = preserveFileRestoreManagedContent(ctx, site.WebRoot, root)
	}
	if err == nil {
		err = removeFileRestoreGeneratedCaches(root)
	}
	root.Close()
	if err != nil {
		return "", err
	}
	if free, err := ops.freeBytes(safety); err != nil || free < fileRestoreFreeReserve {
		return "", errors.New("恢复目录准备后可用空间不足或无法确认；原网站未切换")
	}
	stagedSite := *site
	stagedSite.WebRoot = safety
	if err = ops.prepare(&stagedSite); err != nil {
		return "", fmt.Errorf("恢复目录权限应用失败: %w", err)
	}
	if err = ops.verify(&stagedSite); err != nil {
		return "", fmt.Errorf("恢复目录权限核验失败: %w", err)
	}
	if err = syncFileRestoreTree(ctx, safety, ops.syncDir, ops.syncFile); err != nil {
		return "", err
	}
	if err = ops.revalidate(ctx); err != nil {
		return "", err
	}
	if err = writeFileRestoreJournal(private, site, backupID, taskID, "prepared", ops.syncDir); err != nil {
		return "", err
	}
	if err = ctx.Err(); err != nil {
		return "", err
	}
	if err = ops.exchange(site.WebRoot, safety); err != nil {
		return "", fmt.Errorf("原子目录切换失败，未修改原网站: %w", err)
	}
	exchanged = true
	if err = ops.syncDir(filepath.Dir(site.WebRoot)); err != nil {
		return safety, err
	}
	if err = ops.syncDir(private); err != nil {
		return safety, err
	}
	if err = ops.verify(site); err != nil {
		return safety, fmt.Errorf("恢复后权限核验失败: %w", err)
	}
	if err = writeFileRestoreJournal(private, site, backupID, taskID, "committed", ops.syncDir); err != nil {
		return safety, err
	}
	retained = true
	return safety, nil
}

func writeFileRestoreJournal(dir string, site *models.Website, backupID int, taskID, state string, syncDir func(string) error) error {
	data, err := json.Marshal(map[string]interface{}{"site_id": site.ID, "backup_id": backupID, "task_id": taskID, "state": state, "web_root": site.WebRoot, "safety_path": filepath.Join(dir, "before"), "scope": "full_files", "database_restored": false, "updated_at": time.Now().UTC()})
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".journal-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, filepath.Join(dir, "journal.json")); err != nil {
		return err
	}
	return syncDir(dir)
}

func extractFullFileRestore(ctx context.Context, source io.Reader, root *os.Root, prefix string, freeBytes func(string) (int64, error)) error {
	remaining, err := freeBytes(root.Name())
	if err != nil {
		return fmt.Errorf("无法核对恢复磁盘空间: %w", err)
	}
	// Additional bounded headroom covers the current config/managed-code copy
	// performed after extraction, while retaining the 1 GiB final reserve.
	reserve := fileRestoreFreeReserve + fileRestoreManagedMaxBytes + 1<<20
	if remaining < reserve {
		return errors.New("恢复至少需要保留 1 GiB 可用磁盘空间")
	}
	gz, err := gzip.NewReader(source)
	if err != nil {
		return errors.New("不是有效的 gzip 全量文件备份")
	}
	defer gz.Close()
	// Bound both file contents and tar metadata/padding, preventing oversized
	// headers or a compressed zero-padding bomb from bypassing file-size limits.
	reader := &io.LimitedReader{R: gz, N: fileRestoreMaxBytes + 512*fileRestoreMaxEntries + 1<<20}
	tr := tar.NewReader(reader)
	seen := make(map[string]bool)
	var bytes int64
	var sinceSample int64
	for count := 0; ; count++ {
		if err = ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取 tar 备份失败: %w", err)
		}
		if count >= fileRestoreMaxEntries {
			return errors.New("备份文件数量超过恢复上限")
		}
		name := strings.TrimSuffix(hdr.Name, "/")
		if name == "" || strings.ContainsAny(name, "\\:\x00") || path.IsAbs(name) || path.Clean(name) != name {
			return errors.New("备份包含不安全路径")
		}
		if name != prefix && !strings.HasPrefix(name, prefix+"/") {
			return errors.New("备份内容不属于当前网站根目录")
		}
		name = strings.TrimPrefix(strings.TrimPrefix(name, prefix), "/")
		if seen[name] {
			return errors.New("备份包含重复路径")
		}
		seen[name] = true
		if hdr.Typeflag != tar.TypeDir && hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return errors.New("备份包含链接或特殊文件，不能安全恢复")
		}
		if name == "" {
			if hdr.Typeflag != tar.TypeDir {
				return errors.New("备份根目录类型无效")
			}
			continue
		}
		if hdr.Size < 0 || hdr.Size > fileRestoreMaxBytes-bytes {
			return errors.New("备份解包大小超过恢复上限")
		}
		// Resample periodically and before a large file. Reserve space using the
		// tar declaration before writing, rather than waiting for ENOSPC.
		if (count > 0 && count%32 == 0) || sinceSample >= 64<<20 || hdr.Size >= 64<<20 {
			remaining, err = freeBytes(root.Name())
			if err != nil {
				return fmt.Errorf("无法重新核对恢复磁盘空间: %w", err)
			}
			sinceSample = 0
		}
		if remaining < reserve || hdr.Size > remaining-reserve {
			return errors.New("备份解包空间不足；需要保留至少 1 GiB 可用空间，原网站未切换")
		}
		remaining -= hdr.Size
		sinceSample += hdr.Size
		bytes += hdr.Size
		if hdr.Typeflag == tar.TypeDir {
			if hdr.Size != 0 {
				return errors.New("备份目录大小无效")
			}
			if err = root.MkdirAll(name, 0700); err != nil {
				return err
			}
			continue
		}
		if err = root.MkdirAll(path.Dir(name), 0700); err != nil {
			return err
		}
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		n, copyErr := copyWithContext(ctx, file, tr)
		if copyErr == nil && n != hdr.Size {
			copyErr = io.ErrUnexpectedEOF
		}
		if copyErr == nil {
			copyErr = file.Sync()
		}
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	// tar EOF precedes the gzip trailer. Consume only normal zero tar padding,
	// checking the gzip checksum and rejecting concatenated nonzero payloads.
	buffer := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, readErr := reader.Read(buffer)
		for _, b := range buffer[:n] {
			if b != 0 {
				return errors.New("备份 tar 结尾包含额外内容")
			}
		}
		if readErr == io.EOF {
			if reader.N <= 0 {
				return errors.New("备份解压流超过恢复上限")
			}
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("备份 gzip 校验失败: %w", readErr)
		}
	}
}

func validateFileRestoreWordPress(root *os.Root) error {
	for _, name := range []string{"index.php", "wp-config.php", "wp-load.php", "wp-settings.php", "wp-includes/version.php"} {
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return errors.New("全量备份缺少必要的 WordPress 文件")
		}
	}
	for _, name := range []string{"wp-admin", "wp-includes", "wp-content"} {
		info, err := root.Lstat(name)
		if err != nil || !info.IsDir() {
			return errors.New("全量备份缺少必要的 WordPress 目录")
		}
	}
	return nil
}

func verifyFileRestorePrivateDirectory(name string) error {
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	uid, _, known := wpInventoryFileOwner(info)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || !known || uid != 0 {
		return errors.New("恢复安全副本目录必须由 root 独占")
	}
	return nil
}

func removeFileRestoreGeneratedCaches(root *os.Root) error {
	// The same LSCache directories are disposable in ClearSiteCache; unlike
	// that helper this only removes archive contents from private staging and
	// never regenerates a vhost or restarts the shared web server.
	for _, name := range []string{".lscache", "wp-content/cache", "wp-content/litespeed", "wp-content/upgrade"} {
		if err := root.RemoveAll(name); err != nil {
			return err
		}
	}
	return nil
}

func preserveFileRestoreManagedContent(ctx context.Context, live string, target *os.Root) error {
	source, err := os.OpenRoot(live)
	if err != nil {
		return err
	}
	defer source.Close()
	if err = target.Remove("wp-config.php"); err != nil {
		return err
	}
	if err = copyFileRestoreRegular(ctx, source, target, "wp-config.php", 1<<20); err != nil {
		return fmt.Errorf("保留当前网站配置失败: %w", err)
	}
	// Do not carry an old, expired update-maintenance marker into the live tree.
	if err = target.Remove(".maintenance"); err != nil && !os.IsNotExist(err) {
		return err
	}
	managedPlugin := "wp-content/plugins/" + pluginDirName
	var managedBytes int64
	if err = target.RemoveAll(managedPlugin); err != nil {
		return err
	}
	if info, err := source.Lstat(managedPlugin); err == nil {
		if !info.IsDir() {
			return errors.New("当前面板管理插件目录无效")
		}
		count := 0
		if err = fs.WalkDir(source.FS(), managedPlugin, func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			count++
			if count > 20000 {
				return errors.New("管理插件文件数量异常")
			}
			if entry.IsDir() {
				return target.MkdirAll(name, 0700)
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() > fileRestoreManagedMaxBytes-managedBytes {
				return errors.New("管理插件包含不安全文件或大小异常")
			}
			managedBytes += info.Size()
			return copyFileRestoreRegular(ctx, source, target, name, info.Size())
		}); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	mu := "wp-content/mu-plugins"
	if err = target.MkdirAll(mu, 0700); err != nil {
		return err
	}
	entries, err := readFileRestoreManagedDirectory(target, mu)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "ols-wpanel-") && strings.HasSuffix(entry.Name(), ".php") {
			if err = target.RemoveAll(mu + "/" + entry.Name()); err != nil {
				return err
			}
		}
	}
	entries, err = readFileRestoreManagedDirectory(source, mu)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "ols-wpanel-") && strings.HasSuffix(entry.Name(), ".php") {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > fileRestoreManagedMaxBytes-managedBytes {
				return errors.New("管理 MU 代码大小或文件类型异常")
			}
			managedBytes += info.Size()
			if err = copyFileRestoreRegular(ctx, source, target, mu+"/"+entry.Name(), 1<<20); err != nil {
				return err
			}
		}
	}
	return nil
}

func readFileRestoreManagedDirectory(root *os.Root, name string) ([]fs.DirEntry, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("管理代码目录不是普通目录")
	}
	dir, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(20001)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 20000 {
		return nil, errors.New("管理代码目录文件数量异常")
	}
	return entries, nil
}

func copyFileRestoreRegular(ctx context.Context, source, target *os.Root, name string, limit int64) error {
	info, err := source.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return errors.New("当前配置或管理代码不是可安全复制的普通文件")
	}
	from, err := source.Open(name)
	if err != nil {
		return err
	}
	defer from.Close()
	opened, err := from.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("当前文件在打开时发生变化")
	}
	if err = target.MkdirAll(path.Dir(name), 0700); err != nil {
		return err
	}
	to, err := target.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := copyWithContext(ctx, to, io.LimitReader(from, limit+1))
	if err == nil && (n != info.Size() || n > limit) {
		err = errors.New("当前文件在复制时发生变化")
	}
	if err == nil {
		err = to.Sync()
	}
	closeErr := to.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func prepareFileRestorePermissions(site *models.Website) error {
	uid, gid, err := siteUserIDs(site.SystemUser)
	if err != nil || uid == 0 {
		return errors.New("网站系统用户身份无效")
	}
	if site.FileLockEnabled {
		return ApplySiteFileLockMode(site, EffectiveFileLockMode(site))
	}
	if err = ApplySiteUnlockedPermissions(site); err != nil {
		return err
	}
	managed := filepath.Join(site.WebRoot, "wp-content", "plugins", pluginDirName)
	if _, err = os.Lstat(managed); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return sealCompanionDirectory(managed, gid)
}

func verifyFileRestorePermissions(site *models.Website) error {
	if site.FileLockEnabled {
		return VerifySiteFileLockMode(site, EffectiveFileLockMode(site))
	}
	uid, gid, err := siteUserIDs(site.SystemUser)
	if err != nil || uid == 0 {
		return errors.New("网站系统用户身份无效")
	}
	return filepath.WalkDir(site.WebRoot, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("恢复目录包含不安全文件")
		}
		gotUID, gotGID, err := fileOwnerIDs(info)
		mode := os.FileMode(0644)
		if entry.IsDir() {
			mode = 0755
		} else if name == filepath.Join(site.WebRoot, "wp-config.php") {
			mode = 0600
		}
		wantUID := uid
		managed := filepath.Join(site.WebRoot, "wp-content", "plugins", pluginDirName)
		if name == managed || strings.HasPrefix(name, managed+string(filepath.Separator)) {
			wantUID = 0
			mode = 0444
			if entry.IsDir() {
				mode = 0555
			}
		}
		if err != nil || gotUID != wantUID || gotGID != gid || info.Mode().Perm() != mode {
			return errors.New("恢复目录权限与当前网站策略不一致")
		}
		return nil
	})
}

func syncFileRestoreTree(ctx context.Context, dir string, syncDir func(string) error, syncFile func(*os.File) error) error {
	return filepath.WalkDir(dir, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return syncDir(name)
		}
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		err = syncFile(file)
		closeErr := file.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}

func invalidateFileRestoreSecurityCache(siteID int) {
	websiteSecurityVerificationCache.Lock()
	defer websiteSecurityVerificationCache.Unlock()
	prefix := fmt.Sprintf("%d:", siteID)
	for key := range websiteSecurityVerificationCache.entries {
		if strings.HasPrefix(key, prefix) {
			delete(websiteSecurityVerificationCache.entries, key)
		}
	}
}

// A failed atomic rollback leaves the installed tree uncertain. Do not retain
// a ready lock badge or old request/integrity evidence for that tree.
func markFileRestoreUnresolved(ctx context.Context, db *sql.DB, site *models.Website, removeBaseline func(int) error) error {
	invalidateFileRestoreSecurityCache(site.ID)
	var stateErr error
	if site.FileLockEnabled {
		_, stateErr = db.ExecContext(ctx, `UPDATE websites SET file_lock_apply_status='failed',updated_at=CURRENT_TIMESTAMP WHERE id=?`, site.ID)
	}
	return errors.Join(stateErr, removeBaseline(site.ID))
}
