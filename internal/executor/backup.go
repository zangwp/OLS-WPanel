package executor

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

const databaseBackupCommandTimeout = 6 * time.Hour

var databaseBackupCommand = newDatabaseBackupCommand
var restoreBackupPassword = readMariaDBPassword
var databaseBackupPassword = readMariaDBPassword

func executeCreateBackup(task *Task) TaskResult {
	payload, ok := task.Payload.(*CreateBackupPayload)
	if !ok || payload == nil || payload.Site == nil {
		return TaskResult{Success: false, Message: "任务参数类型错误"}
	}

	site := payload.Site
	if payload.SiteOperation != nil {
		if !databaseBackupSiteOperationOwned(site.ID, payload.SiteOperation) {
			return TaskResult{Success: false, Message: "备份失败: 原网站操作归属已失效"}
		}
	} else {
		if !TryAcquireSiteOpLock(site.ID, "database_backup") {
			return TaskResult{Success: false, Message: "网站维护操作尚未结束，数据库备份未执行"}
		}
		defer ReleaseSiteOpLock(site.ID)
	}
	cfg := config.AppConfig
	if cfg == nil || strings.TrimSpace(cfg.Panel.BackupDir) == "" {
		return TaskResult{Success: false, Message: "备份目录未配置"}
	}

	backupDir := filepath.Join(cfg.Panel.BackupDir, site.Domain, "db")
	os.MkdirAll(backupDir, 0700)

	ts := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s.sql.gz", site.Domain, ts)
	filePath := filepath.Join(backupDir, filename)

	dbPass := databaseBackupPassword()
	if dbPass == "" {
		return TaskResult{Success: false, Message: "无法读取 MariaDB root 密码"}
	}

	if err := dumpDatabaseToGzip(site.DBName, dbPass, filePath); err != nil {
		return TaskResult{Success: false, Message: "备份失败: " + err.Error()}
	}

	info, _ := os.Stat(filePath)
	size := int64(0)
	if info != nil {
		size = info.Size()
	}

	db := database.GetDB()
	autoVal := 0
	if payload.Auto {
		autoVal = 1
	}
	if _, err := db.Exec(`INSERT INTO db_backups (site_id, filename, file_size, db_name, auto) VALUES (?, ?, ?, ?, ?)`,
		site.ID, filename, size, site.DBName, autoVal); err != nil {
		log.Printf("备份记录写入 db_backups 失败 [%s]: %v", site.Domain, err)
		os.Remove(filePath)
		return TaskResult{Success: false, Message: "备份记录保存失败: " + err.Error()}
	}

	SyncBackupToRemote(filePath, BackupSourceDB, site.ID, filename)

	cleanupOldBackups(site.ID, site.Domain, getKeepCount(site.ID))

	return TaskResult{Success: true, Message: "备份完成: " + filename}
}

func executeRestoreBackup(task *Task) TaskResult {
	payload, ok := task.Payload.(*RestoreBackupPayload)
	if !ok || payload == nil {
		return TaskResult{Success: false, Message: "任务参数类型错误"}
	}
	// Ownership transfers from the upload handler at queue admission, including
	// when this task subsequently fails a site, permission or credential check.
	if payload.RemoveFileAfter && payload.FilePath != "" {
		uploadPath, valid := ownedRestoreUploadPath(payload.FilePath)
		if !valid {
			return TaskResult{Message: "恢复失败: 上传文件路径不合法"}
		}
		defer os.Remove(uploadPath)
	}

	site := payload.Site
	if site == nil {
		return TaskResult{Success: false, Message: "恢复失败: 网站不存在"}
	}
	if payload.UpdateBackupPath != "" {
		// The update-backup handler transferred its already-held site lock.
		defer ReleaseSiteOpLock(site.ID)
	} else {
		if !TryAcquireSiteOpLock(site.ID, "restore") {
			return TaskResult{Success: false, Message: "网站维护操作尚未结束"}
		}
		defer ReleaseSiteOpLock(site.ID)
	}
	if blocked, err := database.IsAIDevelopmentAccessBlocking(context.Background(), database.GetDB(), int64(site.ID)); err != nil {
		return TaskResult{Success: false, Message: "检查 AI 开发授权失败"}
	} else if blocked {
		return TaskResult{Success: false, Message: "该网站已开启 AI 开发访问，请先关闭授权"}
	}
	guardCtx, guardCancel := context.WithTimeout(context.Background(), 5*time.Second)
	currentSite, guardErr := validateDatabaseRestoreSite(guardCtx, database.GetDB(), site, payload.UpdateBackupPath != "")
	guardCancel()
	if guardErr != nil {
		return TaskResult{Success: false, Message: "恢复前网站检查失败: " + guardErr.Error()}
	}
	site = currentSite
	cfg := config.AppConfig
	if cfg == nil || strings.TrimSpace(cfg.Panel.BackupDir) == "" {
		return TaskResult{Success: false, Message: "恢复失败: 备份目录未配置"}
	}
	dbPass := restoreBackupPassword()
	if dbPass == "" {
		return TaskResult{Success: false, Message: "无法读取 MariaDB root 密码"}
	}

	var filePath string
	if payload.UpdateBackupPath != "" {
		if !wpUpdateSHA256Pattern.MatchString(payload.ExpectedSHA256) {
			return TaskResult{Success: false, Message: "恢复失败: 更新备份参数不合法"}
		}
		artifactRoot := filepath.Join(filepath.Clean(cfg.Panel.BackupDir), "wp-updates")
		cleanPath := filepath.Clean(payload.UpdateBackupPath)
		if !filepath.IsAbs(cleanPath) || !pathWithin(artifactRoot, cleanPath, false) {
			return TaskResult{Success: false, Message: "恢复失败: 更新备份路径不合法"}
		}
		info, err := os.Lstat(cleanPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return TaskResult{Success: false, Message: "恢复失败: 更新备份文件不可用"}
		}
		actual, _, err := hashRegularFile(cleanPath)
		if err != nil || actual != payload.ExpectedSHA256 {
			return TaskResult{Success: false, Message: "恢复失败: 更新备份校验失败"}
		}
		filePath = cleanPath
	} else if payload.FilePath != "" {
		cleanPath, valid := ownedRestoreUploadPath(payload.FilePath)
		if !valid {
			return TaskResult{Success: false, Message: "恢复失败: 文件路径不合法"}
		}
		filePath = cleanPath
	} else {
		backupDir := filepath.Join(cfg.Panel.BackupDir, site.Domain, "db")
		filePath = filepath.Join(backupDir, payload.Filename)
	}
	if err := validateRestoreBackupFile(filePath); err != nil {
		return TaskResult{Success: false, Message: "恢复文件校验失败: " + err.Error()}
	}
	return restoreDatabaseSafely(int64(site.ID), site.DBName, dbPass, filePath,
		filepath.Join(cfg.Panel.BackupDir, site.Domain, "restore-safety"))
}

func ownedRestoreUploadPath(path string) (string, bool) {
	clean := filepath.Clean(path)
	// Match the upload handler's CreateTemp contract; a malformed internal task
	// must never gain deletion ownership of an arbitrary path.
	return clean, filepath.IsAbs(clean) && filepath.Dir(clean) == filepath.Clean(os.TempDir()) &&
		strings.HasPrefix(filepath.Base(clean), "olswpanel_upload_")
}

func restoreDatabaseFile(filePath, dbName, dbPass string) TaskResult {
	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".gz" {
		return restoreFromGz(filePath, dbName, dbPass)
	}
	if ext == ".sql" {
		return restoreFromSql(filePath, dbName, dbPass)
	}
	if ext == ".zip" {
		return restoreFromZip(filePath, dbName, dbPass)
	}
	return TaskResult{Success: false, Message: "不支持的备份文件格式"}
}

// Keep safety snapshots outside normal backup retention. A concurrent scheduled
// backup must never remove the only rollback copy while an import is in progress.
func restoreDatabaseSafely(siteID int64, dbName, dbPass, source, safetyRoot string) TaskResult {
	if err := os.MkdirAll(safetyRoot, 0700); err != nil {
		return TaskResult{Message: "创建恢复前备份目录失败: " + err.Error()}
	}
	dir, err := os.MkdirTemp(safetyRoot, "restore-*")
	if err != nil {
		return TaskResult{Message: "创建恢复前备份目录失败: " + err.Error()}
	}
	snapshot := filepath.Join(dir, "before-restore.sql.gz")
	keepSnapshot := false
	defer func() {
		if !keepSnapshot {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := dumpDatabaseToGzipWithOptions(dbName, dbPass, snapshot, "--routines", "--events", "--triggers"); err != nil {
		return TaskResult{Message: "创建恢复前备份失败，数据库未修改: " + err.Error()}
	}
	if err := verifyDatabaseSnapshot(snapshot); err != nil {
		return TaskResult{Message: "恢复前备份校验失败，数据库未修改: " + err.Error()}
	}

	// Preserve the verified copy if execution panics or rollback itself fails.
	keepSnapshot = true
	// The dump may take time. Recheck the selected site's database binding
	// before creating an import account or starting any other SQL operation.
	guardCtx, guardCancel := context.WithTimeout(context.Background(), 5*time.Second)
	guardErr := verifyDatabaseRestoreBinding(guardCtx, database.GetDB(), siteID, dbName)
	guardCancel()
	if guardErr != nil {
		return TaskResult{Message: guardErr.Error() + "；数据库未修改；恢复前备份已保留: " + snapshot}
	}
	databaseChanged := false
	result := restoreDatabaseFileBefore(source, dbName, dbPass, func() error {
		// This callback runs only after isolated account/permission checks
		// succeed. A setup or ownership failure leaves original data intact.
		databaseChanged = true
		return clearRestoreDatabase(siteID, dbName, dbPass)
	})
	if result.Success {
		keepSnapshot = false
		return result
	}
	if !databaseChanged {
		keepSnapshot = false
		result.Message += "；数据库未修改"
		return result
	}
	if err := clearRestoreDatabase(siteID, dbName, dbPass); err != nil {
		return TaskResult{Message: result.Message + "；自动回滚失败: " + err.Error() + "；恢复前备份已保留: " + snapshot}
	}
	rollback := restoreDatabaseSnapshot(snapshot, dbName, dbPass)
	if !rollback.Success {
		return TaskResult{Message: result.Message + "；自动回滚失败: " + rollback.Message + "；恢复前备份已保留: " + snapshot}
	}
	keepSnapshot = false
	return TaskResult{Message: result.Message + "；已自动恢复到操作前的数据库"}
}

func restoreDatabaseFileBefore(path, dbName, password string, before func() error) TaskResult {
	file, err := os.Open(path)
	if err != nil {
		return TaskResult{Message: "读取备份文件失败"}
	}
	defer file.Close()
	var src io.Reader = file
	switch strings.ToLower(filepath.Ext(path)) {
	case ".gz":
		gz, err := gzip.NewReader(file)
		if err != nil {
			return TaskResult{Message: "gzip 备份损坏"}
		}
		defer gz.Close()
		src = gz
	case ".zip":
		info, err := file.Stat()
		if err != nil {
			return TaskResult{Message: "读取 zip 备份失败"}
		}
		archive, err := zip.NewReader(file, info.Size())
		if err != nil {
			return TaskResult{Message: "zip 备份损坏"}
		}
		var selected *zip.File
		for _, entry := range archive.File {
			if !entry.FileInfo().IsDir() && strings.HasSuffix(strings.ToLower(entry.Name), ".sql") {
				selected = entry
				break
			}
		}
		if selected == nil {
			return TaskResult{Message: "zip 文件中未找到 .sql 文件"}
		}
		reader, err := selected.Open()
		if err != nil {
			return TaskResult{Message: "读取 zip 内 SQL 失败"}
		}
		defer reader.Close()
		src = reader
	case ".sql":
	default:
		return TaskResult{Message: "不支持的备份文件格式"}
	}
	return restoreSQLReaderWith(src, dbName, password, func(dst io.Writer, src io.Reader) error {
		if err := before(); err != nil {
			return err
		}
		return filterRestoreSQLBuffered(dst, src)
	})
}

func verifyDatabaseSnapshot(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	// Read to EOF to verify the gzip checksum, including snapshots of empty DBs.
	n, err := io.Copy(io.Discard, gz)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("恢复前备份为空")
	}
	return nil
}

func restoreDatabaseSnapshot(path, dbName, dbPass string) TaskResult {
	f, err := os.Open(path)
	if err != nil {
		return TaskResult{Message: err.Error()}
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return TaskResult{Message: err.Error()}
	}
	defer gz.Close()
	// This file was generated by our own mysqldump, not supplied by an upload.
	// Preserve its triggers and view definers when restoring the original state.
	return restoreSQLReader(gz, dbName, dbPass)
}

func restoreFromGz(filePath, dbName, dbPass string) TaskResult {
	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("读取备份文件失败: %v", err)
		return TaskResult{Success: false, Message: "读取备份文件失败"}
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		log.Printf("恢复失败 gzip: %v", err)
		return TaskResult{Success: false, Message: "恢复失败，gzip 文件损坏或格式不正确"}
	}
	defer gz.Close()
	return restoreSQLReader(gz, dbName, dbPass)
}

func restoreFromSql(filePath, dbName, dbPass string) TaskResult {
	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("读取备份文件失败: %v", err)
		return TaskResult{Success: false, Message: "读取备份文件失败"}
	}
	defer f.Close()
	return restoreSQLReader(f, dbName, dbPass)
}

func restoreFromZip(filePath, dbName, dbPass string) TaskResult {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		log.Printf("解压 zip 失败: %v", err)
		return TaskResult{Success: false, Message: "解压 zip 失败"}
	}
	defer r.Close()

	var sqlFile *zip.File
	for _, f := range r.File {
		if !f.FileInfo().IsDir() && strings.HasSuffix(strings.ToLower(f.Name), ".sql") {
			sqlFile = f
			break
		}
	}
	if sqlFile == nil {
		return TaskResult{Success: false, Message: "zip 文件中未找到 .sql 文件"}
	}

	rc, err := sqlFile.Open()
	if err != nil {
		log.Printf("读取 zip 内文件失败: %v", err)
		return TaskResult{Success: false, Message: "读取 zip 内文件失败"}
	}
	defer rc.Close()

	return restoreSQLReader(rc, dbName, dbPass)
}

func restoreSQLReader(r io.Reader, dbName, dbPass string) TaskResult {
	return restoreSQLReaderWith(r, dbName, dbPass, filterRestoreSQLBuffered)
}

func restoreSQLReaderWith(r io.Reader, dbName, dbPass string, copySQL func(io.Writer, io.Reader) error) TaskResult {
	ctx, cancel := context.WithTimeout(context.Background(), databaseBackupCommandTimeout)
	defer cancel()
	return importDatabaseSQL(ctx, databaseBackupCommand, "mysql", r, dbName, dbPass, copySQL)
}

func importDatabaseSQL(ctx context.Context, command databaseImportCommand, client string, r io.Reader, dbName, dbPass string, copySQL func(io.Writer, io.Reader) error) (result TaskResult) {
	release, err := lockDatabaseImport(ctx, dbName)
	if err != nil {
		return TaskResult{Message: "数据库导入等待已取消"}
	}
	defer release()
	if err := ctx.Err(); err != nil {
		return TaskResult{Message: "数据库导入已取消"}
	}
	identity, password, err := prepareDatabaseImportIdentity(ctx, command, client, dbName, dbPass)
	if err != nil {
		return TaskResult{Message: "恢复失败，无法建立仅限所选数据库的导入身份: " + err.Error()}
	}
	defer func() {
		if err := finishDatabaseImportIdentity(command, client, dbPass, identity); err != nil {
			result.Success = false
			result.Message = "恢复未完成确认: " + err.Error()
		}
	}()
	cmd := command(ctx, client, databaseImportClientArgs(identity.User, dbName)...)
	cmd.Env = databaseImportEnvironment(password)
	configureBackupCommandCancellation(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return TaskResult{Success: false, Message: fmt.Sprintf("创建导入管道失败: %v", err)}
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		log.Printf("恢复失败 mysql start: %v", err)
		return TaskResult{Success: false, Message: "恢复失败，mysql 启动失败"}
	}

	if _, err := io.WriteString(stdin, "SET FOREIGN_KEY_CHECKS=0;\n"); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return TaskResult{Success: false, Message: "恢复失败，初始化 mysql 导入失败: " + err.Error()}
	}
	copyErr := copySQL(stdin, r)
	if copyErr == nil {
		_, copyErr = io.WriteString(stdin, "\nSET FOREIGN_KEY_CHECKS=1;\n")
	}
	closeErr := stdin.Close()
	if copyErr != nil {
		waitErr := cmd.Wait()
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			log.Printf("恢复失败 mysql pipe: %v; mysql: %s", copyErr, msg)
			return TaskResult{Success: false, Message: "恢复失败，mysql 导入错误: " + msg}
		}
		if waitErr != nil {
			log.Printf("恢复失败 mysql pipe: %v; wait: %v", copyErr, waitErr)
			return TaskResult{Success: false, Message: "恢复失败，mysql 导入中断: " + waitErr.Error()}
		}
		return TaskResult{Success: false, Message: "恢复失败，写入 mysql 中断: " + copyErr.Error()}
	}
	if closeErr != nil {
		waitErr := cmd.Wait()
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			log.Printf("恢复失败 mysql close: %v; mysql: %s", closeErr, msg)
			return TaskResult{Success: false, Message: "恢复失败，mysql 导入错误: " + msg}
		}
		if waitErr != nil {
			return TaskResult{Success: false, Message: "恢复失败，mysql 导入中断: " + waitErr.Error()}
		}
		return TaskResult{Success: false, Message: "恢复失败，写入 mysql 失败: " + closeErr.Error()}
	}
	if err := cmd.Wait(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return TaskResult{Success: false, Message: "恢复失败，mysql 导入超时"}
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		log.Printf("恢复失败 mysql: %v: %s", err, msg)
		return TaskResult{Success: false, Message: "恢复失败，mysql 导入错误: " + msg}
	}
	return TaskResult{Success: true, Message: "数据库恢复成功"}
}

func validateRestoreBackupFile(filePath string) error {
	ext := strings.ToLower(filepath.Ext(filePath))
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("文件不存在或不可读取")
	}
	if info.IsDir() || info.Size() == 0 {
		return fmt.Errorf("文件为空或格式不正确")
	}

	switch ext {
	case ".sql":
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("读取 SQL 文件失败")
		}
		defer f.Close()
		return validateRestoreSQL(f)
	case ".gz":
		f, err := os.Open(filePath)
		if err != nil {
			return fmt.Errorf("读取 gzip 文件失败")
		}
		defer f.Close()
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("gzip 文件损坏或格式不正确")
		}
		defer gz.Close()
		return validateRestoreSQL(gz)
	case ".zip":
		zr, err := zip.OpenReader(filePath)
		if err != nil {
			return fmt.Errorf("zip 文件损坏或格式不正确")
		}
		defer zr.Close()
		var sqlFile *zip.File
		for _, f := range zr.File {
			if !f.FileInfo().IsDir() && strings.HasSuffix(strings.ToLower(f.Name), ".sql") {
				sqlFile = f
				break
			}
		}
		if sqlFile == nil {
			return fmt.Errorf("zip 文件中未找到 .sql 文件")
		}
		rc, err := sqlFile.Open()
		if err != nil {
			return fmt.Errorf("读取 zip 内 SQL 文件失败")
		}
		defer rc.Close()
		return validateRestoreSQL(rc)
	default:
		return fmt.Errorf("不支持的备份文件格式")
	}
}

func validateRestoreSQL(r io.Reader) error {
	const maxStatementPrefix = 128
	buf := make([]byte, 32*1024)
	sawCreateTable := false
	statementPrefix := ""
	inStatement := false
	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false
	escaped := false

	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			for _, b := range []byte(chunk) {
				if inSingleQuote || inDoubleQuote {
					if escaped {
						escaped = false
						continue
					}
					if b == '\\' {
						escaped = true
						continue
					}
					if inSingleQuote && b == '\'' {
						inSingleQuote = false
					}
					if inDoubleQuote && b == '"' {
						inDoubleQuote = false
					}
					continue
				}
				if inBacktick {
					if b == '`' {
						inBacktick = false
					}
					continue
				}

				if !inStatement {
					if b == '\r' || b == '\n' || b == '\t' || b == ' ' {
						continue
					}
					inStatement = true
					statementPrefix = ""
				}
				if len(statementPrefix) < maxStatementPrefix {
					statementPrefix += string(b)
					if isCreateTableStatement(statementPrefix) {
						sawCreateTable = true
					}
				}
				if b == '\'' {
					inSingleQuote = true
					continue
				}
				if b == '"' {
					inDoubleQuote = true
					continue
				}
				if b == '`' {
					inBacktick = true
					continue
				}
				if b == ';' {
					inStatement = false
					statementPrefix = ""
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("SQL 文件读取失败")
		}
	}

	if !sawCreateTable {
		return fmt.Errorf("未找到建表语句")
	}
	return nil
}

// restoreSQLWriteBufferSize is shared by every database restore entry point
// (regular backup restore and the WordPress core update rollback) so both
// route through the same buffer sizing instead of drifting independently.
const restoreSQLWriteBufferSize = 256 * 1024

// filterRestoreSQLBuffered is the one entry point every mysql-stdin restore
// path must use to stream SQL through writeSanitizedRestoreSQL. dst is
// typically a raw OS pipe (mysql's stdin): writeSanitizedRestoreSQL writes
// non-skipped bytes to dst one at a time, so writing straight to a pipe turns
// a multi-GB import into a syscall per byte. Wrapping dst in a bufio.Writer
// here coalesces those into buffer-sized writes; callers still own closing
// the underlying destination after this returns.
func filterRestoreSQLBuffered(dst io.Writer, src io.Reader) error {
	buffered := bufio.NewWriterSize(dst, restoreSQLWriteBufferSize)
	reader, writer := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := rebindDatabaseRestoreDefiners(writer, src)
		_ = writer.CloseWithError(err)
		done <- err
	}()
	err := writeSanitizedRestoreSQL(buffered, reader)
	_ = reader.CloseWithError(err)
	transformErr := <-done
	if err != nil {
		return err
	}
	if transformErr != nil {
		return transformErr
	}
	return buffered.Flush()
}

func writeSanitizedRestoreSQL(dst io.Writer, src io.Reader) error {
	const maxStatementPrefix = 256
	buf := make([]byte, 32*1024)
	prefix := ""
	held := make([]byte, 0, maxStatementPrefix)
	inStatement := false
	skipStatement := false
	decisionMade := false
	inSingleQuote := false
	inDoubleQuote := false
	inBacktick := false
	escaped := false

	flushHeld := func() error {
		if len(held) == 0 {
			return nil
		}
		_, err := dst.Write(held)
		held = held[:0]
		return err
	}

	for {
		n, err := src.Read(buf)
		if n > 0 {
			for _, b := range buf[:n] {
				outsideString := !inSingleQuote && !inDoubleQuote && !inBacktick
				if outsideString && !inStatement {
					if b == '\r' || b == '\n' || b == '\t' || b == ' ' {
						if _, err := dst.Write([]byte{b}); err != nil {
							return err
						}
						continue
					}
					inStatement = true
					skipStatement = false
					decisionMade = false
					prefix = ""
					held = held[:0]
				}

				if inStatement && outsideString && !decisionMade && len(prefix) < maxStatementPrefix {
					prefix += string(b)
					held = append(held, b)
					if skip, decided := restoreStatementDecision(prefix); decided {
						decisionMade = true
						skipStatement = skip
						if !skipStatement {
							if err := flushHeld(); err != nil {
								return err
							}
						}
						if skipStatement && b == ';' {
							inStatement = false
							skipStatement = false
							decisionMade = false
							prefix = ""
							held = held[:0]
						}
						continue
					}
					if len(prefix) >= maxStatementPrefix {
						decisionMade = true
						if err := flushHeld(); err != nil {
							return err
						}
					}
					continue
				}

				if !skipStatement {
					if err := flushHeld(); err != nil {
						return err
					}
					if _, err := dst.Write([]byte{b}); err != nil {
						return err
					}
				}

				if inSingleQuote || inDoubleQuote {
					if escaped {
						escaped = false
					} else if b == '\\' {
						escaped = true
					} else if inSingleQuote && b == '\'' {
						inSingleQuote = false
					} else if inDoubleQuote && b == '"' {
						inDoubleQuote = false
					}
				} else if inBacktick {
					if b == '`' {
						inBacktick = false
					}
				} else {
					if b == '\'' {
						inSingleQuote = true
					} else if b == '"' {
						inDoubleQuote = true
					} else if b == '`' {
						inBacktick = true
					} else if b == ';' {
						inStatement = false
						skipStatement = false
						decisionMade = false
						prefix = ""
						held = held[:0]
					}
				}
			}
		}
		if err == io.EOF {
			if !skipStatement {
				if err := flushHeld(); err != nil {
					return err
				}
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func restoreStatementDecision(prefix string) (skip, decided bool) {
	normalized := normalizeSQLPrefix(prefix)
	if normalized == "" {
		return false, false
	}
	fields := strings.Fields(normalized)
	if len(fields) == 0 {
		return false, false
	}
	switch fields[0] {
	case "USE":
		return true, true
	case "CREATE":
		if len(fields) < 2 {
			return false, false
		}
		if fields[1] == "DATABASE" {
			return true, true
		}
		if strings.HasPrefix("DATABASE", fields[1]) {
			return false, false
		}
		return false, true
	case "DROP":
		if len(fields) < 2 {
			return false, false
		}
		if strings.HasPrefix("DATABASE", fields[1]) && fields[1] != "DATABASE" {
			return false, false
		}
		return fields[1] == "DATABASE", true
	default:
		if !strings.ContainsAny(prefix, " \t\r\n") {
			if strings.HasPrefix("USE", fields[0]) || strings.HasPrefix("CREATE", fields[0]) || strings.HasPrefix("DROP", fields[0]) {
				return false, false
			}
		}
		return false, true
	}
}

func isCreateTableStatement(prefix string) bool {
	return strings.HasPrefix(normalizeSQLPrefix(prefix), "CREATE TABLE")
}

func normalizeSQLPrefix(s string) string {
	s = strings.ToUpper(s)
	for {
		start := strings.Index(s, "/*")
		if start < 0 {
			break
		}
		end := strings.Index(s[start+2:], "*/")
		if end < 0 {
			s = s[:start]
			break
		}
		s = s[:start] + " " + s[start+2+end+2:]
	}
	for {
		start := strings.Index(s, "--")
		if start < 0 {
			break
		}
		end := strings.IndexByte(s[start:], '\n')
		if end < 0 {
			s = s[:start]
			break
		}
		s = s[:start] + " " + s[start+end+1:]
	}
	for {
		start := strings.Index(s, "#")
		if start < 0 {
			break
		}
		end := strings.IndexByte(s[start:], '\n')
		if end < 0 {
			s = s[:start]
			break
		}
		s = s[:start] + " " + s[start+end+1:]
	}
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}

// ClearDatabaseTables 清空指定数据库中的所有表（保留数据库本身）
func ClearDatabaseTables(siteID int64, dbName, dbPass string) error {
	return clearDatabaseObjects(siteID, dbName, dbPass, false)
}

func clearRestoreDatabase(siteID int64, dbName, dbPass string) error {
	return clearDatabaseObjects(siteID, dbName, dbPass, true)
}

func clearDatabaseObjects(siteID int64, dbName, dbPass string, allObjects bool) error {
	if siteID <= 0 {
		return fmt.Errorf("invalid site ID")
	}
	if blocked, err := database.IsAIDevelopmentAccessBlocking(context.Background(), database.GetDB(), siteID); err != nil {
		return fmt.Errorf("检查 AI 开发授权失败: %w", err)
	} else if blocked {
		return fmt.Errorf("该网站已开启 AI 开发访问，请先关闭授权")
	}
	guardCtx, guardCancel := context.WithTimeout(context.Background(), 5*time.Second)
	guardErr := verifyDatabaseRestoreBinding(guardCtx, database.GetDB(), siteID, dbName)
	guardCancel()
	if guardErr != nil {
		return guardErr
	}
	if !isValidMySQLIdentifier(dbName) {
		return fmt.Errorf("invalid database name")
	}
	if dbPass == "" {
		return fmt.Errorf("无法读取数据库密码")
	}

	ctx, cancel := context.WithTimeout(context.Background(), databaseBackupCommandTimeout)
	defer cancel()
	query := fmt.Sprintf("SELECT CONCAT('DROP TABLE IF EXISTS `', REPLACE(TABLE_NAME, '`', '``'), '`;') FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = '%s' AND TABLE_TYPE = 'BASE TABLE'", dbName)
	if allObjects {
		query = databaseRestoreDropQuery(dbName)
	}
	cmd := databaseBackupCommand(ctx, "mysql", databaseImportClientArgs("root", "--raw", "-N", "-e", query)...)
	cmd.Env = databaseImportEnvironment(dbPass)
	dropSQL, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("获取表列表失败: %s", string(dropSQL))
	}

	mysqlCmd := databaseBackupCommand(ctx, "mysql", databaseImportClientArgs("root", dbName)...)
	mysqlCmd.Env = databaseImportEnvironment(dbPass)
	stdin, err := mysqlCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("准备数据库操作失败")
	}
	var stderr bytes.Buffer
	mysqlCmd.Stderr = &stderr
	if err := mysqlCmd.Start(); err != nil {
		return fmt.Errorf("启动数据库操作失败")
	}
	_, writeErr := fmt.Fprintf(stdin, "SET FOREIGN_KEY_CHECKS = 0;\n%s\nSET FOREIGN_KEY_CHECKS = 1;\n", string(dropSQL))
	closeErr := stdin.Close()
	waitErr := mysqlCmd.Wait()
	if writeErr != nil || closeErr != nil || waitErr != nil {
		return fmt.Errorf("清空数据库失败: %s", stderr.String())
	}
	return nil
}

type automaticDatabaseBackup struct {
	siteID    int
	keepCount int
	domain    string
	dbName    string
}

func executeAutoBackups() {
	db := database.GetDB()

	rows, err := db.Query(`SELECT bs.site_id, bs.keep_count, w.domain, w.db_name FROM backup_settings bs
		JOIN websites w ON w.id = bs.site_id WHERE bs.enabled = 1 AND w.status = 'active'
		AND NOT EXISTS (SELECT 1 FROM site_migration_locks ml WHERE ml.site_id=w.id AND ml.status='active')`)
	if err != nil {
		log.Printf("自动备份: 查询 backup_settings 失败: %v", err)
		return
	}
	var tasks []automaticDatabaseBackup
	for rows.Next() {
		var t automaticDatabaseBackup
		if rows.Scan(&t.siteID, &t.keepCount, &t.domain, &t.dbName) == nil {
			tasks = append(tasks, t)
		}
	}
	rows.Close()

	dbPass := databaseBackupPassword()
	if dbPass == "" {
		log.Printf("自动备份: 无法读取 MariaDB root 密码，跳过")
		return
	}

	count := 0
	failCount := 0
	skipCount := 0
	for _, t := range tasks {
		completed, skipped, err := executeAutomaticDatabaseBackup(t, dbPass)
		if err != nil {
			log.Printf("自动备份失败 [%s]: %v", t.domain, err)
			failCount++
			continue
		}
		if skipped != "" {
			log.Printf("自动备份跳过 [%s]: %s", t.domain, skipped)
			skipCount++
			continue
		}
		if completed {
			count++
		}
	}
	log.Printf("自动备份完成: 成功 %d, 失败 %d, 跳过 %d", count, failCount, skipCount)
}

// Only the independent scheduler owns this slot. Lower-level dump helpers stay
// ungated because full-site/update safety snapshots already hold a site slot.
func executeAutomaticDatabaseBackup(task automaticDatabaseBackup, dbPass string) (bool, string, error) {
	if !TryAcquireSiteOpLock(task.siteID, "automatic_database_backup") {
		return false, "site_operation_busy", nil
	}
	defer ReleaseSiteOpLock(task.siteID)
	allowed, reason, err := siteScheduledWorkAllowed(task.siteID)
	if err != nil {
		return false, "", fmt.Errorf("检查网站运行状态失败: %w", err)
	}
	if !allowed {
		return false, "site_runtime_suspended:" + reason, nil
	}
	cfg := config.AppConfig
	if cfg == nil || strings.TrimSpace(cfg.Panel.BackupDir) == "" {
		return false, "", errors.New("备份目录未配置")
	}
	backupDir := filepath.Join(cfg.Panel.BackupDir, task.domain, "db")
	filename := fmt.Sprintf("%s_%s.sql.gz", task.domain, time.Now().Format("20060102_150405"))
	filePath := filepath.Join(backupDir, filename)
	if err := dumpDatabaseToGzip(task.dbName, dbPass, filePath); err != nil {
		return false, "", err
	}
	info, err := os.Stat(filePath)
	if err != nil {
		os.Remove(filePath)
		return false, "", fmt.Errorf("读取完成的备份文件失败: %w", err)
	}
	if _, err := database.GetDB().Exec(`INSERT INTO db_backups (site_id, filename, file_size, db_name, auto) VALUES (?, ?, ?, ?, 1)`,
		task.siteID, filename, info.Size(), task.dbName); err != nil {
		os.Remove(filePath)
		return false, "", fmt.Errorf("保存备份记录失败: %w", err)
	}
	SyncBackupToRemote(filePath, BackupSourceDB, task.siteID, filename)
	keepCount := task.keepCount
	if keepCount <= 0 {
		keepCount = 7
	}
	cleanupOldBackups(task.siteID, task.domain, keepCount)
	return true, "", nil
}

func getKeepCount(siteID int) int {
	var kc int
	if database.GetDB().QueryRow("SELECT keep_count FROM backup_settings WHERE site_id = ?", siteID).Scan(&kc) != nil || kc <= 0 {
		return 7
	}
	return kc
}

func dumpDatabaseToGzip(dbName, dbPass, filePath string) error {
	// Restore now replaces all schema objects; new ordinary/update backups
	// must retain routines/events/triggers as well as tables and views.
	return dumpDatabaseToGzipWithOptions(dbName, dbPass, filePath, "--routines", "--events", "--triggers")
}

func dumpDatabaseToGzipWithOptions(dbName, dbPass, filePath string, extraOptions ...string) error {
	if !isValidMySQLIdentifier(dbName) {
		return fmt.Errorf("数据库名异常，已拒绝执行")
	}

	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("创建备份目录失败: %w", err)
	}

	outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("创建备份文件失败: %w", err)
	}
	keepFile := false
	fileClosed := false
	defer func() {
		if !fileClosed {
			outFile.Close()
		}
		if !keepFile {
			os.Remove(filePath)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), databaseBackupCommandTimeout)
	defer cancel()
	args := append([]string{"-u", "root"}, extraOptions...)
	args = append(args, dbName)
	cmd := databaseBackupCommand(ctx, "mysqldump", args...)
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+dbPass)
	if err := streamDatabaseDumpToGzip(ctx, cancel, cmd, outFile); err != nil {
		return err
	}
	if err := outFile.Sync(); err != nil {
		return fmt.Errorf("保存备份文件失败: %w", err)
	}
	closeFileErr := outFile.Close()
	fileClosed = true
	if closeFileErr != nil {
		return fmt.Errorf("保存备份文件失败: %w", closeFileErr)
	}
	keepFile = true
	return nil
}

func streamDatabaseDumpToGzip(ctx context.Context, cancel context.CancelFunc, cmd *exec.Cmd, dst io.Writer) error {
	configureBackupCommandCancellation(cmd)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("准备导出失败: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 mysqldump 失败: %w", err)
	}

	gz := gzip.NewWriter(dst)
	copyErr := error(nil)
	if _, err := io.Copy(gz, stdout); err != nil {
		copyErr = err
		// Stop the producer before waiting: after a disk write failure nobody
		// consumes stdout, so mysqldump can otherwise block forever on its pipe.
		cancel()
		_ = stdout.Close()
	}
	closeGzipErr := gz.Close()
	if closeGzipErr != nil {
		cancel()
		_ = stdout.Close()
	}
	waitErr := cmd.Wait()

	if copyErr != nil {
		return fmt.Errorf("写入备份失败: %w", copyErr)
	}
	if closeGzipErr != nil {
		return fmt.Errorf("完成 gzip 写入失败: %w", closeGzipErr)
	}
	if waitErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("mysqldump 执行超时")
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = waitErr.Error()
		}
		return fmt.Errorf("mysqldump 失败: %s", msg)
	}

	return nil
}

type oldDBBackup struct {
	id       int
	filename string
}

func cleanupOldBackups(siteID int, domain string, keepCount int) {
	db := database.GetDB()
	cfg := config.AppConfig

	var total int
	db.QueryRow("SELECT COUNT(*) FROM db_backups WHERE site_id = ?", siteID).Scan(&total)
	if total <= keepCount {
		return
	}

	rows, err := db.Query(`SELECT id, filename FROM db_backups WHERE site_id = ? ORDER BY created_at ASC LIMIT ?`,
		siteID, total-keepCount)
	if err != nil {
		return
	}
	var backups []oldDBBackup
	for rows.Next() {
		var b oldDBBackup
		if rows.Scan(&b.id, &b.filename) == nil {
			backups = append(backups, b)
		}
	}
	rows.Close()
	cleanupOldDBBackupsWith(backups,
		func(filename string) error {
			return os.Remove(filepath.Join(cfg.Panel.BackupDir, domain, "db", filename))
		},
		func(id int) error {
			_, err := db.Exec("DELETE FROM db_backups WHERE id = ?", id)
			return err
		})
}

func cleanupOldDBBackupsWith(backups []oldDBBackup, removeFile func(string) error, deleteRecord func(int) error) {
	for _, b := range backups {
		if err := removeFile(b.filename); err != nil && !os.IsNotExist(err) {
			log.Printf("清理过期数据库备份失败 [%s]: %v", b.filename, err)
			continue
		}
		if err := deleteRecord(b.id); err != nil {
			log.Printf("清理过期数据库备份记录失败 [%s]: %v", b.filename, err)
		}
	}
}

// RunAutoBackup 手动触发一次自动备份，用于测试验证。
func RunAutoBackup() {
	log.Println("手动触发自动备份...")
	executeAutoBackups()
}

func StartAutoBackupScheduler() {
	go func() {
		for {
			now := time.Now()
			next := nextDailyBackupTime(now, 4, 0)
			log.Printf("自动备份调度: 下次执行时间 %s", next.Format("2006-01-02 15:04:05"))
			time.Sleep(next.Sub(now))
			executeAutoBackups()
		}
	}()
}

// StartDBBackupScheduler 面板 SQLite 数据库自动备份调度器（每天凌晨 2:30）
func StartDBBackupScheduler() {
	go func() {
		for {
			now := time.Now()
			next := nextDailyBackupTime(now, 2, 30)
			time.Sleep(next.Sub(now))
			autoBackupPanelDB()
		}
	}()
}

func autoBackupPanelDB() {
	cfg := config.AppConfig
	backupDir := filepath.Join(cfg.Panel.BackupDir, "panel-db")

	path, err := database.BackupDatabase(backupDir)
	if err != nil {
		log.Printf("面板数据库自动备份失败: %v", err)
		return
	}
	if err := database.VerifyDBBackup(path); err != nil {
		os.Remove(path)
		log.Printf("面板数据库自动备份校验失败，已删除无效备份: %v", err)
		return
	}
	log.Printf("面板数据库自动备份完成: %s", path)

	if removed := database.CleanupOldDBBackups(backupDir, 7); removed > 0 {
		log.Printf("面板数据库备份清理: 删除 %d 个旧备份", removed)
	}
}

func getSiteDomain(siteID int) string {
	var domain string
	database.GetDB().QueryRow("SELECT domain FROM websites WHERE id = ?", siteID).Scan(&domain)
	return domain
}

func readMariaDBPassword() string {
	data, err := os.ReadFile("/www/ols-wpanel/config.json")
	if err != nil {
		return ""
	}
	var cfg struct {
		MariaDB struct {
			RootPassword string `json:"root_password"`
		} `json:"mariadb"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.MariaDB.RootPassword == "" {
		return ""
	}
	return cfg.MariaDB.RootPassword
}
