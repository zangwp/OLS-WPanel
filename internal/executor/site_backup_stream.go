package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

type siteBackupDiskWriter struct {
	ctx       context.Context
	file      *os.File
	remaining int64
	written   int64
	free      func(string) (int64, error)
}

func (w *siteBackupDiskWriter) Write(data []byte) (int, error) {
	if err := w.ctx.Err(); err != nil {
		return 0, err
	}
	if w.written > fileRestoreMaxBytes-int64(len(data)) {
		return 0, errors.New("备份压缩组件大小超过安全上限")
	}
	if w.remaining < int64(len(data)) {
		free, err := w.free(filepath.Dir(w.file.Name()))
		if err != nil {
			return 0, err
		}
		if free < fileRestoreFreeReserve+1<<20+int64(len(data)) {
			return 0, errors.New("备份期间磁盘可用空间不足，保留 1 GiB 后停止")
		}
		w.remaining = 1 << 20
	}
	n, err := w.file.Write(data)
	w.remaining -= int64(n)
	w.written += int64(n)
	return n, err
}

func createSiteBackupFileArchive(ctx context.Context, webRoot, path string) (returnedErr error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		if returnedErr != nil {
			_ = os.Remove(path)
		}
	}()
	args := []string{"-czf", "-", "--warning=no-file-changed"}
	args = append(args, siteBackupArtifactExcludes()...)
	args = append(args, "-C", filepath.Dir(webRoot), filepath.Base(webRoot))
	cmd := exec.CommandContext(ctx, "tar", args...)
	configureBackupCommandCancellation(cmd)
	cmd.Stdout = &siteBackupDiskWriter{ctx: ctx, file: file, free: availableFileRestoreBytes}
	cmd.Stderr = io.Discard
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("受控文件归档未完成: %w", err)
	}
	return file.Sync()
}

func dumpSiteBackupDatabase(ctx context.Context, dbName, password, path string) (returnedErr error) {
	if !isValidMySQLIdentifier(dbName) || password == "" {
		return errors.New("数据库备份绑定或凭据不可用")
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		if returnedErr != nil {
			_ = os.Remove(path)
		}
	}()
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := databaseBackupCommand(bounded, "mysqldump", "-u", "root", "--skip-lock-tables", "--skip-dump-date", "--routines", "--events", "--triggers", dbName)
	cmd.Env = append(os.Environ(), "MYSQL_PWD="+password)
	// The streaming helper owns the gzip layer. Pass the guarded disk writer
	// directly so a single decompression yields SQL for the restore path.
	writer := &siteBackupDiskWriter{ctx: ctx, file: file, free: availableFileRestoreBytes}
	if err = streamDatabaseDumpToGzip(bounded, cancel, cmd, writer); err != nil {
		return err
	}
	return file.Sync()
}
