package executor

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
)

var ErrSecuritySettingsBusy = errors.New("另一个安全设置或官方网段刷新正在执行，请稍后重试")

// The daemon and timer CLI use the same SQLite main database and therefore
// the same private lock inode. No environment variable controls this path.
func securitySettingsLockPath(db *sql.DB) (string, error) {
	if db == nil {
		return "", errors.New("安全设置锁需要已初始化的数据库")
	}
	rows, err := db.Query(`PRAGMA database_list`)
	if err != nil {
		return "", fmt.Errorf("读取安全设置数据库位置失败: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sequence int
		var name, filename string
		if err := rows.Scan(&sequence, &name, &filename); err != nil {
			return "", err
		}
		if name == "main" && filepath.IsAbs(filename) {
			return filepath.Join(filepath.Dir(filename), ".ols-wpanel-security-settings.lock"), nil
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return "", errors.New("安全设置锁需要磁盘上的 SQLite 主数据库")
}

func acquireSecuritySettingsProcessLock(db *sql.DB) (func() error, error) {
	path, err := securitySettingsLockPath(db)
	if err != nil {
		return nil, err
	}
	file, err := openSecuritySettingsLock(path)
	if err != nil {
		return nil, fmt.Errorf("打开安全设置锁失败: %w", err)
	}
	locked, err := tryFileBackupKernelLock(file)
	if err != nil || !locked {
		_ = file.Close()
		if err != nil {
			return nil, fmt.Errorf("获取安全设置锁失败: %w", err)
		}
		return nil, ErrSecuritySettingsBusy
	}
	// Never unlink the pathname: a replacement inode would bypass the lock.
	var once sync.Once
	var closeErr error
	return func() error {
		once.Do(func() {
			closeErr = errors.Join(releaseFileBackupKernelLock(file), file.Close())
		})
		return closeErr
	}, nil
}
