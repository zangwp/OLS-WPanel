package executor

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/database"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// Call only after acquiring (or receiving) the website operation slot. A
// queued restore must not turn an earlier HTTP snapshot into authority over a
// database or domain that has since changed.
func validateDatabaseRestoreSite(ctx context.Context, db *sql.DB, expected *models.Website, updateRecovery bool) (*models.Website, error) {
	if db == nil || expected == nil || expected.ID <= 0 {
		return nil, errors.New("无法读取当前网站绑定")
	}
	var current models.Website
	err := db.QueryRowContext(ctx, `SELECT id,domain,db_name,db_user,system_user,status,file_lock_apply_status FROM websites WHERE id=?`, expected.ID).
		Scan(&current.ID, &current.Domain, &current.DBName, &current.DBUser, &current.SystemUser, &current.Status, &current.FileLockApplyStatus)
	if err != nil {
		return nil, errors.New("当前网站不存在或无法读取")
	}
	if !databaseRestoreStatusAllowed(current.Status) || !IsValidDomain(current.Domain) ||
		!databaseRestoreNameAllowed(current.DBName) || !isValidMySQLIdentifier(current.DBUser) || strings.TrimSpace(current.SystemUser) == "" {
		return nil, errors.New("网站状态或当前数据库绑定不可用于恢复")
	}
	if current.Domain != expected.Domain || current.DBName != expected.DBName ||
		(expected.DBUser != "" && current.DBUser != expected.DBUser) ||
		(expected.SystemUser != "" && current.SystemUser != expected.SystemUser) {
		return nil, errors.New("网站或数据库绑定已变化，请重新提交恢复")
	}
	if current.FileLockApplyStatus == "applying" || current.FileLockApplyStatus == "failed" {
		return nil, errors.New("文件保护或维护状态尚未确认，请先处理")
	}
	state, err := websiteSecurityMaintenanceState(ctx, current.ID)
	if err != nil || (state != "locked" && state != "unlocked_permanent") {
		return nil, errors.New("临时维护或回锁状态尚未确认，请先结束维护")
	}
	blocked, err := database.IsAIDevelopmentAccessBlocking(ctx, db, int64(current.ID))
	if err != nil {
		return nil, errors.New("无法确认当前 AI 开发授权状态")
	}
	if blocked {
		return nil, errors.New("该网站已开启 AI 开发访问，请先关闭授权")
	}
	updateQuery := `SELECT COUNT(*) FROM wp_update_tasks WHERE site_id=? AND status IN ('preparing','queued','running')`
	if !updateRecovery {
		updateQuery = `SELECT COUNT(*) FROM wp_update_tasks WHERE site_id=? AND (status IN ('preparing','queued','running') OR (requires_attention=1 AND manual_disposition=''))`
	}
	var count int
	if err := db.QueryRowContext(ctx, updateQuery, current.ID).Scan(&count); err != nil {
		return nil, errors.New("无法确认持久 WordPress 更新状态")
	}
	if count != 0 {
		return nil, errors.New("网站仍有 WordPress 更新任务或待处理的更新结果，请先处理")
	}
	// A failed update's dedicated protected-backup recovery remains possible;
	// it receives its existing site lock and is not blocked by its own attention
	// record. Both paths still reject genuinely active updates and migrations.
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM site_migration_locks WHERE status='active' AND (site_id=? OR domain=?)`, current.ID, current.Domain).Scan(&count); err != nil {
		return nil, errors.New("无法确认持久网站迁移状态")
	}
	if count != 0 {
		return nil, errors.New("网站或域名仍有迁移任务，请先结束迁移")
	}
	return &current, nil
}

func databaseRestoreStatusAllowed(status models.WebsiteStatus) bool {
	// A paused site can be restored offline; deletion, creation, migration and
	// uncertain/error states cannot authorize a destructive database operation.
	return status == models.StatusActive || status == models.StatusPaused
}

func databaseRestoreNameAllowed(name string) bool {
	if !isValidMySQLIdentifier(name) {
		return false
	}
	switch strings.ToLower(name) {
	case "mysql", "information_schema", "performance_schema", "sys":
		return false
	default:
		return true
	}
}

// Recheck immediately before the destructive command, including rollback
// cleanup. Never erase or import into a stale task's previous database binding.
func verifyDatabaseRestoreBinding(ctx context.Context, db *sql.DB, siteID int64, dbName string) error {
	if db == nil || siteID <= 0 || !databaseRestoreNameAllowed(dbName) {
		return errors.New("数据库恢复绑定无效")
	}
	var currentDB string
	var status models.WebsiteStatus
	if err := db.QueryRowContext(ctx, `SELECT db_name,status FROM websites WHERE id=?`, siteID).Scan(&currentDB, &status); err != nil {
		return errors.New("无法确认当前数据库归属")
	}
	if currentDB != dbName || !databaseRestoreStatusAllowed(status) {
		return errors.New("网站或数据库绑定已变化，清空未执行")
	}
	return nil
}
