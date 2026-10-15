package executor

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

const wpUpdateBackupReuseWindow = 6 * time.Hour
const wpUpdateArtifactRetention = 24 * time.Hour
const WPUpdateLogRetention = 7 * 24 * time.Hour

const wpUpdateCleanupBatchSize = 100
const wpUpdateLogCleanupBatchSize = 1000
const wpUpdateCleanupRetryDelay = time.Hour

func (s *wpUpdateStore) recentDatabaseBackup(ctx context.Context, siteID int, now time.Time) (models.WPUpdateRecentDatabaseBackup, error) {
	var result models.WPUpdateRecentDatabaseBackup
	var created string
	err := s.db.QueryRowContext(ctx, `SELECT b.id,b.task_id,b.file_size,b.created_at
		FROM wp_update_task_backups b JOIN wp_update_tasks t ON t.id=b.task_id
		WHERE t.site_id=? AND b.kind='database' AND b.protected=1 AND b.deleted_at IS NULL
		  AND t.backup_ready=1 AND t.requires_attention=0 AND t.rollback_status!='failed'
		  AND b.created_at>=?
		ORDER BY b.created_at DESC,b.id DESC LIMIT 1`,
		siteID, wpUpdateDBTime(now.Add(-wpUpdateBackupReuseWindow))).Scan(
		&result.BackupID, &result.TaskID, &result.FileSize, &created)
	if err != nil {
		return result, err
	}
	parsed, err := parseRequiredWPInventoryTime(created)
	if err != nil {
		return result, err
	}
	result.CreatedAt = parsed
	return result, nil
}

func (s *wpUpdateStore) validateDatabaseBackupChoice(ctx context.Context, siteID int, mode string, sourceID int64, root string, now time.Time) error {
	if mode == "fresh" && sourceID == 0 {
		return nil
	}
	if mode != "reuse" || sourceID <= 0 {
		return errors.New("invalid database backup choice")
	}
	var path, sha string
	var created string
	var size int64
	err := s.db.QueryRowContext(ctx, `SELECT b.file_path,b.file_size,b.sha256,b.created_at
		FROM wp_update_task_backups b JOIN wp_update_tasks t ON t.id=b.task_id
		WHERE b.id=? AND t.site_id=? AND b.kind='database' AND b.protected=1 AND b.deleted_at IS NULL
		  AND t.backup_ready=1 AND t.requires_attention=0 AND t.rollback_status!='failed'`,
		sourceID, siteID).Scan(&path, &size, &sha, &created)
	if err != nil || size <= 0 || !wpUpdateSHA256Pattern.MatchString(sha) {
		return errors.New("database backup unavailable")
	}
	parsed, err := parseRequiredWPInventoryTime(created)
	if err != nil || parsed.Before(now.Add(-wpUpdateBackupReuseWindow)) ||
		!pathWithin(filepath.Clean(root), filepath.Clean(path), false) {
		return errors.New("database backup unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return errors.New("database backup unavailable")
	}
	actual, _, err := hashRegularFile(path)
	if err != nil || actual != sha {
		return errors.New("database backup unavailable")
	}
	return nil
}

func recentBackupOrNil(store *wpUpdateStore, ctx context.Context, siteID int, now time.Time) *models.WPUpdateRecentDatabaseBackup {
	backup, err := store.recentDatabaseBackup(ctx, siteID, now)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return nil
	}
	return &backup
}

func (s *wpUpdateArtifactService) cleanupExpiredArtifacts(ctx context.Context, now time.Time) error {
	if s == nil || s.store == nil || !filepath.IsAbs(s.root) {
		return errors.New("update artifact cleanup unavailable")
	}
	cutoff := wpUpdateDBTime(now.Add(-wpUpdateArtifactRetention))
	rows, err := s.store.db.QueryContext(ctx, `SELECT b.id,b.file_path,b.task_id FROM wp_update_task_backups b
		JOIN wp_update_tasks t ON t.id=b.task_id
		WHERE b.protected=1 AND b.deleted_at IS NULL
		  AND t.status IN ('success','failed')
		  AND t.requires_attention=0 AND t.rollback_status!='failed'
		  AND t.finished_at IS NOT NULL AND t.finished_at<=?
		  AND NOT EXISTS (SELECT 1 FROM wp_update_artifact_cleanup c WHERE c.task_id=t.id)
		  AND NOT EXISTS (SELECT 1 FROM wp_update_artifact_cleanup_retries r WHERE r.task_id=t.id AND r.retry_after>?)
		  AND (b.kind!='database' OR NOT EXISTS (
			SELECT 1 FROM wp_update_tasks r
			WHERE r.database_backup_source_id=b.id AND (
			  r.status NOT IN ('success','failed') OR r.requires_attention=1 OR
			  r.rollback_status='failed' OR r.finished_at IS NULL OR r.finished_at>?
			)
		  ))
		ORDER BY b.id LIMIT ?`, cutoff, wpUpdateDBTime(now), cutoff, wpUpdateCleanupBatchSize)
	if err != nil {
		return err
	}
	type candidate struct {
		id   int64
		path string
		task string
	}
	var candidates []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.path, &item.task); err != nil {
			rows.Close()
			return err
		}
		candidates = append(candidates, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		clean := filepath.Clean(item.path)
		if !pathWithin(s.root, clean, false) {
			if err := s.deferArtifactCleanup(ctx, item.task, now); err != nil {
				return err
			}
			continue
		}
		if info, err := os.Lstat(clean); err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				if err := s.deferArtifactCleanup(ctx, item.task, now); err != nil {
					return err
				}
				continue
			}
			if err := os.Remove(clean); err != nil {
				if err := s.deferArtifactCleanup(ctx, item.task, now); err != nil {
					return err
				}
				continue
			}
		} else if !os.IsNotExist(err) {
			if err := s.deferArtifactCleanup(ctx, item.task, now); err != nil {
				return err
			}
			continue
		}
		if _, err := s.store.db.ExecContext(ctx, `UPDATE wp_update_task_backups
			SET protected=0,deleted_at=?,cleanup_result='deleted'
			WHERE id=? AND protected=1 AND deleted_at IS NULL`,
			wpUpdateDBTime(now), item.id); err != nil {
			return err
		}
	}
	taskRows, err := s.store.db.QueryContext(ctx, `SELECT t.id FROM wp_update_tasks t
		WHERE t.status IN ('success','failed') AND t.requires_attention=0
		  AND t.rollback_status!='failed' AND t.finished_at IS NOT NULL AND t.finished_at<=?
		  AND NOT EXISTS (SELECT 1 FROM wp_update_artifact_cleanup c WHERE c.task_id=t.id)
		  AND NOT EXISTS (SELECT 1 FROM wp_update_artifact_cleanup_retries r WHERE r.task_id=t.id AND r.retry_after>?)
		  AND NOT EXISTS (SELECT 1 FROM wp_update_task_backups b
			WHERE b.task_id=t.id AND b.protected=1 AND b.deleted_at IS NULL)
		  AND NOT EXISTS (SELECT 1 FROM wp_update_tasks r
			WHERE r.database_backup_source_id IN (
			  SELECT b.id FROM wp_update_task_backups b WHERE b.task_id=t.id AND b.kind='database'
			) AND (
			  r.status NOT IN ('success','failed') OR r.requires_attention=1 OR
			  r.rollback_status='failed' OR r.finished_at IS NULL OR r.finished_at>?
			)
		  ) ORDER BY t.finished_at,t.id LIMIT ?`, cutoff, wpUpdateDBTime(now), cutoff, wpUpdateCleanupBatchSize)
	if err != nil {
		return err
	}
	var taskIDs []string
	for taskRows.Next() {
		var id string
		if err := taskRows.Scan(&id); err != nil {
			taskRows.Close()
			return err
		}
		taskIDs = append(taskIDs, id)
	}
	if err := taskRows.Err(); err != nil {
		taskRows.Close()
		return err
	}
	if err := taskRows.Close(); err != nil {
		return err
	}
	for _, id := range taskIDs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !wpUpdateTaskIDPattern.MatchString(id) {
			if err := s.deferArtifactCleanup(ctx, id, now); err != nil {
				return err
			}
			continue
		}
		dir := filepath.Join(s.root, id)
		if info, err := os.Lstat(dir); err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				if err := s.deferArtifactCleanup(ctx, id, now); err != nil {
					return err
				}
				continue
			}
			if err := os.RemoveAll(dir); err != nil {
				if err := s.deferArtifactCleanup(ctx, id, now); err != nil {
					return err
				}
				continue
			}
		} else if !os.IsNotExist(err) {
			if err := s.deferArtifactCleanup(ctx, id, now); err != nil {
				return err
			}
			continue
		}
		// Only a removed/already absent owned directory can become completed.
		// Failed or unsafe paths stay eligible for a later maintenance attempt.
		if _, err := s.store.db.ExecContext(ctx, `INSERT OR IGNORE INTO wp_update_artifact_cleanup(task_id,completed_at) VALUES(?,?)`, id, wpUpdateDBTime(now)); err != nil {
			return err
		}
		if _, err := s.store.db.ExecContext(ctx, `DELETE FROM wp_update_artifact_cleanup_retries WHERE task_id=?`, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *wpUpdateArtifactService) deferArtifactCleanup(ctx context.Context, taskID string, now time.Time) error {
	_, err := s.store.db.ExecContext(ctx, `INSERT INTO wp_update_artifact_cleanup_retries(task_id,retry_after) VALUES(?,?)
		ON CONFLICT(task_id) DO UPDATE SET retry_after=excluded.retry_after`, taskID, wpUpdateDBTime(now.Add(wpUpdateCleanupRetryDelay)))
	return err
}

// cleanupExpiredUpdateLogs 按 7 天窗口分批清理更新任务事件（不区分成功/失败/需人工介入）。
// 每次最多 wpUpdateLogCleanupBatchSize 行；较大的积压由后续维护周期继续处理。
// 与 cleanupExpiredArtifacts 不同，本方法只删事件、不删任务行，避免级联删除
// wp_update_task_backups 行导致备份文件孤儿；任务行仍由其原有逻辑保留。
// 仅依赖 s.store.db，不依赖 s.root，便于独立单测。
func (s *wpUpdateArtifactService) cleanupExpiredUpdateLogs(ctx context.Context, now time.Time) error {
	if s == nil || s.store == nil {
		return errors.New("update log cleanup unavailable")
	}
	cutoff := wpUpdateDBTime(now.Add(-WPUpdateLogRetention))
	_, err := s.store.db.ExecContext(ctx, `DELETE FROM wp_update_task_events WHERE id IN (
		SELECT e.id FROM wp_update_task_events e JOIN wp_update_tasks t ON t.id=e.task_id
		WHERE t.finished_at IS NOT NULL AND t.finished_at<=? ORDER BY e.id LIMIT ?)`, cutoff, wpUpdateLogCleanupBatchSize)
	return err
}
