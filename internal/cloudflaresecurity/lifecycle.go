package cloudflaresecurity

import (
	"context"
	"database/sql"
	"errors"
)

type deletionQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// CheckWebsiteDeletion must also run inside the final DELETE transaction. An
// enabled configuration can create a rule later even when its blacklist is empty.
func CheckWebsiteDeletion(ctx context.Context, query deletionQuery, id int) error {
	var blocked int
	if err := query.QueryRowContext(ctx, `SELECT COUNT(*) FROM website_cloudflare_security WHERE site_id=? AND (enabled=1 OR rule_id<>'' OR pending_hash<>'')`, id).Scan(&blocked); err != nil {
		return errors.New("检查 Cloudflare 网站防护状态失败，未删除网站")
	}
	if blocked != 0 {
		return errors.New("该网站仍启用 Cloudflare 同步或保留待清理规则，请先停用同步并移除面板专属规则，再删除网站")
	}
	return nil
}

// BeginWebsiteDeletion serializes the state transition with Save and Sync. The
// persisted deleting state blocks future enable requests after this short lock
// is released, including retries after interrupted filesystem cleanup.
func BeginWebsiteDeletion(ctx context.Context, db *sql.DB, id int) error {
	operationMu.Lock()
	defer operationMu.Unlock()
	if db == nil {
		return errors.New("网站数据库暂不可用")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return errors.New("开始网站删除状态检查失败")
	}
	defer tx.Rollback()
	if err = CheckWebsiteDeletion(ctx, tx, id); err != nil {
		return err
	}
	var status string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM websites WHERE id=?`, id).Scan(&status); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return errors.New("读取网站删除状态失败")
	}
	if status != "deleting" {
		if _, err = tx.ExecContext(ctx, `UPDATE websites SET status='deleting',updated_at=CURRENT_TIMESTAMP WHERE id=?`, id); err != nil {
			return errors.New("标记网站删除状态失败")
		}
	}
	if err = tx.Commit(); err != nil {
		return errors.New("保存网站删除状态失败")
	}
	return nil
}

func (s *Service) websiteDeleting(ctx context.Context, id int) (bool, error) {
	var status string
	if err := s.DB.QueryRowContext(ctx, `SELECT status FROM websites WHERE id=?`, id).Scan(&status); errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	} else if err != nil {
		return false, errors.New("读取网站删除状态失败")
	}
	return status == "deleting", nil
}
