package database

import "database/sql"

// EnsureWPUpdateCleanupSchema records completed artifact cleanup without
// removing task history or the backup references used by recovery.
func EnsureWPUpdateCleanupSchema(db *sql.DB) error {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS wp_update_artifact_cleanup (
		task_id TEXT PRIMARY KEY,
		completed_at DATETIME NOT NULL,
		FOREIGN KEY (task_id) REFERENCES wp_update_tasks(id) ON DELETE CASCADE
	)`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS wp_update_artifact_cleanup_retries (
		task_id TEXT PRIMARY KEY,
		retry_after DATETIME NOT NULL,
		FOREIGN KEY (task_id) REFERENCES wp_update_tasks(id) ON DELETE CASCADE
	)`)
	return err
}
