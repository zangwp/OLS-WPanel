package database

// imageOptimizerSchemaStatements is shared by fresh installs and the 1.0.49 upgrade
// to keep their tables, constraints, and indexes in sync.
//
// Jobs track batch progress; file records skip unchanged images on later runs.
// Fingerprints use the site, relative path, size, and modification time instead of full content comparisons.
var imageOptimizerSchemaStatements = []string{
	`CREATE TABLE IF NOT EXISTS site_image_optimization_jobs (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		site_id         INTEGER NOT NULL,
		status          TEXT NOT NULL DEFAULT 'queued',
		total_files     INTEGER NOT NULL DEFAULT 0,
		processed_files INTEGER NOT NULL DEFAULT 0,
		succeeded_files INTEGER NOT NULL DEFAULT 0,
		failed_files    INTEGER NOT NULL DEFAULT 0,
		skipped_files   INTEGER NOT NULL DEFAULT 0,
		bytes_before    INTEGER NOT NULL DEFAULT 0,
		bytes_after     INTEGER NOT NULL DEFAULT 0,
		last_error      TEXT NOT NULL DEFAULT '',
		created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		finished_at     DATETIME,
		FOREIGN KEY (site_id) REFERENCES websites(id) ON DELETE CASCADE,
		CHECK (status IN ('queued','running','succeeded','failed','stopped'))
	)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS ux_site_image_optimization_jobs_active_site
		ON site_image_optimization_jobs(site_id) WHERE status IN ('queued','running')`,
	`CREATE INDEX IF NOT EXISTS ix_site_image_optimization_jobs_site
		ON site_image_optimization_jobs(site_id, created_at)`,
	`CREATE TABLE IF NOT EXISTS site_image_optimization_files (
		site_id        INTEGER NOT NULL,
		relative_path  TEXT NOT NULL,
		original_size  INTEGER NOT NULL,
		optimized_size INTEGER NOT NULL,
		mtime_unix     INTEGER NOT NULL,
		processed_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (site_id, relative_path),
		FOREIGN KEY (site_id) REFERENCES websites(id) ON DELETE CASCADE
	)`,
}
