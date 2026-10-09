package database

const wpSecuritySourcePositionsSchema = `CREATE TABLE IF NOT EXISTS wp_security_log_source_positions (
	site_id INTEGER NOT NULL,
	source TEXT NOT NULL,
	byte_offset INTEGER NOT NULL DEFAULT 0,
	first_line_hash TEXT NOT NULL DEFAULT '',
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (site_id, source),
	FOREIGN KEY (site_id) REFERENCES websites(id) ON DELETE CASCADE
)`
