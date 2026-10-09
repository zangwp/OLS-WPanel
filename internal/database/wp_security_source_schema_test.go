package database

import "testing"

func TestSecuritySourceCursorMigrationPreservesLegacyAndCascades(t *testing.T) {
	openTempDB(t)
	if err := RunMigrations(); err != nil {
		t.Fatal(err)
	}
	if err := RunUpgrades(); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`INSERT INTO websites (id,name,domain,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path) VALUES (7,'test','test.example','wp_test','/www/test','/logs/test','test_db','test_user','/tmp/test.sock','/etc/test.conf');
INSERT INTO wp_security_log_positions (site_id,byte_offset,first_line_hash) VALUES (7,500,'legacy');
DROP TABLE wp_security_log_source_positions;
DELETE FROM schema_version;
INSERT INTO schema_version(version) VALUES ('1.0.73')`); err != nil {
		t.Fatal(err)
	}
	if err := RunUpgrades(); err != nil {
		t.Fatal(err)
	}
	if err := RunUpgrades(); err != nil {
		t.Fatal(err)
	}
	var legacy int
	if err := DB.QueryRow(`SELECT byte_offset FROM wp_security_log_positions WHERE site_id=7`).Scan(&legacy); err != nil || legacy != 500 {
		t.Fatalf("legacy offset lost: %d %v", legacy, err)
	}
	for _, source := range []string{"access.log", "wp-login-security.log"} {
		if _, err := DB.Exec(`INSERT INTO wp_security_log_source_positions(site_id,source,byte_offset) VALUES(7,?,?)`, source, len(source)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := DB.Exec(`UPDATE wp_security_log_source_positions SET byte_offset=900 WHERE site_id=7 AND source='access.log'`); err != nil {
		t.Fatal(err)
	}
	var login int
	if err := DB.QueryRow(`SELECT byte_offset FROM wp_security_log_source_positions WHERE site_id=7 AND source='wp-login-security.log'`).Scan(&login); err != nil || login != len("wp-login-security.log") {
		t.Fatalf("login cursor mixed: %d %v", login, err)
	}
	if _, err := DB.Exec(`DELETE FROM websites WHERE id=7`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM wp_security_log_source_positions WHERE site_id=7`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cursor not cascaded: %d %v", count, err)
	}
}
