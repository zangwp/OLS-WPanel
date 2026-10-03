package database

import "testing"

func TestSiteRenewalPreferenceUpgradeAndHistory(t *testing.T) {
	openTempDB(t)
	if err := RunMigrations(); err != nil {
		t.Fatal(err)
	}
	if _, err := DB.Exec(`INSERT INTO websites(id,name,domain,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path) VALUES(999,'renew','renew.example.com','wp_renew','/tmp/renew','/tmp/log','db','user','/tmp/php','/tmp/ols')`); err != nil {
		t.Fatal(err)
	}
	if enabled, err := SiteSSLRenewalEnabled(999); err != nil || !enabled {
		t.Fatalf("existing default: %v %v", enabled, err)
	}
	if _, err := DB.Exec(`INSERT INTO site_ssl_renewal(site_id,enabled) VALUES(999,0)`); err != nil {
		t.Fatal(err)
	}
	if err := RecordSiteSSLRenewal(999, "success"); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrations(); err != nil {
		t.Fatal(err)
	}
	if enabled, err := SiteSSLRenewalEnabled(999); err != nil || enabled {
		t.Fatalf("disabled preference lost: %v %v", enabled, err)
	}
	var stamp, status string
	if err := DB.QueryRow(`SELECT last_attempt,last_status FROM site_ssl_renewal WHERE site_id=999`).Scan(&stamp, &status); err != nil || stamp == "" || status != "success" {
		t.Fatalf("history: %q %q %v", stamp, status, err)
	}
	if _, err := DB.Exec(`DELETE FROM websites WHERE id=999`); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM site_ssl_renewal WHERE site_id=999`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("orphan preference: %d %v", count, err)
	}
}
