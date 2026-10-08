package database

import "testing"

func TestAccountSecuritySchemaUpgradePreservesProtection(t *testing.T) {
	openTempDB(t)
	if err := RunMigrations(); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`INSERT INTO account_mfa(admin_id,enabled,secret,last_counter) VALUES(1,1,x'010203',12345)`,
		`INSERT INTO account_mfa_recovery(admin_id,code_hash) VALUES(1,'retained-hash')`,
		`INSERT INTO account_security_preferences(username,notifications_enabled) VALUES('admin',0)`,
		`INSERT INTO account_security_events(id,username,event,ip,user_agent,created_at) VALUES('existing-event','admin','login_success','127.0.0.1','test',1)`,
	} {
		if _, err := DB.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := RunMigrations(); err != nil {
		t.Fatal(err)
	}
	var enabled bool
	var counter int64
	if err := DB.QueryRow(`SELECT enabled,last_counter FROM account_mfa WHERE admin_id=1`).Scan(&enabled, &counter); err != nil || !enabled || counter != 12345 {
		t.Fatalf("MFA state changed: enabled=%v counter=%v error=%v", enabled, counter, err)
	}
	if err := DB.QueryRow(`SELECT notifications_enabled FROM account_security_preferences WHERE username='admin'`).Scan(&enabled); err != nil || enabled {
		t.Fatalf("notification preference changed: %v %v", enabled, err)
	}
	for _, table := range []string{"account_mfa_recovery", "account_security_events"} {
		var count int
		if err := DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s records changed: count=%v error=%v", table, count, err)
		}
	}
}
