package middleware

import (
	"fmt"
	"testing"
	"time"
)

func insertTestBan(t *testing.T, tracker *LoginAttemptTracker, ip, jail string) {
	t.Helper()
	expires := time.Now().UTC().Add(time.Hour).Format("2006-01-02 15:04:05")
	if _, err := tracker.DB.Exec(
		`INSERT INTO firewall_bans (ip_address, ban_level, reason, source_jail, expires_at, ban_count)
		 VALUES (?, 2, 'test', ?, ?, 1)`,
		ip, jail, expires,
	); err != nil {
		t.Fatalf("insert test ban: %v", err)
	}
}

func TestIsBannedIgnoresOLSWPanelLoginSource(t *testing.T) {
	db := newScanDefenseTestDB(t)
	tracker := &LoginAttemptTracker{DB: db}
	insertTestBan(t, tracker, "203.0.113.10", "olswpanel-login")

	banned, err := tracker.IsBanned("203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if banned {
		t.Fatal("a olswpanel-login-only ban must not block panel access")
	}
}

func TestIsBannedHonorsOtherSources(t *testing.T) {
	db := newScanDefenseTestDB(t)
	tracker := &LoginAttemptTracker{DB: db}

	jails := []string{"olswpanel", "olswpanel-404", "olswpanel-sshd", "panel", "panel_scan", "manual"}
	for i, jail := range jails {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		insertTestBan(t, tracker, ip, jail)
		banned, err := tracker.IsBanned(ip)
		if err != nil {
			t.Fatal(err)
		}
		if !banned {
			t.Fatalf("a %s ban should still block panel access", jail)
		}
	}
}

func TestIsBannedReportsDatabaseFailure(t *testing.T) {
	db := newScanDefenseTestDB(t)
	tracker := &LoginAttemptTracker{DB: db}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if banned, err := tracker.IsBanned("203.0.113.10"); err == nil || banned {
		t.Fatalf("banned=%t err=%v, want database error", banned, err)
	}
}

func TestPanelFailuresStillBanAfterWordPressLoginBan(t *testing.T) {
	for _, attemptType := range []string{"basic_auth", "web_login"} {
		t.Run(attemptType, func(t *testing.T) {
			db := newScanDefenseTestDB(t)
			if _, err := db.Exec(`CREATE TABLE login_attempts (ip_address TEXT NOT NULL, attempt_type TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
				t.Fatal(err)
			}
			tracker := NewLoginAttemptTracker(db, 3, 1, 1)
			ip := "203.0.113.10"
			insertTestBan(t, tracker, ip, "olswpanel-login")
			calls := 0
			original := loginAttemptAddPersistBan
			loginAttemptAddPersistBan = func(got string) error {
				if got != ip {
					t.Fatalf("persist IP=%q, want %q", got, ip)
				}
				calls++
				return nil
			}
			t.Cleanup(func() { loginAttemptAddPersistBan = original })
			for i := 0; i < 2; i++ {
				tracker.RecordAttempt(ip, attemptType)
			}
			if banned, err := tracker.IsBanned(ip); err != nil || banned || calls != 0 {
				t.Fatalf("before threshold: banned=%t err=%v calls=%d", banned, err, calls)
			}
			tracker.RecordAttempt(ip, attemptType)
			if banned, err := tracker.IsBanned(ip); err != nil || !banned || calls != 1 {
				t.Fatalf("after threshold: banned=%t err=%v calls=%d", banned, err, calls)
			}
			tracker.RecordAttempt(ip, attemptType)
			var panelBans, websiteBans int
			if err := db.QueryRow(`SELECT COUNT(*) FROM firewall_bans WHERE ip_address=? AND source_jail='panel'`, ip).Scan(&panelBans); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM firewall_bans WHERE ip_address=? AND source_jail='olswpanel-login'`, ip).Scan(&websiteBans); err != nil {
				t.Fatal(err)
			}
			if panelBans != 1 || websiteBans != 1 || calls != 1 {
				t.Fatalf("panel bans=%d website bans=%d persist calls=%d", panelBans, websiteBans, calls)
			}
		})
	}
}
