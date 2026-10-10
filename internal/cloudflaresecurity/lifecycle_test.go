package cloudflaresecurity

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCloudflareDeletionBlocksEnabledOwnedAndUncertainRules(t *testing.T) {
	for _, scenario := range []string{"enabled-empty", "disabled-owned", "disabled-uncertain-create"} {
		t.Run(scenario, func(t *testing.T) {
			s := newTestService(t)
			saveTestConfig(t, s, 1)
			fake := &fakeCloudflare{t: t}
			useFake(s, fake)
			ctx := context.Background()
			if scenario != "enabled-empty" {
				addTestBan(t, s, "198.51.100.1", "olswpanel-sqli", "")
				fake.failAfterWrite = scenario == "disabled-uncertain-create"
				_, err := s.Sync(ctx, 1)
				if scenario == "disabled-owned" && err != nil || scenario == "disabled-uncertain-create" && err == nil {
					t.Fatal("owned/uncertain fixture failed", err)
				}
				if _, err = s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount}); err != nil {
					t.Fatal(err)
				}
			}
			before := len(fake.mutations)
			if err := BeginWebsiteDeletion(ctx, s.DB, 1); err == nil {
				t.Fatal("active or uncleared configuration permitted deletion")
			}
			var status string
			if err := s.DB.QueryRow(`SELECT status FROM websites WHERE id=1`).Scan(&status); err != nil || status != "active" || len(fake.mutations) != before {
				t.Fatal("blocked deletion changed site/remote state", status, err)
			}
			if _, err := s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Sync(ctx, 1); err != nil {
				t.Fatal(err)
			}
			if err := BeginWebsiteDeletion(ctx, s.DB, 1); err != nil {
				t.Fatal("cleaned website could not enter deletion", err)
			}
			if err := BeginWebsiteDeletion(ctx, s.DB, 1); err != nil {
				t.Fatal("interrupted deletion state could not be retried", err)
			}
			if _, err := s.Save(ctx, 1, Update{Enabled: true, AccountID: testAccount, APIToken: testToken}); err == nil {
				t.Fatal("deleting website could reenable remote sync")
			}
		})
	}
}

func TestCloudflareDeletionWaitsForConcurrentSaveAndChecksCommittedConfig(t *testing.T) {
	s := newTestService(t)
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	entered, release := make(chan struct{}), make(chan struct{})
	first := true
	s.Client.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if first {
			first = false
			close(entered)
			<-release
		}
		return fake.transport(r)
	})
	saved, deleted := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := s.Save(context.Background(), 1, Update{Enabled: true, AccountID: testAccount, APIToken: testToken})
		saved <- err
	}()
	<-entered
	go func() { deleted <- BeginWebsiteDeletion(context.Background(), s.DB, 1) }()
	select {
	case err := <-deleted:
		close(release)
		t.Fatal("deletion did not wait for configuration operation", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-saved; err != nil {
		t.Fatal(err)
	}
	if err := <-deleted; err == nil {
		t.Fatal("delete ignored the newly committed enabled configuration")
	}
}

func TestCloudflareFailedDeletionTransitionRollsBackAndDoesNotLockWebsite(t *testing.T) {
	s := newTestService(t)
	if _, err := s.DB.Exec(`CREATE TRIGGER reject_deletion_status BEFORE UPDATE ON websites WHEN NEW.status='deleting' BEGIN SELECT RAISE(ABORT,'injected state failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := BeginWebsiteDeletion(context.Background(), s.DB, 1); err == nil {
		t.Fatal("failed deletion transition reported success")
	}
	var status string
	if err := s.DB.QueryRow(`SELECT status FROM websites WHERE id=1`).Scan(&status); err != nil || status != "active" {
		t.Fatal("failed transition changed state", status, err)
	}
	saveTestConfig(t, s, 1)
}

func TestCloudflareSaveCannotPersistAfterWebsiteDisappearsDuringZoneLookup(t *testing.T) {
	s := newTestService(t)
	fake := &fakeCloudflare{t: t}
	removed := false
	s.Client.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if !removed {
			removed = true
			if _, err := s.DB.Exec(`DELETE FROM websites WHERE id=1`); err != nil {
				t.Fatal(err)
			}
		}
		return fake.transport(r)
	})
	if _, err := s.Save(context.Background(), 1, Update{Enabled: true, AccountID: testAccount, APIToken: testToken}); err == nil {
		t.Fatal("configuration persisted after concurrent direct deletion")
	}
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM website_cloudflare_security WHERE site_id=1`).Scan(&count); err != nil || count != 0 || len(fake.mutations) != 0 {
		t.Fatal("orphaned enabled configuration or WAF mutation created", count, err)
	}
}

func TestCloudflareDeletingWebsiteOnlyCleansAndRetriesOwnedRule(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	// Simulate an interrupted deletion from a previous version.
	if _, err := s.DB.Exec(`UPDATE websites SET status='deleting' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	fake.unauthorized = true
	if err := s.SyncAll(ctx); err == nil {
		t.Fatal("failed cleanup unexpectedly succeeded")
	}
	fake.unauthorized = false
	if err := s.SyncAll(ctx); err != nil {
		t.Fatal("disabled deleting-site cleanup was not retried", err)
	}
	if len(fake.rs.Rules) != 0 || strings.Join(fake.mutations, ",") != "CREATE_ENTRYPOINT,DELETE_RULE" {
		t.Fatal("deleting website created or retained a rule", fake.mutations)
	}
}

func TestCloudflareEmptyBlacklistCleansSavedRuleDespiteCurrentDomainErrors(t *testing.T) {
	for _, scenario := range []string{"invalid-alias", "outside-zone-alias", "changed-primary", "invalid-primary"} {
		t.Run(scenario, func(t *testing.T) {
			s := newTestService(t)
			saveTestConfig(t, s, 1)
			addTestBan(t, s, "198.51.100.1", "olswpanel-sqli", "")
			fake := &fakeCloudflare{t: t}
			useFake(s, fake)
			ctx := context.Background()
			if _, err := s.Sync(ctx, 1); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(`UPDATE firewall_bans SET unbanned_at=CURRENT_TIMESTAMP`); err != nil {
				t.Fatal(err)
			}
			queries := map[string]string{
				"invalid-alias":      `UPDATE websites SET aliases='https://invalid.example.com/path' WHERE id=1`,
				"outside-zone-alias": `UPDATE websites SET aliases='other.example.net' WHERE id=1`,
				"changed-primary":    `UPDATE websites SET domain='changed.example.com' WHERE id=1`,
				"invalid-primary":    `UPDATE websites SET domain='https://invalid.example.com/path' WHERE id=1`,
			}
			if _, err := s.DB.Exec(queries[scenario]); err != nil {
				t.Fatal(err)
			}
			status, err := s.Sync(ctx, 1)
			if err != nil || status.RuleID != "" || len(fake.rs.Rules) != 0 || len(status.CoveredHostnames) != 0 {
				t.Fatal("empty blacklist cleanup blocked by new coverage", status, err)
			}
		})
	}
}

func TestCloudflareEmptyBlacklistStillRejectsExternallyModifiedOwnedRule(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-sqli", "")
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	fake.rs.Rules[0].Description = "administrator changed rule"
	if _, err := s.DB.Exec(`UPDATE firewall_bans SET unbanned_at=CURRENT_TIMESTAMP`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(ctx, 1); err == nil || len(fake.rs.Rules) != 1 || len(fake.mutations) != 1 {
		t.Fatal("empty blacklist bypassed ownership check", err)
	}
}
