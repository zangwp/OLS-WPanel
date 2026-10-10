package cloudflaresecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

func testZoneNamed(id, name, account string) zone {
	z := zone{ID: id, Name: name}
	z.Account.ID = account
	return z
}
func setAliases(t *testing.T, s *Service, id int, aliases string) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE websites SET aliases=? WHERE id=?`, aliases, id); err != nil {
		t.Fatal(err)
	}
}
func autoSave(t *testing.T, s *Service, id int) Status {
	t.Helper()
	status, err := s.Save(context.Background(), id, Update{Enabled: true, AccountID: testAccount, APIToken: testToken})
	if err != nil {
		t.Fatal(err)
	}
	return status
}

func TestCloudflareAutoZoneUsesExactMostPreciseAccountScopedSuffix(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(`UPDATE websites SET domain='api.shop.example.com' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	parentID := "ffffffffffffffffffffffffffffffff"
	fake := &fakeCloudflare{t: t, zones: []zone{testZoneNamed(parentID, "example.com", testAccount), testZoneNamed(testZone, "shop.example.com", testAccount), testZoneNamed("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "shop.example.com", "99999999999999999999999999999999")}}
	useFake(s, fake)
	status := autoSave(t, s, 1)
	if status.ZoneID != testZone || status.ZoneName != "shop.example.com" || status.WebsiteHostnames[0] != "api.shop.example.com" || len(status.CoveredHostnames) != 0 {
		t.Fatal("incorrect automatic binding", status)
	}
	if len(fake.mutations) != 0 {
		t.Fatal("Save mutated WAF")
	}
	if _, err := s.TestUpdate(ctx, 1, &Update{AccountID: testAccount, APIToken: testToken}); err != nil {
		t.Fatal(err)
	}
	// A token restricted to the parent zone can still discover that visible
	// zone after more-specific exact candidates return an empty list.
	s2 := newTestService(t)
	if _, err := s2.DB.Exec(`UPDATE websites SET domain='api.shop.example.com' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	scoped := &fakeCloudflare{t: t}
	useFake(s2, scoped)
	if got := autoSave(t, s2, 1); got.ZoneID != testZone || got.ZoneName != "example.com" {
		t.Fatal("scoped token did not find visible parent")
	}
}

func TestCloudflareAutoZoneAmbiguityAndAccountMismatchDoNotSaveOrMutate(t *testing.T) {
	for _, scenario := range []string{"ambiguous", "foreign-account", "no-visible-zone"} {
		t.Run(scenario, func(t *testing.T) {
			s := newTestService(t)
			fake := &fakeCloudflare{t: t}
			useFake(s, fake)
			switch scenario {
			case "ambiguous":
				fake.zones = []zone{testZoneNamed(testZone, "example.com", testAccount), testZoneNamed("ffffffffffffffffffffffffffffffff", "example.com", testAccount)}
			case "no-visible-zone":
				fake.zones = []zone{}
			case "foreign-account":
				s.Client.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
					if r.URL.Query().Get("account.id") != testAccount {
						t.Fatal("account filter missing")
					}
					return apiResponse(200, []zone{testZoneNamed(testZone, "example.com", "ffffffffffffffffffffffffffffffff")}), nil
				})
			}
			if _, err := s.Save(context.Background(), 1, Update{Enabled: true, AccountID: testAccount, APIToken: testToken}); err == nil {
				t.Fatal("unsafe lookup accepted")
			}
			var count int
			if err := s.DB.QueryRow(`SELECT COUNT(*) FROM website_cloudflare_security`).Scan(&count); err != nil || count != 0 || len(fake.mutations) != 0 {
				t.Fatal("failed lookup saved or wrote WAF")
			}
		})
	}
}

func TestCloudflareZonePaginationIsCompleteBoundedAndRejectsAmbiguousLaterPage(t *testing.T) {
	for _, pages := range []int{2, 21} {
		t.Run(fmt.Sprint(pages), func(t *testing.T) {
			s := newTestService(t)
			fake := &fakeCloudflare{t: t, zonePages: map[int][]zone{1: {testZoneNamed(testZone, "example.com", testAccount)}, 2: {testZoneNamed("ffffffffffffffffffffffffffffffff", "example.com", testAccount)}}, zoneTotalPages: pages}
			useFake(s, fake)
			if _, err := s.Save(context.Background(), 1, Update{Enabled: true, AccountID: testAccount, APIToken: testToken}); err == nil {
				t.Fatal("partial or ambiguous pages accepted")
			}
			var count int
			s.DB.QueryRow(`SELECT COUNT(*) FROM website_cloudflare_security`).Scan(&count)
			if count != 0 || len(fake.mutations) != 0 {
				t.Fatal("partial result persisted")
			}
		})
	}
}

func TestCloudflareRegisteredWWWAndAliasesUpdateLegacySingleRuleAndCoverage(t *testing.T) {
	s := newTestService(t)
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	autoSave(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	first, err := s.Sync(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fake.rs.Rules[0].Expression, "www.") || strings.Join(first.CoveredHostnames, ",") != "example.com" {
		t.Fatal("implicit www or incorrect original coverage")
	}
	setAliases(t, s, 1, "WWW.Example.COM.\nblog.example.com\nexample.com\nwww.example.com")
	before, err := s.Get(ctx, 1)
	if err != nil || before.SyncStatus != "pending" || len(before.WebsiteHostnames) != 3 || strings.Join(before.CoveredHostnames, ",") != "example.com" {
		t.Fatal("current and confirmed coverage conflated", before, err)
	}
	second, err := s.Sync(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"example.com", "blog.example.com", "www.example.com"}
	if !sameHosts(second.CoveredHostnames, expected) || !strings.Contains(fake.rs.Rules[0].Expression, `http.host in {"example.com" "blog.example.com" "www.example.com"}`) {
		t.Fatal("registered hosts missing", second)
	}
	setAliases(t, s, 1, "www.example.com")
	third, err := s.Sync(ctx, 1)
	if err != nil || strings.Contains(fake.rs.Rules[0].Expression, "blog.example.com") || len(third.CoveredHostnames) != 2 {
		t.Fatal("removed alias retained", err)
	}
	if _, err := s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount}); err != nil {
		t.Fatal(err)
	}
	if status, err := s.Sync(ctx, 1); err != nil || status.RuleID != "" || len(status.CoveredHostnames) != 0 {
		t.Fatal("multi-host owned cleanup failed", status, err)
	}
	if strings.Join(fake.mutations, ",") != "CREATE_ENTRYPOINT,PATCH_RULE,PATCH_RULE,DELETE_RULE" {
		t.Fatal("unexpected duplicate or whole ruleset write", fake.mutations)
	}
}

func TestCloudflareOutOfZoneAndDelegatedAliasFailWholeGroupBeforeWAFMutation(t *testing.T) {
	for _, alias := range []string{"www.other.net", "login.child.example.com"} {
		t.Run(alias, func(t *testing.T) {
			s := newTestService(t)
			fake := &fakeCloudflare{t: t}
			useFake(s, fake)
			ctx := context.Background()
			autoSave(t, s, 1)
			addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
			if _, err := s.Sync(ctx, 1); err != nil {
				t.Fatal(err)
			}
			fake.zones = []zone{testZoneNamed(testZone, "example.com", testAccount), testZoneNamed("ffffffffffffffffffffffffffffffff", "child.example.com", testAccount)}
			setAliases(t, s, 1, alias)
			before := ruleHash(fake.rs.Rules[0])
			if _, err := s.Sync(ctx, 1); err == nil {
				t.Fatal("out of zone alias partially accepted")
			}
			status, err := s.Get(ctx, 1)
			if err != nil || status.CoverageError == "" || len(status.CoveredHostnames) != 1 || len(fake.mutations) != 1 || ruleHash(fake.rs.Rules[0]) != before {
				t.Fatal("failed coverage did not preserve old scope", status, err)
			}
		})
	}
	// A new configuration with a cross-zone alias fails before saving secrets.
	s := newTestService(t)
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	setAliases(t, s, 1, "www.other.net")
	if _, err := s.Save(context.Background(), 1, Update{Enabled: true, AccountID: testAccount, APIToken: testToken}); err == nil {
		t.Fatal("cross-zone initial save accepted")
	}
	var count int
	s.DB.QueryRow(`SELECT COUNT(*) FROM website_cloudflare_security`).Scan(&count)
	if count != 0 {
		t.Fatal("cross-zone token/config was persisted")
	}
}

func TestCloudflareInvalidCurrentAliasDoesNotBlockDisabledCleanup(t *testing.T) {
	s := newTestService(t)
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	autoSave(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	setAliases(t, s, 1, "https://invalid.example.com/path")
	if status, err := s.Get(ctx, 1); err != nil || status.CoverageError == "" || status.SyncStatus != "pending" {
		t.Fatal("bad alias unreadable status", status, err)
	}
	if _, err := s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount}); err != nil {
		t.Fatal("disable blocked", err)
	}
	if status, err := s.Sync(ctx, 1); err != nil || status.RuleID != "" || len(fake.rs.Rules) != 0 || len(status.CoveredHostnames) != 0 {
		t.Fatal("bad alias blocked original binding cleanup", status, err)
	}
}

func TestCloudflareOwnedRotationPreservesZoneThenCleanupAllowsRediscovery(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.DB.Exec(`UPDATE websites SET domain='store.example.com' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	autoSave(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	newToken := "rotated-account-only-token-1234567890"
	fake.acceptedToken = newToken
	requests := len(fake.requests)
	rotated, err := s.Save(ctx, 1, Update{Enabled: true, AccountID: testAccount, APIToken: newToken})
	if err != nil || rotated.ZoneID != testZone || len(fake.requests) != requests {
		t.Fatal("owned implicit-zone rotation performed lookup or lost binding", err)
	}
	childID := "ffffffffffffffffffffffffffffffff"
	fake.zones = []zone{testZoneNamed(testZone, "example.com", testAccount), testZoneNamed(childID, "store.example.com", testAccount)}
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("more precise visible child silently rebound owned rule")
	}
	if _, err := s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	rebound, err := s.Save(ctx, 1, Update{Enabled: true, AccountID: testAccount})
	if err != nil || rebound.ZoneID != childID || rebound.ZoneName != "store.example.com" {
		t.Fatal("cleaned binding could not be automatically rediscovered", rebound, err)
	}
	if len(fake.mutations) != 2 {
		t.Fatal("rediscovery wrote remote rule before requested sync")
	}
}

func TestCloudflareCoverageSchemaUpgradesPreviousLocalTable(t *testing.T) {
	s := newTestService(t)
	if _, err := s.DB.Exec(`DROP TABLE website_cloudflare_security`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(cloudflareOldSchemaForTest); err != nil {
		t.Fatal(err)
	}
	if err := database.RunMigrations(); err != nil {
		t.Fatal(err)
	}
	status, err := s.Get(context.Background(), 1)
	if err != nil || status.CoveredHostnames == nil || status.WebsiteHostnames == nil {
		t.Fatal("old schema coverage upgrade failed", err)
	}
}

const cloudflareOldSchemaForTest = `CREATE TABLE website_cloudflare_security(site_id INTEGER PRIMARY KEY,hostname TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 0,account_id TEXT NOT NULL DEFAULT '',zone_id TEXT NOT NULL DEFAULT '',token_ciphertext TEXT NOT NULL DEFAULT '',rule_ref TEXT NOT NULL,ruleset_id TEXT NOT NULL DEFAULT '',rule_id TEXT NOT NULL DEFAULT '',applied_hash TEXT NOT NULL DEFAULT '',pending_hash TEXT NOT NULL DEFAULT '',sync_status TEXT NOT NULL DEFAULT 'disabled',last_error TEXT NOT NULL DEFAULT '',last_sync_at TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)`

func TestCloudflareZoneQueryRejectsMetadataAndResultScopeMismatch(t *testing.T) {
	s := newTestService(t)
	s.Client.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		data, _ := json.Marshal(map[string]any{"success": true, "result": []zone{testZoneNamed(testZone, "unrelated.net", testAccount)}, "result_info": map[string]int{"page": 1, "total_pages": 1}})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
	})
	if _, err := s.Client.resolveCoverage(context.Background(), testAccount, testToken, []string{"example.com"}, nil); err == nil {
		t.Fatal("substring/unrelated query result accepted")
	}
}

func TestCloudflarePrimaryChangeDuringZoneReadCannotWriteUncleanableRule(t *testing.T) {
	s := newTestService(t)
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	autoSave(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	old := ruleHash(fake.rs.Rules[0])
	changed := false
	s.Client.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if !changed && r.URL.Path == "/client/v4/zones/"+testZone {
			changed = true
			if _, err := s.DB.Exec(`UPDATE websites SET domain='changed.example.com' WHERE id=1`); err != nil {
				t.Fatal(err)
			}
		}
		return fake.transport(r)
	})
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("primary read race accepted")
	}
	if len(fake.mutations) != 1 || ruleHash(fake.rs.Rules[0]) != old {
		t.Fatal("primary race wrote an unowned hostname")
	}
	if _, err := s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(ctx, 1); err != nil || len(fake.rs.Rules) != 0 {
		t.Fatal("old binding could not be cleaned after primary change", err)
	}
}
