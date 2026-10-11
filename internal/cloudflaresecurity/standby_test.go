package cloudflaresecurity

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

func TestCloudflareStandbyRuleCreatedWithoutBansAndReusedThroughBanLifecycle(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	setAliases(t, s, 1, "www.example.com")
	// Host protection events must never become website bans.
	addTestBan(t, s, "198.51.100.10", "olswpanel-sshd", "")
	addTestBan(t, s, "198.51.100.11", "panel_scan", "")
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	status, err := s.Sync(ctx, 1)
	if err != nil || status.SyncStatus != "synced" || status.RuleID != testRuleID || !status.ActiveIPCountKnown || status.ActiveIPCount != 0 || !sameHosts(status.CoveredHostnames, []string{"example.com", "www.example.com"}) {
		t.Fatal("empty website blacklist did not create a confirmed standby rule", status, err)
	}
	want := `(http.host in {"example.com" "www.example.com"}) and (ssl and not ssl)`
	if len(fake.rs.Rules) != 1 || fake.rs.Rules[0].Expression != want || !fake.rs.Rules[0].Enabled {
		t.Fatal("standby rule can match traffic or contains server bans", fake.rs.Rules)
	}
	if _, err := s.Sync(ctx, 1); err != nil || len(fake.mutations) != 1 {
		t.Fatal("unchanged empty blacklist duplicated or rewrote the rule", err)
	}
	addTestBan(t, s, "198.51.100.1", "olswpanel-sqli", "")
	if status, err := s.Get(ctx, 1); err != nil || status.SyncStatus != "pending" || status.ActiveIPCount != 1 {
		t.Fatal("new ban claimed synchronized before the remote update", status, err)
	}
	status, err = s.Sync(ctx, 1)
	if err != nil || status.RuleID != testRuleID || status.ActiveIPCount != 1 || strings.Contains(fake.rs.Rules[0].Expression, "ssl") || !strings.Contains(fake.rs.Rules[0].Expression, "ip.src in {198.51.100.1}") {
		t.Fatal("new website ban did not activate the same rule", status, err)
	}
	if _, err := s.DB.Exec(`UPDATE firewall_bans SET unbanned_at=CURRENT_TIMESTAMP WHERE source_jail='olswpanel-sqli'`); err != nil {
		t.Fatal(err)
	}
	if status, err := s.Get(ctx, 1); err != nil || status.SyncStatus != "pending" || status.ActiveIPCount != 0 {
		t.Fatal("last unban claimed standby before the remote update", status, err)
	}
	status, err = s.Sync(ctx, 1)
	if err != nil || status.RuleID != testRuleID || status.ActiveIPCount != 0 || fake.rs.Rules[0].Expression != want || len(status.CoveredHostnames) != 2 {
		t.Fatal("last unban deleted the rule instead of returning to standby", status, err)
	}
	if _, err := s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount}); err != nil {
		t.Fatal(err)
	}
	status, err = s.Sync(ctx, 1)
	if err != nil || status.SyncStatus != "disabled" || status.RuleID != "" || len(status.CoveredHostnames) != 0 || len(fake.rs.Rules) != 0 {
		t.Fatal("disabled standby rule was not removed", status, err)
	}
	if strings.Join(fake.mutations, ",") != "CREATE_ENTRYPOINT,PATCH_RULE,PATCH_RULE,DELETE_RULE" {
		t.Fatal("unexpected lifecycle writes", fake.mutations)
	}
}

func TestCloudflareStandbyRuleWriteFailureCannotReportSynced(t *testing.T) {
	for _, statusCode := range []int{403, 400} {
		s := newTestService(t)
		saveTestConfig(t, s, 1)
		fake := &fakeCloudflare{t: t, writeStatus: statusCode}
		useFake(s, fake)
		ctx := context.Background()
		// Passing a read-only test must not skip the actual standby write.
		if _, err := s.Test(ctx, 1); err != nil {
			t.Fatal("read-only test unexpectedly failed", err)
		}
		if _, err := s.Sync(ctx, 1); err == nil {
			t.Fatal("write-denied or capacity failure reported success", statusCode)
		}
		status, err := s.Get(ctx, 1)
		if err != nil || status.SyncStatus != "error" || status.RuleID != "" || status.LastError == "" || status.LastSyncAt != "" || len(status.CoveredHostnames) != 0 || len(fake.mutations) != 0 {
			t.Fatal("failed standby creation claimed a rule or coverage", status, err)
		}
	}
}

func TestCloudflareStandbyUncertainWritesRecoverWithoutDuplicate(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	fake := &fakeCloudflare{t: t, failAfterWrite: true}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("lost create response reported synced")
	}
	if status, err := s.Sync(ctx, 1); err != nil || status.RuleID != testRuleID || len(fake.rs.Rules) != 1 || len(fake.mutations) != 1 {
		t.Fatal("standby create retry duplicated or lost ownership", status, err)
	}
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE firewall_bans SET unbanned_at=CURRENT_TIMESTAMP`); err != nil {
		t.Fatal(err)
	}
	fake.failAfterWrite = true
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("lost standby patch response reported synced")
	}
	if status, err := s.Sync(ctx, 1); err != nil || status.RuleID != testRuleID || len(fake.rs.Rules) != 1 || len(fake.mutations) != 3 || !strings.HasSuffix(fake.rs.Rules[0].Expression, "and (ssl and not ssl)") {
		t.Fatal("standby patch retry duplicated or lost ownership", status, err)
	}
}

func TestCloudflareLegacyEmptySyncNeedsStandbyCreation(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	if _, err := s.DB.Exec(`UPDATE website_cloudflare_security SET sync_status='synced',last_sync_at=CURRENT_TIMESTAMP WHERE site_id=1`); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if status, err := s.Get(ctx, 1); err != nil || status.SyncStatus != "pending" || status.RuleID != "" {
		t.Fatal("legacy no-rule result still claims synchronized rule", status, err)
	}
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	if status, err := s.Sync(ctx, 1); err != nil || status.SyncStatus != "synced" || status.RuleID != testRuleID {
		t.Fatal("legacy empty result did not upgrade through a real write", status, err)
	}
}

func TestCloudflareStandbyRequiresValidFullHostCoverage(t *testing.T) {
	for _, alias := range []string{"www.other.net", "https://invalid.example.com/path", "login.child.example.com"} {
		s := newTestService(t)
		saveTestConfig(t, s, 1)
		setAliases(t, s, 1, alias)
		fake := &fakeCloudflare{t: t, zones: []zone{testZoneNamed(testZone, "example.com", testAccount), testZoneNamed("ffffffffffffffffffffffffffffffff", "child.example.com", testAccount)}}
		useFake(s, fake)
		if _, err := s.Sync(context.Background(), 1); err == nil || len(fake.mutations) != 0 {
			t.Fatal("empty standby bypassed invalid/cross-zone/delegated host checks", alias, err)
		}
	}
}

func TestCloudflareStandbyExpressionOwnershipIsExact(t *testing.T) {
	if _, err := expressionForHosts(nil, nil); err == nil {
		t.Fatal("empty rule without a hostname accepted")
	}
	for _, hosts := range [][]string{{"example.com"}, {"example.com", "www.example.com"}} {
		text, err := expressionForHosts(hosts, nil)
		parsed, ok := hostsFromExpression(text)
		if err != nil || !ok || !sameHosts(hosts, parsed) || !strings.HasSuffix(text, "and (ssl and not ssl)") {
			t.Fatal("standby ownership cannot round-trip", text, err)
		}
		for _, suffix := range []string{" or ssl", " or not ssl"} {
			if _, ok := hostsFromExpression(text + suffix); ok {
				t.Fatal("widened standby expression accepted", text+suffix)
			}
		}
	}
	// Large hostname groups must retain the same expression-size limit even
	// though the blacklist is empty; never truncate confirmed coverage.
	hosts := []string{"example.com"}
	for i := 0; i < 80; i++ {
		hosts = append(hosts, strings.Repeat("a", 60)+strconv.Itoa(i)+"."+strings.Repeat("b", 60)+".example.com")
	}
	if _, err := expressionForHosts(hosts, nil); err == nil || !strings.Contains(err.Error(), "4096") {
		t.Fatal("oversized standby host expression was accepted", err)
	}
}
