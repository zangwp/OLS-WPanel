package cloudflaresecurity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

const testAccount = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testZone = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testRuleset = "cccccccccccccccccccccccccccccccc"
const testRuleID = "dddddddddddddddddddddddddddddddd"
const testToken = "test-only-opaque-cloudflare-token-1234567890"

func newTestService(t *testing.T) *Service {
	t.Helper()
	cycleMu.Lock()
	cycleCursor = 0
	cycleMu.Unlock()
	old := database.DB
	if err := database.Open(filepath.Join(t.TempDir(), "panel.db")); err != nil {
		t.Fatal(err)
	}
	db := database.GetDB()
	t.Cleanup(func() { db.Close(); database.DB = old })
	if err := database.RunMigrations(); err != nil {
		t.Fatal(err)
	}
	for id, host := range []string{"example.com", "shop.example.com"} {
		if _, err := db.Exec(`INSERT INTO websites(id,name,domain,status,system_user,web_root,log_dir,db_name,db_user,lsphp_socket_path,ols_vhost_config_path) VALUES(?,?,?,'active','wp_test','/www/test','/logs/test','db_test','wp_test','/tmp/test.sock','/conf/test')`, id+1, host, host); err != nil {
			t.Fatal(err)
		}
	}
	s := NewService(db)
	key := []byte("01234567890123456789012345678901")
	// Native Windows cannot assert Unix 0600; use the same AES-GCM functions
	// with an injected private test key. Filesystem fail-closed cases below still
	// execute independently, and production retains the strict Unix checks.
	s.seal = func(id int, token string) (string, error) { return sealWithKey(key, id, token) }
	s.open = func(id int, text string) (string, error) { return openWithKey(key, id, text) }
	return s
}
func saveTestConfig(t *testing.T, s *Service, id int) {
	t.Helper()
	if _, err := s.Save(context.Background(), id, Update{Enabled: true, AccountID: testAccount, ZoneID: testZone, APIToken: testToken}); err != nil {
		t.Fatal(err)
	}
}
func addTestBan(t *testing.T, s *Service, ip, jail, expiry string) {
	t.Helper()
	var expires any
	if expiry != "" {
		expires = expiry
	}
	if _, err := s.DB.Exec(`INSERT INTO firewall_bans(ip_address,source_jail,expires_at) VALUES(?,?,?)`, ip, jail, expires); err != nil {
		t.Fatal(err)
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func apiResponse(status int, result any) *http.Response {
	data, _ := json.Marshal(map[string]any{"success": status < 300, "result": result})
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}
}

type fakeCloudflare struct {
	t               *testing.T
	rs              ruleset
	exists          bool
	mutations       []string
	failAfterWrite  bool
	failBeforeWrite bool
	changedHost     string
	unauthorized    bool
	mismatchAccount bool
	acceptedToken   string
	requests        []string
	zones           []zone
	zonePages       map[int][]zone
	zoneTotalPages  int
}

func (f *fakeCloudflare) transport(r *http.Request) (*http.Response, error) {
	f.t.Helper()
	if r.URL.Scheme != "https" || r.URL.Host != "api.cloudflare.com" {
		f.t.Fatal("request escaped fixed API origin")
	}
	p := strings.TrimPrefix(r.URL.Path, "/client/v4")
	f.requests = append(f.requests, r.Method+" "+p)
	accepted := f.acceptedToken
	if accepted == "" {
		accepted = testToken
	}
	if r.Header.Get("Authorization") != "Bearer "+accepted {
		return apiResponse(403, map[string]string{"echo": r.Header.Get("Authorization")}), nil
	}
	if f.unauthorized {
		return apiResponse(403, map[string]string{"echo": testToken}), nil
	}
	if p == "/zones" && r.Method == http.MethodGet {
		q := r.URL.Query()
		if q.Get("account.id") == "" || q.Get("name") == "" || q.Get("match") != "all" || q.Get("per_page") != "50" {
			f.t.Fatal("zone lookup missing scoped exact query")
		}
		zones := f.zones
		if zones == nil {
			z := zone{ID: testZone, Name: "example.com"}
			z.Account.ID = testAccount
			zones = []zone{z}
		}
		var found []zone
		for _, z := range zones {
			if z.Name == q.Get("name") && z.Account.ID == q.Get("account.id") {
				found = append(found, z)
			}
		}
		if f.zonePages != nil {
			page := 1
			fmt.Sscan(q.Get("page"), &page)
			data, _ := json.Marshal(map[string]any{"success": true, "result": f.zonePages[page], "result_info": map[string]int{"page": page, "total_pages": f.zoneTotalPages}})
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
		}
		return apiResponse(200, found), nil
	}
	if p == "/zones/"+testZone && r.Method == http.MethodGet {
		z := zone{ID: testZone, Name: "example.com"}
		z.Account.ID = testAccount
		for _, candidate := range f.zones {
			if candidate.ID == testZone {
				z = candidate
			}
		}
		if f.mismatchAccount {
			z.Account.ID = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		}
		return apiResponse(200, z), nil
	}
	if r.Method == http.MethodGet && p == "/zones/"+testZone+"/rulesets/phases/"+phase+"/entrypoint" {
		if !f.exists {
			return apiResponse(404, nil), nil
		}
		return apiResponse(200, f.rs), nil
	}
	if r.Method == http.MethodPost && p == "/zones/"+testZone+"/rulesets" {
		var body struct {
			Kind  string `json:"kind"`
			Phase string `json:"phase"`
			Rules []rule `json:"rules"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Rules) != 1 {
			f.t.Fatal("invalid new entrypoint body")
		}
		f.exists = true
		f.rs = ruleset{ID: testRuleset, Kind: body.Kind, Phase: body.Phase, Rules: body.Rules}
		f.rs.Rules[0].ID = testRuleID
		f.mutations = append(f.mutations, "CREATE_ENTRYPOINT")
		if f.failAfterWrite {
			f.failAfterWrite = false
			return nil, errors.New("network timeout contains " + testToken)
		}
		return apiResponse(200, f.rs), nil
	}
	base := "/zones/" + testZone + "/rulesets/" + testRuleset + "/rules"
	if r.Method == http.MethodPost && p == base {
		var rule rule
		if json.NewDecoder(r.Body).Decode(&rule) != nil {
			f.t.Fatal("invalid new rule")
		}
		rule.ID = testRuleID
		f.rs.Rules = append(f.rs.Rules, rule)
		f.mutations = append(f.mutations, "POST_RULE")
		if f.failAfterWrite {
			f.failAfterWrite = false
			return nil, errors.New("network timeout contains " + testToken)
		}
		return apiResponse(200, f.rs), nil
	}
	if r.Method == http.MethodPatch && p == base+"/"+testRuleID {
		if f.failBeforeWrite {
			f.failBeforeWrite = false
			return nil, errors.New("timeout before remote change")
		}
		var rule rule
		if json.NewDecoder(r.Body).Decode(&rule) != nil {
			f.t.Fatal("invalid patch rule")
		}
		rule.ID = testRuleID
		found := false
		for i := range f.rs.Rules {
			if f.rs.Rules[i].ID == testRuleID {
				f.rs.Rules[i] = rule
				found = true
			}
		}
		if !found {
			f.t.Fatal("patched non-owned rule")
		}
		f.mutations = append(f.mutations, "PATCH_RULE")
		if f.failAfterWrite {
			f.failAfterWrite = false
			return nil, errors.New("network timeout contains " + testToken)
		}
		return apiResponse(200, f.rs), nil
	}
	if r.Method == http.MethodDelete && p == base+"/"+testRuleID {
		rules := f.rs.Rules[:0]
		for _, r := range f.rs.Rules {
			if r.ID != testRuleID {
				rules = append(rules, r)
			}
		}
		f.rs.Rules = rules
		f.mutations = append(f.mutations, "DELETE_RULE")
		return apiResponse(200, map[string]string{"id": testRuleset}), nil
	}
	f.t.Fatalf("unexpected method/path %s %s", r.Method, p)
	return nil, nil
}
func useFake(s *Service, f *fakeCloudflare) { s.Client.HTTP.Transport = transportFunc(f.transport) }

func TestCloudflareCredentialsAreEncryptedSiteBoundAndRedacted(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	ctx := context.Background()
	status, err := s.Get(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(status)
	if strings.Contains(string(data), testToken) || strings.Contains(string(data), "ciphertext") {
		t.Fatal("status leaked token")
	}
	cfg, err := s.load(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Ciphertext == testToken || strings.Contains(cfg.Ciphertext, testToken) {
		t.Fatal("plaintext stored")
	}
	if value, err := s.open(1, cfg.Ciphertext); err != nil || value != testToken {
		t.Fatal("token did not round-trip")
	}
	if _, err := s.open(2, cfg.Ciphertext); err == nil {
		t.Fatal("token decrypted for another site")
	}
	_, err = s.Save(ctx, 1, Update{Enabled: true, AccountID: testAccount, ZoneID: testZone})
	if err != nil {
		t.Fatal("blank token did not preserve credential:", err)
	}
}
func TestCloudflareMissingKeyNeverReplacesExistingEncryptedCredentials(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	if _, err := secretKey(s.DB, true); err == nil {
		t.Fatal("missing key recreated despite existing token")
	}
	var seq int
	var name, path string
	if err := s.DB.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "cloudflare-security.key")); !os.IsNotExist(err) {
		t.Fatal("key file was created")
	}
}

func TestCloudflareDamagedExistingKeyIsNeverOverwritten(t *testing.T) {
	s := newTestService(t)
	var seq int
	var name, path string
	if err := s.DB.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(filepath.Dir(path), "cloudflare-security.key")
	original := []byte("damaged-existing-key")
	if err := os.WriteFile(keyPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := secretKey(s.DB, true); err == nil {
		t.Fatal("damaged key accepted")
	}
	got, err := os.ReadFile(keyPath)
	if err != nil || string(got) != string(original) {
		t.Fatal("existing damaged key replaced")
	}
}
func TestCloudflareUnixKeyCreationPermissionsAndSymlinkRejection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix owner-only permissions and no-symlink key installation require Unix")
	}
	s := newTestService(t)
	key, err := secretKey(s.DB, true)
	if err != nil || len(key) != 32 {
		t.Fatalf("new key failed %v", err)
	}
	var seq int
	var name, path string
	if err = s.DB.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(filepath.Dir(path), "cloudflare-security.key")
	info, err := os.Stat(keyPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("key not owner-only")
	}
	second, err := secretKey(s.DB, false)
	if err != nil || string(second) != string(key) {
		t.Fatal("key rotated on read")
	}
	if err = os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(path), "symlink-target")
	if err = os.WriteFile(target, key, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, keyPath); err != nil {
		t.Fatal(err)
	}
	if _, err = secretKey(s.DB, true); err == nil {
		t.Fatal("symlink key accepted")
	}
}
func TestCloudflareDesiredIPsUnionJailsExcludeHostAndExpiredBans(t *testing.T) {
	s := newTestService(t)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "2999-01-01 00:00:00")
	addTestBan(t, s, "198.51.100.1", "olswpanel-sqli", "2999-01-02 00:00:00")
	addTestBan(t, s, "::ffff:198.51.100.1", "olswpanel", "2999-01-01 00:00:00")
	addTestBan(t, s, "2001:db8::1", "olswpanel-404", "")
	for i, jail := range []string{"olswpanel-sshd", "panel", "panel_scan", "manual"} {
		addTestBan(t, s, fmt.Sprintf("198.51.100.%d", i+5), jail, "")
	}
	addTestBan(t, s, "198.51.100.50", "olswpanel-login", "2000-01-01 00:00:00")
	ips, err := s.activeIPs(context.Background())
	if err != nil || strings.Join(ips, ",") != "198.51.100.1,2001:db8::1" {
		t.Fatalf("unexpected desired set %v %v", ips, err)
	}
	if _, err := s.DB.Exec(`UPDATE firewall_bans SET unbanned_at=CURRENT_TIMESTAMP WHERE source_jail IN ('olswpanel-login','olswpanel')`); err != nil {
		t.Fatal(err)
	}
	ips, err = s.activeIPs(context.Background())
	if err != nil || strings.Join(ips, ",") != "198.51.100.1,2001:db8::1" {
		t.Fatal("one jail's unban removed another active reference")
	}
}
func TestCloudflareCreatePatchDeleteOnlyOwnedRuleWithOfficialRulesetResponse(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	admin := rule{ID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", Ref: "admin-rule", Action: "skip", Expression: `http.host eq "example.com"`, Enabled: true, Description: "Administrator managed"}
	fake := &fakeCloudflare{t: t, exists: true, rs: ruleset{ID: testRuleset, Kind: "zone", Phase: phase, Rules: []rule{admin}}}
	useFake(s, fake)
	ctx := context.Background()
	status, err := s.Sync(ctx, 1)
	if err != nil || status.RuleID != testRuleID || status.SyncStatus != "synced" {
		t.Fatalf("first sync %v %v", status, err)
	}
	if len(fake.rs.Rules) != 2 || ruleHash(fake.rs.Rules[0]) != ruleHash(admin) || fake.rs.Rules[1].Expression != `(http.host eq "example.com") and ip.src in {198.51.100.1}` {
		t.Fatal("admin order/rule or exact hostname changed")
	}
	addTestBan(t, s, "2001:db8::1", "olswpanel-sqli", "")
	if _, err = s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if ruleHash(fake.rs.Rules[0]) != ruleHash(admin) || !strings.Contains(fake.rs.Rules[1].Expression, "2001:db8::1") {
		t.Fatal("patch damaged administrator rule or lost IPv6")
	}
	if _, err = s.DB.Exec(`UPDATE firewall_bans SET unbanned_at=CURRENT_TIMESTAMP`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if len(fake.rs.Rules) != 1 || ruleHash(fake.rs.Rules[0]) != ruleHash(admin) {
		t.Fatal("cleanup deleted another rule")
	}
	if strings.Join(fake.mutations, ",") != "POST_RULE,PATCH_RULE,DELETE_RULE" {
		t.Fatal("unexpected mutation methods", fake.mutations)
	}
}
func TestCloudflareUnknownCreateResponseRecoversWithoutDuplicateAndLocksRebind(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	fake := &fakeCloudflare{t: t, failAfterWrite: true}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatal("uncertain create incorrectly successful or leaked token")
	}
	status, err := s.Get(ctx, 1)
	if err != nil || !status.CleanupRequired || status.RuleID != "" || status.SyncStatus != "error" {
		t.Fatal("uncertain write state missing")
	}
	if _, err = s.Save(ctx, 1, Update{Enabled: true, AccountID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", ZoneID: testZone}); err == nil {
		t.Fatal("rebind allowed with uncertain remote create")
	}
	if _, err = s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if len(fake.rs.Rules) != 1 || len(fake.mutations) != 1 {
		t.Fatal("retry duplicated rule")
	}
}
func TestCloudflareExternalRuleModificationFailsClosed(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	fake.rs.Rules[0].Expression = `ip.src in {198.51.100.1}`
	addTestBan(t, s, "198.51.100.2", "olswpanel-sqli", "")
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("overwrote externally modified owned rule")
	}
	if len(fake.mutations) != 1 {
		t.Fatal("mutated rule after ownership conflict")
	}
}
func TestCloudflareDisabledCleanupIsExplicitAndIgnoresInvalidGlobalIP(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE websites SET domain='new.example.com' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	status, err := s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount, ZoneID: testZone})
	if err != nil || status.SyncStatus != "removal_required" || status.Hostname != "example.com" {
		t.Fatalf("disable state %v %v", status, err)
	}
	addTestBan(t, s, "bad attacker controlled string", "olswpanel-login", "")
	if err = s.SyncAll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fake.rs.Rules) != 1 {
		t.Fatal("background removed live disabled site's rule")
	}
	status, err = s.Sync(ctx, 1)
	if err != nil || status.RuleID != "" || status.SyncStatus != "disabled" || status.ActiveIPCountKnown {
		t.Fatalf("explicit cleanup blocked by invalid new IP: %v %v", status, err)
	}
}
func TestCloudflareCapacityFailurePreservesRemoteRuleAndReportsUnsynced(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	before := fake.rs.Rules[0]
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 600; i++ {
		if _, err = tx.Exec(`INSERT INTO firewall_bans(ip_address,source_jail) VALUES(?,'olswpanel-sqli')`, fmt.Sprintf("2001:db8::%x", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Sync(ctx, 1); err == nil || !strings.Contains(err.Error(), "4096") {
		t.Fatal("capacity silently truncated or widened")
	}
	if ruleHash(fake.rs.Rules[0]) != ruleHash(before) || len(fake.mutations) != 1 {
		t.Fatal("capacity failure mutated remote state")
	}
}
func TestCloudflareReadOnlyUnsavedTestValidatesAccountAndDoesNotPersist(t *testing.T) {
	s := newTestService(t)
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	input := &Update{AccountID: testAccount, ZoneID: testZone, APIToken: testToken}
	status, err := s.TestUpdate(ctx, 1, input)
	if err != nil || !status.TokenConfigured {
		t.Fatalf("test %v %v", status, err)
	}
	var count int
	if err = s.DB.QueryRow(`SELECT COUNT(*) FROM website_cloudflare_security`).Scan(&count); err != nil || count != 0 || len(fake.mutations) != 0 {
		t.Fatal("read-only test persisted or mutated")
	}
	fake.mismatchAccount = true
	if _, err = s.TestUpdate(ctx, 1, input); err == nil {
		t.Fatal("mismatched account accepted")
	}
	fake.mismatchAccount = false
	fake.unauthorized = true
	if _, err = s.TestUpdate(ctx, 1, input); err == nil || strings.Contains(err.Error(), testToken) {
		t.Fatal("permission error absent or disclosed response body")
	}
}
func TestCloudflareOrphanRuleIsCleanedWithoutDeletingOtherSites(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`DELETE FROM websites WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncAll(ctx); err != nil {
		t.Fatal(err)
	}
	cfg, err := s.load(ctx, 1)
	if err != nil || cfg.RuleID != "" || cfg.Enabled || len(fake.rs.Rules) != 0 {
		t.Fatal("orphan cleanup did not converge")
	}
}

func TestCloudflareExternalActionParametersOrDescriptionModificationFailsClosed(t *testing.T) {
	for _, field := range []string{"action_parameters", "description", "logging"} {
		t.Run(field, func(t *testing.T) {
			s := newTestService(t)
			saveTestConfig(t, s, 1)
			addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
			fake := &fakeCloudflare{t: t}
			useFake(s, fake)
			ctx := context.Background()
			if _, err := s.Sync(ctx, 1); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "action_parameters":
				fake.rs.Rules[0].ActionParameters = json.RawMessage(`{"response":{"status_code":403,"content":"custom"}}`)
			case "description":
				fake.rs.Rules[0].Description = "Manually changed"
			case "logging":
				fake.rs.Rules[0].Logging = json.RawMessage(`{"enabled":false}`)
			}
			if _, err := s.Sync(ctx, 1); err == nil {
				t.Fatal("external change accepted")
			}
			if len(fake.mutations) != 1 {
				t.Fatal("external change overwritten")
			}
			if _, err := s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount, ZoneID: testZone}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Sync(ctx, 1); err == nil {
				t.Fatal("externally modified rule deleted")
			}
		})
	}
}

func TestCloudflareUncertainPatchKeepsVerifiedBaselineAcrossNewDesiredChanges(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	addTestBan(t, s, "198.51.100.2", "olswpanel-sqli", "")
	fake.failAfterWrite = true
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("lost response treated as success")
	}
	baseline := ruleHash(fake.rs.Rules[0])
	addTestBan(t, s, "198.51.100.3", "olswpanel-sqli", "")
	fake.failBeforeWrite = true
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("failed remote patch treated as success")
	}
	cfg, err := s.load(ctx, 1)
	if err != nil || cfg.AppliedHash != baseline {
		t.Fatal("verified uncertain B baseline was lost")
	}
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal("retry falsely treated baseline as outside modification:", err)
	}
	if !strings.Contains(fake.rs.Rules[0].Expression, "198.51.100.3") {
		t.Fatal("new desired state did not converge")
	}
}

func TestCloudflareAccountsAndHostsRemainSeparateAndInterruptedCycleIsFair(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	account2 := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	zone2 := "ffffffffffffffffffffffffffffffff"
	token2 := "different-account-opaque-test-token-1234567890"
	if _, err := s.Save(context.Background(), 2, Update{Enabled: true, AccountID: account2, ZoneID: zone2, APIToken: token2}); err != nil {
		t.Fatal(err)
	}
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	states := map[string]ruleset{}
	var visited []string
	interrupt := true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Client.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/client/v4/zones" && r.Method == http.MethodGet {
			q := r.URL.Query()
			account, token, zoneID := testAccount, testToken, testZone
			if q.Get("account.id") == account2 {
				account, token, zoneID = account2, token2, zone2
			}
			if q.Get("account.id") != account || r.Header.Get("Authorization") != "Bearer "+token {
				t.Fatal("cross-account lookup")
			}
			var found []zone
			if q.Get("name") == "example.com" {
				z := zone{ID: zoneID, Name: "example.com"}
				z.Account.ID = account
				found = append(found, z)
			}
			return apiResponse(200, found), nil
		}
		p := strings.TrimPrefix(r.URL.Path, "/client/v4/zones/")
		parts := strings.Split(p, "/")
		zoneID := parts[0]
		account, token := testAccount, testToken
		if zoneID == zone2 {
			account, token = account2, token2
		} else if zoneID != testZone {
			t.Fatal("unexpected zone")
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Fatal("cross-account credential leak")
		}
		if len(parts) == 1 && r.Method == http.MethodGet {
			visited = append(visited, zoneID)
			if interrupt {
				interrupt = false
				cancel()
				return nil, errors.New("first site timed out")
			}
			z := zone{ID: zoneID, Name: "example.com"}
			z.Account.ID = account
			return apiResponse(200, z), nil
		}
		if r.Method == http.MethodGet {
			state, ok := states[zoneID]
			if !ok {
				return apiResponse(404, nil), nil
			}
			return apiResponse(200, state), nil
		}
		if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "rulesets" {
			var body struct {
				Rules []rule `json:"rules"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Rules) != 1 {
				t.Fatal("invalid body")
			}
			expectedHost := "example.com"
			if zoneID == zone2 {
				expectedHost = "shop.example.com"
			}
			if !strings.HasPrefix(body.Rules[0].Expression, fmt.Sprintf(`(http.host eq %q) and`, expectedHost)) {
				t.Fatal("rule used another website hostname")
			}
			body.Rules[0].ID = testRuleID
			state := ruleset{ID: testRuleset, Kind: "zone", Phase: phase, Rules: body.Rules}
			states[zoneID] = state
			return apiResponse(200, state), nil
		}
		t.Fatalf("unexpected path/method %s %s", r.Method, p)
		return nil, nil
	})
	if err := s.SyncAll(ctx); err == nil {
		t.Fatal("interrupted cycle reported success")
	}
	if err := s.SyncAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(visited) != 3 || visited[0] != testZone || visited[1] != zone2 || visited[2] != testZone {
		t.Fatal("second account starved after first site's interrupted attempt", visited)
	}
	if len(states) != 2 {
		t.Fatal("independent accounts did not synchronize")
	}
}

func TestCloudflareRevokedTokenRotationKeepsOwnedRuleAndSupportsCleanup(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	fake := &fakeCloudflare{t: t}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal(err)
	}
	before, err := s.load(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	newToken := "replacement-authorized-cloudflare-token-1234567890"
	fake.acceptedToken = newToken
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("revoked credential did not fail")
	}
	// Even a locally unreadable old ciphertext must not gate the explicit new
	// token save. A real missing encryption key remains fail-closed below.
	open := s.open
	s.open = func(id int, text string) (string, error) {
		if text == before.Ciphertext {
			return "", errors.New("old ciphertext deliberately unreadable")
		}
		return open(id, text)
	}
	requests := len(fake.requests)
	status, err := s.Save(ctx, 1, Update{Enabled: true, AccountID: testAccount, ZoneID: testZone, APIToken: newToken})
	if err != nil || status.RuleID != testRuleID {
		t.Fatalf("same binding replacement failed: %v", err)
	}
	if len(fake.requests) != requests {
		t.Fatal("save made a remote API request")
	}
	after, err := s.load(ctx, 1)
	if err != nil || after.Ref != before.Ref || after.RuleID != before.RuleID || after.RulesetID != before.RulesetID || after.AppliedHash != before.AppliedHash || after.Ciphertext == before.Ciphertext {
		t.Fatal("rotation changed ownership or did not replace encrypted credential")
	}
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal("authorized rotated credential did not recover owned rule:", err)
	}
	if len(fake.mutations) != 1 || len(fake.rs.Rules) != 1 {
		t.Fatal("rotation duplicated or unnecessarily rewrote owned rule")
	}
	if _, err := s.Save(ctx, 1, Update{Enabled: false, AccountID: testAccount, ZoneID: testZone}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal("rotated credential could not clean up old rule:", err)
	}
	if len(fake.rs.Rules) != 0 || strings.Join(fake.mutations, ",") != "CREATE_ENTRYPOINT,DELETE_RULE" {
		t.Fatal("cleanup damaged or left owned rule")
	}
}

func TestCloudflarePendingCreateCanRotateTokenWithoutDuplicateOrForeignScopeMutation(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	addTestBan(t, s, "198.51.100.1", "olswpanel-login", "")
	fake := &fakeCloudflare{t: t, failAfterWrite: true}
	useFake(s, fake)
	ctx := context.Background()
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("unknown create response reported success")
	}
	before, err := s.load(ctx, 1)
	if err != nil || before.PendingHash == "" {
		t.Fatal("pending owned state absent")
	}
	foreignToken := "foreign-account-opaque-token-1234567890"
	correctToken := "rotated-correct-account-token-1234567890"
	fake.acceptedToken = correctToken
	if _, err := s.Save(ctx, 1, Update{Enabled: true, AccountID: testAccount, ZoneID: testZone, APIToken: foreignToken}); err != nil {
		t.Fatal("same-binding save must remain recoverable:", err)
	}
	after, err := s.load(ctx, 1)
	if err != nil || after.Ref != before.Ref || after.PendingHash != before.PendingHash || after.RuleID != before.RuleID {
		t.Fatal("rotation discarded pending create ownership")
	}
	if _, err := s.Sync(ctx, 1); err == nil {
		t.Fatal("wrong-account replacement credential accepted")
	}
	if len(fake.mutations) != 1 {
		t.Fatal("wrong-account token mutated a WAF rule")
	}
	for _, path := range fake.requests {
		if path != "GET /zones" && !strings.Contains(path, "/zones/"+testZone) {
			t.Fatal("rotation sent a request to a foreign zone")
		}
	}
	if _, err := s.Save(ctx, 1, Update{Enabled: true, AccountID: testAccount, ZoneID: testZone, APIToken: correctToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(ctx, 1); err != nil {
		t.Fatal("correct replacement could not recover uncertain creation:", err)
	}
	if len(fake.mutations) != 1 || len(fake.rs.Rules) != 1 {
		t.Fatal("uncertain creation duplicated after rotation")
	}
	if _, err := s.Save(ctx, 1, Update{Enabled: true, AccountID: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", ZoneID: testZone, APIToken: correctToken}); err == nil {
		t.Fatal("credential rotation bypassed account cleanup requirement")
	}
}

func TestCloudflareRotationCannotReplaceMissingEncryptionKey(t *testing.T) {
	s := newTestService(t)
	saveTestConfig(t, s, 1)
	before, err := s.load(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	s.seal = func(id int, token string) (string, error) { return sealToken(s.DB, id, token) }
	if _, err := s.Save(context.Background(), 1, Update{Enabled: true, AccountID: testAccount, ZoneID: testZone, APIToken: "new-token-with-missing-local-key-1234567890"}); err == nil {
		t.Fatal("rotation silently generated replacement key")
	}
	after, err := s.load(context.Background(), 1)
	if err != nil || after.Ciphertext != before.Ciphertext {
		t.Fatal("failed key recovery changed stored ciphertext")
	}
}
