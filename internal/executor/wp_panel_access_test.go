package executor

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

func wpAccessTestTicket() WPPanelAccessTicket {
	return WPPanelAccessTicket{SiteID: 8, SiteIdentity: "current-installation", UID: 1008, AdministratorID: 7, AdministratorLogin: "site-admin", AdministratorProof: strings.Repeat("e", 64), Generation: strings.Repeat("a", 32), SessionToken: "panel-session", PanelUsername: "panel-admin"}
}

func TestWPPanelAccessTokenIsBoundAndConsumedOnce(t *testing.T) {
	store := NewWPPanelAccessTokenStore()
	ticket := wpAccessTestTicket()
	token, expires, err := store.Issue(ticket)
	if err != nil || len(token) != 43 || expires.IsZero() {
		t.Fatalf("issue failed: %v", err)
	}
	for _, wrong := range []struct {
		site, uid  int
		generation string
	}{{9, 1008, ticket.Generation}, {8, 1009, ticket.Generation}, {8, 0, ticket.Generation}, {8, 1008, strings.Repeat("b", 32)}} {
		if _, err := store.Consume(token, wrong.site, wrong.uid, wrong.generation); err == nil {
			t.Fatal("accepted authorization for a different principal")
		}
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := store.Consume(token, ticket.SiteID, ticket.UID, ticket.Generation); err == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("concurrent consumers accepted=%d", accepted.Load())
	}
	if _, err := store.Consume(token, ticket.SiteID, ticket.UID, ticket.Generation); err == nil {
		t.Fatal("replayed consumed token")
	}
}

func TestWPPanelAccessTokenExpiresRevokesAndReplaces(t *testing.T) {
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	store := NewWPPanelAccessTokenStore()
	store.now = func() time.Time { return now }
	ticket := wpAccessTestTicket()
	first, _, _ := store.Issue(ticket)
	second, _, _ := store.Issue(ticket)
	if _, err := store.Consume(first, ticket.SiteID, ticket.UID, ticket.Generation); err == nil {
		t.Fatal("replaced authorization remained valid")
	}
	now = now.Add(WPPanelAccessLifetime)
	if _, err := store.Consume(second, ticket.SiteID, ticket.UID, ticket.Generation); err == nil {
		t.Fatal("authorization accepted at exact expiry")
	}
	if len(store.tickets) != 0 {
		t.Fatal("expired entries were not removed")
	}
	third, _, _ := store.Issue(ticket)
	store.Revoke(ticket.SiteID, ticket.SessionToken)
	if _, err := store.Consume(third, ticket.SiteID, ticket.UID, ticket.Generation); err == nil {
		t.Fatal("revoked authorization remained valid")
	}
	for _, raw := range []string{"", strings.Repeat("a", 43), strings.Repeat("a", 100)} {
		if _, err := store.Consume(raw, ticket.SiteID, ticket.UID, ticket.Generation); err == nil {
			t.Fatal("accepted unissued token")
		}
	}
}

func TestWPPanelAccessURLRejectsCrossOriginAndPathConfusion(t *testing.T) {
	site := &models.Website{Domain: "example.com", SSLEnabled: true}
	for _, raw := range []string{"https://evil.test/wp/sign-in", "https://example.com.evil.test/wp/sign-in", "//evil.test/wp/sign-in", "https://user:pass@example.com/wp/sign-in", "http://example.com/wp/sign-in", "https://example.com:8443/wp/sign-in", "https://example.com/wp2/sign-in", "https://example.com/wp/../sign-in", "https://example.com/wp/%2e%2e/sign-in", "https://example.com/wp/sign%2fin", "https://example.com/wp/sign%5cin", "https://example.com/wp/sign-in#fragment", "https://example.com/wp/sign-in?redirect_to=https%3A%2F%2Fevil.test%2F"} {
		if _, err := ValidateWPPanelAccessURL(site, "/wp", raw); err == nil {
			t.Fatalf("accepted unsafe login URL: %q", raw)
		}
	}
	for _, raw := range []string{"https://example.com/wp/sign-in", "/wp/sign-in", "https://example.com:443/wp/sign-in", "https://example.com/wp/sign-in?redirect_to=%2Fwp%2Fwp-admin%2F"} {
		if _, err := ValidateWPPanelAccessURL(site, "/wp", raw); err != nil {
			t.Fatalf("rejected safe login URL %q: %v", raw, err)
		}
	}
	for _, suffix := range []string{"wp-admin", "wp-login", "foo.php", "../foo", " foo", "ab", "BadRoute"} {
		if ValidateWPPanelAccessSuffix(suffix) == nil {
			t.Fatalf("accepted unsafe suffix %q", suffix)
		}
	}
	if err := ValidateWPPanelAccessSuffix("staff-signin"); err != nil {
		t.Fatal(err)
	}
}

func TestWPPanelAccessBrokerRequiresUnixPeerAndPOSTBody(t *testing.T) {
	var calls int
	handler := wpPanelAccessBrokerHandler(func(ctx context.Context, token string, site, uid int, generation string) (WPPanelAccessGrant, error) {
		calls++
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
			t.Fatal("broker redemption reached storage without a whole-operation deadline")
		}
		if uid != 1008 || site != 8 || len(token) != 43 {
			t.Fatal("broker principal mismatch")
		}
		return WPPanelAccessGrant{AdministratorID: 7}, nil
	})
	body := `{"token":"` + strings.Repeat("a", 43) + `","site_id":8,"generation":"` + strings.Repeat("b", 32) + `"}`
	for _, test := range []struct {
		method, path, body string
		uid                int
		want               int
	}{{"POST", "/redeem", body, 0, 403}, {"GET", "/redeem", body, 1008, 403}, {"POST", "/redeem?token=x", body, 1008, 403}, {"POST", "/redeem", body + `{}`, 1008, 403}, {"POST", "/redeem", strings.Repeat("x", 4096), 1008, 403}, {"POST", "/redeem", body, 1008, 200}} {
		r := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
		if test.uid != 0 {
			r = r.WithContext(context.WithValue(r.Context(), wpPanelAccessPeerUIDKey{}, test.uid))
		}
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != test.want {
			t.Fatalf("request %s %s: status=%d", test.method, test.path, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("broker reply was cacheable")
		}
	}
	if calls != 1 {
		t.Fatalf("unauthenticated broker reached redemption: calls=%d", calls)
	}
}

func TestWPPanelAccessStatusNeverSerializesAuthenticationProofs(t *testing.T) {
	status := WPPanelAccessStatus{SiteURL: "https://example.com/wp", AdministratorProofs: map[int]string{7: "secret-proof"}, Administrators: []WPPanelAccessAdministrator{{ID: 7, Login: "admin", DisplayName: "Admin"}}}
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret-proof") || strings.Contains(string(raw), "site_url") {
		t.Fatalf("status exposed private authentication data: %s", raw)
	}
}

func TestWPPanelAccessSiteIdentityChangesOnReinstallation(t *testing.T) {
	site := models.Website{ID: 8, Domain: "example.com", SystemUser: "site_8", WebRoot: "/www/example.com", DBName: "site8", CreatedAt: time.Now()}
	identity := WPPanelAccessSiteIdentity(&site)
	site.CreatedAt = site.CreatedAt.Add(time.Second)
	if identity == WPPanelAccessSiteIdentity(&site) {
		t.Fatal("reinstallation retained authorization identity")
	}
	site.CreatedAt = site.CreatedAt.Add(-time.Second)
	site.DBName = "new_database"
	if identity == WPPanelAccessSiteIdentity(&site) {
		t.Fatal("replaced database retained authorization identity")
	}
}
