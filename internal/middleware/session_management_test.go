package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestSessionsReturnCopiesAndNeverExposeBearerTokens(t *testing.T) {
	store := &SessionStore{}
	first := store.CreateWithMetadata("admin", "192.0.2.1", "Browser\r\nAgent")
	if first.ID == first.Token || first.ID == "" {
		t.Fatal("display ID must be independent")
	}
	token := first.Token
	first.Username = "attacker"
	got := store.Get(token)
	if got.Username != "admin" || got.UserAgent != "BrowserAgent" {
		t.Fatalf("stored session changed: %+v", got)
	}
	got.ExpiresAt = time.Time{}
	if store.Get(token) == nil {
		t.Fatal("Get returned mutable stored state")
	}
	list := store.List("admin", token)
	if len(list) != 1 || !list[0].Current || list[0].Token != "" {
		t.Fatal("invalid summary")
	}
	encoded, err := json.Marshal(list)
	if err != nil || strings.Contains(string(encoded), token) || strings.Contains(string(encoded), "Token") {
		t.Fatal("bearer token exposed")
	}
	list[0].Username = "attacker"
	if store.Get(token).Username != "admin" {
		t.Fatal("summary was not copied")
	}
}

func TestSessionPageRedirectAbortsProtectedHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	called := false
	r.GET("/panel/protected", SessionRequired(), func(c *gin.Context) { called = true; c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/panel/protected", nil)
	req.Header.Set("Accept", "text/html")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if called || w.Code != http.StatusFound {
		t.Fatal("redirect allowed protected handler to execute")
	}
}

func TestSessionRevocationIsScopedAndPreservesCurrent(t *testing.T) {
	store := &SessionStore{}
	current := store.Create("admin")
	other := store.Create("admin")
	foreign := store.Create("other")
	if store.DeleteByID("admin", foreign.ID) || store.DeleteByID("admin", other.Token) {
		t.Fatal("foreign or bearer identifier accepted")
	}
	if n := store.DeleteOthers("admin", current.Token); n != 1 {
		t.Fatalf("revoked %d sessions", n)
	}
	if store.Get(other.Token) != nil || store.Get(current.Token) == nil || store.Get(foreign.Token) == nil {
		t.Fatal("incorrect revocation scope")
	}
	if !store.DeleteByID("admin", current.ID) || store.Get(current.Token) != nil {
		t.Fatal("own session was not revoked")
	}
	store.DeleteAll()
	if store.Get(foreign.Token) != nil {
		t.Fatal("DeleteAll compatibility lost")
	}
}

func TestSessionConcurrentReadsAndExpiredLists(t *testing.T) {
	store := &SessionStore{}
	session := store.Create("admin")
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				copy := store.Get(session.Token)
				if copy != nil {
					copy.Username = "local-only"
				}
				store.List("admin", session.Token)
			}
		}()
	}
	wg.Wait()
	store.mu.Lock()
	store.sessions[session.Token].ExpiresAt = time.Now().Add(-time.Second)
	store.mu.Unlock()
	if len(store.List("admin", session.Token)) != 0 || store.Get(session.Token) != nil {
		t.Fatal("expired session retained")
	}
}
