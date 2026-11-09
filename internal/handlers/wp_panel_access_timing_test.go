package handlers

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/executor"
)

func TestWPPanelAccessLoginResponseUsesServerClockWithoutExtendingTicket(t *testing.T) {
	store := executor.NewWPPanelAccessTokenStore()
	generation := strings.Repeat("a", 32)
	token, expires, err := store.Issue(executor.WPPanelAccessTicket{
		SiteID: 1, UID: 1008, AdministratorID: 7, SiteIdentity: "site-identity",
		AdministratorProof: "administrator-proof", SessionToken: "authenticated-session", Generation: generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	serverTime := time.Now()
	data, err := json.Marshal(wpPanelAccessLoginResponse("https://site.example/index.php", token, generation, expires, serverTime))
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		ServerTime time.Time `json:"server_time"`
		ExpiresAt  time.Time `json:"expires_at"`
		ExpiresIn  int       `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	if !response.ServerTime.Equal(serverTime) || !response.ExpiresAt.Equal(expires) || response.ExpiresIn != 60 {
		t.Fatal("JSON clock metadata does not describe the issued ticket")
	}
	remaining := response.ExpiresAt.Sub(response.ServerTime)
	if remaining <= 0 || remaining > executor.WPPanelAccessLifetime || executor.WPPanelAccessLifetime != 60*time.Second {
		t.Fatal("response extended or expired the issued ticket")
	}
	if _, err := store.Consume(token, 1, 1008, generation); err != nil {
		t.Fatal("clock metadata changed the ticket binding")
	}
	if _, err := store.Consume(token, 1, 1008, generation); err == nil {
		t.Fatal("clock metadata allowed ticket reuse")
	}
}
