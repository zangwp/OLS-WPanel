package executor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const WPPanelAccessLifetime = 60 * time.Second

// WPPanelAccessTicket is kept only in panel memory. None of these credentials
// are serialized to logs, disk or the WordPress browser redirect URL.
type WPPanelAccessTicket struct {
	SiteID             int
	SiteIdentity       string
	UID                int
	AdministratorID    int
	AdministratorLogin string
	AdministratorProof string
	Generation         string
	SessionToken       string
	PanelUsername      string
	ExpiresAt          time.Time
}

type WPPanelAccessTokenStore struct {
	mu      sync.Mutex
	tickets map[[32]byte]WPPanelAccessTicket
	now     func() time.Time
}

var DefaultWPPanelAccessTokens = NewWPPanelAccessTokenStore()

func NewWPPanelAccessTokenStore() *WPPanelAccessTokenStore {
	return &WPPanelAccessTokenStore{tickets: make(map[[32]byte]WPPanelAccessTicket), now: time.Now}
}

func (s *WPPanelAccessTokenStore) Issue(ticket WPPanelAccessTicket) (string, time.Time, error) {
	if ticket.SiteID <= 0 || ticket.UID <= 0 || ticket.AdministratorID <= 0 || ticket.SessionToken == "" || ticket.Generation == "" || ticket.SiteIdentity == "" || ticket.AdministratorProof == "" {
		return "", time.Time{}, errors.New("invalid WordPress login authorization")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	// At most one outstanding authorization per session and website.
	for key, current := range s.tickets {
		if current.SiteID == ticket.SiteID && current.SessionToken == ticket.SessionToken {
			delete(s.tickets, key)
		}
	}
	if len(s.tickets) >= 1024 {
		return "", time.Time{}, errors.New("WordPress login authorization limit reached")
	}
	ticket.ExpiresAt = s.now().Add(WPPanelAccessLifetime)
	s.tickets[sha256.Sum256([]byte(token))] = ticket
	return token, ticket.ExpiresAt, nil
}

// Consume checks the Unix peer identity before removing the ticket. Successful
// removal is atomic; even overlapping PHP requests cannot reuse a ticket.
func (s *WPPanelAccessTokenStore) Consume(token string, siteID, uid int, generation string) (WPPanelAccessTicket, error) {
	if raw, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(raw) != 32 || len(token) != 43 {
		return WPPanelAccessTicket{}, errors.New("invalid WordPress login authorization")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	key := sha256.Sum256([]byte(token))
	ticket, ok := s.tickets[key]
	if !ok || ticket.SiteID != siteID || ticket.UID != uid || uid <= 0 || ticket.Generation != generation {
		return WPPanelAccessTicket{}, errors.New("invalid WordPress login authorization")
	}
	delete(s.tickets, key)
	return ticket, nil
}

func (s *WPPanelAccessTokenStore) Revoke(siteID int, sessionToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, ticket := range s.tickets {
		if (siteID == 0 || ticket.SiteID == siteID) && (sessionToken == "" || ticket.SessionToken == sessionToken) {
			delete(s.tickets, key)
		}
	}
}

func (s *WPPanelAccessTokenStore) CleanExpired() { s.mu.Lock(); defer s.mu.Unlock(); s.cleanLocked() }
func (s *WPPanelAccessTokenStore) cleanLocked() {
	now := s.now()
	for key, ticket := range s.tickets {
		if !now.Before(ticket.ExpiresAt) {
			delete(s.tickets, key)
		}
	}
}
