package middleware

import (
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Session struct {
	Token      string    `json:"-"`
	ID         string    `json:"id"`
	Username   string    `json:"-"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type SessionSummary struct {
	Session
	Current bool `json:"current"`
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

var GlobalSessionStore = &SessionStore{
	sessions: make(map[string]*Session),
}

func (s *SessionStore) Create(username string) *Session {
	return s.CreateWithMetadata(username, "", "")
}

func (s *SessionStore) CreateWithMetadata(username, ip, userAgent string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]*Session)
	}

	now := time.Now()
	session := &Session{
		Token:    uuid.New().String(),
		ID:       uuid.New().String(),
		Username: username,
		IP:       ip,
		UserAgent: strings.Map(func(r rune) rune {
			if r < 32 || r == 127 {
				return -1
			}
			return r
		}, string([]rune(userAgent)[:min(len([]rune(userAgent)), 512)])),
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(30 * time.Minute),
	}
	s.sessions[session.Token] = session
	copy := *session
	return &copy
}

func (s *SessionStore) Get(token string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[token]
	if !ok {
		return nil
	}
	now := time.Now()
	if !now.Before(session.ExpiresAt) {
		delete(s.sessions, token)
		return nil
	}
	// 滑动续期：每次有效访问延长 30 分钟
	session.LastSeenAt = now
	session.ExpiresAt = now.Add(30 * time.Minute)
	copy := *session
	return &copy
}

// List returns copies and an independent display ID, never a bearer token.
func (s *SessionStore) List(username, currentToken string) []SessionSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]SessionSummary, 0)
	now := time.Now()
	for token, session := range s.sessions {
		if !now.Before(session.ExpiresAt) {
			delete(s.sessions, token)
			continue
		}
		if session.Username == username {
			copy := *session
			copy.Token = ""
			result = append(result, SessionSummary{Session: copy, Current: token == currentToken})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result
}

func (s *SessionStore) DeleteByID(username, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, session := range s.sessions {
		if session.Username == username && session.ID == id {
			delete(s.sessions, token)
			return true
		}
	}
	return false
}

func (s *SessionStore) DeleteOthers(username, currentToken string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for token, session := range s.sessions {
		if session.Username == username && token != currentToken {
			delete(s.sessions, token)
			count++
		}
	}
	return count
}

func (s *SessionStore) CleanExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for token, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}

func (s *SessionStore) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

func (s *SessionStore) DeleteAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[string]*Session)
}

func SessionRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("wp_session")
		if err != nil || token == "" {
			abortSession(c, "请先登录")
			return
		}

		session := GlobalSessionStore.Get(token)
		if session == nil {
			abortSession(c, "会话已过期，请重新登录")
			return
		}

		// 滑动续期客户端 Cookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     "wp_session",
			Value:    session.Token,
			MaxAge:   1800,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})

		c.Set("session_username", session.Username)
		c.Next()
	}
}

func abortSession(c *gin.Context, msg string) {
	c.Abort()
	c.SetCookie("wp_session", "", -1, "/", "", false, true)

	if isPageRequest(c) {
		prefix := extractPrefix(c)
		c.Redirect(http.StatusFound, prefix+"/login")
		return
	}

	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"success": false,
		"message": msg,
	})
}

func isPageRequest(c *gin.Context) bool {
	accept := c.GetHeader("Accept")
	return strings.Contains(accept, "text/html")
}

func extractPrefix(c *gin.Context) string {
	path := strings.Trim(c.Request.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) > 0 {
		return "/" + parts[0]
	}
	return ""
}
