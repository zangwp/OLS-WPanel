package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zangwp/OLS-WPanel/internal/middleware"
)

type delayedAccountBody struct {
	entered, release chan struct{}
	once             sync.Once
}

func (b *delayedAccountBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}

func TestIncompleteAccountBodyDoesNotHoldAuthenticationLock(t *testing.T) {
	for _, path := range []string{"/login", "/mfa/setup", "/mfa/confirm", "/mfa/disable", "/mfa/recovery-codes"} {
		t.Run(path, func(t *testing.T) {
			h, router := setupMFAHandler(t)
			// Notification transport is unrelated to admission/credential locking.
			// Keep this test's audit records without racing asynchronous delivery.
			if _, err := h.DB.Exec(`INSERT INTO account_security_preferences(username,notifications_enabled) VALUES('admin',0)`); err != nil {
				t.Fatal(err)
			}
			session := middleware.GlobalSessionStore.Create("admin")
			body := &delayedAccountBody{entered: make(chan struct{}), release: make(chan struct{})}
			req := httptest.NewRequest(http.MethodPost, path, body)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-CSRF-Token", "test-csrf")
			req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "test-csrf"})
			req.AddCookie(&http.Cookie{Name: "wp_session", Value: session.Token})
			done := make(chan struct{})
			go func() { defer close(done); router.ServeHTTP(httptest.NewRecorder(), req) }()
			var releaseOnce sync.Once
			releaseBody := func() { releaseOnce.Do(func() { close(body.release) }) }
			t.Cleanup(func() { releaseBody(); <-done })
			select {
			case <-body.entered:
			case <-time.After(time.Second):
				t.Fatal("body was not read")
			}
			mutation := make(chan struct{})
			go func() { unlock := LockAccountAuthentication(); unlock(); close(mutation) }()
			select {
			case <-mutation:
			case <-time.After(time.Second):
				releaseBody()
				<-done
				t.Fatal("incomplete body holds account mutation lock")
			}
			login := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				login <- mfaHandlerCall(t, router, "/login", "", map[string]string{"username": "admin", "password": "correct-password"})
			}()
			select {
			case response := <-login:
				if response.Code != http.StatusOK {
					t.Errorf("concurrent login=%d %s", response.Code, response.Body.String())
				}
			case <-time.After(time.Second):
				releaseBody()
				<-done
				t.Fatal("incomplete body blocks login")
			}
			releaseBody()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("body release did not finish request")
			}
		})
	}
}

type accountDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *accountDeadlineRecorder) SetReadDeadline(value time.Time) error {
	w.deadlines = append(w.deadlines, value)
	return nil
}

func TestAccountBodyReadDeadlineIsLimitedAndCleared(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := &accountDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(`{"name":"ok"}`))
	c.Request.Header.Set("Content-Type", "application/json")
	var body struct {
		Name string `json:"name"`
	}
	start := time.Now()
	if err := bindAccountRequest(c, &body); err != nil {
		t.Fatal(err)
	}
	if len(w.deadlines) != 2 || w.deadlines[0].Before(start.Add(accountRequestBodyTimeout-time.Second)) || w.deadlines[0].After(time.Now().Add(accountRequestBodyTimeout)) || !w.deadlines[1].IsZero() {
		t.Fatalf("unexpected read deadlines: %v", w.deadlines)
	}
}

func TestAccountBodySizeIsLimitedBeforeCredentialProcessing(t *testing.T) {
	h, router := setupMFAHandler(t)
	w := mfaHandlerCall(t, router, "/login", "", map[string]string{"username": "admin", "password": strings.Repeat("x", 5000)})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized login=%d %s", w.Code, w.Body.String())
	}
	var attempts int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM account_mfa_attempts`).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatal("oversized body reached sensitive credential processing")
	}
}

func TestParsedLoginStillRechecksMFAInsideAuthenticationLock(t *testing.T) {
	h, router := setupMFAHandler(t)
	unlocked := LockAccountAuthentication()
	var unlockOnce sync.Once
	unlock := func() { unlockOnce.Do(unlocked) }
	defer unlock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- mfaHandlerCall(t, router, "/login", "", map[string]string{"username": "admin", "password": "correct-password"})
	}()
	select {
	case <-done:
		unlock()
		t.Fatal("login escaped account lock")
	case <-time.After(20 * time.Millisecond):
	}
	enableHandlerMFA(t, h)
	unlock()
	select {
	case w := <-done:
		requireNoLoginSession(t, w)
		if !strings.Contains(w.Body.String(), `"mfa_required":true`) {
			t.Fatalf("login did not recheck newly enabled MFA: %s", w.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("login did not finish")
	}
}
