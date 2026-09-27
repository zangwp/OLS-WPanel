package middleware

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetCSRFTokenUsesHardenedCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/login", nil)

	if !SetCSRFToken(ctx) {
		t.Fatal("SetCSRFToken failed")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%d, want 1", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != "csrf_token" || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie attributes are not hardened: %+v", cookie)
	}
	decoded, err := hex.DecodeString(cookie.Value)
	if err != nil || len(decoded) != csrfTokenLength {
		t.Fatalf("invalid token length or encoding: len=%d err=%v", len(decoded), err)
	}
	if got := recorder.Header().Get("X-CSRF-Token"); got != cookie.Value {
		t.Fatalf("response token=%q, want cookie token", got)
	}
}

func TestCSRFRequiresExactTokenMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(CSRF())
	router.POST("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for _, tc := range []struct {
		name   string
		cookie string
		header string
		want   int
	}{
		{name: "match", cookie: "exact-token", header: "exact-token", want: http.StatusNoContent},
		{name: "mismatch", cookie: "exact-token", header: "other-token", want: http.StatusForbidden},
		{name: "missing", want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "csrf_token", Value: tc.cookie})
			}
			if tc.header != "" {
				req.Header.Set("X-CSRF-Token", tc.header)
			}
			router.ServeHTTP(recorder, req)
			if recorder.Code != tc.want {
				t.Fatalf("status=%d, want %d", recorder.Code, tc.want)
			}
		})
	}
}
