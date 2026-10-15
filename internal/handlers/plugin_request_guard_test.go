package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

type pluginTrackingBody struct {
	reader io.Reader
	read   int
}

func (b *pluginTrackingBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (*pluginTrackingBody) Close() error { return nil }

type pluginDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (w *pluginDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func TestPluginRequestGuardRejectsBeforeReadingOrMaintenance(t *testing.T) {
	for _, tc := range []struct {
		name, remote, key string
	}{
		{"remote", "198.51.100.7:1234", "secret"},
		{"spoofed loopback", "198.51.100.7:1234", "secret"},
		{"missing key", "127.0.0.1:1234", ""},
		{"oversized key", "127.0.0.1:1234", strings.Repeat("k", 257)},
		{"not an address", "localhost:1234", "secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			group := router.Group("/panel")
			group.Use(PluginRequestGuard())
			group.Use(func(c *gin.Context) { t.Error("rejected request reached maintenance") })
			group.POST("/api/sites/optimizer-settings", func(c *gin.Context) { t.Error("rejected request reached handler") })
			body := &pluginTrackingBody{reader: strings.NewReader(`{"domain":"example.com"}`)}
			req := httptest.NewRequest(http.MethodPost, "/panel/api/sites/optimizer-settings", nil)
			req.RemoteAddr = tc.remote
			req.Body = body
			req.Header.Set("X-OLS-WPanel-Key", tc.key)
			req.Header.Set("X-Forwarded-For", "127.0.0.1")
			req.Header.Set("X-Real-IP", "::1")
			rec := &pluginDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized || body.read != 0 || !req.Close || rec.Header().Get("Connection") != "close" {
				t.Fatalf("status=%d read=%d close=%v", rec.Code, body.read, req.Close)
			}
			if len(rec.deadlines) != 1 || rec.deadlines[0].After(time.Now()) {
				t.Fatalf("unread body not expired: %v", rec.deadlines)
			}
		})
	}
}

func TestPluginRequestGuardBoundsKnownAndChunkedBodies(t *testing.T) {
	for _, declared := range []int64{pluginRequestBodyLimit + 1, -1} {
		t.Run(fmt.Sprint(declared), func(t *testing.T) {
			router := gin.New()
			router.POST("/plugin", PluginRequestGuard(), func(c *gin.Context) { t.Error("oversized request reached handler") })
			body := &pluginTrackingBody{reader: strings.NewReader(strings.Repeat("x", 2*pluginRequestBodyLimit))}
			req := httptest.NewRequest(http.MethodPost, "/plugin", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("X-OLS-WPanel-Key", "secret")
			req.Body, req.ContentLength = body, declared
			rec := &pluginDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusRequestEntityTooLarge || body.read > pluginRequestBodyLimit+1 || !req.Close {
				t.Fatalf("status=%d read=%d close=%v", rec.Code, body.read, req.Close)
			}
			if declared > 0 && body.read != 0 {
				t.Fatalf("declared oversized body read %d bytes", body.read)
			}
		})
	}
}

func TestPluginRequestGuardReplaysJSONAndClearsDeadlineBeforeHandler(t *testing.T) {
	for _, remote := range []string{"127.0.0.1:1234", "[::1]:1234"} {
		t.Run(remote, func(t *testing.T) {
			rec := &pluginDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			router := gin.New()
			router.PUT("/plugin", PluginRequestGuard(), func(c *gin.Context) {
				if len(rec.deadlines) != 2 || !rec.deadlines[1].IsZero() {
					t.Errorf("deadline leaked into handler: %v", rec.deadlines)
				}
				var payload struct {
					Domain string `json:"domain"`
				}
				if c.ShouldBindJSON(&payload) != nil || payload.Domain != "example.com" {
					t.Error("plugin JSON was not preserved")
				}
				c.Status(http.StatusNoContent)
			})
			req := httptest.NewRequest(http.MethodPut, "https://panel.example.com/plugin", strings.NewReader(`{"domain":"example.com"}`))
			req.RemoteAddr = remote
			req.Header.Set("X-OLS-WPanel-Key", "secret")
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent || req.Close {
				t.Fatalf("status=%d close=%v", rec.Code, req.Close)
			}
		})
	}
}

func TestPluginRequestGuardKeepsSiteKeyAuthentication(t *testing.T) {
	setupCacheHelperTestDB(t)
	router := gin.New()
	router.GET("/plugin", PluginRequestGuard(), (&CacheHelperHandler{}).FindByDomain)
	for _, tc := range []struct {
		key    string
		status int
	}{{"secret", 200}, {"wrong-key", 401}} {
		req := httptest.NewRequest(http.MethodGet, "/plugin?domain=example.com", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-OLS-WPanel-Key", tc.key)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Fatalf("status=%d want=%d", rec.Code, tc.status)
		}
	}
}

func TestPluginRequestGuardTimesOutIncompleteBodyOverHTTP(t *testing.T) {
	router := gin.New()
	router.POST("/plugin", pluginRequestGuard(100*time.Millisecond), func(c *gin.Context) { t.Error("incomplete body reached handler") })
	server := httptest.NewServer(router)
	defer server.Close()
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, err = fmt.Fprint(conn, "POST /plugin HTTP/1.1\r\nHost: panel.example.com\r\nX-OLS-WPanel-Key: secret\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{\"domain\":")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusRequestTimeout || !response.Close {
		t.Fatalf("status=%d close=%v", response.StatusCode, response.Close)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
}

func TestPluginRequestGuardPreservesKeepAliveAndUnrelatedUploads(t *testing.T) {
	router := gin.New()
	router.POST("/plugin", pluginRequestGuard(100*time.Millisecond), func(c *gin.Context) {
		var payload map[string]string
		if json.NewDecoder(c.Request.Body).Decode(&payload) != nil {
			c.Status(400)
			return
		}
		c.JSON(200, payload)
	})
	router.POST("/upload", func(c *gin.Context) {
		n, _ := io.Copy(io.Discard, c.Request.Body)
		c.JSON(200, n)
	})
	server := httptest.NewServer(router)
	defer server.Close()
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	for i := 0; i < 2; i++ {
		_, err = fmt.Fprint(conn, "POST /plugin HTTP/1.1\r\nHost: panel.example.com\r\nX-OLS-WPanel-Key: secret\r\nContent-Type: application/json\r\nContent-Length: 24\r\n\r\n{\"domain\":\"example.com\"}")
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != 200 || response.Close {
			t.Fatalf("response=%v read=%v", response, readErr)
		}
		if i == 0 {
			time.Sleep(150 * time.Millisecond)
		}
	}
	response, err := server.Client().Post(server.URL+"/upload", "application/octet-stream", strings.NewReader(strings.Repeat("x", 2*pluginRequestBodyLimit)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var count int
	if json.NewDecoder(response.Body).Decode(&count) != nil || count != 2*pluginRequestBodyLimit {
		t.Fatalf("unrelated upload bytes=%d", count)
	}
}
