package executor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type cacheProbeRoundTrip func(*http.Request) (*http.Response, error)

func (f cacheProbeRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestVerifyLiteSpeedPageCacheAnonymousWarmRequestThenHit(t *testing.T) {
	calls := 0
	client := &http.Client{Transport: cacheProbeRoundTrip(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != http.MethodGet || req.URL.String() != "https://example.com/" || req.URL.RawQuery != "" {
			t.Fatalf("probe request=%s %s", req.Method, req.URL)
		}
		for _, header := range []string{"Cookie", "Authorization", "Cache-Control", "X-Forwarded-For", "Referer"} {
			if req.Header.Get(header) != "" {
				t.Fatalf("probe must be anonymous/ordinary: %s", header)
			}
		}
		cache := "miss"
		if calls == 2 {
			cache = "hit"
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html; charset=UTF-8"}, "X-Litespeed-Cache": {cache}}, Body: io.NopCloser(strings.NewReader("<html></html>"))}, nil
	})}
	result := verifyLiteSpeedPageCacheWithClient(context.Background(), client, "example.com", true)
	if result.State != "hit" || result.Reason != "cache_hit_observed" || calls != 2 || len(result.Attempts) != 2 || result.Source != "local_origin" || result.CheckedAt == "" {
		t.Fatalf("unexpected result %#v calls=%d", result, calls)
	}
	if result.Attempts[0].CacheHeader != "miss" || result.Attempts[1].CacheHeader != "hit" {
		t.Fatalf("missing bounded header evidence: %#v", result.Attempts)
	}
}

func TestVerifyLiteSpeedPageCacheNeverEquatesMissOrNoHeaderWithDisabled(t *testing.T) {
	for _, tc := range []struct{ header, state, reason string }{
		{"miss", "miss", "cache_miss_observed"},
		{"", "unknown", "cache_header_absent"},
		{"hit,unexpected", "unknown", "cache_header_unrecognized"},
	} {
		t.Run(tc.header, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: cacheProbeRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}, "X-Litespeed-Cache": {tc.header}}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
			})}
			result := verifyLiteSpeedPageCacheWithClient(context.Background(), client, "example.com", false)
			if result.State != tc.state || result.Reason != tc.reason || calls != 2 {
				t.Fatalf("result=%#v calls=%d", result, calls)
			}
		})
	}
}

func TestVerifyLiteSpeedPageCacheStopsAtPrivateOrUnsafeResponse(t *testing.T) {
	for _, tc := range []struct {
		name, state, reason string
		status              int
		headers             http.Header
		body                string
	}{
		{"private header", "bypass", "private_or_uncacheable_response", 200, http.Header{"Cache-Control": {"private"}}, "ok"},
		{"private second header", "bypass", "private_or_uncacheable_response", 200, http.Header{"Cache-Control": {"public", "private=Set-Cookie"}}, "ok"},
		{"private after bounded evidence", "bypass", "private_or_uncacheable_response", 200, http.Header{"Cache-Control": {strings.Repeat("public,", 60) + "no-store"}}, "ok"},
		{"private cache hit", "bypass", "private_or_uncacheable_response", 200, http.Header{"X-Litespeed-Cache": {"hit,private"}}, "ok"},
		{"login cookie", "bypass", "private_or_uncacheable_response", 200, http.Header{"Set-Cookie": {"wordpress_logged_in=secret"}}, "ok"},
		{"uncacheable", "bypass", "private_or_uncacheable_response", 200, http.Header{"X-Litespeed-Cache-Control": {"no-cache"}}, "ok"},
		{"redirect", "unknown", "redirect", 302, http.Header{"Location": {"http://169.254.169.254/"}}, "ok"},
		{"admin denied", "unknown", "http_status", 403, http.Header{}, "ok"},
		{"not HTML", "unknown", "non_html_response", 200, http.Header{"Content-Type": {"application/json"}}, "ok"},
		{"body too large", "unknown", "response_unavailable", 200, http.Header{}, strings.Repeat("a", liteSpeedCacheProbeBodyLimit+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: cacheProbeRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				headers := tc.headers.Clone()
				if headers.Get("Content-Type") == "" {
					headers.Set("Content-Type", "text/html")
				}
				return &http.Response{StatusCode: tc.status, Header: headers, Body: io.NopCloser(strings.NewReader(tc.body))}, nil
			})}
			result := verifyLiteSpeedPageCacheWithClient(context.Background(), client, "example.com", false)
			if result.State != tc.state || result.Reason != tc.reason || calls != 1 {
				t.Fatalf("result=%#v calls=%d", result, calls)
			}
			for _, attempt := range result.Attempts {
				if len(attempt.CacheControl) > 256 || strings.Contains(attempt.CacheHeader, "secret") {
					t.Fatal("evidence must be bounded and exclude cookie values")
				}
			}
		})
	}
}

func TestLiteSpeedCacheProbeClientRejectsRedirectsAndUnapprovedDestinations(t *testing.T) {
	client, transport := newLiteSpeedCacheProbeClient("example.com", true)
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil || transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.ServerName != "example.com" || client.Jar != nil || client.Timeout == 0 {
		t.Fatal("probe must be direct, certificate-verified, anonymous and bounded")
	}
	if !errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("probe must not follow a redirect to login/private/external URLs")
	}
	for _, address := range []string{"169.254.169.254:443", "127.0.0.1:443", "other.example.com:443", "example.com:80", "example.com:8443"} {
		if conn, err := transport.DialContext(context.Background(), "tcp", address); err == nil {
			conn.Close()
			t.Fatalf("accepted destination %s", address)
		}
	}
	for _, invalid := range []string{"127.0.0.1", "169.254.169.254", "example.com:443", "example.com/admin", "user:secret@example.com"} {
		result := verifyLiteSpeedPageCacheWithClient(context.Background(), client, invalid, true)
		if result.State != "unknown" || result.Reason != "invalid_origin" || len(result.Attempts) != 0 {
			t.Fatalf("accepted host %q: %#v", invalid, result)
		}
	}
}

func TestVerifyLiteSpeedPageCacheKeepsTLSFailuresUnknown(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("X-LiteSpeed-Cache", "hit") }))
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		if err != nil {
			t.Logf("local TLS fixture connection failed: %v", err)
		}
		return conn, err
	}}
	defer transport.CloseIdleConnections()
	result := verifyLiteSpeedPageCacheWithClient(context.Background(), &http.Client{Transport: transport}, "example.com", true)
	if result.State != "unknown" || result.Reason != "tls_verification_failed" || len(result.Attempts) != 0 {
		t.Fatalf("self-signed/untrusted TLS cannot prove hit: %#v", result)
	}
	for _, err := range []error{x509.HostnameError{}, context.DeadlineExceeded, errors.New("connection refused")} {
		if reason := liteSpeedCacheProbeErrorReason(err); reason == "" {
			t.Fatal("network failures need typed reasons")
		}
	}
}

func TestVerifyLiteSpeedPageCacheDoesNotProbeInactiveOrUnmanagedSites(t *testing.T) {
	result := VerifyLiteSpeedPageCache(context.Background(), nil, nil)
	if result.State != "unknown" || result.Reason != "unsupported_site" || len(result.Attempts) != 0 {
		t.Fatalf("unmanaged site must not issue network requests: %#v", result)
	}
	cfg, site := liteSpeedCacheConfigFixture(t, strings.Replace(testLiteSpeedCacheModule, "enableCache 0", "enableCache 1", 1))
	result = VerifyLiteSpeedPageCache(context.Background(), cfg, site)
	if result.State != "unknown" || result.Reason != "unsafe_public_cache_default" || len(result.Attempts) != 0 {
		t.Fatalf("legacy blanket caching must be repaired before probing: %#v", result)
	}
}
