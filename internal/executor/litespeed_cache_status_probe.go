package executor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

const liteSpeedCacheProbeBodyLimit = 1024 * 1024

type LiteSpeedPageCacheAttempt struct {
	StatusCode       int    `json:"status_code"`
	CacheHeader      string `json:"cache_header"`
	CacheControl     string `json:"cache_control"`
	LiteSpeedControl string `json:"litespeed_cache_control"`
	SetCookie        bool   `json:"set_cookie"`
	ContentType      string `json:"content_type"`
}

type LiteSpeedPageCacheVerification struct {
	State     string                      `json:"state"`
	Reason    string                      `json:"reason"`
	CheckedAt string                      `json:"checked_at"`
	URL       string                      `json:"url,omitempty"`
	Source    string                      `json:"source"`
	Attempts  []LiteSpeedPageCacheAttempt `json:"attempts"`
}

// VerifyLiteSpeedPageCache never resolves arbitrary destinations or follows a
// redirect. It samples only the canonical homepage of an active managed vhost,
// anonymously, through the local origin. It does not measure CDN edge caching.
func VerifyLiteSpeedPageCache(ctx context.Context, cfg *config.Config, site *models.Website) LiteSpeedPageCacheVerification {
	result := newLiteSpeedCacheVerification()
	state, reason, _ := observeLiteSpeedServerCache(cfg, site)
	if state != "configured" {
		result.Reason = reason
		return result
	}
	client, transport := newLiteSpeedCacheProbeClient(site.Domain, site.SSLEnabled)
	defer transport.CloseIdleConnections()
	return verifyLiteSpeedPageCacheWithClient(ctx, client, site.Domain, site.SSLEnabled)
}

func newLiteSpeedCacheVerification() LiteSpeedPageCacheVerification {
	return LiteSpeedPageCacheVerification{State: "unknown", Reason: "not_verified", Source: "local_origin", CheckedAt: time.Now().UTC().Format(time.RFC3339), Attempts: []LiteSpeedPageCacheAttempt{}}
}

func newLiteSpeedCacheProbeClient(domain string, useTLS bool) (*http.Client, *http.Transport) {
	port := "80"
	if useTLS {
		port = "443"
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 32 * 1024,
		TLSHandshakeTimeout:    2 * time.Second,
		ResponseHeaderTimeout:  3 * time.Second,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, ServerName: domain},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, requestedPort, err := net.SplitHostPort(address)
			if !IsValidDomain(domain) || err != nil || !strings.EqualFold(host, domain) || requestedPort != port {
				return nil, errors.New("cache probe destination rejected")
			}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
		},
	}
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, transport
}

func verifyLiteSpeedPageCacheWithClient(ctx context.Context, client *http.Client, domain string, useTLS bool) LiteSpeedPageCacheVerification {
	result := newLiteSpeedCacheVerification()
	if !IsValidDomain(domain) || client == nil {
		result.Reason = "invalid_origin"
		return result
	}
	// Keep these guarantees even if another caller supplies its own transport.
	probeClient := *client
	probeClient.Jar = nil
	probeClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if probeClient.Timeout <= 0 || probeClient.Timeout > 4*time.Second {
		probeClient.Timeout = 4 * time.Second
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	origin := (&url.URL{Scheme: scheme, Host: domain, Path: "/"}).String()
	result.URL = origin
	for attempt := 0; attempt < 2; attempt++ {
		result.State = "unknown"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin, nil)
		if err != nil {
			result.Reason = "invalid_origin"
			return result
		}
		req.Header.Set("User-Agent", "OLS-WPanel-Page-Cache-Check")
		req.Header.Set("Accept", "text/html")
		// No Cookie, Authorization, cache-busting query or no-cache request
		// header: a second ordinary anonymous request may use the first entry.
		resp, err := probeClient.Do(req)
		if err != nil {
			result.Reason = liteSpeedCacheProbeErrorReason(err)
			return result
		}
		evidence := LiteSpeedPageCacheAttempt{
			StatusCode:       resp.StatusCode,
			CacheHeader:      cacheProbeHeader(resp.Header.Get("X-LiteSpeed-Cache")),
			CacheControl:     cacheProbeHeader(resp.Header.Get("Cache-Control")),
			LiteSpeedControl: cacheProbeHeader(resp.Header.Get("X-LiteSpeed-Cache-Control")),
			SetCookie:        len(resp.Header.Values("Set-Cookie")) > 0,
			ContentType:      cacheProbeHeader(resp.Header.Get("Content-Type")),
		}
		result.Attempts = append(result.Attempts, evidence)
		read, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, liteSpeedCacheProbeBodyLimit+1))
		resp.Body.Close()
		if readErr != nil || read > liteSpeedCacheProbeBodyLimit {
			result.Reason = "response_unavailable"
			return result
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			result.Reason = "redirect"
			return result
		}
		if resp.StatusCode != http.StatusOK {
			result.Reason = "http_status"
			return result
		}
		mediaType, _, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if mediaErr != nil || !strings.EqualFold(mediaType, "text/html") {
			result.Reason = "non_html_response"
			return result
		}
		if evidence.SetCookie || cacheControlPreventsPublicCache(strings.Join(resp.Header.Values("Cache-Control"), ",")) || cacheControlPreventsPublicCache(strings.Join(resp.Header.Values("X-LiteSpeed-Cache-Control"), ",")) || cacheHeaderHasToken(strings.Join(resp.Header.Values("X-LiteSpeed-Cache"), ","), "private") {
			result.State, result.Reason = "bypass", "private_or_uncacheable_response"
			return result
		}
		if len(resp.Header.Values("X-LiteSpeed-Cache")) > 1 {
			result.Reason = "cache_header_ambiguous"
			return result
		}
		if strings.EqualFold(strings.TrimSpace(evidence.CacheHeader), "hit") {
			result.State, result.Reason = "hit", "cache_hit_observed"
			continue
		}
		if strings.EqualFold(strings.TrimSpace(evidence.CacheHeader), "miss") {
			result.State, result.Reason = "miss", "cache_miss_observed"
		} else if strings.EqualFold(strings.TrimSpace(evidence.CacheHeader), "no-cache") {
			result.State, result.Reason = "bypass", "private_or_uncacheable_response"
			return result
		} else {
			result.State, result.Reason = "unknown", "cache_header_absent"
			if evidence.CacheHeader != "" {
				result.Reason = "cache_header_unrecognized"
			}
		}
	}
	return result
}

func cacheProbeHeader(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 256 {
		return value[:256]
	}
	return value
}

func cacheHeaderHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func cacheControlPreventsPublicCache(value string) bool {
	for _, part := range strings.Split(value, ",") {
		name := strings.TrimSpace(strings.SplitN(part, "=", 2)[0])
		if strings.EqualFold(name, "private") || strings.EqualFold(name, "no-store") || strings.EqualFold(name, "no-cache") {
			return true
		}
	}
	return false
}

func liteSpeedCacheProbeErrorReason(err error) string {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &verification) {
		return "tls_verification_failed"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "request_timeout"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "request_timeout"
	}
	return "origin_unreachable"
}
