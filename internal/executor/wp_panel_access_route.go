package executor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/models"
)

// VerifyWPPanelAccessLoginRoute tests the real front controller before the new
// suffix is committed. It dials this machine's OLS listener, never user DNS, and
// does not follow redirects or submit a login/attack/password request.
func VerifyWPPanelAccessLoginRoute(ctx context.Context, site *models.Website, settings WPPanelAccessSettings) error {
	if site == nil || !IsValidDomain(site.Domain) || settings.LoginSuffix == "" || len(settings.Generation) != 32 {
		return wpPanelAccessError("route_unavailable")
	}
	scheme, endpoint := "http", "127.0.0.1:80"
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: site.Domain}
	if site.SSLEnabled {
		scheme, endpoint = "https", "127.0.0.1:443"
		// Configured private certificates may be trusted locally, while normal TLS
		// hostname/validity checks remain active. There is no insecure mode.
		if info, err := os.Stat(site.SSLCertPath); err == nil && info.Mode().IsRegular() && info.Size() <= 1<<20 {
			if data, err := os.ReadFile(site.SSLCertPath); err == nil {
				roots, err := x509.SystemCertPool()
				if err != nil || roots == nil {
					roots = x509.NewCertPool()
				}
				if roots.AppendCertsFromPEM(data) {
					tlsConfig.RootCAs = roots
				}
			}
		}
	}
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", endpoint)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return verifyWPPanelAccessLoginRouteWithClient(ctx, client, scheme+"://"+site.Domain+strings.TrimSuffix(settings.InstallationPath, "/")+"/"+settings.LoginSuffix, settings.Generation)
}

func verifyWPPanelAccessLoginRouteWithClient(ctx context.Context, client *http.Client, route, generation string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, route, nil)
	if err != nil {
		return wpPanelAccessError("route_unavailable")
	}
	req.Header.Set("User-Agent", "OLS-WPanel-Login-Route-Check/1")
	req.Header.Set("Cache-Control", "no-cache")
	response, err := client.Do(req)
	if err != nil {
		return wpPanelAccessError("route_unavailable")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode != http.StatusOK || response.Header.Get("X-OLS-WPanel-Login-Route") != generation {
		return wpPanelAccessError("route_unavailable")
	}
	return nil
}
