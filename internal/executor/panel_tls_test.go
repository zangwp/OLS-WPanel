package executor

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestNormalizePanelDomain(t *testing.T) {
	for _, bad := range []string{"", "192.0.2.1", "https://panel.example.com", "panel.example.com:8443", "panel.example.com/path", "-panel.example.com", "panel.example.com\nother"} {
		if _, err := NormalizePanelDomain(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if got, err := NormalizePanelDomain(" Panel.Example.COM "); err != nil || got != "panel.example.com" {
		t.Fatalf("normalization: %q %v", got, err)
	}
}

func TestPanelDomainProbePinsHostAndAddressAndClassifiesHTTPFailures(t *testing.T) {
	oldDial := dialPanelDomainHTTP
	t.Cleanup(func() { dialPanelDomainHTTP = oldDial })
	address := net.IPAddr{IP: net.ParseIP("2001:4860:4860::8888")}
	for _, tc := range []struct {
		name       string
		status     int
		body, code string
	}{
		{"success", 200, "secret-probe", ""},
		{"redirect", 302, "redirect", "panel_domain_http_redirect"},
		{"denied", 403, "forbidden", "panel_domain_http_status"},
		{"wrong-vhost", 200, "unrelated website", "panel_domain_challenge_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Host != "panel.example.com" || r.URL.Path != "/.well-known/acme-challenge/panel-probe-secret-probe" || r.Header.Get("Cache-Control") != "no-store" {
					t.Errorf("wrong probe: %s %s", r.Host, r.URL.Path)
				}
				w.Header().Set("Location", "https://sensitive-user:password@other.example/token")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			dialPanelDomainHTTP = func(ctx context.Context, network, target string) (net.Conn, error) {
				if target != "[2001:4860:4860::8888]:80" {
					t.Errorf("not pinned to validated IPv6: %s", target)
				}
				return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
			}
			err := probePanelDomainAddress(context.Background(), "panel.example.com", address, "secret-probe")
			if tc.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			code, details := PanelDomainErrorInfo(err)
			if code != tc.code || details["address_family"] != "IPv6" || details["address"] != address.IP.String() || details["redirect_location"] != "" {
				t.Fatalf("diagnosis: %s %+v", code, details)
			}
		})
	}
	dialPanelDomainHTTP = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("private implementation path")
	}
	if code, _ := PanelDomainErrorInfo(probePanelDomainAddress(context.Background(), "panel.example.com", address, "token")); code != "panel_domain_http_unreachable" {
		t.Fatalf("connection error: %s", code)
	}
}

func TestPanelDomainChecksEveryPublishedAddressAndCleansProbe(t *testing.T) {
	paths, _, _ := panelACMEMigrationFixture(t)
	oldCfg, oldLookup, oldDial, oldRun := config.AppConfig, lookupPanelDomainIPs, dialPanelDomainHTTP, runOLSCommand
	t.Cleanup(func() {
		config.AppConfig, lookupPanelDomainIPs, dialPanelDomainHTTP, runOLSCommand = oldCfg, oldLookup, oldDial, oldRun
	})
	config.AppConfig = &config.Config{Paths: config.PathsConfig{OLSRoot: paths.root, OLSManagedConfig: paths.managed, OLSBinary: paths.binary}}
	runOLSCommand = func(string, ...string) ([]byte, error) { return nil, nil }
	ipv4, ipv6 := net.IPAddr{IP: net.ParseIP("8.8.8.8")}, net.IPAddr{IP: net.ParseIP("2001:4860:4860::8888")}
	lookupPanelDomainIPs = func(context.Context, string) ([]net.IPAddr, error) { return []net.IPAddr{ipv4, ipv4, ipv6}, nil }
	root, _ := olsDefaultVHostPaths(paths)
	good := httptest.NewServer(http.FileServer(http.Dir(root)))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("old IPv6 server")) }))
	defer bad.Close()
	var visited []string
	dialPanelDomainHTTP = func(ctx context.Context, network, target string) (net.Conn, error) {
		visited = append(visited, target)
		url := good.URL
		if strings.HasPrefix(target, "[") {
			url = bad.URL
		}
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(url, "http://"))
	}
	if code, details := PanelDomainErrorInfo(CheckPanelDomain(context.Background(), "panel.example.com")); code != "panel_domain_challenge_mismatch" || details["address_family"] != "IPv6" {
		t.Fatalf("stale IPv6 hidden: %s %+v", code, details)
	}
	if !reflect.DeepEqual(visited, []string{"8.8.8.8:80", "[2001:4860:4860::8888]:80"}) {
		t.Fatalf("did not verify every unique record: %v", visited)
	}
	files, err := os.ReadDir(filepath.Join(root, ".well-known", "acme-challenge"))
	if err != nil || len(files) != 0 {
		t.Fatalf("failed probe left token files: %v %v", files, err)
	}
}

func TestPanelDomainRejectsPrivateDNSBeforeAnyRoutingWrite(t *testing.T) {
	oldLookup := lookupPanelDomainIPs
	t.Cleanup(func() { lookupPanelDomainIPs = oldLookup })
	lookupPanelDomainIPs = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	code, _ := PanelDomainErrorInfo(CheckPanelDomain(context.Background(), "panel.example.com"))
	if code != "panel_domain_dns_not_public" {
		t.Fatalf("private DNS accepted: %s", code)
	}
}
func TestPanelTLSRejectsTraversalGeneration(t *testing.T) {
	root := t.TempDir()
	cert := filepath.Join(root, "panel.crt")
	if err := os.WriteFile(filepath.Join(root, "panel-tls-active.json"), []byte(`{"domain":"panel.example.com","generation":"../outside"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPanelTLSState(cert); err == nil {
		t.Fatal("accepted traversal")
	}
}
