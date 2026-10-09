package executor

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

var panelCertificate atomic.Pointer[tls.Certificate]
var panelCertificateMu sync.Mutex
var panelDomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// PanelDomainError provides a stable, localizable diagnosis without exposing
// filesystem paths, command output or certificate account information.
type PanelDomainError struct {
	Code    string            `json:"error_code"`
	Details map[string]string `json:"details,omitempty"`
	cause   error
}

func (e *PanelDomainError) Error() string { return e.Code }
func (e *PanelDomainError) Unwrap() error { return e.cause }

func panelDomainError(code string, cause error, details map[string]string) error {
	return &PanelDomainError{Code: code, Details: details, cause: cause}
}

func PanelDomainErrorInfo(err error) (string, map[string]string) {
	var diagnosis *PanelDomainError
	if errors.As(err, &diagnosis) {
		return diagnosis.Code, diagnosis.Details
	}
	return "panel_certificate_failed", nil
}

var lookupPanelDomainIPs = net.DefaultResolver.LookupIPAddr
var dialPanelDomainHTTP = func(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
}

func NormalizePanelDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if len(domain) > 253 || !panelDomainPattern.MatchString(domain) || net.ParseIP(domain) != nil {
		return "", panelDomainError("panel_domain_invalid", nil, nil)
	}
	return domain, nil
}

type PanelTLSState struct {
	Domain     string `json:"domain"`
	Generation string `json:"generation"`
}

func ReadPanelTLSState(certPath string) (PanelTLSState, error) {
	var state PanelTLSState
	data, err := os.ReadFile(filepath.Join(filepath.Dir(certPath), "panel-tls-active.json"))
	if os.IsNotExist(err) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err = json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	if !regexp.MustCompile(`^panel-tls-[a-f0-9]{32}$`).MatchString(state.Generation) {
		return state, fmt.Errorf("invalid certificate generation")
	}
	domain, err := NormalizePanelDomain(state.Domain)
	if err != nil {
		return state, err
	}
	state.Domain = domain
	return state, nil
}
func InitializePanelCertificate(certPath, keyPath string) error {
	state, err := ReadPanelTLSState(certPath)
	if err != nil {
		return err
	}
	if state.Generation != "" {
		root := filepath.Join(filepath.Dir(certPath), state.Generation)
		if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe active certificate directory")
		}
		certPath, keyPath = filepath.Join(root, "panel.crt"), filepath.Join(root, "panel.key")
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return err
	}
	if state.Domain != "" {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return err
		}
		if err = leaf.VerifyHostname(state.Domain); err != nil {
			return err
		}
	}
	panelCertificate.Store(&cert)
	return nil
}
func GetPanelCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := panelCertificate.Load()
	if cert == nil {
		return nil, fmt.Errorf("panel certificate unavailable")
	}
	return cert, nil
}

// Prove that the configured hostname serves a random file from this server.
// Pin the HTTP connection to previously validated public DNS addresses.
func CheckPanelDomain(ctx context.Context, domain string) error {
	_, err := checkPanelDomain(ctx, domain)
	return err
}

func checkPanelDomain(ctx context.Context, domain string) (string, error) {
	domain, err := NormalizePanelDomain(domain)
	if err != nil {
		return "", err
	}
	addresses, err := lookupPanelDomainIPs(ctx, domain)
	if err != nil {
		return "", panelDomainError("panel_domain_dns_failed", err, nil)
	}
	if len(addresses) == 0 {
		return "", panelDomainError("panel_domain_dns_empty", nil, nil)
	}
	for _, address := range addresses {
		if !IsPublicIPAddress(address.IP.String()) {
			return "", panelDomainError("panel_domain_dns_not_public", nil, panelDomainAddressDetails(address))
		}
	}
	root, err := panelACMERootForDomain(domain)
	if err != nil {
		return "", panelDomainError("panel_domain_route_unavailable", err, nil)
	}
	if info, err := os.Lstat(root); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", panelDomainError("panel_domain_route_unavailable", err, nil)
	}
	challenge := filepath.Join(root, ".well-known", "acme-challenge")
	if err := ensurePanelACMEChallengeDirectory(root); err != nil {
		return "", panelDomainError("panel_domain_route_unavailable", err, nil)
	}

	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	value := hex.EncodeToString(token)
	probePath := filepath.Join(challenge, "panel-probe-"+value)
	if err := os.WriteFile(probePath, []byte(value), 0644); err != nil {
		return "", panelDomainError("panel_domain_route_unavailable", err, nil)
	}
	defer os.Remove(probePath)
	// Every published A/AAAA record must work. Trying the next address only on
	// connection failure hid stale IPv6 records and round-robin DNS mistakes.
	seen := make(map[string]bool)
	for _, address := range addresses {
		if seen[address.IP.String()] {
			continue
		}
		seen[address.IP.String()] = true
		if err := probePanelDomainAddress(ctx, domain, address, value); err != nil {
			return "", err
		}
	}
	return root, nil
}

func panelDomainAddressDetails(address net.IPAddr) map[string]string {
	family := "IPv6"
	if address.IP.To4() != nil {
		family = "IPv4"
	}
	return map[string]string{"address": address.IP.String(), "address_family": family}
}

func probePanelDomainAddress(ctx context.Context, domain string, address net.IPAddr, value string) error {
	details := panelDomainAddressDetails(address)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialPanelDomainHTTP(ctx, network, net.JoinHostPort(address.IP.String(), "80"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain+"/.well-known/acme-challenge/panel-probe-"+value, nil)
	if err != nil {
		return panelDomainError("panel_domain_invalid", err, nil)
	}
	req.Header.Set("Cache-Control", "no-store")
	response, err := client.Do(req)
	if err != nil {
		return panelDomainError("panel_domain_http_unreachable", err, details)
	}
	defer response.Body.Close()
	details["http_status"] = fmt.Sprint(response.StatusCode)
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		// Do not return a redirect URL: it can contain credentials or tokens and
		// an unrelated destination must never be followed by the pinned probe.
		return panelDomainError("panel_domain_http_redirect", nil, details)
	}
	if response.StatusCode != http.StatusOK {
		return panelDomainError("panel_domain_http_status", nil, details)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil || string(data) != value {
		return panelDomainError("panel_domain_challenge_mismatch", err, details)
	}
	return nil
}

func writePanelTLSFile(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("unsafe certificate path")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".panel-tls-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}

func ApplyPanelDomainCertificate(ctx context.Context, cfg *config.Config, domain string) error {
	return applyPanelDomainCertificate(ctx, cfg, domain, false)
}

func applyPanelDomainCertificate(ctx context.Context, cfg *config.Config, domain string, renewal bool) error {
	panelCertificateMu.Lock()
	defer panelCertificateMu.Unlock()
	domain, err := NormalizePanelDomain(domain)
	if err != nil {
		return err
	}
	if cfg == nil || cfg.Panel.TLSCertPath == "" || cfg.Panel.TLSKeyPath == "" || cfg.Panel.TLSPort <= 0 {
		return fmt.Errorf("panel HTTPS must already be configured")
	}
	if renewal {
		state, stateErr := ReadPanelTLSState(cfg.Panel.TLSCertPath)
		if stateErr != nil {
			return stateErr
		}
		// A manual domain change may have completed while renewal waited for the lock.
		if state.Domain != domain {
			return nil
		}
	}
	root, err := checkPanelDomain(ctx, domain)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(cfg.Panel.DataDir, ".panel-cert-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	if _, err = obtainLegoCert(domain, "", root, stage); err != nil {
		return err
	}
	certBytes, err := os.ReadFile(filepath.Join(stage, "fullchain.pem"))
	if err != nil {
		return err
	}
	keyBytes, err := os.ReadFile(filepath.Join(stage, "privkey.pem"))
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if err = leaf.VerifyHostname(domain); err != nil {
		return err
	}
	token := make([]byte, 16)
	if _, err = rand.Read(token); err != nil {
		return err
	}
	generation := "panel-tls-" + hex.EncodeToString(token)
	parent := filepath.Dir(cfg.Panel.TLSCertPath)
	target := filepath.Join(parent, generation)
	if err = os.Mkdir(target, 0700); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(target)
		}
	}()
	if err = writePanelTLSFile(filepath.Join(target, "panel.crt"), certBytes, 0644); err != nil {
		return err
	}
	if err = writePanelTLSFile(filepath.Join(target, "panel.key"), keyBytes, 0600); err != nil {
		return err
	}
	// Publish one atomic pointer to a complete certificate/key generation.
	// The configured self-signed fallback files remain untouched.
	stateBytes, err := json.Marshal(PanelTLSState{Domain: domain, Generation: generation})
	if err != nil {
		return err
	}
	if err = writePanelTLSFile(filepath.Join(parent, "panel-tls-active.json"), stateBytes, 0600); err != nil {
		return err
	}
	committed = true
	panelCertificate.Store(&pair)
	return nil
}

func StartPanelCertificateRenewal(cfg *config.Config) {
	go func() {
		timer := time.NewTicker(12 * time.Hour)
		defer timer.Stop()
		for range timer.C {
			state, err := ReadPanelTLSState(cfg.Panel.TLSCertPath)
			if err != nil || state.Domain == "" {
				continue
			}
			domain := state.Domain
			cert := panelCertificate.Load()
			if cert == nil || len(cert.Certificate) == 0 {
				continue
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil || time.Until(leaf.NotAfter) > 30*24*time.Hour {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			err = applyPanelDomainCertificate(ctx, cfg, domain, true)
			cancel()
			message := ""
			if err != nil {
				code, details := PanelDomainErrorInfo(err)
				encoded, _ := json.Marshal(PanelDomainError{Code: code, Details: details})
				message = string(encoded)
			}
			_, _ = database.GetDB().Exec(`INSERT INTO security_settings(skey,svalue,updated_at) VALUES('panel_certificate_renewal_error',?,CURRENT_TIMESTAMP) ON CONFLICT(skey) DO UPDATE SET svalue=excluded.svalue,updated_at=excluded.updated_at`, message)
		}
	}()
}
