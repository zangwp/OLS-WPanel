package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

type securityStatusTransport func(*http.Request) (*http.Response, error)

func TestSiteSecurityNativePolicyRequiresActiveCode(t *testing.T) {
	active := renderWPNativePolicy("<?php\n", false, true)
	if !siteSecurityNativePolicyMatches(active, false, true) {
		t.Fatal("managed policy not recognized")
	}
	block := nativePolicyBlock.FindString(active)
	for _, inactive := range []string{"<?php\n$example = <<<'EXAMPLE'\n" + block + "\nEXAMPLE;\n", "<?php\n$example = '" + strings.ReplaceAll(block, "'", "\\'") + "';\n"} {
		if siteSecurityNativePolicyMatches(inactive, false, true) {
			t.Fatal("policy example treated as installed")
		}
	}
}

func (f securityStatusTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSiteSecurityDenialEvidence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		control   int
		deny      int
		broken    bool
		effective bool
	}{
		{"verified", 404, 403, false, true}, {"blanket forbidden", 403, 403, false, false},
		{"service failure", 503, 403, false, false}, {"not enforced", 404, 404, false, false},
		{"network unavailable", 0, 0, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			client := &http.Client{Transport: securityStatusTransport(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.Method != http.MethodHead || r.URL.Host != "127.0.0.1:80" || r.Host != "site.example.com" || r.URL.RawQuery != "" {
					t.Fatalf("unsafe probe: %v", r)
				}
				if tc.broken {
					return nil, errors.New("offline")
				}
				code := tc.deny
				if strings.HasPrefix(r.URL.Path, "/.well-known/") || strings.HasPrefix(r.URL.Path, "/ols-wpanel-readonly-security-control") {
					code = tc.control
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
			})}
			result := observeSiteSecurityDenialsWithClient(context.Background(), client, "site.example.com", true, true)
			for _, key := range []string{"xmlrpc", "uploads_php", "sensitive_files"} {
				if result[key] != tc.effective {
					t.Fatalf("%s: %v", key, result)
				}
			}
			if !tc.effective && (tc.control == 403 || tc.control >= 500 || tc.broken) && requests != 1 {
				t.Fatal("must stop after failed control")
			}
		})
	}
}

func TestSiteSecurityRejectsUnsafeHost(t *testing.T) {
	client := &http.Client{Transport: securityStatusTransport(func(*http.Request) (*http.Response, error) { t.Fatal("invalid host caused a request"); return nil, nil })}
	for _, host := range []string{"", "site.com\r\nX: y", "https://site.com", "site.com:81", "../etc", "a..b"} {
		if len(observeSiteSecurityDenialsWithClient(context.Background(), client, host, true, true)) != 0 {
			t.Fatal(host)
		}
	}
}

func TestSiteSecurityFileBoundary(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "vhost.conf")
	if err := os.WriteFile(file, []byte("allowed"), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := readSiteSecurityFile(root, file, 20)
	if err != nil || string(data) != "allowed" {
		t.Fatalf("read: %q %v", data, err)
	}
	for _, target := range []string{root, filepath.Join(filepath.Dir(root), "outside.conf"), "relative"} {
		if _, err := readSiteSecurityFile(root, target, 20); err == nil {
			t.Fatalf("unsafe target accepted: %s", target)
		}
	}
	if _, err := readSiteSecurityFile(root, file, 3); err == nil {
		t.Fatal("oversized config accepted")
	}
	link := filepath.Join(root, "link.conf")
	if err := os.Symlink(file, link); err == nil {
		if _, err := readSiteSecurityFile(root, link, 20); err == nil {
			t.Fatal("symlink accepted")
		}
	}
}

func TestSiteSecuritySavedFlagsCannotBecomeEffective(t *testing.T) {
	report := models.WebsiteSecurityStatus{Checks: []models.WebsiteSecurityCheck{{Key: "xmlrpc", State: "unknown"}}}
	SetWebsiteSecurityCheck(&report, "xmlrpc", "effective", securityBool(true), nil)
	if report.Checks[0].State == "effective" {
		t.Fatal("configured flag earned verified status")
	}
	SetWebsiteSecurityCheck(&report, "xmlrpc", "effective", securityBool(true), securityBool(false))
	if report.Checks[0].State == "effective" {
		t.Fatal("negative observation earned verified status")
	}
	SetWebsiteSecurityCheck(&report, "xmlrpc", "effective", securityBool(true), securityBool(true))
	if report.Checks[0].State != "effective" {
		t.Fatal("positive observation rejected")
	}
}

func TestSiteSecurityConstantInspection(t *testing.T) {
	if !siteSecurityBoolConstant("define('WP_DEBUG_DISPLAY', false);", "WP_DEBUG_DISPLAY", false) {
		t.Fatal("explicit false not recognized")
	}
	for _, content := range []string{"// define('WP_DEBUG_DISPLAY', false);", "/*\ndefine('WP_DEBUG_DISPLAY', false);\n*/", "define('WP_DEBUG_DISPLAY', true);", "define('WP_DEBUG_DISPLAY', getenv('DEBUG'));", "define('WP_DEBUG_DISPLAY', true);\ndefine('WP_DEBUG_DISPLAY', false);"} {
		if siteSecurityBoolConstant(content, "WP_DEBUG_DISPLAY", false) {
			t.Fatal("unsafe or unproven value accepted")
		}
	}
}

func TestSiteSecurityConstantInspectionIsConservative(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		confirmed     bool
	}{
		{"case insensitive function and bool", "DEFINE(\"WP_DEBUG_DISPLAY\", FALSE);", true},
		{"global define", "\\define('WP_DEBUG_DISPLAY', false);", true},
		{"comments between tokens", "define /* note */ ( 'WP_DEBUG_DISPLAY', /* current */ false );", true},
		{"commented value beside current value", "/* define('WP_DEBUG_DISPLAY', true); */\ndefine('WP_DEBUG_DISPLAY', false);", true},
		{"case sensitive name", "define('wp_debug_display', false);", false},
		{"dynamic value duplicate first", "define('WP_DEBUG_DISPLAY', getenv('DEBUG'));\ndefine('WP_DEBUG_DISPLAY', false);", false},
		{"dynamic value duplicate last", "define('WP_DEBUG_DISPLAY', false);\ndefine('WP_DEBUG_DISPLAY', is_debug());", false},
		{"literal duplicates", "define('WP_DEBUG_DISPLAY', false);\ndefine('WP_DEBUG_DISPLAY', FALSE);", false},
		{"string value duplicate", "define('WP_DEBUG_DISPLAY', 'false');\ndefine('WP_DEBUG_DISPLAY', false);", false},
		{"const duplicate", "const WP_DEBUG_DISPLAY = false;\ndefine('WP_DEBUG_DISPLAY', false);", false},
		{"different case constant is distinct", "const wp_debug_display = true;\ndefine('WP_DEBUG_DISPLAY', false);", true},
		{"multiline single quoted string", "$snippet = '\ndefine(\"WP_DEBUG_DISPLAY\", false);\n';", false},
		{"multiline double quoted string", "$snippet = \"\ndefine('WP_DEBUG_DISPLAY', false);\n\";", false},
		{"escaped quotes in string", "$snippet = \"escaped \\\" quote\ndefine('WP_DEBUG_DISPLAY', false);\n\";", false},
		{"backtick command string", "$snippet = `\ndefine('WP_DEBUG_DISPLAY', false);\n`;", false},
		{"real definition after string", "$snippet = \"\ndefine('WP_DEBUG_DISPLAY', true);\n\";\ndefine('WP_DEBUG_DISPLAY', false);", true},
		{"nowdoc", "$snippet = <<<'PHP_TEXT'\ndefine('WP_DEBUG_DISPLAY', false);\nPHP_TEXT;\n", false},
		{"heredoc", "$snippet = <<<PHP_TEXT\ndefine('WP_DEBUG_DISPLAY', false);\nPHP_TEXT;\n", false},
		{"quoted heredoc", "$snippet = <<<\"PHP_TEXT\"\ndefine('WP_DEBUG_DISPLAY', false);\nPHP_TEXT;\n", false},
		{"real definition after nowdoc", "$snippet = <<<'PHP_TEXT'\ndefine('WP_DEBUG_DISPLAY', true);\nPHP_TEXT;\ndefine('WP_DEBUG_DISPLAY', false);", true},
		{"indented closing label", "$snippet = <<<'PHP_TEXT'\n  define('WP_DEBUG_DISPLAY', true);\n  PHP_TEXT;\ndefine('WP_DEBUG_DISPLAY', false);", true},
		{"unclosed heredoc", "$snippet = <<<PHP_TEXT\ndefine('WP_DEBUG_DISPLAY', false);", false},
		{"malformed heredoc", "$snippet = <<<'PHP_TEXT\ndefine('WP_DEBUG_DISPLAY', false);", false},
		{"object method", "$object->define('WP_DEBUG_DISPLAY', false);", false},
		{"static method", "Settings::define('WP_DEBUG_DISPLAY', false);", false},
		{"variable function", "$define('WP_DEBUG_DISPLAY', false);", false},
		{"namespaced function", "Settings\\define('WP_DEBUG_DISPLAY', false);", false},
		{"computed bool", "define('WP_DEBUG_DISPLAY', false || true);", false},
		{"case insensitive legacy argument", "define('WP_DEBUG_DISPLAY', false, true);", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if confirmed := siteSecurityBoolConstant(tc.content, "WP_DEBUG_DISPLAY", false); confirmed != tc.confirmed {
				t.Fatalf("confirmed=%v, want %v for %q", confirmed, tc.confirmed, tc.content)
			}
		})
	}
}

func TestSiteSecurityPHPMaskingPreservesOffsetsAndLineBreaks(t *testing.T) {
	content := "<?php\r\n$url='https://example.test/a#b'; // define('WP_DEBUG_DISPLAY', true);\r\n/* note\r\n */\r\ndefine('WP_DEBUG_DISPLAY', false);\r\n"
	masked := siteSecurityPHPWithoutComments(content)
	if len(masked) != len(content) || strings.Count(masked, "\r\n") != strings.Count(content, "\r\n") {
		t.Fatalf("source positions changed: %q", masked)
	}
	if !siteSecurityBoolConstant(content, "WP_DEBUG_DISPLAY", false) {
		t.Fatal("URL or comment obscured the active definition")
	}
}

func TestSiteSecurityDefaultHostACMEExceptionIsNotProtection(t *testing.T) {
	requests := 0
	client := &http.Client{Transport: securityStatusTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		code := http.StatusForbidden
		if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
			code = http.StatusNotFound
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	result := observeSiteSecurityDenialsWithClient(context.Background(), client, "site.example.com", true, true)
	if len(result) != 0 || requests != 2 {
		t.Fatalf("default host mistaken for site's rules: %v, requests=%d", result, requests)
	}
}

func TestSiteSecurityProbesNeverFollowRedirects(t *testing.T) {
	requests := 0
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: securityStatusTransport(func(r *http.Request) (*http.Response, error) {
			requests++
			if r.Method != http.MethodHead || r.URL.Host != "127.0.0.1:80" || r.Host != "site.example.com" || r.URL.RawQuery != "" || r.Header.Get("User-Agent") != "OLS-WPanel-ReadOnly-Security-Check" {
				t.Fatalf("unexpected request: %s %s Host=%s", r.Method, r.URL, r.Host)
			}
			return &http.Response{StatusCode: http.StatusFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{"Location": {"https://external.example/probe"}}}, nil
		}),
	}
	result := observeSiteSecurityDenialsWithClient(context.Background(), client, "site.example.com", true, true)
	if result["sensitive_files"] || result["xmlrpc"] || result["uploads_php"] || requests != 5 {
		t.Fatalf("redirect not handled conservatively: %v, requests=%d", result, requests)
	}
}

func TestSiteSecurityCanceledContextCannotVerifyProtection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: securityStatusTransport(func(r *http.Request) (*http.Response, error) {
		return nil, r.Context().Err()
	})}
	if result := observeSiteSecurityDenialsWithClient(ctx, client, "site.example.com", true, true); len(result) != 0 {
		t.Fatalf("canceled probe produced evidence: %v", result)
	}
}

func TestSiteSecurityPHPProbesExcludeWordPressPaths(t *testing.T) {
	var paths []string
	client := &http.Client{Transport: securityStatusTransport(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		code := http.StatusNotFound
		if strings.HasPrefix(r.URL.Path, "/.git/") {
			code = http.StatusForbidden
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	result := observeSiteSecurityDenialsWithClient(context.Background(), client, "site.example.com", false, true)
	if !result["sensitive_files"] || len(paths) != 3 || result["xmlrpc"] || result["uploads_php"] {
		t.Fatalf("PHP site used WordPress checks: %v %v", paths, result)
	}
}

func TestSiteSecurityUnknownAndFailedFilesCannotBecomeEffective(t *testing.T) {
	original := config.AppConfig
	t.Cleanup(func() { config.AppConfig = original })
	site := &models.Website{ID: 12, Domain: "site.example.com", SiteType: "wordpress", Status: models.StatusPaused, SSLEnabled: true, MonitoringEnabled: true, DisableApplicationPasswords: true, DisableFileEditing: true}
	config.AppConfig = nil
	unknown := CollectWebsiteSecurityStatus(context.Background(), site)
	config.AppConfig = &config.Config{Paths: config.PathsConfig{WWWRoot: t.TempDir(), OLSVHostsAvailable: t.TempDir()}}
	site.WebRoot = filepath.Join(config.AppConfig.Paths.WWWRoot, "site")
	site.OLSVHostConfigPath = filepath.Join(config.AppConfig.Paths.OLSVHostsAvailable, "site.conf")
	failed := CollectWebsiteSecurityStatus(context.Background(), site)
	for _, report := range []models.WebsiteSecurityStatus{unknown, failed} {
		for _, check := range report.Checks {
			if check.State == "effective" || check.Effective != nil && *check.Effective {
				t.Fatalf("missing runtime or file data earned protection: %+v", check)
			}
		}
	}
}

func TestSiteSecurityPHPUnsupportedAndReadOnly(t *testing.T) {
	original := config.AppConfig
	t.Cleanup(func() { config.AppConfig = original })
	root := t.TempDir()
	config.AppConfig = &config.Config{Paths: config.PathsConfig{WWWRoot: root, OLSVHostsAvailable: root}}
	vhost := "rewrite {\n  enable                 1\n  autoLoadHtaccess       1\n  rules                  <<<END_rules\n" + olsSiteSecurityRewriteRules(&OLSVHostData{SiteType: "php"})
	vhostPath := filepath.Join(root, "site.conf")
	if err := os.WriteFile(vhostPath, []byte(vhost), 0600); err != nil {
		t.Fatal(err)
	}
	site := &models.Website{ID: 15, Domain: "site.example.com", SiteType: "php", Status: models.StatusPaused, WebRoot: root, OLSVHostConfigPath: vhostPath}
	report := CollectWebsiteSecurityStatus(context.Background(), site)
	for _, check := range report.Checks {
		switch check.Key {
		case "login_protection", "xmlrpc", "application_passwords", "uploads_php", "file_editing", "debug_display", "anomaly_monitor", "wp_updates", "sql_injection":
			if check.State != "unsupported" || check.Configured != nil || check.Effective != nil {
				t.Fatalf("unsupported feature reported a policy: %+v", check)
			}
		case "sensitive_files":
			if check.State != "configured" || check.Effective != nil {
				t.Fatalf("saved PHP rules reported effective: %+v", check)
			}
		}
	}
	data, err := os.ReadFile(vhostPath)
	entries, readErr := os.ReadDir(root)
	if err != nil || string(data) != vhost || readErr != nil || len(entries) != 1 {
		t.Fatal("read-only inspection changed configuration")
	}
}
