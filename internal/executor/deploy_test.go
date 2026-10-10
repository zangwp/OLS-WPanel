package executor

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

// TestDownloadWPUsesLocalCacheWithoutNetwork proves downloadWP wires
// cfg.Paths.WordPressPackage into AcquireCorePackage correctly: a warm cache
// is deployed with zero network access, matching what deployWordPress needs
// during site creation on a server with no outbound connectivity.
func TestDownloadWPUsesLocalCacheWithoutNetwork(t *testing.T) {
	cachePath := wordPressZIPWithVersion(t, "7.1")
	cfg := &config.Config{Paths: config.PathsConfig{WordPressPackage: cachePath}}
	destPath := filepath.Join(t.TempDir(), "wordpress.zip")

	if err := downloadWP(context.Background(), cfg, destPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateWordPressPackage(context.Background(), destPath); err != nil {
		t.Fatalf("deployed file is not a valid package: %v", err)
	}
}

func TestLiteSpeedCacheActivatorRunsWithoutAdminVisit(t *testing.T) {
	content := liteSpeedCacheActivator()
	for _, required := range []string{
		"add_action('init'",
		"is_blog_installed()",
		"litespeed-cache/litespeed-cache.php",
		"activate_plugin($plugin, '', false, true)",
		"@unlink(__FILE__)",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("activator missing %q", required)
		}
	}
	if strings.Contains(content, "current_user_can") || strings.Contains(content, "admin_init") {
		t.Fatal("activation must not wait for an administrator dashboard visit")
	}
}

// TestDeployWordPressExtractsCachedPackageIntoWebRoot exercises the full
// deployWordPress path (download + unzip + move into webRoot) against a
// locally cached package, with no network involved.
func TestDeployWordPressExtractsCachedPackageIntoWebRoot(t *testing.T) {
	cachePath := wordPressZIPWithVersion(t, "7.1")
	cfg := &config.Config{Paths: config.PathsConfig{WordPressPackage: cachePath}}
	webRoot := t.TempDir()
	tmpDir := filepath.Join(t.TempDir(), "deploy-work")

	if err := deployWordPress(context.Background(), cfg, webRoot, tmpDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(webRoot, "wp-admin", "index.php")); err != nil {
		t.Fatalf("wp-admin/index.php missing after deploy: %v", err)
	}
	if _, err := os.Stat(filepath.Join(webRoot, "wp-includes", "version.php")); err != nil {
		t.Fatalf("wp-includes/version.php missing after deploy: %v", err)
	}
	if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
		t.Fatal("deployWordPress must clean up its temp working directory")
	}
	if _, err := os.Stat(filepath.Join(webRoot, "wp-content", "mu-plugins", newWordPressDefaultsHelper)); !os.IsNotExist(err) {
		t.Fatal("generic deployment/reinstallation scheduled fresh-install cleanup")
	}
	if _, err := os.Stat(filepath.Join(webRoot, ".htaccess")); !os.IsNotExist(err) {
		t.Fatal("generic deployment/reinstallation injected new-site rewrite rules")
	}
}

func TestNewWordPressDeploymentCarriesTheActualPackageOriginToDeferredCleanup(t *testing.T) {
	files := map[string]string{
		"wordpress/wp-admin/index.php":                           "<?php",
		"wordpress/wp-includes/load.php":                         "<?php",
		"wordpress/wp-includes/version.php":                      "<?php\n$wp_version = '7.0.2';\n",
		"wordpress/wp-settings.php":                              "<?php",
		"wordpress/wp-load.php":                                  "<?php",
		"wordpress/wp-content/plugins/akismet/akismet.php":       "bundled-or-custom-akismet",
		"wordpress/wp-content/plugins/hello.php":                 "bundled-or-custom-hello",
		"wordpress/wp-content/themes/twentytwentyfive/style.css": "active-theme",
		"wordpress/wp-content/themes/twentytwentyfour/style.css": "bundled-or-custom-theme",
	}
	body, err := os.ReadFile(writeTestZIP(t, files))
	if err != nil {
		t.Fatal(err)
	}
	const packageRules = "# uploaded package rules\nRewriteRule ^special$ /custom.php [L]\n"
	files["wordpress/.htaccess"] = packageRules
	customBody, err := os.ReadFile(writeTestZIP(t, files))
	if err != nil {
		t.Fatal(err)
	}
	previousExec := shellExec
	t.Cleanup(func() { shellExec = previousExec })
	// Only the unzip process boundary is replaced; acquisition, validation,
	// receipt/hash checks, extraction files and preparation are production code.
	shellExec = func(binary string, args ...string) (string, error) {
		if binary != "unzip" || len(args) != 5 || args[0] != "-q" || args[1] != "-o" || args[3] != "-d" {
			return "", fmt.Errorf("unexpected command %s %v", binary, args)
		}
		reader, err := zip.OpenReader(args[2])
		if err != nil {
			return "", err
		}
		defer reader.Close()
		for _, entry := range reader.File {
			path := filepath.Join(args[4], filepath.FromSlash(entry.Name))
			if entry.FileInfo().IsDir() {
				if err := os.MkdirAll(path, 0755); err != nil {
					return "", err
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return "", err
			}
			rc, err := entry.Open()
			if err != nil {
				return "", err
			}
			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return "", err
			}
			if err := os.WriteFile(path, content, 0644); err != nil {
				return "", err
			}
		}
		return "", nil
	}
	for _, state := range []string{"official new", "uploaded new", "uploaded new with htaccess", "legacy cache new", "official reinstall"} {
		t.Run(state, func(t *testing.T) {
			archiveBody := body
			if state == "uploaded new with htaccess" {
				archiveBody = customBody
			}
			cache := filepath.Join(t.TempDir(), "wordpress.zip")
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(archiveBody)), Header: make(http.Header), Request: req}, nil
			})}
			service, err := NewWPPackageService(cache, client)
			if err != nil {
				t.Fatal(err)
			}
			if state == "official new" || state == "official reinstall" {
				_, err = service.DownloadLatest(t.Context())
			} else {
				_, err = service.PublishUpload(t.Context(), bytes.NewReader(archiveBody), int64(len(archiveBody)))
				if err == nil && state == "legacy cache new" {
					err = os.Remove(cache + ".origin.json")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			cfg := &config.Config{Paths: config.PathsConfig{WordPressPackage: cache}}
			work := filepath.Join(t.TempDir(), "deploy")
			if state == "official reinstall" {
				err = deployWordPress(t.Context(), cfg, root, work)
			} else {
				err = deployNewWordPress(t.Context(), cfg, root, work)
			}
			if err != nil {
				t.Fatal(err)
			}
			helper, err := os.ReadFile(filepath.Join(root, "wp-content", "mu-plugins", newWordPressDefaultsHelper))
			if state == "official reinstall" {
				if !os.IsNotExist(err) {
					t.Fatalf("reinstallation injected cleanup: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				wantOfficial := state == "official new"
				if strings.Contains(string(helper), `"official_package":true`) != wantOfficial {
					t.Fatalf("deferred cleanup received wrong archive origin for %s", state)
				}
			}
			rewrite, err := os.ReadFile(filepath.Join(root, ".htaccess"))
			if state == "official reinstall" {
				if !os.IsNotExist(err) {
					t.Fatal("reinstallation injected new-site rewrite rules")
				}
			} else {
				wantRewrite := newWordPressRootRewrite
				if state == "uploaded new with htaccess" {
					wantRewrite = packageRules
				}
				if err != nil || string(rewrite) != wantRewrite {
					t.Fatalf("wrong first-load rewrite rules for %s: %q, %v", state, rewrite, err)
				}
			}
			if _, err := os.Stat(work); !os.IsNotExist(err) {
				t.Fatal("temporary archive was retained")
			}
		})
	}
}

func TestDownloadWPSurfacesErrorWhenCacheMissingAndRefreshUnavailable(t *testing.T) {
	// An unresolvable WordPressPackage path with no real cache and no
	// network in this test environment must fail cleanly, not panic, and
	// must not leave a partial file behind.
	cfg := &config.Config{Paths: config.PathsConfig{WordPressPackage: filepath.Join(t.TempDir(), "missing.zip")}}
	destPath := filepath.Join(t.TempDir(), "wordpress.zip")
	ctx, cancel := context.WithTimeout(context.Background(), 0) // already-expired context: refresh must fail fast, not hit the real network
	defer cancel()

	if err := downloadWP(ctx, cfg, destPath); err == nil {
		t.Fatal("expected an error when the cache is empty and the context is already done")
	}
	if _, err := os.Stat(destPath); !os.IsNotExist(err) {
		t.Fatal("a failed download must not leave a partial file at destPath")
	}
}
