package executor

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func newWordPressDefaultsFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range map[string]string{
		"wp-content/plugins/akismet/akismet.php":                 "bundled-akismet",
		"wp-content/plugins/hello.php":                           "bundled-hello",
		"wp-content/plugins/litespeed-cache/litespeed-cache.php": "litespeed-cache",
		"wp-content/plugins/studio-custom/main.php":              "custom-plugin",
		"wp-content/themes/twentytwentythree/style.css":          "bundled-2023",
		"wp-content/themes/twentytwentyfour/style.css":           "bundled-2024",
		"wp-content/themes/twentytwentyfive/style.css":           "bundled-2025",
		"wp-content/themes/studio-child/style.css":               "custom-child",
		"wp-content/themes/twentytwentyfive-custom/style.css":    "custom-theme",
		"wp-content/mu-plugins/ols-wpanel-login-log.php":         "panel-logging",
		"wp-content/mu-plugins/ols-wpanel-lscache-activate.php":  "panel-cache-activator",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestPrepareNewWordPressDefaultsLeavesContentIntactAndRefusesOverwrite(t *testing.T) {
	root := newWordPressDefaultsFixture(t)
	if err := prepareNewWordPressDefaults(root, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "wp-content", "mu-plugins", newWordPressDefaultsHelper)
	before, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(before), "__OLS_WPANEL_DEFAULTS_MANIFEST__") {
		t.Fatalf("helper not rendered: %v", err)
	}
	for _, name := range []string{"plugins/akismet/akismet.php", "plugins/hello.php", "themes/twentytwentyfive/style.css", "mu-plugins/ols-wpanel-login-log.php"} {
		if _, err := os.Stat(filepath.Join(root, "wp-content", filepath.FromSlash(name))); err != nil {
			t.Fatalf("preparation changed %s: %v", name, err)
		}
	}
	if err := prepareNewWordPressDefaults(root, true); err == nil {
		t.Fatal("existing helper or custom content must never be overwritten")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("a failed repeated preparation changed the existing helper")
	}
}

func TestNewWordPressDefaultFingerprintDetectsContentAndDirectoryChanges(t *testing.T) {
	root := newWordPressDefaultsFixture(t)
	path := filepath.Join(root, "wp-content", "themes", "twentytwentyfive")
	original, err := fingerprintNewWordPressDefault(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "style.css"), []byte("user modification"), 0644); err != nil {
		t.Fatal(err)
	}
	modified, err := fingerprintNewWordPressDefault(path)
	if err != nil || reflect.DeepEqual(original, modified) {
		t.Fatal("modified default theme was not distinguishable from bundled content")
	}
	if err := os.Mkdir(filepath.Join(path, "custom-empty-directory"), 0755); err != nil {
		t.Fatal(err)
	}
	additional, err := fingerprintNewWordPressDefault(path)
	if err != nil || reflect.DeepEqual(modified, additional) {
		t.Fatal("additional custom directories must prevent default theme deletion")
	}
}

func TestNewWordPressDefaultFingerprintRejectsSymlinks(t *testing.T) {
	root := newWordPressDefaultsFixture(t)
	path := filepath.Join(root, "wp-content", "themes", "twentytwentyfive")
	if err := os.Symlink(filepath.Join(root, "wp-content", "plugins", "hello.php"), filepath.Join(path, "linked.php")); err != nil {
		t.Skipf("host does not permit symlink fixture: %v", err)
	}
	if _, err := fingerprintNewWordPressDefault(path); err == nil {
		t.Fatal("symlink in a default theme was accepted")
	}
}

func TestNewWordPressDefaultsCleanupRunsOnlyOnInstallAndProtectsUserContent(t *testing.T) {
	php := os.Getenv("OLS_WP_DEFAULTS_TEST_PHP")
	if php == "" {
		var err error
		php, err = exec.LookPath("php")
		if err != nil {
			t.Skip("PHP CLI unavailable; set OLS_WP_DEFAULTS_TEST_PHP for filesystem hook tests")
		}
	}
	for _, state := range []string{"fresh", "child theme", "existing", "repeat", "modified theme", "additional custom file", "active plugin", "missing active theme", "multisite", "filesystem failure", "uploaded customized package", "legacy unverified package"} {
		t.Run(state, func(t *testing.T) {
			root := newWordPressDefaultsFixture(t)
			verified := state != "uploaded customized package" && state != "legacy unverified package"
			if state == "uploaded customized package" {
				// Modification precedes preparation: it must not become an
				// apparently official baseline merely because its slug matches.
				for _, name := range []string{"plugins/akismet/akismet.php", "themes/twentytwentythree/style.css"} {
					if err := os.WriteFile(filepath.Join(root, "wp-content", filepath.FromSlash(name)), []byte("customized-in-upload"), 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := prepareNewWordPressDefaults(root, verified); err != nil {
				t.Fatal(err)
			}
			configuration := map[string]interface{}{
				"root": filepath.ToSlash(root), "helper": filepath.ToSlash(filepath.Join(root, "wp-content", "mu-plugins", newWordPressDefaultsHelper)),
				"stylesheet": "twentytwentyfive", "template": "twentytwentyfive", "active_plugins": []string{}, "mode": state, "multisite": state == "multisite",
			}
			switch state {
			case "child theme":
				configuration["stylesheet"], configuration["template"] = "studio-child", "twentytwentyfour"
			case "modified theme":
				if err := os.WriteFile(filepath.Join(root, "wp-content", "themes", "twentytwentythree", "style.css"), []byte("customized-default"), 0644); err != nil {
					t.Fatal(err)
				}
			case "additional custom file":
				if err := os.WriteFile(filepath.Join(root, "wp-content", "themes", "twentytwentythree", "custom.php"), []byte("user code"), 0644); err != nil {
					t.Fatal(err)
				}
			case "active plugin":
				configuration["active_plugins"] = []string{"akismet/akismet.php"}
			case "missing active theme":
				configuration["stylesheet"], configuration["template"] = "", ""
			case "filesystem failure":
				// Windows enforces the read-only attribute even when the parent
				// directory is writable. Unix root may legitimately bypass it.
				if err := os.Chmod(filepath.Join(root, "wp-content", "plugins", "hello.php"), 0444); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "wp-content", "plugins", "hello.php"), 0644) })
			}
			input, err := json.Marshal(configuration)
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(php, filepath.Join("testdata", "wp_new_install_defaults_fixture.php"))
			command.Stdin = bytes.NewReader(input)
			var stderr bytes.Buffer
			command.Stderr = &stderr
			output, err := command.Output()
			if err != nil {
				t.Fatalf("real PHP helper failed: %v\n%s", err, stderr.String())
			}
			var result struct {
				Record struct {
					Status         string   `json:"status"`
					RemovedPlugins []string `json:"removed_plugins"`
					RemovedThemes  []string `json:"removed_themes"`
					RetainedThemes []string `json:"retained_themes"`
					Errors         []string `json:"errors"`
				} `json:"record"`
				Registered   []string `json:"registered"`
				HelperExists bool     `json:"helper_exists"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("PHP result invalid: %v\n%s", err, output)
			}
			if !reflect.DeepEqual(result.Registered, []string{"wp_install"}) {
				t.Fatalf("cleanup registered outside new installation: %v", result.Registered)
			}
			if state == "existing" {
				if !result.HelperExists || result.Record.Status != "" {
					t.Fatal("normal bootstrap of an existing/restored site performed cleanup")
				}
				for _, name := range []string{"plugins/hello.php", "plugins/akismet/akismet.php", "themes/twentytwentythree/style.css"} {
					if _, err := os.Stat(filepath.Join(root, "wp-content", filepath.FromSlash(name))); err != nil {
						t.Fatalf("existing content changed: %s", name)
					}
				}
			} else {
				if result.HelperExists {
					t.Fatal("one-shot helper remained after the install hook")
				}
				wantStatus := "completed"
				if !verified {
					wantStatus = "skipped"
					if len(result.Record.RemovedPlugins) != 0 || len(result.Record.RemovedThemes) != 0 || len(result.Record.Errors) == 0 {
						t.Fatalf("unverified package cleanup not skipped and recorded: %+v", result.Record)
					}
					for _, name := range []string{"plugins/akismet/akismet.php", "plugins/hello.php", "themes/twentytwentythree/style.css", "themes/twentytwentyfour/style.css", "themes/twentytwentyfive/style.css"} {
						if _, err := os.Stat(filepath.Join(root, "wp-content", filepath.FromSlash(name))); err != nil {
							t.Fatalf("unverified or uploaded package content was deleted: %s", name)
						}
					}
				}
				if state == "modified theme" || state == "additional custom file" || state == "active plugin" || state == "missing active theme" || state == "multisite" {
					wantStatus = "partial"
				}
				if state == "filesystem failure" {
					if _, err := os.Stat(filepath.Join(root, "wp-content", "plugins", "hello.php")); err == nil {
						wantStatus = "partial"
						if len(result.Record.Errors) == 0 {
							t.Fatal("filesystem deletion failure was not recorded")
						}
					}
				}
				if result.Record.Status != wantStatus {
					t.Fatalf("record status = %s, want %s: %v", result.Record.Status, wantStatus, result.Record.Errors)
				}
				if state == "fresh" || state == "repeat" {
					if !reflect.DeepEqual(result.Record.RemovedPlugins, []string{"akismet", "hello.php"}) || !reflect.DeepEqual(result.Record.RemovedThemes, []string{"twentytwentyfour", "twentytwentythree"}) {
						t.Fatalf("bundled defaults were not removed: %+v", result.Record)
					}
				}
				if state == "repeat" {
					content, err := os.ReadFile(filepath.Join(root, "wp-content", "plugins", "hello.php"))
					if err != nil || string(content) != "user-installed-again" {
						t.Fatal("repeated hook deleted newly installed user content")
					}
				}
				if state == "child theme" {
					for _, slug := range []string{"studio-child", "twentytwentyfour"} {
						if _, err := os.Stat(filepath.Join(root, "wp-content", "themes", slug, "style.css")); err != nil {
							t.Fatalf("active child or parent deleted: %s", slug)
						}
					}
				}
				if state == "modified theme" || state == "additional custom file" || state == "missing active theme" {
					if _, err := os.Stat(filepath.Join(root, "wp-content", "themes", "twentytwentythree", "style.css")); err != nil {
						t.Fatal("modified default or unverifiable active theme was deleted")
					}
				}
				if state == "active plugin" {
					if _, err := os.Stat(filepath.Join(root, "wp-content", "plugins", "akismet", "akismet.php")); err != nil {
						t.Fatal("active plugin was deleted")
					}
				}
			}
			for _, name := range []string{"plugins/litespeed-cache/litespeed-cache.php", "plugins/studio-custom/main.php", "themes/studio-child/style.css", "themes/twentytwentyfive-custom/style.css", "mu-plugins/ols-wpanel-login-log.php", "mu-plugins/ols-wpanel-lscache-activate.php"} {
				if _, err := os.Stat(filepath.Join(root, "wp-content", filepath.FromSlash(name))); err != nil {
					t.Fatalf("protected custom or panel content changed: %s", name)
				}
			}
		})
	}
}
