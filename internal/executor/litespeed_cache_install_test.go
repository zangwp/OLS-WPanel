package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiteSpeedCacheInstallPreservesExistingPluginDirectories(t *testing.T) {
	for _, complete := range []bool{true, false} {
		t.Run(map[bool]string{true: "complete", false: "incomplete"}[complete], func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "wp-content", "plugins", "litespeed-cache")
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			name := "custom-settings.json"
			if complete {
				name = "litespeed-cache.php"
			}
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("existing-plugin"), 0644); err != nil {
				t.Fatal(err)
			}
			activated := false
			service := liteSpeedCacheInstallService{activate: func(_, _ string) error { activated = true; return nil }}
			// Nil network/runtime/publisher dependencies also prove that an
			// existing directory never reaches download or replacement.
			installed, err := service.ensure(t.Context(), root, "site-user", "8.3")
			if installed || (err == nil) != complete || activated != complete {
				t.Fatalf("installed=%t activated=%t error=%v", installed, activated, err)
			}
			body, err := os.ReadFile(path)
			if err != nil || string(body) != "existing-plugin" {
				t.Fatalf("existing plugin changed: %q %v", body, err)
			}
		})
	}
}

func TestLiteSpeedCacheInstallUsesSiteRuntimeAndCleansVerifiedPackage(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(t.TempDir(), "verified.zip")
	if err := os.WriteFile(path, []byte("verified-package"), 0600); err != nil {
		t.Fatal(err)
	}
	var order []string
	service := liteSpeedCacheInstallService{
		versions: func(_ context.Context, gotRoot, branch string) (string, string, error) {
			if gotRoot != root || branch != "8.3" {
				t.Fatalf("wrong site/runtime: %s %s", gotRoot, branch)
			}
			order = append(order, "versions")
			return "6.9.4", "8.3.27", nil
		},
		acquire: func(_ context.Context, wp, php string) (liteSpeedCachePackage, error) {
			if wp != "6.9.4" || php != "8.3.27" {
				t.Fatalf("wrong compatibility: %s %s", wp, php)
			}
			order = append(order, "acquire")
			return liteSpeedCachePackage{Path: path, Version: "7.9.2", SHA256: "verified-digest"}, nil
		},
		publish: func(_ context.Context, gotPath, digest, gotRoot, user string) error {
			if gotPath != path || digest != "verified-digest" || gotRoot != root || user != "site-user" {
				t.Fatal("wrong publication arguments")
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatal(err)
			}
			order = append(order, "publish")
			return nil
		},
		activate: func(_, _ string) error { order = append(order, "activate"); return nil },
	}
	installed, err := service.ensure(t.Context(), root, "site-user", "8.3")
	if err != nil || !installed || strings.Join(order, ",") != "versions,acquire,publish,activate" {
		t.Fatalf("installed=%t error=%v order=%v", installed, err, order)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("temporary package retained: %v", err)
	}
}

func TestLiteSpeedCacheInstallStopsOnFailureAndCancellation(t *testing.T) {
	for _, cancelDownload := range []bool{false, true} {
		t.Run(map[bool]string{false: "download failure", true: "cancelled after download"}[cancelDownload], func(t *testing.T) {
			root := t.TempDir()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			path := filepath.Join(t.TempDir(), "verified.zip")
			service := liteSpeedCacheInstallService{
				versions: func(context.Context, string, string) (string, string, error) { return "6.9", "8.3.27", nil },
				acquire: func(context.Context, string, string) (liteSpeedCachePackage, error) {
					if !cancelDownload {
						return liteSpeedCachePackage{}, errors.New("no verified package")
					}
					if err := os.WriteFile(path, []byte("verified"), 0600); err != nil {
						t.Fatal(err)
					}
					cancel()
					return liteSpeedCachePackage{Path: path}, nil
				},
			}
			installed, err := service.ensure(ctx, root, "site-user", "8.3")
			if installed || err == nil {
				t.Fatalf("installed=%t error=%v", installed, err)
			}
			if cancelDownload && !errors.Is(err, context.Canceled) {
				t.Fatalf("unexpected cancellation: %v", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("temporary archive retained: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, "wp-content")); !os.IsNotExist(err) {
				t.Fatalf("failed install modified site: %v", err)
			}
		})
	}
}

func TestLiteSpeedCacheInstallUsesLegacySitePHPBranch(t *testing.T) {
	var selected string
	service := liteSpeedCacheInstallService{
		versions: func(_ context.Context, _, branch string) (string, string, error) {
			selected = branch
			return "", "", errors.New("stop before network")
		},
	}
	_, err := service.ensure(t.Context(), t.TempDir(), "site-user", "")
	if err == nil || selected != "8.3" {
		t.Fatalf("legacy site used PHP branch %q, error=%v", selected, err)
	}
}
