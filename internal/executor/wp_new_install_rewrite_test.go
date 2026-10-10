package executor

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestNewWordPressRewriteIsReadyBeforeFirstVHostLoad(t *testing.T) {
	root := t.TempDir()
	if err := prepareNewWordPressRewrite(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".htaccess")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, directive := range []string{
		"<IfModule mod_rewrite.c>\nRewriteEngine On\n",
		"[E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]",
		"RewriteRule ^index\\.php$ - [L]\n",
		"RewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n",
	} {
		if !strings.Contains(content, directive) {
			t.Fatalf("first-load rules missing %q", directive)
		}
	}
	if info, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0644) {
		t.Fatalf("first-load rules unavailable or unreadable: %v", err)
	}
}

func TestNewWordPressRewritePreservesExistingRulesAndMode(t *testing.T) {
	for _, content := range []string{"", "# Package custom rules\nRewriteRule ^special$ /custom.php [L]\n"} {
		t.Run(content, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, ".htaccess")
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := prepareNewWordPressRewrite(root); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != content {
				t.Fatalf("existing rules replaced: %q, %v", data, err)
			}
			after, err := os.Stat(path)
			if err != nil || after.Mode() != before.Mode() || after.ModTime() != before.ModTime() {
				t.Fatal("existing file metadata changed")
			}
		})
	}
}

func TestNewWordPressRewriteCreationIsExclusive(t *testing.T) {
	root := t.TempDir()
	var wait sync.WaitGroup
	for range 16 {
		wait.Go(func() {
			if err := prepareNewWordPressRewrite(root); err != nil {
				t.Error(err)
			}
		})
	}
	wait.Wait()
	data, err := os.ReadFile(filepath.Join(root, ".htaccess"))
	if err != nil || string(data) != newWordPressRootRewrite {
		t.Fatalf("concurrent preparations left incomplete rules: %q, %v", data, err)
	}
}

func TestNewWordPressRewriteRejectsUnsafeRoot(t *testing.T) {
	previousConfig := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previousConfig })
	managedRoot := t.TempDir()
	config.AppConfig = &config.Config{Paths: config.PathsConfig{WWWRoot: managedRoot}}
	if err := prepareNewWordPressRewrite(t.TempDir()); err == nil {
		t.Fatal("rules were created outside the managed website tree")
	}
	if _, err := os.Lstat(filepath.Join(managedRoot, ".htaccess")); !os.IsNotExist(err) {
		t.Fatal("unsafe request left unexpected rules")
	}
}

func TestNewWordPressRewriteRejectsSymlink(t *testing.T) {
	previousConfig := config.AppConfig
	t.Cleanup(func() { config.AppConfig = previousConfig })
	managedRoot := t.TempDir()
	config.AppConfig = &config.Config{Paths: config.PathsConfig{WWWRoot: managedRoot}}
	root := filepath.Join(managedRoot, "site")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(managedRoot, "external-rules")
	if err := os.WriteFile(outside, []byte("preserve me"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".htaccess")); err != nil {
		t.Skipf("host cannot create symlink: %v", err)
	}
	if err := prepareNewWordPressRewrite(root); err == nil {
		t.Fatal("symlink target accepted")
	}
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "preserve me" {
		t.Fatal("external symlink target changed")
	}
}
