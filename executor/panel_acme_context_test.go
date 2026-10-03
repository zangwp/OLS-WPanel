package executor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExistingACMEContextRepairsMissingDirectoryWithoutRestart(t *testing.T) {
	paths := olsRuntimePaths{managed: filepath.Join(t.TempDir(), "sites.conf")}
	root, configPath := olsDefaultVHostPaths(paths)
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	content := "vhDomain                ols-wpanel.invalid\n" + panelACMEContext(root)
	if err := os.WriteFile(configPath, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	old := runOLSCommand
	t.Cleanup(func() { runOLSCommand = old })
	runOLSCommand = func(string, ...string) ([]byte, error) {
		t.Fatal("directory-only repair must not restart OLS")
		return nil, nil
	}
	for i := 0; i < 2; i++ {
		if err := ensurePanelACMEContextAt(paths); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{filepath.Join(root, ".well-known"), filepath.Join(root, ".well-known", "acme-challenge")} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			t.Fatalf("missing challenge directory %s: %v", dir, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0755 {
			t.Fatalf("permissions: %v", info.Mode())
		}
	}
	got, _ := os.ReadFile(configPath)
	if string(got) != content {
		t.Fatal("existing config changed")
	}
}

func TestACMEContextCreatesDirectoryBeforeValidationAndRollsBack(t *testing.T) {
	paths := olsRuntimePaths{managed: filepath.Join(t.TempDir(), "sites.conf"), binary: "ols-test"}
	root, path := olsDefaultVHostPaths(paths)
	if err := os.Mkdir(root, 0755); err != nil {
		t.Fatal(err)
	}
	content := "vhDomain                ols-wpanel.invalid\ndocRoot " + filepath.ToSlash(root) + "/\n"
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	old := runOLSCommand
	t.Cleanup(func() { runOLSCommand = old })
	validated := false
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name != "ols-test" {
			t.Fatal("must not restart invalid config")
		}
		if _, err := os.Stat(filepath.Join(root, ".well-known", "acme-challenge")); err != nil {
			t.Fatal(err)
		}
		validated = true
		return []byte("unrelated validation error"), errors.New("invalid config")
	}
	if err := ensurePanelACMEContextAt(paths); err == nil {
		t.Fatal("validation failure ignored")
	}
	if !validated {
		t.Fatal("config was not validated")
	}
	got, _ := os.ReadFile(path)
	if string(got) != content {
		t.Fatal("failed migration did not roll back")
	}
}

func TestACMEChallengeDirectoryPreservesFilesAndRepairsMode(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".well-known", "acme-challenge")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "existing-token")
	if err := os.WriteFile(file, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ensurePanelACMEChallengeDirectory(root); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(file)
	if string(got) != "keep" {
		t.Fatal("challenge contents changed")
	}
	info, _ := os.Stat(dir)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0755 {
		t.Fatal("restrictive mode was not repaired")
	}
}

func TestACMEChallengeDirectoryRejectsFilesAndSymlinks(t *testing.T) {
	for _, kind := range []string{"file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, ".well-known")
			if kind == "file" {
				if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				outside := t.TempDir()
				if err := os.Symlink(outside, target); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			if err := ensurePanelACMEChallengeDirectory(root); err == nil {
				t.Fatal("unsafe path accepted")
			}
			if kind == "file" {
				got, _ := os.ReadFile(target)
				if string(got) != "keep" {
					t.Fatal("file overwritten")
				}
			}
		})
	}
}

func TestACMEContextDoesNotTouchCustomConfig(t *testing.T) {
	paths := olsRuntimePaths{managed: filepath.Join(t.TempDir(), "sites.conf")}
	root, path := olsDefaultVHostPaths(paths)
	content := "vhDomain custom.invalid\n" + panelACMEContext(root)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ensurePanelACMEContextAt(paths); err == nil || !strings.Contains(err.Error(), "custom") {
		t.Fatalf("custom config: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("custom config directories modified")
	}
}
