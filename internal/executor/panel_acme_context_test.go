package executor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestExistingACMEContextRepairsMissingDirectoryWithoutRestart(t *testing.T) {
	base := t.TempDir()
	paths := olsRuntimePaths{root: base, managed: filepath.Join(base, "sites.conf")}
	root, configPath := olsDefaultVHostPaths(paths)
	if err := os.MkdirAll(root, 0755); err != nil {
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
	base := t.TempDir()
	paths := olsRuntimePaths{root: base, managed: filepath.Join(base, "sites.conf"), binary: "ols-test"}
	root, path := olsDefaultVHostPaths(paths)
	if err := os.MkdirAll(root, 0755); err != nil {
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
	base := t.TempDir()
	paths := olsRuntimePaths{root: base, managed: filepath.Join(base, "sites.conf")}
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

func panelACMEMigrationFixture(t *testing.T) (olsRuntimePaths, string, string) {
	t.Helper()
	base := t.TempDir()
	paths := olsRuntimePaths{root: base, managed: filepath.Join(base, "conf", "ols-wpanel", "sites.conf"), binary: "ols-test"}
	legacyRoot := filepath.Join(filepath.Dir(paths.managed), "default-vhost-root")
	if err := os.MkdirAll(legacyRoot, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(paths.managed), 0750); err != nil {
		t.Fatal(err)
	}
	_, path := olsDefaultVHostPaths(paths)
	content := fmt.Sprintf("docRoot                 %s/\nvhDomain                ols-wpanel.invalid\ncontext / {\n  location               %s/\n  allowBrowse            0\n}\n", filepath.ToSlash(legacyRoot), filepath.ToSlash(legacyRoot)) + panelACMEContext(legacyRoot)
	registry := fmt.Sprintf("# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.\nvirtualHost olsw_default {\n  vhRoot                 %s/\n  restrained             1\n  enableScript           0\n  configFile             %s\n}\nvirtualHost untouched {\n  vhRoot /keep/site/\n}\nlistener OLSWPanelHTTP {\n  map untouched www.example.com\n  map olsw_default *\n}\n", filepath.ToSlash(legacyRoot), filepath.ToSlash(path))
	for name, value := range map[string]string{path: content, paths.managed: registry} {
		if err := os.WriteFile(name, []byte(value), 0640); err != nil {
			t.Fatal(err)
		}
	}
	return paths, content, registry
}

func TestPanelACMELegacyPrivateRootMigratesWithoutOpeningConfigDirectory(t *testing.T) {
	paths, _, registry := panelACMEMigrationFixture(t)
	legacy := filepath.Join(filepath.Dir(paths.managed), "default-vhost-root")
	if err := os.WriteFile(filepath.Join(legacy, "keep-token"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}
	oldRun := runOLSCommand
	t.Cleanup(func() { runOLSCommand = oldRun })
	restarts := 0
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "restart" {
			restarts++
		}
		return nil, nil
	}
	for i := 0; i < 2; i++ {
		if err := ensurePanelACMEContextAt(paths); err != nil {
			t.Fatal(err)
		}
	}
	root, path := olsDefaultVHostPaths(paths)
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), panelACMEContext(root)) || !strings.Contains(string(got), "allowBrowse            0") || strings.Contains(string(got), filepath.ToSlash(legacy)) {
		t.Fatalf("unsafe migration: %s", got)
	}
	gotRegistry, _ := os.ReadFile(paths.managed)
	expectedRegistry := strings.Replace(registry, filepath.ToSlash(legacy)+"/", filepath.ToSlash(root)+"/", 1)
	if string(gotRegistry) != expectedRegistry || restarts != 1 {
		t.Fatalf("registry/map changed or non-idempotent restart: %s, restarts=%d", gotRegistry, restarts)
	}
	for _, path := range []string{filepath.Dir(paths.managed), paths.managed} {
		info, _ := os.Stat(path)
		want := os.FileMode(0640)
		if info.IsDir() {
			want = 0750
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != want {
			t.Fatalf("private configuration mode changed: %s %v", path, info.Mode())
		}
	}
	if got, _ := os.ReadFile(filepath.Join(legacy, "keep-token")); string(got) != "keep" {
		t.Fatal("legacy root data deleted")
	}
	if info, err := os.Stat(filepath.Join(root, ".well-known", "acme-challenge")); err != nil || !info.IsDir() {
		t.Fatalf("public challenge unavailable: %v", err)
	}
}

func TestPanelACMERootMigrationRestoresBothFilesAfterFailedReload(t *testing.T) {
	paths, content, registry := panelACMEMigrationFixture(t)
	oldRun := runOLSCommand
	t.Cleanup(func() { runOLSCommand = oldRun })
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name == "ols-test" {
			return []byte("invalid"), errors.New("invalid")
		}
		t.Fatal("invalid config must not restart")
		return nil, nil
	}
	if err := ensurePanelACMEContextAt(paths); err == nil {
		t.Fatal("validation failure ignored")
	}
	_, path := olsDefaultVHostPaths(paths)
	for name, want := range map[string]string{path: content, paths.managed: registry} {
		got, _ := os.ReadFile(name)
		if string(got) != want {
			t.Fatalf("rollback failed for %s", name)
		}
	}
}

func TestPanelACMERootMigrationRestoresBeforeRecoveringFailedRestart(t *testing.T) {
	paths, content, registry := panelACMEMigrationFixture(t)
	_, path := olsDefaultVHostPaths(paths)
	oldRun := runOLSCommand
	t.Cleanup(func() { runOLSCommand = oldRun })
	restarts := 0
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" && len(args) > 0 && args[0] == "restart" {
			restarts++
			if restarts == 1 {
				return []byte("failed"), errors.New("restart failed")
			}
			for name, want := range map[string]string{path: content, paths.managed: registry} {
				got, _ := os.ReadFile(name)
				if string(got) != want {
					t.Fatalf("recovery restarted partial rollback for %s", name)
				}
			}
		}
		return nil, nil
	}
	if err := ensurePanelACMEContextAt(paths); err == nil || restarts != 2 {
		t.Fatalf("restart failure ignored: %v, restarts=%d", err, restarts)
	}
}

func TestPanelACMERootMigrationStillRestoresRegistryIfDefaultRollbackFails(t *testing.T) {
	paths, _, registry := panelACMEMigrationFixture(t)
	_, path := olsDefaultVHostPaths(paths)
	oldRun := runOLSCommand
	t.Cleanup(func() { runOLSCommand = oldRun })
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name != "ols-test" {
			t.Fatal("invalid configuration must not restart")
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
		return []byte("invalid"), errors.New("validation failed")
	}
	if err := ensurePanelACMEContextAt(paths); err == nil || !strings.Contains(err.Error(), "default-host rollback failed") {
		t.Fatalf("rollback failure hidden: %v", err)
	}
	if got, _ := os.ReadFile(paths.managed); string(got) != registry {
		t.Fatal("registry left at migrated root after other rollback failed")
	}
}

func TestPanelACMECustomChallengeContextIsRejectedBeforeRegistryWrite(t *testing.T) {
	paths, content, registry := panelACMEMigrationFixture(t)
	_, path := olsDefaultVHostPaths(paths)
	content = strings.Replace(content, "allowBrowse            1", "allowBrowse            0", 1)
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	oldRun := runOLSCommand
	t.Cleanup(func() { runOLSCommand = oldRun })
	runOLSCommand = func(string, ...string) ([]byte, error) {
		t.Fatal("custom configuration must not restart")
		return nil, nil
	}
	if err := ensurePanelACMEContextAt(paths); err == nil || !strings.Contains(err.Error(), "custom ACME") {
		t.Fatalf("custom context accepted: %v", err)
	}
	for name, want := range map[string]string{path: content, paths.managed: registry} {
		got, _ := os.ReadFile(name)
		if string(got) != want {
			t.Fatalf("custom-context refusal changed %s", name)
		}
	}
}

func TestPanelACMEPublicRootRejectsFileWithoutChangingIt(t *testing.T) {
	base := t.TempDir()
	paths := olsRuntimePaths{root: base, managed: filepath.Join(base, "sites.conf")}
	path := filepath.Join(base, "html")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensurePanelACMEPublicRoot(paths); err == nil {
		t.Fatal("replaced public-root file")
	}
	if got, _ := os.ReadFile(path); string(got) != "keep" {
		t.Fatal("public-root file overwritten")
	}
}

func TestPanelACMEPublicRootRejectsReplacementSymlink(t *testing.T) {
	base := t.TempDir()
	paths := olsRuntimePaths{root: base, managed: filepath.Join(base, "sites.conf")}
	if err := os.Symlink(t.TempDir(), filepath.Join(base, "html")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := ensurePanelACMEPublicRoot(paths); err == nil {
		t.Fatal("followed replacement public-root symlink")
	}
}

func TestPanelACMERootReusesMappedWebsiteWithoutEditingItsConfiguration(t *testing.T) {
	base := t.TempDir()
	available := filepath.Join(base, "conf", "sites-available")
	if err := os.MkdirAll(available, 0750); err != nil {
		t.Fatal(err)
	}
	paths := olsRuntimePaths{root: base, managed: filepath.Join(base, "registry.conf")}
	path := filepath.Join(available, "site.conf")
	root := filepath.Join(base, "website")
	content := fmt.Sprintf("# OLS-WPanel-Format: 1\n# OLS-WPanel-VHost: olsw_site\n# OLS-WPanel-Domains: www.example.com,panel.example.com\n# OLS-WPanel-VHRoot: %s\nrewrite {\n  enable 1\n}\n", root)
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	registry := fmt.Sprintf("# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.\nvirtualHost olsw_site {\n  configFile %s\n}\nlistener OLSWPanelHTTP {\n  map olsw_site www.example.com,panel.example.com\n  map olsw_default *\n}\n", filepath.ToSlash(path))
	if err := os.WriteFile(paths.managed, []byte(registry), 0640); err != nil {
		t.Fatal(err)
	}
	oldCfg := config.AppConfig
	config.AppConfig = nil
	t.Cleanup(func() { config.AppConfig = oldCfg })
	got, err := panelACMERootAt(paths, "panel.example.com")
	if err != nil || got != root {
		t.Fatalf("mapped root: %s %v", got, err)
	}
	if got, _ := os.ReadFile(path); string(got) != content {
		t.Fatal("website configuration changed")
	}
	if got, _ := os.ReadFile(paths.managed); string(got) != registry {
		t.Fatal("HTTP mapping changed")
	}
}
