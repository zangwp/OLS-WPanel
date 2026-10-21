//go:build linux

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func liteSpeedCachePublishFixture(t *testing.T) (archive, digest, webRoot, plugins string) {
	t.Helper()
	archive = writeComponentZIP(t, []componentZIPEntry{
		{name: "litespeed-cache/litespeed-cache.php", body: pluginHeader("LiteSpeed Cache", "7.9.2")},
		{name: "litespeed-cache/assets/cache.js", body: "fixture plugin asset"},
	})
	report, err := InspectZIP(t.Context(), archive, WordPressFullZIPPolicy())
	if err != nil {
		t.Fatal(err)
	}
	webRoot = t.TempDir()
	plugins = filepath.Join(webRoot, "wp-content", "plugins")
	if err := os.MkdirAll(plugins, 0755); err != nil {
		t.Fatal(err)
	}
	return archive, report.SHA256, webRoot, plugins
}

func stubLiteSpeedCachePublishChown(t *testing.T, hook func(string) error) *atomic.Int32 {
	t.Helper()
	previous := shellExec
	t.Cleanup(func() { shellExec = previous })
	calls := new(atomic.Int32)
	shellExec = func(binary string, args ...string) (string, error) {
		if binary != "chown" || len(args) != 5 || args[0] != "-h" || args[1] != "-R" || args[2] != "--" || args[3] != "wp_test:wp_test" ||
			!strings.HasPrefix(args[4], fmt.Sprintf("/proc/%d/fd/", os.Getpid())) || !strings.HasSuffix(args[4], "/litespeed-cache") {
			return "", fmt.Errorf("unexpected publication command: %s %v", binary, args)
		}
		calls.Add(1)
		if hook != nil {
			return "", hook(args[4])
		}
		return "", nil
	}
	return calls
}

func assertLiteSpeedCachePublicationStageClean(t *testing.T, plugins string) {
	t.Helper()
	entries, err := os.ReadDir(plugins)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".ols-wpanel-lscache-") {
			t.Fatalf("publication stage was retained: %s", entry.Name())
		}
	}
}

func TestPublishLiteSpeedCachePackageInstallsOnlyNewNormalizedFiles(t *testing.T) {
	archive, digest, webRoot, plugins := liteSpeedCachePublishFixture(t)
	if err := os.Chmod(plugins, 0701); err != nil {
		t.Fatal(err)
	}
	calls := stubLiteSpeedCachePublishChown(t, func(staged string) error {
		parent, err := os.Stat(filepath.Dir(staged))
		if err != nil || parent.Mode().Perm() != 0700 {
			return fmt.Errorf("publication stage must remain private: %v", err)
		}
		if _, err := os.Stat(filepath.Join(plugins, "litespeed-cache")); !os.IsNotExist(err) {
			return fmt.Errorf("plugin became live before ownership was prepared: %v", err)
		}
		// Exercise the actual child-process /proc path and GNU chown options
		// without requiring root or a pre-existing website account.
		owner := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
		if output, err := exec.Command("chown", "-h", "-R", "--", owner, staged).CombinedOutput(); err != nil {
			return fmt.Errorf("held stage descriptor is inaccessible to chown: %w: %s", err, output)
		}
		return nil
	})
	if err := publishLiteSpeedCachePackage(t.Context(), archive, digest, webRoot, "wp_test"); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("ownership calls = %d, want 1", calls.Load())
	}
	for relative, mode := range map[string]os.FileMode{
		"litespeed-cache": 0755, "litespeed-cache/assets": 0755,
		"litespeed-cache/litespeed-cache.php": 0644, "litespeed-cache/assets/cache.js": 0644,
	} {
		info, err := os.Stat(filepath.Join(plugins, relative))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s: mode should be %o, info=%v err=%v", relative, mode, info, err)
		}
	}
	parent, err := os.Stat(plugins)
	if err != nil || parent.Mode().Perm() != 0701 {
		t.Fatalf("existing plugin parent permissions changed: %v %v", parent, err)
	}
	assertLiteSpeedCachePublicationStageClean(t, plugins)
}

func TestPublishLiteSpeedCachePackageRejectsChangedArchive(t *testing.T) {
	archive, _, webRoot, plugins := liteSpeedCachePublishFixture(t)
	calls := stubLiteSpeedCachePublishChown(t, nil)
	err := publishLiteSpeedCachePackage(t.Context(), archive, strings.Repeat("0", 64), webRoot, "wp_test")
	if ArchiveErrorCode(err) != "archive_digest_mismatch" {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
	entries, err := os.ReadDir(plugins)
	if err != nil || len(entries) != 0 || calls.Load() != 0 {
		t.Fatalf("changed archive wrote plugin files: entries=%v calls=%d err=%v", entries, calls.Load(), err)
	}
}

func TestPublishLiteSpeedCachePackagePreservesExistingCompleteAndPartialDirectories(t *testing.T) {
	for _, complete := range []bool{true, false} {
		t.Run(fmt.Sprintf("complete=%v", complete), func(t *testing.T) {
			archive, digest, webRoot, plugins := liteSpeedCachePublishFixture(t)
			target := filepath.Join(plugins, "litespeed-cache")
			if err := os.Mkdir(target, 0700); err != nil {
				t.Fatal(err)
			}
			name := "keep.txt"
			if complete {
				name = "litespeed-cache.php"
			}
			path := filepath.Join(target, name)
			if err := os.WriteFile(path, []byte("original user file"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := stubLiteSpeedCachePublishChown(t, nil)
			if err := publishLiteSpeedCachePackage(t.Context(), archive, digest, webRoot, "wp_test"); !errors.Is(err, os.ErrExist) {
				t.Fatalf("expected existing directory refusal, got %v", err)
			}
			body, err := os.ReadFile(path)
			if err != nil || string(body) != "original user file" || calls.Load() != 0 {
				t.Fatalf("existing plugin was modified: content=%q calls=%d err=%v", body, calls.Load(), err)
			}
			info, err := os.Stat(target)
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatalf("existing plugin permissions changed: %v %v", info, err)
			}
			assertLiteSpeedCachePublicationStageClean(t, plugins)
		})
	}
}

func TestPublishLiteSpeedCachePackageRejectsSymbolicLinksInEverySitePath(t *testing.T) {
	for _, component := range []string{"root", "wp-content", "plugins", "litespeed-cache"} {
		t.Run(component, func(t *testing.T) {
			archive, digest, webRoot, plugins := liteSpeedCachePublishFixture(t)
			outside := t.TempDir()
			sentinel := filepath.Join(outside, "keep.txt")
			if err := os.WriteFile(sentinel, []byte("outside"), 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(plugins, "litespeed-cache")
			if component == "root" {
				link = filepath.Join(t.TempDir(), "site-link")
				webRoot = link
			} else if component == "wp-content" || component == "plugins" {
				link = filepath.Join(webRoot, "wp-content")
				if component == "plugins" {
					link = plugins
				}
				if err := os.RemoveAll(link); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			calls := stubLiteSpeedCachePublishChown(t, nil)
			if err := publishLiteSpeedCachePackage(t.Context(), archive, digest, webRoot, "wp_test"); err == nil {
				t.Fatal("accepted a symbolic-link site path")
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 1 || entries[0].Name() != "keep.txt" || calls.Load() != 0 {
				t.Fatalf("symlink target changed: entries=%v calls=%d err=%v", entries, calls.Load(), err)
			}
		})
	}
}

func TestPublishLiteSpeedCachePackageRejectsParentSwapDuringOwnership(t *testing.T) {
	archive, digest, webRoot, plugins := liteSpeedCachePublishFixture(t)
	oldPlugins := plugins + ".moved"
	outside := t.TempDir()
	stubLiteSpeedCachePublishChown(t, func(_ string) error {
		if err := os.Rename(plugins, oldPlugins); err != nil {
			return err
		}
		return os.Symlink(outside, plugins)
	})
	if err := publishLiteSpeedCachePackage(t.Context(), archive, digest, webRoot, "wp_test"); err == nil || !strings.Contains(err.Error(), "changed during installation") {
		t.Fatalf("expected changed-parent refusal, got %v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatalf("replacement parent was written: entries=%v err=%v", entries, err)
	}
	assertLiteSpeedCachePublicationStageClean(t, oldPlugins)
}

func TestPublishLiteSpeedCachePackageCancellationBeforePublicationCleansStage(t *testing.T) {
	for _, timing := range []string{"before", "after ownership"} {
		t.Run(timing, func(t *testing.T) {
			archive, digest, webRoot, plugins := liteSpeedCachePublishFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stubLiteSpeedCachePublishChown(t, func(_ string) error { cancel(); return nil })
			if timing == "before" {
				cancel()
			}
			if err := publishLiteSpeedCachePackage(ctx, archive, digest, webRoot, "wp_test"); !errors.Is(err, context.Canceled) {
				t.Fatalf("expected cancellation, got %v", err)
			}
			entries, err := os.ReadDir(plugins)
			if err != nil || len(entries) != 0 {
				t.Fatalf("canceled publication wrote live files: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestPublishLiteSpeedCachePackageConcurrentPublicationNeverOverwrites(t *testing.T) {
	archive, digest, webRoot, plugins := liteSpeedCachePublishFixture(t)
	const workers = 4
	var arrived atomic.Int32
	ready := make(chan struct{})
	stubLiteSpeedCachePublishChown(t, func(_ string) error {
		if arrived.Add(1) == workers {
			close(ready)
		}
		select {
		case <-ready:
			return nil
		case <-time.After(10 * time.Second):
			return errors.New("competing publications did not reach ownership preparation")
		}
	})
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for range workers {
		wg.Go(func() { results <- publishLiteSpeedCachePackage(t.Context(), archive, digest, webRoot, "wp_test") })
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, os.ErrExist) {
			t.Fatalf("unexpected competing publication error: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("successful publications = %d, want exactly one", success)
	}
	assertLiteSpeedCachePublicationStageClean(t, plugins)
}

func TestPublishLiteSpeedCachePackagePreservesDirectoryCreatedAtPublication(t *testing.T) {
	archive, digest, webRoot, plugins := liteSpeedCachePublishFixture(t)
	target := filepath.Join(plugins, "litespeed-cache")
	stubLiteSpeedCachePublishChown(t, func(_ string) error { return os.Mkdir(target, 0700) })
	if err := publishLiteSpeedCachePackage(t.Context(), archive, digest, webRoot, "wp_test"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected no-replace failure, got %v", err)
	}
	entries, err := os.ReadDir(target)
	info, statErr := os.Stat(target)
	if err != nil || statErr != nil || len(entries) != 0 || info.Mode().Perm() != 0700 {
		t.Fatalf("racing directory was modified: entries=%v info=%v err=%v/%v", entries, info, err, statErr)
	}
	assertLiteSpeedCachePublicationStageClean(t, plugins)
}

func TestPublishLiteSpeedCachePackagePreservesSymlinkCreatedAtPublication(t *testing.T) {
	archive, digest, webRoot, plugins := liteSpeedCachePublishFixture(t)
	outside := t.TempDir()
	target := filepath.Join(plugins, "litespeed-cache")
	stubLiteSpeedCachePublishChown(t, func(_ string) error { return os.Symlink(outside, target) })
	if err := publishLiteSpeedCachePackage(t.Context(), archive, digest, webRoot, "wp_test"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected no-replace failure, got %v", err)
	}
	actual, err := os.Readlink(target)
	entries, readErr := os.ReadDir(outside)
	if err != nil || actual != outside || readErr != nil || len(entries) != 0 {
		t.Fatalf("racing symlink was modified: target=%q entries=%v err=%v/%v", actual, entries, err, readErr)
	}
	assertLiteSpeedCachePublicationStageClean(t, plugins)
}

func TestPublishLiteSpeedCachePackageOwnershipFailureNeverPublishes(t *testing.T) {
	archive, digest, webRoot, plugins := liteSpeedCachePublishFixture(t)
	stubLiteSpeedCachePublishChown(t, func(_ string) error { return errors.New("injected ownership failure") })
	if err := publishLiteSpeedCachePackage(t.Context(), archive, digest, webRoot, "wp_test"); err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("expected ownership failure, got %v", err)
	}
	entries, err := os.ReadDir(plugins)
	if err != nil || len(entries) != 0 {
		t.Fatalf("ownership failure wrote live files: entries=%v err=%v", entries, err)
	}
}
