package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestOPcacheClearMarksDetachedWorkersBeforeRestartingOLS(t *testing.T) {
	var operations []string
	paths := olsRuntimePaths{root: "/configured/ols", binary: "/configured/ols/bin/openlitespeed"}
	run := func(_ context.Context, command string, args ...string) ([]byte, error) {
		operations = append(operations, command+" "+strings.Join(args, " "))
		return nil, nil
	}
	mark := func(root string) error {
		operations = append(operations, "mark "+root)
		return nil
	}
	if err := requestOPcacheClear(context.Background(), paths, run, mark); err != nil {
		t.Fatal(err)
	}
	want := []string{"/configured/ols/bin/openlitespeed -t", "mark /configured/ols", "systemctl restart lshttpd"}
	if !reflect.DeepEqual(operations, want) {
		t.Fatalf("operations=%v, want %v", operations, want)
	}
}

func TestOPcacheClearStopsAtValidationOrMarkerFailure(t *testing.T) {
	for _, failure := range []string{"validation", "marker", "restart"} {
		t.Run(failure, func(t *testing.T) {
			var commands, marks int
			run := func(_ context.Context, _ string, _ ...string) ([]byte, error) {
				commands++
				if (commands == 1 && failure == "validation") || (commands == 2 && failure == "restart") {
					return []byte("fixture failure"), errors.New("failed")
				}
				return nil, nil
			}
			mark := func(string) error {
				marks++
				if failure == "marker" {
					return errors.New("marker unavailable")
				}
				return nil
			}
			err := requestOPcacheClear(context.Background(), olsRuntimePaths{}, run, mark)
			if err == nil {
				t.Fatal("failure was reported as a successful cache clear")
			}
			if failure == "validation" && (commands != 1 || marks != 0) {
				t.Fatalf("invalid configuration caused mutation: commands=%d marks=%d", commands, marks)
			}
			if failure == "marker" && (commands != 1 || marks != 1) {
				t.Fatalf("marker failure restarted OLS: commands=%d marks=%d", commands, marks)
			}
			if failure == "restart" && !strings.Contains(err.Error(), "标记已写入") {
				t.Fatalf("restart failure hid the pending PHP restart: %v", err)
			}
		})
	}
}

func TestOPcacheClearCanceledAfterValidationDoesNotWriteMarker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	marked := false
	run := func(context.Context, string, ...string) ([]byte, error) {
		cancel()
		return nil, nil
	}
	err := requestOPcacheClear(ctx, olsRuntimePaths{}, run, func(string) error { marked = true; return nil })
	if !errors.Is(err, context.Canceled) || marked {
		t.Fatalf("cancellation did not stop before mutation: err=%v marked=%v", err, marked)
	}
}

func TestOPcacheRestartMarkerReplacesOnlyExistingPrivateMarker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("anchored Root.Rename is unavailable in the Windows sandbox; OLS runs on Linux")
	}
	root := t.TempDir()
	directory := filepath.Join(root, "admin", "tmp")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(directory, ".lsphp_restart.txt")
	if err := os.WriteFile(marker, []byte("old marker"), 0644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(marker, old, old); err != nil {
		t.Fatal(err)
	}
	if err := writeOPcacheRestartMarker(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(marker)
	if err != nil || !info.Mode().IsRegular() || !info.ModTime().After(old) {
		t.Fatalf("restart marker not refreshed: info=%v err=%v", info, err)
	}
	if data, err := os.ReadFile(marker); err != nil || len(data) != 0 {
		t.Fatalf("replacement marker=%q err=%v", data, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != ".lsphp_restart.txt" {
		t.Fatalf("temporary marker files leaked: %v %v", entries, err)
	}
}

func TestOPcacheRestartMarkerDoesNotCreateMissingAdminDirectory(t *testing.T) {
	root := t.TempDir()
	if err := writeOPcacheRestartMarker(root); err == nil {
		t.Fatal("missing OLS admin directory treated as a queued PHP restart")
	}
	if _, err := os.Stat(filepath.Join(root, "admin")); !os.IsNotExist(err) {
		t.Fatalf("missing admin directory was created: %v", err)
	}
}

func TestOPcacheRestartMarkerCreatesFixedServerMarker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("anchored Root.Rename is unavailable in the Windows sandbox; OLS runs on Linux")
	}
	root := t.TempDir()
	directory := filepath.Join(root, "admin", "tmp")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := writeOPcacheRestartMarker(root); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != ".lsphp_restart.txt" || !entries[0].Type().IsRegular() {
		t.Fatalf("unexpected PHP restart marker entries: %v %v", entries, err)
	}
}

func TestOPcacheRestartMarkerRejectsSymlinkMarkerWithoutTouchingTarget(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "admin", "tmp")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(target, []byte("keep unchanged"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(directory, ".lsphp_restart.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeOPcacheRestartMarker(root); err == nil {
		t.Fatal("symlink marker accepted")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "keep unchanged" {
		t.Fatalf("symlink target changed: %q %v", data, err)
	}
}

func TestOPcacheRestartMarkerRejectsSymlinkAdminDirectory(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "admin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "admin", "tmp")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeOPcacheRestartMarker(root); err == nil {
		t.Fatal("symlink admin directory accepted")
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("outside directory changed: %v %v", entries, err)
	}
}
