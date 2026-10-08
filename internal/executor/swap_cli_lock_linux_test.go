package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSwapCLILockSerializesIndependentOpensAndSurvivesRelease(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "swap.lock")
	first, err := acquireSwapCLILock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := acquireSwapCLILock(path); err == nil {
		_ = second.Close()
		t.Fatal("second lock succeeded while first was held")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := acquireSwapCLILock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("lock inode was removed after release")
	}
}

func TestSwapCLILockRejectsUnsafeIdentities(t *testing.T) {
	t.Run("permissions", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "swap.lock")
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if lock, err := acquireSwapCLILock(path); err == nil {
			_ = lock.Close()
			t.Fatal("unsafe lock file permissions accepted")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "swap.lock")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if lock, err := acquireSwapCLILock(path); err == nil {
			_ = lock.Close()
			t.Fatal("symlink lock accepted")
		}
	})
	t.Run("public-directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if lock, err := acquireSwapCLILock(filepath.Join(dir, "swap.lock")); err == nil {
			_ = lock.Close()
			t.Fatal("public lock directory accepted")
		}
	})
}
