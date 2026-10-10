//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFullFileRestoreLinuxExchangeKeepsBothDirectories(t *testing.T) {
	parent := t.TempDir()
	live, staged := filepath.Join(parent, "live"), filepath.Join(parent, "staged")
	for name, body := range map[string]string{live: "old", staged: "new"} {
		if err := os.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(name, "index.php"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := exchangeFileRestoreDirectories(live, staged); err != nil {
		t.Fatal(err)
	}
	assertFullRestoreFile(t, filepath.Join(live, "index.php"), "new")
	assertFullRestoreFile(t, filepath.Join(staged, "index.php"), "old")
	if err := exchangeFileRestoreDirectories(live, staged); err != nil {
		t.Fatal(err)
	}
	assertFullRestoreFile(t, filepath.Join(live, "index.php"), "old")
	assertFullRestoreFile(t, filepath.Join(staged, "index.php"), "new")
}
