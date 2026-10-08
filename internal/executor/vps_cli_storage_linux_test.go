package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVPSCLIPrivateStateRejectsLinksAndLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.jsonl")
	if err := os.WriteFile(path, []byte("private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if data, err := readVPSCLIPrivateFile(path, 64); err != nil || string(data) != "private fixture" {
		t.Fatalf("valid private file rejected: %q %v", data, err)
	}
	if _, err := readVPSCLIPrivateFile(path, 4); err == nil {
		t.Fatal("oversized state accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readVPSCLIPrivateFile(path, 64); err == nil {
		t.Fatal("publicly readable history accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readVPSCLIPrivateFile(symlink, 64); err == nil {
		t.Fatal("symlink state accepted")
	}
	hardlink := filepath.Join(dir, "hardlink")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readVPSCLIPrivateFile(path, 64); err == nil {
		t.Fatal("multiply linked state accepted")
	}
}
