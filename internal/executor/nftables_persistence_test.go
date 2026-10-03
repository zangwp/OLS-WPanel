package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateNftablesPersistenceConfig(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.conf")
	if err := validateNftablesPersistenceConfig(missing); err == nil {
		t.Fatal("missing nftables config was accepted")
	}

	empty := filepath.Join(dir, "empty.conf")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateNftablesPersistenceConfig(empty); err == nil {
		t.Fatal("empty nftables config was accepted")
	}

	valid := filepath.Join(dir, "nftables.conf")
	if err := os.WriteFile(valid, []byte("table inet filter {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateNftablesPersistenceConfig(valid); err != nil {
		t.Fatalf("valid nftables config was rejected: %v", err)
	}
}
