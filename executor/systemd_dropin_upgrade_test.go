package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRepairManagedServiceDropInsUpdatesOnlyLegacyContent(t *testing.T) {
	root := t.TempDir()
	writeDropIn(t, root, "lsws", managedServiceDropInLegacyContent)
	writeDropIn(t, root, "redis-server", managedServiceDropInFixedContent)
	writeDropIn(t, root, "mariadb", "[Service]\nRestart=on-failure\nRestartSec=2s\nStartLimitIntervalSec=0\n")

	changed, err := repairManagedServiceDropIns(root)
	if err != nil {
		t.Fatalf("repairManagedServiceDropIns() error = %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}

	if got := readDropIn(t, root, "lsws"); got != managedServiceDropInFixedContent {
		t.Fatalf("lsws drop-in = %q, want fixed content", got)
	}
	if got := readDropIn(t, root, "redis-server"); got != managedServiceDropInFixedContent {
		t.Fatalf("redis drop-in = %q, want fixed content", got)
	}
	if got := readDropIn(t, root, "mariadb"); got != "[Service]\nRestart=on-failure\nRestartSec=2s\nStartLimitIntervalSec=0\n" {
		t.Fatalf("custom mariadb drop-in was overwritten: %q", got)
	}
	if _, err := os.Stat(filepath.Join(root, "openlitespeed.service.d", "ols-wpanel.conf")); !os.IsNotExist(err) {
		t.Fatalf("legacy openlitespeed drop-in stat err = %v, want not exist", err)
	}
}

func TestRepairManagedServiceDropInsReportsNoChangeWhenAlreadyFixed(t *testing.T) {
	root := t.TempDir()
	for _, svc := range []string{"lsws", "mariadb", "redis-server"} {
		writeDropIn(t, root, svc, managedServiceDropInFixedContent)
	}

	changed, err := repairManagedServiceDropIns(root)
	if err != nil {
		t.Fatalf("repairManagedServiceDropIns() error = %v", err)
	}
	if changed {
		t.Fatal("changed = true, want false")
	}
}

func TestRepairManagedServiceDropInsBoundedReplacesOnlyPanelPolicies(t *testing.T) {
	root := t.TempDir()
	writeDropIn(t, root, "lsws", managedServiceDropInLegacyContent)
	writeDropIn(t, root, "lshttpd", managedServiceDropInFixedContent)
	writeDropIn(t, root, "redis-server", managedServiceDropInBoundedContent)
	custom := "[Service]\nRestart=on-failure\nRestartSec=30s\n"
	writeDropIn(t, root, "mariadb", custom)

	changed, err := repairManagedServiceDropInsBounded(root)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	for _, svc := range []string{"lsws", "lshttpd", "redis-server"} {
		if got := readDropIn(t, root, svc); got != managedServiceDropInBoundedContent {
			t.Fatalf("%s drop-in = %q, want bounded policy", svc, got)
		}
	}
	if got := readDropIn(t, root, "mariadb"); got != custom {
		t.Fatalf("custom mariadb policy was overwritten: %q", got)
	}
}

func writeDropIn(t *testing.T, root, svc, content string) {
	t.Helper()
	dir := filepath.Join(root, svc+".service.d")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", dir, err)
	}
	path := filepath.Join(dir, "ols-wpanel.conf")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func readDropIn(t *testing.T, root, svc string) string {
	t.Helper()
	path := filepath.Join(root, svc+".service.d", "ols-wpanel.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", path, err)
	}
	return string(data)
}
