package tests

import (
	"os/exec"
	"testing"
)

func TestLiteSpeedCacheStatusAndMigration(t *testing.T) {
	php, err := exec.LookPath("php")
	if err != nil {
		t.Skip("PHP CLI unavailable")
	}
	if out, err := exec.Command(php, "-n", "php/litespeed_cache_status.php").CombinedOutput(); err != nil {
		t.Fatalf("LiteSpeed cache status and migration checks: %v\n%s", err, out)
	}
}
