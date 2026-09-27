package executor

import (
	"os"
	"testing"
)

// Unit tests validate the generated PHP source directly. Runtime integration
// tests exercise the real LSPHP CLI inside the supported distribution probes.
func TestMain(m *testing.M) {
	lintManagedPHPFile = func(string) error { return nil }
	os.Exit(m.Run())
}
