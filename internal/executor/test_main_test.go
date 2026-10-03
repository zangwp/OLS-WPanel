package executor

import (
	"os"
	"os/user"
	"testing"
)

// Unit tests validate the generated PHP source directly. Runtime integration
// tests exercise the real LSPHP CLI inside the supported distribution probes.
func TestMain(m *testing.M) {
	lintManagedPHPFile = func(string) error { return nil }
	// The production daemon runs as root and must repair the fallback vhost to
	// www-data. GitHub-hosted test runners are deliberately unprivileged, so
	// keep the identity validation real while replacing only the privileged
	// filesystem side effect. Focused ols_config tests override these hooks to
	// assert the exact UID/GID and failure behavior.
	lookupOLSDefaultVHostUser = func(name string) (*user.User, error) {
		return &user.User{Username: name, Uid: "33", Gid: "33"}, nil
	}
	chownOLSDefaultVHostRoot = func(string, int, int) error { return nil }
	os.Exit(m.Run())
}
