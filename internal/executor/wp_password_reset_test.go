package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePasswordResetMode(t *testing.T) {
	for _, m := range []string{PasswordResetModeAllow, PasswordResetModeAll, PasswordResetModeAdmin} {
		if got, err := ValidatePasswordResetMode(m); err != nil || got != m {
			t.Fatalf("ValidatePasswordResetMode(%q) = %q, %v; want %q, nil", m, got, err, m)
		}
	}
	if _, err := ValidatePasswordResetMode("bogus"); err == nil {
		t.Fatalf("ValidatePasswordResetMode(bogus) expected error")
	}
}

func TestApplyWPPasswordResetModeAll(t *testing.T) {
	root := t.TempDir()
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAll); err != nil {
		t.Fatalf("apply all: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "wp-content", "mu-plugins", wpPasswordResetPluginFile))
	if err != nil {
		t.Fatalf("read mu-plugin: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, olsWPanelPasswordResetMarker) {
		t.Fatalf("marker missing")
	}
	if !strings.Contains(content, "allow_password_reset") || !strings.Contains(content, "__return_false") {
		t.Fatalf("allow_password_reset filter missing")
	}
	if !strings.Contains(content, "login_head") || !strings.Contains(content, "p#nav") {
		t.Fatalf("login link hiding missing")
	}
}

func TestApplyWPPasswordResetModeAdmin(t *testing.T) {
	root := t.TempDir()
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAdmin); err != nil {
		t.Fatalf("apply admin: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "wp-content", "mu-plugins", wpPasswordResetPluginFile))
	if err != nil {
		t.Fatalf("read mu-plugin: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "has_cap('administrator')") {
		t.Fatalf("administrator capability check missing")
	}
	if strings.Contains(content, "login_head") {
		t.Fatalf("admin mode must not hide login link")
	}
}

func TestApplyWPPasswordResetModeAllFilterSignature(t *testing.T) {
	root := t.TempDir()
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAll); err != nil {
		t.Fatalf("apply all: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "wp-content", "mu-plugins", wpPasswordResetPluginFile))
	if err != nil {
		t.Fatalf("read mu-plugin: %v", err)
	}
	content := string(data)
	// Disabling all resets must register allow_password_reset with __return_false.
	if !strings.Contains(content, "add_filter('allow_password_reset', '__return_false');") {
		t.Fatalf("all mode filter signature missing")
	}
}

func TestApplyWPPasswordResetModeAdminFilterSignature(t *testing.T) {
	root := t.TempDir()
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAdmin); err != nil {
		t.Fatalf("apply admin: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "wp-content", "mu-plugins", wpPasswordResetPluginFile))
	if err != nil {
		t.Fatalf("read mu-plugin: %v", err)
	}
	content := string(data)
	// The admin-only filter needs priority 10 and two arguments so WordPress passes $user_id
	// to the callback for the administrator check.
	if !strings.Contains(content, "add_filter('allow_password_reset', function ($allow, $user_id) {") {
		t.Fatalf("admin filter opening signature missing")
	}
	if !strings.Contains(content, ", 10, 2);") {
		t.Fatalf("admin filter priority/accepted_args (10, 2) missing")
	}
}

func TestApplyWPPasswordResetModeMkdirAllFails(t *testing.T) {
	root := t.TempDir()
	// A regular file at mu-plugins forces MkdirAll to fail.
	if err := os.MkdirAll(filepath.Join(root, "wp-content"), 0755); err != nil {
		t.Fatalf("mkdir wp-content: %v", err)
	}
	blocker := filepath.Join(root, "wp-content", "mu-plugins")
	if err := os.WriteFile(blocker, []byte("block"), 0644); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAll); err == nil {
		t.Fatalf("expected error when mu-plugins path is a regular file")
	}
}

func TestApplyWPPasswordResetModeWriteFails(t *testing.T) {
	root := t.TempDir()
	muDir := filepath.Join(root, "wp-content", "mu-plugins")
	if err := os.MkdirAll(muDir, 0755); err != nil {
		t.Fatalf("mkdir mu-plugins: %v", err)
	}
	// A directory at the target file path forces WriteFile to fail.
	if err := os.MkdirAll(filepath.Join(muDir, wpPasswordResetPluginFile), 0755); err != nil {
		t.Fatalf("mkdir plugin path as dir: %v", err)
	}
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAll); err == nil {
		t.Fatalf("expected error when plugin path is a directory")
	}
}

func TestApplyWPPasswordResetModeChownFails(t *testing.T) {
	root := t.TempDir()
	// An unknown system user must surface the ChownSitePath lookup error.
	if err := ApplyWPPasswordResetMode(root, "no-such-system-user-xyz-12345", PasswordResetModeAll); err == nil {
		t.Fatalf("expected error when system user does not exist")
	}
}

func TestApplyWPPasswordResetModeAllowRemovesFile(t *testing.T) {
	root := t.TempDir()
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAll); err != nil {
		t.Fatalf("seed all: %v", err)
	}
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAllow); err != nil {
		t.Fatalf("apply allow: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "wp-content", "mu-plugins", wpPasswordResetPluginFile)); !os.IsNotExist(err) {
		t.Fatalf("mu-plugin should be removed in allow mode")
	}
}

func TestApplyWPPasswordResetModeAllowNoFileIsNoop(t *testing.T) {
	root := t.TempDir()
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAllow); err != nil {
		t.Fatalf("apply allow on empty site: %v", err)
	}
}

func TestApplyWPPasswordResetModeRejectsRelativeWebRoot(t *testing.T) {
	if err := ApplyWPPasswordResetMode("sites/example", "", PasswordResetModeAll); err == nil {
		t.Fatalf("expected error for relative webRoot")
	}
}

func TestApplyWPPasswordResetModeRejectsFilesystemRoot(t *testing.T) {
	if err := ApplyWPPasswordResetMode("/", "", PasswordResetModeAll); err == nil {
		t.Fatalf("expected error for filesystem root webRoot")
	}
}

func TestApplyWPPasswordResetModeWritesInsideWebRoot(t *testing.T) {
	root := t.TempDir()
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAll); err != nil {
		t.Fatalf("apply all: %v", err)
	}
	want := filepath.Join(root, "wp-content", "mu-plugins", wpPasswordResetPluginFile)
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("mu-plugin not written at expected path %s: %v", want, err)
	}
	// The fixed subdirectory must remain inside webRoot after path cleaning.
}

func TestApplyWPPasswordResetModeRejectsSymlinkedMuPlugins(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "wp-content"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "wp-content", "mu-plugins")); err != nil {
		t.Fatal(err)
	}
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAll); err == nil {
		t.Fatal("expected symlink rejection")
	}
	if _, err := os.Stat(filepath.Join(outside, wpPasswordResetPluginFile)); !os.IsNotExist(err) {
		t.Fatalf("outside plugin unexpectedly written: %v", err)
	}
}

func TestWPPasswordResetModeMatchesActualFile(t *testing.T) {
	root := t.TempDir()
	if matches, err := WPPasswordResetModeMatches(root, PasswordResetModeAllow); err != nil || !matches {
		t.Fatalf("empty allow state = %v, %v", matches, err)
	}
	if err := ApplyWPPasswordResetMode(root, "", PasswordResetModeAdmin); err != nil {
		t.Fatal(err)
	}
	if matches, err := WPPasswordResetModeMatches(root, PasswordResetModeAdmin); err != nil || !matches {
		t.Fatalf("admin state = %v, %v", matches, err)
	}
	path := filepath.Join(root, "wp-content", "mu-plugins", wpPasswordResetPluginFile)
	if err := os.WriteFile(path, []byte("<?php // damaged"), 0644); err != nil {
		t.Fatal(err)
	}
	if matches, err := WPPasswordResetModeMatches(root, PasswordResetModeAdmin); err != nil || matches {
		t.Fatalf("damaged state = %v, %v", matches, err)
	}
}
