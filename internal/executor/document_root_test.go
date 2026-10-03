package executor

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeDocumentRootSubdir(t *testing.T) {
	tests := []struct {
		name     string
		siteType string
		input    string
		want     string
		wantErr  bool
	}{
		{name: "empty php", siteType: "php", input: "", want: ""},
		{name: "public php", siteType: "php", input: "public", want: "public"},
		{name: "public slash php", siteType: "php", input: "public/", want: "public"},
		{name: "escape php", siteType: "php", input: "../public", wantErr: true},
		{name: "nested php", siteType: "php", input: "public/subdir", wantErr: true},
		{name: "wordpress ignores public", siteType: "wordpress", input: "public", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeDocumentRootSubdir(tt.siteType, tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeDocumentRootSubdir() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeDocumentRootSubdir() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnsureEffectiveDocumentRootReportsOwnershipFailure(t *testing.T) {
	oldSetOwner := setEffectiveDocumentRootOwner
	setEffectiveDocumentRootOwner = func(user, path string) error {
		if user != "wp_example" || !strings.HasSuffix(path, string(filepath.Separator)+"public") {
			t.Fatalf("unexpected ownership request user=%q path=%q", user, path)
		}
		return errors.New("injected chown failure")
	}
	t.Cleanup(func() { setEffectiveDocumentRootOwner = oldSetOwner })

	_, err := EnsureEffectiveDocumentRoot(filepath.Join(t.TempDir(), "example.com"), "php", "public", "wp_example")
	if err == nil || !strings.Contains(err.Error(), "设置Web入口目录权限失败") {
		t.Fatalf("EnsureEffectiveDocumentRoot() error = %v", err)
	}
}

func TestEffectiveDocumentRoot(t *testing.T) {
	projectRoot := filepath.Join(t.TempDir(), "example.com")

	if got := EffectiveDocumentRoot(projectRoot, "wordpress", "public"); got != filepath.Clean(projectRoot) {
		t.Fatalf("wordpress EffectiveDocumentRoot() = %q, want %q", got, filepath.Clean(projectRoot))
	}

	want := filepath.Join(projectRoot, "public")
	if got := EffectiveDocumentRoot(projectRoot, "php", "public"); got != want {
		t.Fatalf("php EffectiveDocumentRoot() = %q, want %q", got, want)
	}
}

func TestEnsureEffectiveDocumentRootCreatesPublic(t *testing.T) {
	projectRoot := filepath.Join(t.TempDir(), "example.com")

	got, err := EnsureEffectiveDocumentRoot(projectRoot, "php", "public", "")
	if err != nil {
		t.Fatalf("EnsureEffectiveDocumentRoot() error = %v", err)
	}

	want := filepath.Join(projectRoot, "public")
	if got != want {
		t.Fatalf("EnsureEffectiveDocumentRoot() = %q, want %q", got, want)
	}
	if _, err := filepath.EvalSymlinks(want); err != nil {
		t.Fatalf("public directory should exist: %v", err)
	}
}
