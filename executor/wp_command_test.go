package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsurePanelCommandsAt_WritesLowerAndUpperAliases(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "lowercase-o"),
		filepath.Join(dir, "uppercase-O"),
	}

	if err := ensurePanelCommandsAt(paths...); err != nil {
		t.Fatalf("ensurePanelCommandsAt failed: %v", err)
	}
	for _, path := range paths {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != panelCommandScript {
			t.Fatalf("unexpected command content at %s", path)
		}
	}
	if !strings.Contains(panelCommandScript, "用法: o <命令>（也可使用大写 O）") {
		t.Fatal("panel command help does not document the O alias")
	}
	if strings.Contains(panelCommandScript, "olsw status") {
		t.Fatal("panel command script still advertises the removed command")
	}
	for _, expected := range []string{"o update", "o uninstall", "run_lifecycle --repair", "run_lifecycle --uninstall", "ENTRY_URL=https://ols.zangyubin.top/install"} {
		if !strings.Contains(panelCommandScript, expected) {
			t.Fatalf("panel command script is missing lifecycle command %q", expected)
		}
	}
}

func TestPanelCommandScriptHasValidBashSyntax(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	path := filepath.Join(t.TempDir(), "panel-command")
	if err := os.WriteFile(path, []byte(panelCommandScript), 0755); err != nil {
		t.Fatalf("write panel command script: %v", err)
	}
	if output, err := exec.Command(bash, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("panel command script has invalid Bash syntax: %v\n%s", err, output)
	}
}

func TestEnsurePanelCommandsAt_RefusesUnrelatedCommandWithoutPartialWrite(t *testing.T) {
	dir := t.TempDir()
	occupied := filepath.Join(dir, "lowercase-o")
	other := filepath.Join(dir, "uppercase-O")
	original := []byte("#!/bin/sh\necho unrelated\n")
	if err := os.WriteFile(occupied, original, 0755); err != nil {
		t.Fatalf("seed unrelated command: %v", err)
	}

	if err := ensurePanelCommandsAt(occupied, other); err == nil {
		t.Fatal("expected an occupied command path to be rejected")
	}
	got, err := os.ReadFile(occupied)
	if err != nil {
		t.Fatalf("read unrelated command: %v", err)
	}
	if string(got) != string(original) {
		t.Fatal("unrelated command was modified")
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatalf("second alias was written despite preflight failure: %v", err)
	}
}

func TestEnsurePanelCommandsAt_ReplacesOwnedCommands(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "lowercase-o"),
		filepath.Join(dir, "uppercase-O"),
	}
	old := []byte("#!/bin/bash\n" + panelCommandMarker + "\necho old\n")
	for _, path := range paths {
		if err := os.WriteFile(path, old, 0644); err != nil {
			t.Fatalf("seed owned command %s: %v", path, err)
		}
	}

	if err := ensurePanelCommandsAt(paths...); err != nil {
		t.Fatalf("replace owned commands: %v", err)
	}
	for _, path := range paths {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read replaced command %s: %v", path, err)
		}
		if string(got) != panelCommandScript {
			t.Fatalf("owned command %s was not updated", path)
		}
	}
}

func TestWriteFileAtomic_WritesContentAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o")
	content := []byte("#!/bin/bash\necho hi\n")

	if err := writeFileAtomic(path, content, 0755); err != nil {
		t.Fatalf("writeFileAtomic failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: got %q, want %q", got, content)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat written file: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0755 {
		t.Fatalf("unexpected permissions: got %v, want 0755", info.Mode().Perm())
	}

	// No leftover temp files in the target directory.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("failed to read dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "o" {
		t.Fatalf("unexpected directory contents: %v", entries)
	}
}

func TestWriteFileAtomic_OverwritesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o")
	if err := os.WriteFile(path, []byte("old content"), 0644); err != nil {
		t.Fatalf("failed to seed existing file: %v", err)
	}

	newContent := []byte("new content")
	if err := writeFileAtomic(path, newContent, 0755); err != nil {
		t.Fatalf("writeFileAtomic failed: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if string(got) != string(newContent) {
		t.Fatalf("content mismatch: got %q, want %q", got, newContent)
	}
}
