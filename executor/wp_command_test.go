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

func runPanelMenuFixture(t *testing.T, body string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash unavailable")
	}
	definitions, _, ok := strings.Cut(panelCommandScript, "\ncase \"${1:-}\" in")
	if !ok {
		t.Fatal("CLI dispatch not found")
	}
	fixture := definitions + `
interactive() { return 0; }
tput() { echo 80; }
panel_summary() { echo FIXTURE_PANEL; }
read_view() { echo "VIEW:$1"; }
pause_page() { echo PAUSE; }
need_root() { return 0; }
confirm_vps() { return 0; }
mutate() { echo "MUTATION:$*"; }
BIN=mutate
TERM=xterm
index=0
pick() {
    [ "$index" -lt "${#choices[@]}" ] || return 1
    choice="${choices[$index]}"
    index=$((index+1))
}
` + body
	path := filepath.Join(t.TempDir(), "menu-fixture.sh")
	if err := os.WriteFile(path, []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bash, path).CombinedOutput()
	if err != nil {
		t.Fatalf("menu fixture: %v\n%s", err, out)
	}
	return string(out)
}

func TestPanelMenuReturnsWithoutRepeatingResults(t *testing.T) {
	out := runPanelMenuFixture(t, "choices=(1 4 1 0 0 0)\nvps_menu\n")
	if strings.Count(out, "VIEW:info") != 1 || strings.Count(out, "VIEW:dns") != 1 || strings.Count(out, "PAUSE") != 1 {
		t.Fatalf("result pause/navigation failed: %s", out)
	}
	if strings.Count(out, "\033[2J\033[H") < 5 {
		t.Fatal("interactive screens were not redrawn")
	}
	if strings.Contains(out, "MUTATION:") {
		t.Fatal("viewing or returning mutated the system")
	}
}

func TestPanelDNSReturnAndRestoreAreSeparateActions(t *testing.T) {
	back := runPanelMenuFixture(t, "choices=(0)\nsettings_page dns\n")
	if strings.Contains(back, "MUTATION:") {
		t.Fatal("zero must only return")
	}
	restore := runPanelMenuFixture(t, "choices=(3 0)\nsettings_page dns\n")
	if strings.Count(restore, "MUTATION:--vps-tool dns --vps-value default") != 1 {
		t.Fatalf("explicit restore did not dispatch once: %s", restore)
	}
}

func TestDNSCandidateViewAndUnavailableActionsNeverMutate(t *testing.T) {
	out := runPanelMenuFixture(t, "choices=(1 0 0)\nsettings_page dns\n")
	if !strings.Contains(out, "VIEW:dns-preset") || strings.Contains(out, "MUTATION:") {
		t.Fatalf("candidate navigation: %s", out)
	}
	out = runPanelMenuFixture(t, "read_view() { echo VIEW:$1; return 2; }\nchoices=(2 0)\ndns_preset_page international\n")
	if strings.Contains(out, "MUTATION:") {
		t.Fatal("read-only DNS changed")
	}
	out = runPanelMenuFixture(t, "read_view() { echo VIEW:$1; return 2; }\nchoices=(4 0)\nsettings_page tuning\n")
	if strings.Contains(out, "MUTATION:") {
		t.Fatal("restore without baseline changed system")
	}
}

func TestOrdinaryConfirmationAcceptsCaseInsensitiveYes(t *testing.T) {
	out := runPanelMenuFixture(t, "for input in y Y yes YES Yes; do is_yes \"$input\" || exit 8; done\nfor input in '' n no yesterday; do if is_yes \"$input\"; then exit 9; fi; done\necho CONFIRM_OK\n")
	if !strings.Contains(out, "CONFIRM_OK") {
		t.Fatal(out)
	}
}

func TestPanelActualPythonFormatter(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	path := "panel_cli_render_test.py"
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join("executor", path)
	}
	if out, err := exec.Command(python, path).CombinedOutput(); err != nil {
		t.Fatalf("formatter regression: %v\n%s", err, out)
	}
}

func TestPerformanceMenuDispatchAndSimplifiedNavigation(t *testing.T) {
	out := runPanelMenuFixture(t, "choices=(1 2 4 0)\nsettings_page tuning\n")
	for _, mode := range []string{"balanced", "website", "default"} {
		if strings.Count(out, "MUTATION:--vps-tool tuning --vps-value "+mode) != 1 {
			t.Fatalf("wrong tuning dispatch for %s: %s", mode, out)
		}
	}
	ip := runPanelMenuFixture(t, "choices=(0)\nsettings_page ip\n")
	if strings.Contains(ip, "4. 网络连通性检测") {
		t.Fatal("duplicate network action")
	}
	advanced := runPanelMenuFixture(t, "choices=(0)\nadvanced_menu\n")
	if strings.Contains(advanced, "安装路径与面板详情") {
		t.Fatal("duplicate details action")
	}
}

func TestPerformanceStatusRefreshDoesNotMutate(t *testing.T) {
	out := runPanelMenuFixture(t, "choices=(1 0)\nperformance_menu\n")
	if strings.Contains(out, "MUTATION:") || strings.Count(out, "VIEW:tuning") != 2 {
		t.Fatalf("status/refresh must only read: %s", out)
	}
	if strings.Contains(out, "1. 设为") {
		t.Fatal("queue changes exposed on status page")
	}
	advanced := runPanelMenuFixture(t, "choices=(2 0 0)\nperformance_menu\n")
	if !strings.Contains(advanced, "高级设置 · 连接队列") || strings.Contains(advanced, "MUTATION:") {
		t.Fatalf("opening/returning from advanced mutated state: %s", advanced)
	}
	canceled := runPanelMenuFixture(t, "confirm_vps() { return 1; }\nchoices=(2 1 0 0)\nperformance_menu\n")
	if strings.Contains(canceled, "MUTATION:") || !strings.Contains(canceled, "已取消") {
		t.Fatalf("canceled queue change was not safe: %s", canceled)
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
