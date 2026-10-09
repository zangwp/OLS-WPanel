package executor

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestWPSecurityLogsFollowConfiguredRootAndOnlySingleSiteDirectories(t *testing.T) {
	old := config.AppConfig
	t.Cleanup(func() { config.AppConfig = old })
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(cwd, "configured-site-logs")
	if _, err := cleanFail2banWebsiteLogRoot(root); err != nil {
		t.Skipf("working directory is not a supported configured log path: %v", err)
	}
	config.AppConfig = &config.Config{Paths: config.PathsConfig{WWWLogs: root}}
	for _, tt := range []struct {
		dir   string
		allow bool
	}{
		{filepath.Join(root, "example.com"), true},
		{root, false},
		{filepath.Dir(root), false},
		{filepath.Join(root+"-neighbor", "example.com"), false},
		{filepath.Join(root, "example.com", "nested"), false},
		{"relative/example.com", false},
		{filepath.Join(root, "example.com") + "\n", false},
	} {
		if got := isAllowedSiteLogDir(tt.dir); got != tt.allow {
			t.Errorf("configured root dir %q allowed=%v, want%v", tt.dir, got, tt.allow)
		}
	}
	config.AppConfig.Paths.WWWLogs = "/"
	if isAllowedSiteLogDir(filepath.Join(root, "example.com")) {
		t.Fatal("invalid configured log root must fail closed")
	}
}

func TestOpenSafeWPSecurityLogAcceptsRegularAndRejectsDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	if err := os.WriteFile(path, []byte("observed event\n"), 0600); err != nil {
		t.Fatal(err)
	}
	allowed := func(candidate string) bool { return candidate == dir }
	f, err := openSafeWPSecurityLog(path, allowed)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil || string(data) != "observed event\n" {
		t.Fatalf("safe ordinary log read=(%q,%v)", data, err)
	}
	if f, err := openSafeWPSecurityLog(path, func(string) bool { return false }); err == nil {
		f.Close()
		t.Fatal("source outside the approved site root accepted")
	}
	if f, err := openSafeWPSecurityLog(dir, func(string) bool { return true }); err == nil {
		f.Close()
		t.Fatal("directory opened as a log file")
	}
}

func TestOpenSafeWPSecurityLogRejectsSymlinkFileAndParent(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	outsideLog := filepath.Join(outside, "access.log")
	if err := os.WriteFile(outsideLog, []byte("outside content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "access.log")
	if err := os.Symlink(outsideLog, link); err != nil {
		t.Skipf("symlinks unavailable in this environment: %v", err)
	}
	if f, err := openSafeWPSecurityLog(link, func(string) bool { return true }); err == nil {
		f.Close()
		t.Fatal("symlink log file accepted")
	}
	parentLink := filepath.Join(dir, "parent-link")
	if err := os.Symlink(outside, parentLink); err != nil {
		t.Fatal(err)
	}
	if f, err := openSafeWPSecurityLog(filepath.Join(parentLink, "access.log"), func(string) bool { return true }); err == nil {
		f.Close()
		t.Fatal("symlink parent crossed to outside log directory")
	}
}

func TestOpenSafeWPSecurityLogRejectsReplacedInode(t *testing.T) {
	dir := t.TempDir()
	path, replacement := filepath.Join(dir, "access.log"), filepath.Join(dir, "replacement.log")
	if err := os.WriteFile(path, []byte("original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := openWPSecurityLogFile
	t.Cleanup(func() { openWPSecurityLogFile = old })
	openWPSecurityLogFile = func(requested string) (*os.File, error) {
		if err := os.Remove(requested); err != nil {
			return nil, err
		}
		if err := os.Rename(replacement, requested); err != nil {
			return nil, err
		}
		return old(requested)
	}
	if f, err := openSafeWPSecurityLog(path, func(string) bool { return true }); err == nil {
		f.Close()
		t.Fatal("log inode replaced between inspection and open was accepted")
	}
}
