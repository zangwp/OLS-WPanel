package executor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestWPLoginAuditSurvivesIndependentPolicyChanges(t *testing.T) {
	original := "<?php\n// custom settings\n/* That's all, stop editing! Happy publishing. */\n"
	path := filepath.Join(t.TempDir(), "site.log")
	installed := renderWPLoginFailureLogging(original, path)
	if installed != renderWPLoginFailureLogging(installed, path) {
		t.Fatal("login audit installation is not idempotent")
	}
	if got := renderWPLoginFailureLogging(installed, ""); got != original {
		t.Fatal("removing audit changed unrelated settings")
	}
	for _, updates := range []bool{false, true} {
		for _, passwords := range []bool{false, true} {
			got := renderWPNativePolicy(installed, updates, passwords)
			if wpLoginAuditBlock.FindString(got) != wpLoginAuditBlock.FindString(installed) {
				t.Fatal("an unrelated WordPress policy disabled authentication audit")
			}
		}
	}
}

func TestWPLoginAuditUsesRealFailuresAndTrustedRemoteAddress(t *testing.T) {
	php, err := exec.LookPath("php-cgi")
	if err != nil {
		t.Skip("PHP CGI unavailable")
	}
	root := t.TempDir()
	logPath := filepath.Join(root, "login.log")
	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	script := `<?php
class WP_Error {
 private $code;
 function __construct($code){ $this->code=$code; }
 function get_error_code(){ return $this->code; }
}
require __DIR__ . '/policy.php';
$hooks=$GLOBALS['wp_filter']['wp_login_failed'][PHP_INT_MAX] ?? array();
if (count($hooks)!==1 || $hooks[0]['accepted_args']!==2) { echo 'bad hook'; exit(1); }
$callback=$hooks[0]['function'];
$error=new WP_Error(getenv('AUDIT_ERROR'));
$callback("private-user\nforged-line", $error);
$callback('same failure duplicate', $error);
echo 'audit ok';
`
	policyPath := filepath.Join(root, "policy.php")
	if err := os.WriteFile(policyPath, []byte(renderWPLoginFailureLogging("<?php\n", logPath)), 0600); err != nil {
		t.Fatal(err)
	}
	harnessPath := filepath.Join(root, "harness.php")
	if err := os.WriteFile(harnessPath, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	run := func(ip, code string) {
		t.Helper()
		cmd := exec.Command(php, "-n", "-q", harnessPath)
		cmd.Env = append(os.Environ(), "REDIRECT_STATUS=1", "SCRIPT_FILENAME="+harnessPath,
			"REQUEST_METHOD=POST", "REMOTE_ADDR="+ip, "HTTP_X_FORWARDED_FOR=1.1.1.1",
			"HTTP_CF_CONNECTING_IP=8.8.8.8", "AUDIT_ERROR="+code)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.HasSuffix(strings.TrimSpace(string(out)), "audit ok") {
			t.Fatalf("PHP audit harness: %s, %v", out, err)
		}
	}
	for _, tc := range []struct{ ip, code string }{
		{"1.1.1.1", "incorrect_password"},
		{"8.8.8.8", "invalid_username"},
		{"2606:4700::1111", "invalid_email"},
	} {
		run(tc.ip, tc.code)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("failure must be counted once per request, got %q", data)
	}
	lineRE := regexp.MustCompile(`^\S+ \[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\] OLS_WPANEL_LOGIN_FAILED$`)
	for _, line := range lines {
		if !lineRE.MatchString(line) {
			t.Fatalf("unexpected/secret-bearing log line: %q", line)
		}
	}
	for _, ip := range []string{"127.0.0.1", "192.168.1.2", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:192.168.1.2", "bogus\n1.1.1.1"} {
		run(ip, "incorrect_password")
	}
	for _, code := range []string{"empty_username", "empty_password", "captcha_failed", "two_factor_required", "authentication_failed", ""} {
		run("1.1.1.1", code)
	}
	after, err := os.ReadFile(logPath)
	if err != nil || string(after) != string(data) {
		t.Fatal("private/spoofed IP or non-password failure produced a ban signal")
	}
	// The logger is bounded even when the rotation timer has not run yet.
	f, err := os.OpenFile(logPath, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(wpLoginFailureLogLimit); err != nil {
		t.Fatal(err)
	}
	f.Close()
	run("1.1.1.1", "incorrect_password")
	if info, err := os.Stat(logPath); err != nil || info.Size() != wpLoginFailureLogLimit {
		t.Fatal("audit log exceeded its size bound")
	}
	if cli, err := exec.LookPath("php"); err == nil {
		out, err := exec.Command(cli, "-n", "-r", `require $argv[1]; echo isset($GLOBALS['wp_filter']['wp_login_failed']) ? 'hook registered' : 'cli ok';`, policyPath).CombinedOutput()
		if err != nil || string(out) != "cli ok" {
			t.Fatalf("CLI/inventory must not register an HTTP login hook: %s, %v", out, err)
		}
	}
}

func TestWPLoginAuditRejectsEscapingLogPaths(t *testing.T) {
	old := config.AppConfig
	config.AppConfig = &config.Config{}
	config.AppConfig.Paths.WWWLogs = filepath.Join(t.TempDir(), "logs")
	t.Cleanup(func() { config.AppConfig = old })
	for _, path := range []string{"", "relative/path", config.AppConfig.Paths.WWWLogs,
		filepath.Join(config.AppConfig.Paths.WWWLogs, "..", "outside"),
		filepath.Join(config.AppConfig.Paths.WWWLogs, "site", "nested"), "bad\npath"} {
		if _, err := wpLoginAuditLogPath(path); err == nil {
			t.Fatalf("unsafe log path accepted: %q", path)
		}
	}
}

func TestWPLoginAuditRejectsUnsafeOwnedFiles(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("root-owned log provisioning requires Linux root")
	}
	old := config.AppConfig
	base, err := os.MkdirTemp("/tmp", "ols-wpanel-login-audit-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	config.AppConfig = &config.Config{}
	config.AppConfig.Paths.WWWLogs = base
	t.Cleanup(func() { config.AppConfig = old })
	siteLog := filepath.Join(base, "site")
	if err := os.Mkdir(siteLog, 0755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(siteLog, wpLoginFailureLogName)
	outside := filepath.Join(base, "private")
	if err := os.WriteFile(outside, []byte("private content"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, link := range []func(string, string) error{os.Symlink, os.Link} {
		if err := link(outside, logPath); err != nil {
			t.Fatal(err)
		}
		if _, err := prepareWPLoginFailureLog(siteLog, "www-data"); err == nil {
			t.Fatal("linked audit log was accepted")
		}
		os.Remove(logPath)
		data, err := os.ReadFile(outside)
		if err != nil || string(data) != "private content" {
			t.Fatal("unsafe log target was modified")
		}
	}
	if err := os.WriteFile(logPath, nil, 0666); err != nil {
		t.Fatal(err)
	}
	os.Chmod(logPath, 0666)
	if _, err := prepareWPLoginFailureLog(siteLog, "www-data"); err == nil {
		t.Fatal("world-writable audit log was accepted")
	}
	os.Remove(logPath)
	if _, err := prepareWPLoginFailureLog(siteLog, "www-data"); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(logPath)
	uid, gid, _ := fileOwnerIDs(info)
	_, siteGID, _ := siteUserIDs("www-data")
	if uid != 0 || gid != siteGID || info.Mode().Perm() != 0660 {
		t.Fatal(fmt.Sprintf("unexpected audit log owner/mode: %d:%d %o", uid, gid, info.Mode().Perm()))
	}
}
