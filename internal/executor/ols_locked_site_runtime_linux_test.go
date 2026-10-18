//go:build linux

package executor

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/models"
)

// This opt-in test owns the server configuration only inside a disposable
// container. The normal suite must never restart an installed web server.
func TestOLSLockedSiteRuntimeLinux(t *testing.T) {
	if os.Getenv("OLS_WPANEL_LOCKED_SITE_RUNTIME_TEST") != "1" {
		t.Skip("requires the disposable OpenLiteSpeed runtime container")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the runtime container must run as root")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing to replace server configuration outside a Docker container")
	}
	const binary = "/usr/local/lsws/bin/openlitespeed"
	const control = "/usr/local/lsws/bin/lswsctrl"
	for _, path := range []string{binary, control, "/usr/local/lsws/lsphp85/bin/lsphp"} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("required installed runtime %s: %v", path, err)
		}
	}
	run := func(name string, args ...string) []byte {
		t.Helper()
		out, err := runOLSCommandBounded(60*time.Second, name, args...)
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return out
	}
	root, err := os.MkdirTemp("/tmp", "ols-locked-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = runOLSCommandBounded(20*time.Second, control, "stop")
		_ = os.RemoveAll(root)
	})
	oldConfig, oldCommand := config.AppConfig, runOLSCommand
	oldDefaultLookup, oldDefaultChown := lookupOLSDefaultVHostUser, chownOLSDefaultVHostRoot
	oldExecutionUser, oldExecutionGroup := lookupOLSVHostExecutionUser, lookupOLSVHostExecutionGroup
	t.Cleanup(func() {
		config.AppConfig, runOLSCommand = oldConfig, oldCommand
		lookupOLSDefaultVHostUser, chownOLSDefaultVHostRoot = oldDefaultLookup, oldDefaultChown
		lookupOLSVHostExecutionUser, lookupOLSVHostExecutionGroup = oldExecutionUser, oldExecutionGroup
	})
	lookupOLSDefaultVHostUser, chownOLSDefaultVHostRoot = user.Lookup, os.Chown
	lookupOLSVHostExecutionUser, lookupOLSVHostExecutionGroup = user.Lookup, user.LookupGroup
	managed := "/usr/local/lsws/conf/ols-wpanel-runtime"
	available, enabled := filepath.Join(managed, "sites-available"), filepath.Join(managed, "sites-enabled")
	www, logs, sockets := filepath.Join(root, "www"), filepath.Join(root, "logs"), filepath.Join(root, "sockets")
	for _, dir := range []string{managed, available, enabled, www, logs, sockets} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(sockets, os.ModeSticky|0777); err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(managed, "default.crt"), filepath.Join(managed, "default.key")
	run("openssl", "req", "-x509", "-nodes", "-days", "1", "-newkey", "rsa:2048", "-keyout", key, "-out", cert, "-subj", "/CN=localhost")
	config.AppConfig = &config.Config{Paths: config.PathsConfig{
		WWWRoot: www, WWWLogs: logs, OLSRoot: "/usr/local/lsws", OLSMainConfig: "/usr/local/lsws/conf/httpd_config.conf",
		OLSManagedConfig: filepath.Join(managed, "sites.conf"), OLSVHostsAvailable: available, OLSVHostsEnabled: enabled,
		OLSBinary: binary, LSPHPBinary: "/usr/local/lsws/lsphp85/bin/lsphp", OLSListenerCert: cert, OLSListenerKey: key,
	}}
	main := "serverName OLS-WPanel-Locked-Site-CI\nuser nobody\ngroup nogroup\npriority 0\nautoFix503 1\ngracefulRestartTimeout 10\nmime conf/mime.properties\nshowVersionNumber 0\nadminEmails root@localhost\nindexFiles index.php,index.html\ndisableWebAdmin 1\nerrorlog logs/error.log {\n logLevel WARN\n rollingSize 20M\n}\naccessControl {\n allow ALL\n}\nmodule cache {\n ls_enabled 1\n checkPrivateCache 1\n checkPublicCache 1\n enableCache 0\n}\ninclude " + config.AppConfig.Paths.OLSManagedConfig + "\n"
	if err := os.WriteFile(config.AppConfig.Paths.OLSMainConfig, []byte(main), 0640); err != nil {
		t.Fatal(err)
	}
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			if len(args) != 2 || args[0] != "restart" || args[1] != "lshttpd" {
				return nil, fmt.Errorf("unexpected runtime service operation: %v", args)
			}
			return runOLSCommandBounded(60*time.Second, control, "restart")
		}
		return runOLSCommandBounded(60*time.Second, name, args...)
	}
	if err := ensureOLSDefaultVHost(currentOLSRuntimePaths()); err != nil {
		t.Fatal(err)
	}
	seenIDs := map[int]bool{}
	var sites []*models.Website
	var locked []*models.Website
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 3 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	for i := 1; i <= 3; i++ {
		domain, account := fmt.Sprintf("locked-%d.example.test", i), fmt.Sprintf("wp_locked_rt%d", i)
		webRoot := filepath.Join(www, domain)
		run("useradd", "--system", "--user-group", "--home-dir", webRoot, "--no-create-home", "--shell", "/usr/sbin/nologin", account)
		uid, gid, err := siteUserIDs(account)
		if err != nil || uid < 11 || gid < 10 || seenIDs[uid] {
			t.Fatalf("site account must have an independent non-root UID/GID: uid=%d gid=%d err=%v", uid, gid, err)
		}
		seenIDs[uid] = true
		for _, dir := range []string{webRoot, filepath.Join(webRoot, "wp-content", "uploads"), filepath.Join(logs, domain)} {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(dir, uid, gid); err != nil {
				t.Fatal(err)
			}
		}
		probe := `<?php
header('Content-Type: application/json');
$proof = __DIR__ . '/wp-content/uploads/process-owner.txt';
$written = file_put_contents($proof, (string) getmypid());
$root_write = @file_put_contents(__DIR__ . '/protected-write.txt', 'must be blocked on locked sites');
echo json_encode(['site' => ` + strconv.Quote(domain) + `, 'pid' => getmypid(), 'written' => $written !== false, 'root_write' => $root_write !== false]);
`
		for path, contents := range map[string]string{filepath.Join(webRoot, "index.php"): probe, filepath.Join(webRoot, "wp-config.php"): "<?php\n// Runtime fixture, not a WordPress installation.\n"} {
			if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, uid, gid); err != nil {
				t.Fatal(err)
			}
		}
		site := &models.Website{ID: i, Domain: domain, WebRoot: webRoot, SystemUser: account, SiteType: "wordpress"}
		data := &OLSVHostData{Domain: domain, WebRoot: webRoot, LogDir: filepath.Join(logs, domain), SystemUser: account,
			SiteType: "wordpress", PHPProxy: "unix:" + filepath.Join(sockets, fmt.Sprintf("site%d.sock", i)), PHPMaxChildren: 2, TemplateVer: "runtime-test", AccessLogMode: "all"}
		content, err := renderOLSVHostConfig(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := applyOLSVHostConfig(nil, content, filepath.Join(available, domain+".conf"), filepath.Join(enabled, domain+".conf")); err != nil {
			t.Fatalf("adding site %d while earlier sites are locked: %v", i, err)
		}
		sites = append(sites, site)
		for _, lockedSite := range locked {
			if err := VerifySiteFileLockMode(lockedSite, FileLockModeStandard); err != nil {
				t.Fatalf("adding site %d changed an earlier site's lock: %v", i, err)
			}
		}
		for _, current := range sites {
			olsAssertSiteProcessIdentity(t, client, current, current.ID < i)
		}
		if i < 3 {
			if err := ApplySiteFileLockMode(site, FileLockModeStandard); err != nil {
				t.Fatal(err)
			}
			if err := VerifySiteFileLockMode(site, FileLockModeStandard); err != nil {
				t.Fatal(err)
			}
			locked = append(locked, site)
			out := run(binary, "-t")
			if strings.Contains(string(out), "smaller than minimum requirement") {
				t.Fatalf("locked root owner leaked into the configured execution identity: %s", out)
			}
			if i == 1 {
				olsAssertLegacyLockedRegistryFails(t, binary, config.AppConfig.Paths.OLSManagedConfig)
			}
		}
	}
	for _, site := range locked {
		if err := VerifySiteFileLockMode(site, FileLockModeStandard); err != nil {
			t.Fatal(err)
		}
	}
	t.Log("OLS_LOCKED_SITE_RUNTIME_OK: three registered sites, two root-owned locked roots, independent PHP process UID/GID")
}

func olsAssertLegacyLockedRegistryFails(t *testing.T, binary, path string) {
	t.Helper()
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var legacy strings.Builder
	for _, line := range strings.Split(string(current), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && (fields[0] == "user" || fields[0] == "group") {
			continue
		}
		legacy.WriteString(line + "\n")
	}
	if err := os.WriteFile(path, []byte(legacy.String()), 0640); err != nil {
		t.Fatal(err)
	}
	out, checkErr := runOLSCommandBounded(20*time.Second, binary, "-t")
	if err := os.WriteFile(path, current, 0640); err != nil {
		t.Fatal(err)
	}
	if checkErr == nil || !strings.Contains(string(out), "smaller than minimum requirement") {
		t.Fatalf("negative control did not reproduce the locked-root UID rejection: err=%v output=%s", checkErr, out)
	}
	t.Log("OLS_LOCKED_SITE_LEGACY_REPRODUCED: removing explicit identity rejects UID 0")
}

func olsAssertSiteProcessIdentity(t *testing.T, client *http.Client, site *models.Website, locked bool) {
	t.Helper()
	uid, gid, err := siteUserIDs(site.SystemUser)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Site      string `json:"site"`
		PID       int    `json:"pid"`
		Written   bool   `json:"written"`
		RootWrite bool   `json:"root_write"`
	}
	deadline := time.Now().Add(30 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/index.php?runtime_probe="+strconv.FormatInt(time.Now().UnixNano(), 10), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = site.Domain
		response, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
			response.Body.Close()
			last = fmt.Sprintf("HTTP %d: %s (read=%v)", response.StatusCode, body, readErr)
			if response.StatusCode == http.StatusOK && readErr == nil && json.Unmarshal(body, &result) == nil && result.Site == site.Domain && result.PID > 1 {
				break
			}
		} else {
			last = err.Error()
		}
		time.Sleep(200 * time.Millisecond)
	}
	if result.Site != site.Domain || result.PID <= 1 || !result.Written || (locked && result.RootWrite) {
		t.Fatalf("PHP request did not preserve the site's lock and writable uploads: site=%s locked=%t result=%+v last=%s", site.Domain, locked, result, last)
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", result.PID))
	if err != nil {
		t.Fatalf("read actual LSAPI worker credentials: %v", err)
	}
	for _, field := range []struct {
		name string
		id   int
	}{{"Uid:", uid}, {"Gid:", gid}} {
		found := false
		for _, line := range strings.Split(string(status), "\n") {
			parts := strings.Fields(line)
			if len(parts) == 5 && parts[0] == field.name {
				found = true
				for _, value := range parts[1:] {
					if value != strconv.Itoa(field.id) {
						t.Fatalf("%s PHP worker %d has unexpected credentials: %s", site.Domain, result.PID, line)
					}
				}
			}
		}
		if !found {
			t.Fatalf("missing kernel worker credential %s", field.name)
		}
	}
	proof, err := os.Stat(filepath.Join(site.WebRoot, "wp-content", "uploads", "process-owner.txt"))
	if err != nil {
		t.Fatal(err)
	}
	proofUID, proofGID, err := fileOwnerIDs(proof)
	if err != nil || proofUID != uid || proofGID != gid {
		t.Fatalf("PHP wrote the uploads file under another identity: uid=%d gid=%d err=%v", proofUID, proofGID, err)
	}
	t.Logf("OLS_SITE_PROCESS_OK: %s pid=%d uid=%d gid=%d locked=%t", site.Domain, result.PID, uid, gid, locked)
}
