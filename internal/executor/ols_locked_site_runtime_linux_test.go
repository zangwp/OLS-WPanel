//go:build linux

package executor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
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
	controlLog := filepath.Join(root, "lswsctrl.log")
	t.Cleanup(func() {
		if t.Failed() {
			olsDumpRuntimeLogs(t, controlLog)
		}
		_, _ = olsRunRuntimeControl(control, "stop", controlLog)
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
	main := olsRuntimeMainConfigFromInstaller(t, "/src/install.sh", config.AppConfig.Paths.OLSManagedConfig)
	if err := os.WriteFile(config.AppConfig.Paths.OLSMainConfig, []byte(main), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/tmp/lshttpd/swap", 0755); err != nil {
		t.Fatal(err)
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	nobodyUID, uidErr := strconv.Atoi(nobody.Uid)
	nobodyGID, gidErr := strconv.Atoi(nobody.Gid)
	if uidErr != nil || gidErr != nil {
		t.Fatal("invalid nobody account in runtime container")
	}
	if err := os.Chown("/tmp/lshttpd", nobodyUID, nobodyGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown("/tmp/lshttpd/swap", nobodyUID, nobodyGID); err != nil {
		t.Fatal(err)
	}
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name == "systemctl" {
			if len(args) != 2 || args[0] != "restart" || args[1] != "lshttpd" {
				return nil, fmt.Errorf("unexpected runtime service operation: %v", args)
			}
			return olsRunRuntimeControl(control, "restart", controlLog)
		}
		return runOLSCommandBounded(60*time.Second, name, args...)
	}
	if err := ensureOLSDefaultVHost(currentOLSRuntimePaths()); err != nil {
		t.Fatal(err)
	}
	seenIDs := map[int]bool{}
	var sites []*models.Website
	var locked []*models.Website
	protected := map[int]map[string]olsLockedRuntimeEntry{}
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
$cache_write = @file_put_contents(__DIR__ . '/.lscache/php-write.txt', 'must be blocked for PHP');
echo json_encode(['site' => ` + strconv.Quote(domain) + `, 'pid' => getmypid(), 'written' => $written !== false, 'root_write' => $root_write !== false, 'cache_readable' => is_readable(__DIR__ . '/.lscache'), 'cache_write' => $cache_write !== false]);
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
		for _, current := range sites {
			olsAssertSiteProcessIdentity(t, client, current, current.ID < i)
		}
		for _, lockedSite := range locked {
			olsAssertLockedSiteRuntime(t, lockedSite, protected[lockedSite.ID])
		}
		if i < 3 {
			if err := ApplySiteFileLockMode(site, FileLockModeStandard); err != nil {
				t.Fatal(err)
			}
			if err := VerifySiteFileLockMode(site, FileLockModeStandard); err != nil {
				t.Fatal(err)
			}
			protected[site.ID] = olsLockedRuntimeSnapshot(t, site, false)
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
	olsAssertMaintenanceRuntime(t, client, sites[2], root, available, enabled, func() {
		for _, site := range locked {
			olsAssertSiteProcessIdentity(t, client, site, true)
			olsAssertLockedSiteRuntime(t, site, protected[site.ID])
		}
	})
	for _, site := range sites {
		olsAssertSiteProcessIdentity(t, client, site, site.ID < 3)
	}
	for _, site := range locked {
		olsAssertLockedSiteRuntime(t, site, protected[site.ID])
	}
	t.Log("OLS_LOCKED_SITE_RUNTIME_OK: three registered sites, two root-owned locked roots, independent PHP process UID/GID")
}

type olsLockedRuntimeEntry struct {
	directory bool
	digest    [sha256.Size]byte
}

func olsAssertLockedSiteRuntime(t *testing.T, site *models.Website, baseline map[string]olsLockedRuntimeEntry) {
	t.Helper()
	current := olsLockedRuntimeSnapshot(t, site, true)
	for path, before := range baseline {
		if after, exists := current[path]; !exists || after != before {
			t.Fatalf("protected website content changed after reload: %s/%s", site.Domain, path)
		}
	}
	for path := range current {
		if _, exists := baseline[path]; !exists {
			t.Fatalf("unexpected protected website content after reload: %s/%s", site.Domain, path)
		}
	}
}

// VerifySiteFileLockMode checks the immediate lock transition. The running OLS
// cache module owns .lscache as nobody:nogroup 02770; all website code retains
// the lock's strict owner/mode policy and the original content hashes.
func olsLockedRuntimeSnapshot(t *testing.T, site *models.Website, running bool) map[string]olsLockedRuntimeEntry {
	t.Helper()
	if err := rejectWPFileLockSymlinks(site.WebRoot); err != nil {
		t.Fatal(err)
	}
	if !wpConfigFileModsLocked(site.WebRoot) {
		t.Fatal("locked website lost DISALLOW_FILE_MODS")
	}
	uid, gid, err := siteUserIDs(site.SystemUser)
	if err != nil {
		t.Fatal(err)
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]olsLockedRuntimeEntry{}
	err = filepath.WalkDir(site.WebRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected symlink in runtime website fixture: %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		owner, group, err := fileOwnerIDs(info)
		if err != nil {
			return err
		}
		if path == filepath.Join(site.WebRoot, ".lscache") {
			if !info.IsDir() {
				return fmt.Errorf("OLS runtime cache is not a directory: %s", path)
			}
			if running {
				mode := info.Mode().Perm()
				if info.Mode()&os.ModeSetgid != 0 {
					mode |= 02000
				}
				t.Logf("OLS_RUNTIME_CACHE_METADATA: %s uid=%d gid=%d mode=%04o", path, owner, group, mode)
				if strconv.Itoa(owner) != nobody.Uid || strconv.Itoa(group) != nobody.Gid || info.Mode().Perm() != 0770 || info.Mode()&os.ModeSetgid == 0 || info.Mode()&(os.ModeSetuid|os.ModeSticky) != 0 {
					return fmt.Errorf("OLS runtime cache must remain nobody:nogroup 02770: %s", path)
				}
			}
			return filepath.SkipDir
		}
		writable := wpFileLockPermissionWritablePath(FileLockModeStandard, site.WebRoot, path, info.IsDir())
		wantOwner, wantMode := 0, os.FileMode(0444)
		if writable {
			wantOwner, wantMode = uid, modeForWritablePath(entry)
		} else if info.IsDir() {
			wantMode = 0555
		} else if path == filepath.Join(site.WebRoot, "wp-config.php") {
			wantMode = 0440
		}
		if owner != wantOwner || group != gid || info.Mode().Perm() != wantMode {
			return fmt.Errorf("runtime file lock metadata changed: %s uid=%d gid=%d mode=%v", path, owner, group, info.Mode())
		}
		if writable {
			return nil
		}
		relative, err := filepath.Rel(site.WebRoot, path)
		if err != nil {
			return err
		}
		snapshot := olsLockedRuntimeEntry{directory: info.IsDir()}
		if !info.IsDir() {
			contents, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			snapshot.digest = sha256.Sum256(contents)
		}
		entries[relative] = snapshot
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func olsAssertMaintenanceRuntime(t *testing.T, client *http.Client, site *models.Website, root, available, enabled string, assertOtherSites func()) {
	t.Helper()
	target, link := filepath.Join(available, site.Domain+".conf"), filepath.Join(enabled, site.Domain+".conf")
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	maintenanceRoot := filepath.Join(root, "maintenance")
	if err := os.Mkdir(maintenanceRoot, 0555); err != nil {
		t.Fatal(err)
	}
	const marker = "a31a9b36-2d77-4d82-8f55-b64fe66f4474"
	if err := os.WriteFile(filepath.Join(maintenanceRoot, "maintenance.html"), []byte("Website backup maintenance. "+marker), 0644); err != nil {
		t.Fatal(err)
	}
	// Preserve the historical bytes independently of the current renderer:
	// older backup journals authenticate this exact format by its hash.
	legacy := fmt.Sprintf(`# OLS-WPanel-Format: 1
# OLS-WPanel-VHost: olsw_%s
# OLS-WPanel-Domains: %s
# OLS-WPanel-VHRoot: %s
docRoot %s
vhDomain %s
enableGzip 0
index {
 useServer 0
 indexFiles maintenance.html
}
context / {
 type NULL
 location %s/
 allowBrowse 1
 extraHeaders <<<END_headers
Cache-Control: no-store
X-OLS-WPanel-Backup: %s
END_headers
}
rewrite {
 enable 1
 autoLoadHtaccess 0
 rules <<<END_rules
RewriteRule ^ - [R=503,L]
END_rules
}
`, buildSiteName(site.Domain), site.Domain, maintenanceRoot, maintenanceRoot, site.Domain, maintenanceRoot, marker)
	if err := applyOLSVHostConfig(nil, legacy, target, link); err != nil {
		t.Fatalf("apply legacy root-owned static maintenance: %v", err)
	}
	olsAssertMaintenanceRegistry(t, site, "www-data")
	olsAssertLegacyMaintenanceResponses(t, site)
	appliedLegacy, err := os.ReadFile(target)
	if err != nil || string(appliedLegacy) != legacy {
		t.Fatalf("legacy maintenance bytes changed during identity registration: %v", err)
	}
	assertOtherSites()
	t.Log("OLS_LEGACY_MAINTENANCE_RUNTIME_OK: unchanged historical template returns 503 for POST/GET/HEAD, disables PHP, and preserves the live website; historical response headers are not assumed")
	tlsSite := *site
	tlsSite.SSLEnabled = true
	tlsSite.SSLCertPath = currentOLSRuntimePaths().listenerCert
	tlsSite.SSLKeyPath = currentOLSRuntimePaths().listenerKey
	maintenance, err := renderSiteBackupMaintenance(&tlsSite, maintenanceRoot, marker)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(maintenance, olsMetadataUserPrefix+site.SystemUser+"\n") != 1 {
		t.Fatal("current maintenance renderer lost its explicit site identity")
	}
	if err := applyOLSVHostConfig(nil, maintenance, target, link); err != nil {
		t.Fatalf("apply current static maintenance: %v", err)
	}
	olsAssertMaintenanceRegistry(t, site, site.SystemUser)
	olsAssertCurrentMaintenanceResponses(t, &tlsSite, marker)
	assertOtherSites()
	t.Log("OLS_MAINTENANCE_HEADERS_RUNTIME_OK: current renderer passes production HTTP/HTTPS POST verification with real 503, backup marker, and no-store")
	info, err := os.Stat(maintenanceRoot)
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, err := fileOwnerIDs(info)
	if err != nil || uid != 0 || gid != 0 || info.Mode().Perm() != 0555 {
		t.Fatalf("maintenance root permissions changed: uid=%d gid=%d mode=%v err=%v", uid, gid, info.Mode(), err)
	}
	if err := applyOLSVHostConfig(nil, string(original), target, link); err != nil {
		t.Fatalf("restore PHP site after static maintenance: %v", err)
	}
	olsAssertSiteProcessIdentity(t, client, site, false)
}

func olsAssertMaintenanceRegistry(t *testing.T, site *models.Website, executionUser string) {
	t.Helper()
	registry, err := os.ReadFile(currentOLSRuntimePaths().managed)
	if err != nil {
		t.Fatal(err)
	}
	_, block, found := strings.Cut(string(registry), "virtualHost olsw_"+buildSiteName(site.Domain)+" {\n")
	if !found {
		t.Fatal("maintenance vhost is absent from registry")
	}
	block, _, _ = strings.Cut(block, "\n}")
	fields := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			fields[parts[0]] = parts[1]
		}
	}
	if fields["user"] != executionUser || fields["group"] != executionUser || fields["enableScript"] != "0" || fields["setUIDMode"] != "2" {
		t.Fatalf("maintenance enabled scripts or lost its intended execution identity: %s", block)
	}
}

func olsAssertLegacyMaintenanceResponses(t *testing.T, site *models.Website) {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lastReadiness := "no response"
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1/", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = site.Domain
		response, err := client.Do(request)
		if err == nil {
			_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 8192))
			response.Body.Close()
			lastReadiness = fmt.Sprintf("HTTP %d read=%v", response.StatusCode, readErr)
			if response.StatusCode == http.StatusServiceUnavailable && readErr == nil {
				break
			}
		} else if ctx.Err() == nil {
			lastReadiness = err.Error()
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatalf("legacy maintenance never became ready: %s; %v", lastReadiness, ctx.Err())
		case <-timer.C:
		}
	}
	proofPath := filepath.Join(site.WebRoot, "wp-content", "uploads", "process-owner.txt")
	proof, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodHead} {
		for _, path := range []string{"/", "/wp-login.php", "/wp-cron.php", "/wp-json/", "/index.php"} {
			request, err := http.NewRequest(method, "http://127.0.0.1"+path, strings.NewReader("backup_probe=1"))
			if err != nil {
				t.Fatal(err)
			}
			request.Host = site.Domain
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("legacy maintenance %s %s: %v", method, path, err)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
			response.Body.Close()
			if readErr != nil || response.StatusCode != http.StatusServiceUnavailable || strings.Contains(string(body), `"site":"`+site.Domain+`"`) {
				t.Fatalf("legacy maintenance did not stop the PHP endpoint: %s %s status=%d body=%q err=%v", method, path, response.StatusCode, body, readErr)
			}
			t.Logf("OLS_LEGACY_MAINTENANCE_HTTP: %s %s status=%d cache-control=%q backup-marker=%q", method, path,
				response.StatusCode, response.Header.Values("Cache-Control"), response.Header.Values("X-OLS-WPanel-Backup"))
		}
	}
	after, err := os.Stat(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(proofPath)
	if err != nil || string(contents) != string(proof) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("legacy maintenance allowed the original PHP probe to write its uploads file: %v", err)
	}
}

func olsAssertCurrentMaintenanceResponses(t *testing.T, site *models.Website, marker string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var firstFailure, lastFailure error
	for {
		err := verifySiteBackupMaintenance(ctx, site, marker, true)
		if err == nil {
			break
		}
		if firstFailure == nil {
			firstFailure = err
			t.Logf("OLS_MAINTENANCE_FIRST_FAILURE: %v", err)
			olsMaintenanceHTTPDiagnostics(t, site.Domain)
		}
		if ctx.Err() == nil {
			lastFailure = err
		}
		if ctx.Err() != nil {
			t.Fatalf("current maintenance failed real HTTP 503 verification: first=%v; last before deadline=%v; final=%v", firstFailure, lastFailure, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func olsMaintenanceHTTPDiagnostics(t *testing.T, domain string) {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	for _, probe := range []struct{ method, path string }{
		{http.MethodPost, "/"}, {http.MethodPost, "/wp-login.php"}, {http.MethodPost, "/wp-cron.php"},
		{http.MethodPost, "/wp-json/"}, {http.MethodGet, "/"}, {http.MethodHead, "/"},
	} {
		request, err := http.NewRequest(probe.method, "http://127.0.0.1"+probe.path, strings.NewReader("backup_probe=1"))
		if err != nil {
			t.Logf("OLS_MAINTENANCE_HTTP: request %s %s: %v", probe.method, probe.path, err)
			continue
		}
		request.Host = domain
		response, err := client.Do(request)
		if err != nil {
			t.Logf("OLS_MAINTENANCE_HTTP: %s %s: %v", probe.method, probe.path, err)
			continue
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 512))
		response.Body.Close()
		t.Logf("OLS_MAINTENANCE_HTTP: %s %s status=%d cache-control=%q backup-marker=%q content-type=%q read=%v body=%q", probe.method, probe.path,
			response.StatusCode, response.Header.Values("Cache-Control"), response.Header.Values("X-OLS-WPanel-Backup"), response.Header.Get("Content-Type"), readErr, body)
	}
}

func olsRuntimeMainConfigFromInstaller(t *testing.T, path, managed string) string {
	t.Helper()
	script, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const start = "cat > \"$OLS_MAIN_CONF\" << 'OLSHTTPEOF'\n"
	const end = "\nOLSHTTPEOF\n"
	text := strings.ReplaceAll(string(script), "\r\n", "\n")
	if strings.Count(text, start) != 1 {
		t.Fatal("installer must have one production OpenLiteSpeed main configuration")
	}
	_, remainder, _ := strings.Cut(text, start)
	main, _, found := strings.Cut(remainder, end)
	if !found {
		t.Fatal("unterminated installer OpenLiteSpeed main configuration")
	}
	const include = "include /usr/local/lsws/conf/ols-wpanel/sites.conf"
	if strings.Count(main, include) != 1 {
		t.Fatal("installer main configuration must include the managed registry exactly once")
	}
	return strings.Replace(main, include, "include "+managed, 1) + "\n"
}

// A daemon can inherit lswsctrl's output descriptors. Use a regular file so
// checking the controller's real exit status never waits for the daemon's EOF.
func olsRunRuntimeControl(control, action, logPath string) ([]byte, error) {
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(log, "\n$ lswsctrl %s\n", action); err != nil {
		log.Close()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, control, action)
	command.Stdout, command.Stderr = log, log
	runErr := command.Run()
	closeErr := log.Close()
	output, readErr := os.ReadFile(logPath)
	if ctx.Err() != nil {
		return output, fmt.Errorf("lswsctrl %s timed out: %w", action, ctx.Err())
	}
	return output, errors.Join(runErr, closeErr, readErr)
}

func olsDumpRuntimeLogs(t *testing.T, controlLog string) {
	t.Helper()
	for _, path := range []string{controlLog, "/usr/local/lsws/logs/error.log", "/usr/local/lsws/logs/lsrestart.log", "/usr/local/lsws/logs/stderr.log"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Logf("runtime diagnostic %s: %v", path, err)
			continue
		}
		if len(data) > 32<<10 {
			data = data[len(data)-(32<<10):]
		}
		t.Logf("runtime diagnostic %s:\n%s", path, data)
	}
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
		Site       string `json:"site"`
		PID        int    `json:"pid"`
		Written    bool   `json:"written"`
		RootWrite  bool   `json:"root_write"`
		CacheRead  bool   `json:"cache_readable"`
		CacheWrite bool   `json:"cache_write"`
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
	if result.Site != site.Domain || result.PID <= 1 || !result.Written || (locked && result.RootWrite) || result.CacheRead || result.CacheWrite {
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
