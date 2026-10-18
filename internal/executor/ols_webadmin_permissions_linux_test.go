//go:build linux

package executor

import (
	"bytes"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func TestOLSWebAdminReadAccessLinux(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root for independent WebAdmin and website user checks")
	}
	const adminUID, phpUID, sharedGID = 61001, 61002, 65534
	fixture, err := os.MkdirTemp("/tmp", "ols-webadmin-permissions-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(fixture) })
	if err := os.Chmod(fixture, 0755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(fixture, "lsws")
	managed := filepath.Join(root, "conf", "ols-wpanel")
	available := filepath.Join(managed, "sites-available")
	for _, directory := range []string{root, filepath.Dir(managed), managed, available} {
		if err := os.MkdirAll(directory, 0750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(filepath.Dir(managed), adminUID, sharedGID); err != nil {
		t.Fatal(err)
	}
	// Let PHP traverse the same directories, so a bad ACL grant cannot hide
	// behind a separate parent-directory denial.
	for _, directory := range []string{root, managed, available} {
		if err := os.Chmod(directory, 0751); err != nil {
			t.Fatal(err)
		}
	}
	main := filepath.Join(root, "conf", "httpd_config.conf")
	registry := filepath.Join(managed, "sites.conf")
	fallback := filepath.Join(managed, "default-vhost.conf")
	vhost := filepath.Join(available, "example.com.conf")
	private := filepath.Join(managed, "default.key")
	certificate := filepath.Join(managed, "default.crt")
	unrelated := filepath.Join(managed, "credentials.conf")
	runtimeSecret := filepath.Join(root, "admin", "tmp", "session")
	if err := os.MkdirAll(filepath.Dir(runtimeSecret), 0755); err != nil {
		t.Fatal(err)
	}
	vhostContent := "# OLS-WPanel-Format: 1\n# OLS-WPanel-VHost: olsw_example\n# OLS-WPanel-Domains: example.com\n# OLS-WPanel-VHRoot: /www/example.com\ndocRoot /www/example.com/\n"
	content := map[string]string{
		main:     "serverName OLS-WPanel\ninclude " + registry + "\n",
		registry: "# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.\n",
		fallback: "docRoot /www/default/\n", vhost: vhostContent,
		private: "private key fixture", certificate: "certificate fixture", unrelated: "unrelated credential fixture", runtimeSecret: "session fixture",
	}
	for path, data := range content {
		if err := os.WriteFile(path, []byte(data), 0640); err != nil {
			t.Fatal(err)
		}
	}
	oldConfig, oldLookup := config.AppConfig, lookupOLSWebAdminUser
	t.Cleanup(func() { config.AppConfig, lookupOLSWebAdminUser = oldConfig, oldLookup })
	config.AppConfig = &config.Config{Paths: config.PathsConfig{OLSRoot: root, OLSMainConfig: main, OLSManagedConfig: registry, OLSVHostsAvailable: available}}
	lookupOLSWebAdminUser = func(string) (*user.User, error) {
		return &user.User{Uid: "61001", Gid: "65534"}, nil
	}
	canOpen := func(uid uint32, path string, write bool) bool {
		script := `exec 3<"$1"`
		if write {
			script = `exec 3>>"$1"`
		}
		cmd := exec.Command("/bin/sh", "-c", script, "acl-test", path)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: sharedGID, Groups: []uint32{sharedGID}}}
		return cmd.Run() == nil
	}
	assertAccess := func() {
		t.Helper()
		for _, path := range []string{main, registry, fallback, vhost} {
			if !canOpen(adminUID, path, false) || canOpen(adminUID, path, true) || canOpen(phpUID, path, false) {
				t.Fatalf("incorrect WebAdmin read-only or shared-group isolation: %s", path)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			owner, group, err := fileOwnerIDs(info)
			if err != nil || owner != 0 || group != 0 || info.Mode().Perm() != 0640 {
				t.Fatalf("root-owned 0640 config metadata changed: %s", path)
			}
		}
		for _, path := range []string{private, certificate, unrelated, runtimeSecret} {
			if canOpen(adminUID, path, false) || canOpen(phpUID, path, false) {
				t.Fatalf("read grant escaped the managed configuration allowlist: %s", path)
			}
		}
	}
	if canOpen(adminUID, main, false) {
		t.Fatal("fixture did not reproduce root-owned configuration denial")
	}
	if err := EnsureOLSWebAdminConfigReadAccess(); err != nil {
		t.Fatal(err)
	}
	assertAccess()
	if err := EnsureOLSWebAdminConfigReadAccess(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{registry, fallback, vhost, private, certificate, unrelated, runtimeSecret} {
		if err := writeOLSFileAtomic(path, []byte(content[path]), 0640); err != nil {
			t.Fatal(err)
		}
	}
	newVHost := filepath.Join(available, "new.example.com.conf")
	if err := writeOLSFileAtomic(newVHost, []byte(vhostContent), 0640); err != nil {
		t.Fatal(err)
	}
	if !canOpen(adminUID, newVHost, false) || canOpen(phpUID, newVHost, false) || canOpen(adminUID, newVHost, true) {
		t.Fatal("newly created vhost did not retain isolated WebAdmin read access")
	}
	metadata, err := os.Stat(main)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOLSTrustedProxyConfigAtomic(main, []byte(content[main]+"# updated proxy config\n"), metadata); err != nil {
		t.Fatal(err)
	}
	assertAccess()
	if err := writeOLSTrustedProxyConfigAtomic(main, []byte(content[main]), metadata); err != nil {
		t.Fatal(err)
	}
	assertAccess()
	for _, target := range []string{vhost, available} {
		t.Run("reject-link-"+filepath.Base(target), func(t *testing.T) {
			original := target + ".original"
			if err := os.Rename(target, original); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Remove(target); os.Rename(original, target) })
			if err := os.Symlink(original, target); err != nil {
				t.Fatal(err)
			}
			if err := EnsureOLSWebAdminConfigReadAccess(); err == nil {
				t.Fatal("symlink was accepted for configuration permissions")
			}
		})
	}
	t.Run("reject-hardlink", func(t *testing.T) {
		link := filepath.Join(fixture, "vhost-hardlink")
		if err := os.Link(vhost, link); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(link)
		if err := EnsureOLSWebAdminConfigReadAccess(); err == nil {
			t.Fatal("hardlinked configuration was accepted")
		}
	})
	t.Run("preserve-unrelated-effective-acl", func(t *testing.T) {
		file, err := os.OpenFile(main, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		old := encodeOLSACLForTest(olsACLEntry{olsACLUserObj, 6, olsACLNoID}, olsACLEntry{olsACLUser, 4, phpUID}, olsACLEntry{olsACLGroupObj, 4, olsACLNoID}, olsACLEntry{olsACLMask, 0, olsACLNoID}, olsACLEntry{olsACLOther, 0, olsACLNoID})
		if err := writeOLSAccessACL(file, old); err != nil {
			t.Fatal(err)
		}
		if err := EnsureOLSWebAdminConfigReadAccess(); err != nil {
			t.Fatal(err)
		}
		if !canOpen(adminUID, main, false) || canOpen(phpUID, main, false) {
			t.Fatal("ACL mask expansion exposed the config to a previously masked user")
		}
	})
	t.Run("reject-unmanaged-conf", func(t *testing.T) {
		path := filepath.Join(available, "secret.conf")
		if err := writeOLSFileAtomic(path, []byte("private unrelated configuration"), 0640); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(path)
		if canOpen(adminUID, path, false) {
			t.Fatal(".conf extension alone granted access to an unrelated file")
		}
		if err := EnsureOLSWebAdminConfigReadAccess(); err == nil {
			t.Fatal("backfill accepted a .conf without managed metadata")
		}
	})
	for path, expected := range content {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, []byte(expected)) {
			t.Fatalf("permission repair changed config contents: %s: %v", path, err)
		}
	}
}
