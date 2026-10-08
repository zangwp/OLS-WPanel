//go:build linux

package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestDNSAtomicFileReplacementKeepsPermissionsAndIgnoresFixedTempSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	victim := filepath.Join(dir, "unrelated")
	if err := os.WriteFile(path, []byte("nameserver 8.8.8.8\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path+".new"); err != nil {
		t.Fatal(err)
	}
	original, err := readDNSFileSnapshot(path, false)
	if err != nil {
		t.Fatal(err)
	}
	next := original
	next.Data = []byte(dnsManagedMarker + "\nnameserver 1.1.1.1\n")
	if err := writeDNSFileSnapshotAtomic(path, next); err != nil {
		t.Fatal(err)
	}
	actual, err := readDNSFileSnapshot(path, false)
	if err != nil || !sameDNSSnapshot(next, actual) {
		t.Fatalf("replacement mismatch: %+v %v", actual, err)
	}
	unchanged, _ := os.ReadFile(victim)
	if string(unchanged) != "do not replace" {
		t.Fatal("fixed temp symlink target modified")
	}
	files, _ := os.ReadDir(dir)
	for _, file := range files {
		if strings.Contains(file.Name(), ".ols-dns-") {
			t.Fatal("temporary file not cleaned")
		}
	}
	if err := writeDNSFileSnapshotAtomic(path, original); err != nil {
		t.Fatal(err)
	}
	restored, _ := readDNSFileSnapshot(path, false)
	if !sameDNSSnapshot(original, restored) {
		t.Fatal("exact original not restored")
	}
}

func TestDNSFileIdentityRejectsSymlinksHardlinksWritableFilesAndAncestors(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "writable", "symlink-ancestor"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			original := filepath.Join(dir, "original")
			if err := os.WriteFile(original, []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "resolv.conf")
			switch kind {
			case "symlink":
				if err := os.Symlink(original, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(original, path); err != nil {
					t.Fatal(err)
				}
			case "writable":
				path = original
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			case "symlink-ancestor":
				real := filepath.Join(dir, "real")
				os.Mkdir(real, 0o700)
				os.WriteFile(filepath.Join(real, "resolv.conf"), []byte("unchanged"), 0o600)
				alias := filepath.Join(dir, "alias")
				if err := os.Symlink(real, alias); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(alias, "resolv.conf")
			}
			if _, err := readDNSFileSnapshot(path, false); err == nil {
				t.Fatal("unsafe file identity accepted")
			}
			uid, gid := dnsFileOwner()
			if err := writeDNSFileSnapshotAtomic(path, dnsFileSnapshot{Exists: true, Data: []byte("replacement"), Mode: 0o600, UID: uid, GID: gid}); err == nil {
				t.Fatal("unsafe file replaced")
			}
			data, _ := os.ReadFile(original)
			if string(data) != "unchanged" {
				t.Fatal("unsafe target modified")
			}
		})
	}
}

func TestDNSMissingDropInStatusDoesNotCreateDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent", "drop-in.conf")
	if snapshot, err := readDNSFileSnapshot(path, true); err != nil || snapshot.Exists {
		t.Fatalf("missing drop-in status wrong: %+v %v", snapshot, err)
	}
	if _, err := os.Lstat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only status created directories")
	}
}

func TestDNSStatusRejectsDeviceAndFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{fifo, "/dev/zero"} {
		link := filepath.Join(dir, "resolver-link")
		os.Remove(link)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := readDNSStatusFile(link); err == nil {
			t.Fatal("nonregular resolver source accepted")
		}
	}
}

func TestDNSPrivateLockSerializesProcessesAndRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "dns.lock")
	first, err := acquireDNSManagerLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	if second, err := acquireDNSManagerLock(path); err == nil {
		second()
		t.Fatal("concurrent independent lock succeeded")
	}
	first()
	second, err := acquireDNSManagerLock(path)
	if err != nil {
		t.Fatal(err)
	}
	second()
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("lock inode removed on release")
	}
	for _, kind := range []string{"public-directory", "public-file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "dns.lock")
			switch kind {
			case "public-directory":
				os.Chmod(dir, 0o755)
			case "public-file":
				os.WriteFile(path, nil, 0o644)
			case "symlink":
				target := filepath.Join(dir, "target")
				os.WriteFile(target, nil, 0o600)
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if unlock, err := acquireDNSManagerLock(path); err == nil {
				unlock()
				t.Fatal("unsafe lock accepted")
			}
		})
	}
}

func TestDNSManagerIdentifiesKnownSymlinkOwnersWithoutTakingOver(t *testing.T) {
	f := newDNSFixture(t)
	for _, tc := range []struct{ folder, manager string }{{"NetworkManager", "NetworkManager"}, {"resolvconf", "resolvconf"}, {"systemd/resolve", "systemd-resolved"}, {"unknown", "symbolic-link"}} {
		t.Run(tc.manager, func(t *testing.T) {
			os.Remove(f.paths.ResolvConf)
			target := filepath.Join(filepath.Dir(f.paths.ResolvConf), tc.folder, "resolv.conf")
			os.MkdirAll(filepath.Dir(target), 0o700)
			os.WriteFile(target, []byte("nameserver 8.8.8.8\n"), 0o600)
			if err := os.Symlink(target, f.paths.ResolvConf); err != nil {
				t.Fatal(err)
			}
			if manager := detectDNSManager(); manager != tc.manager {
				t.Fatalf("owner=%s, want %s", manager, tc.manager)
			}
		})
	}
}
