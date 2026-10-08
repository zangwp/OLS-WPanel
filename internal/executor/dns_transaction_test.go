package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Every mutation and network operation is replaced with bounded fixture I/O.
// These tests never read or write the host's DNS, attributes, services or routes.
type dnsFixture struct {
	t                *testing.T
	paths            dnsManagerPaths
	metadata         map[string]dnsFileSnapshot
	writes           []string
	probes           []string
	denied           map[string]bool
	resolved, ipv6   bool
	verify           func(context.Context) error
	writeFailure     func(string, dnsFileSnapshot) error
	restartFailure   bool
	resolvedInactive bool
}

func newDNSFixture(t *testing.T) *dnsFixture {
	t.Helper()
	dir := t.TempDir()
	f := &dnsFixture{t: t, paths: dnsManagerPaths{ResolvConf: filepath.Join(dir, "resolv.conf"), DropIn: filepath.Join(dir, "resolved.conf.d", "50-ols-wpanel-dns.conf"), Backup: filepath.Join(dir, "private", "original.json"), Lock: filepath.Join(dir, "run", "dns.lock")}, metadata: map[string]dnsFileSnapshot{}, denied: map[string]bool{}, ipv6: true}
	oldPaths, oldSupported, oldCommand := dnsPaths, dnsSupported, dnsCommandContext
	oldRead, oldWrite, oldLock, oldPrivate := dnsReadSnapshot, dnsWriteSnapshot, dnsAcquireLock, dnsPrivateDirectory
	oldProbe, oldVerify := dnsProbeAddress, dnsVerifyCurrent
	oldManager := dnsDetectManager
	t.Cleanup(func() {
		dnsPaths, dnsSupported, dnsCommandContext = oldPaths, oldSupported, oldCommand
		dnsReadSnapshot, dnsWriteSnapshot, dnsAcquireLock, dnsPrivateDirectory = oldRead, oldWrite, oldLock, oldPrivate
		dnsProbeAddress, dnsVerifyCurrent = oldProbe, oldVerify
		dnsDetectManager = oldManager
	})
	dnsPaths = f.paths
	dnsSupported = func() bool { return true }
	dnsDetectManager = func() string {
		if f.resolved {
			return "systemd-resolved"
		}
		return detectDNSManager()
	}
	dnsReadSnapshot = f.read
	dnsWriteSnapshot = f.write
	dnsAcquireLock = func(path string) (func(), error) { f.bound(path); return func() {}, nil }
	dnsPrivateDirectory = func(path string, create bool) error {
		f.bound(path)
		if create {
			return os.MkdirAll(filepath.Dir(path), 0o700)
		}
		_, err := os.Lstat(filepath.Dir(path))
		return err
	}
	dnsProbeAddress = func(_ context.Context, network, address string) bool {
		f.probes = append(f.probes, network+":"+address)
		return !f.denied[address]
	}
	dnsVerifyCurrent = func(ctx context.Context) error {
		if f.verify != nil {
			return f.verify(ctx)
		}
		return nil
	}
	dnsCommandContext = f.command
	f.put(f.paths.ResolvConf, []byte("# administrator comment\nsearch example.internal\noptions timeout:2 attempts:3\nnameserver 8.8.8.8\n"), 0o640, false)
	return f
}

func (f *dnsFixture) bound(path string) {
	f.t.Helper()
	if path != f.paths.ResolvConf && path != f.paths.DropIn && path != f.paths.Backup && path != f.paths.Lock {
		f.t.Fatalf("fixture attempted host path: %q", path)
	}
}
func (f *dnsFixture) put(path string, data []byte, mode uint32, immutable bool) {
	f.t.Helper()
	f.bound(path)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		f.t.Fatal(err)
	}
	uid, gid := dnsFileOwner()
	f.metadata[path] = dnsFileSnapshot{Exists: true, Data: append([]byte{}, data...), Mode: mode, UID: uid, GID: gid, Immutable: immutable}
}
func (f *dnsFixture) read(path string, allowMissing bool) (dnsFileSnapshot, error) {
	f.bound(path)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return dnsFileSnapshot{}, nil
	}
	if err != nil {
		return dnsFileSnapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return dnsFileSnapshot{}, errors.New("fixture rejects symlink and special file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return dnsFileSnapshot{}, err
	}
	meta := f.metadata[path]
	meta.Exists, meta.Data = true, data
	return meta, nil
}
func (f *dnsFixture) write(path string, next dnsFileSnapshot) error {
	f.bound(path)
	f.writes = append(f.writes, path)
	if f.writeFailure != nil {
		if err := f.writeFailure(path, next); err != nil {
			return err
		}
	}
	if !next.Exists {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		delete(f.metadata, path)
		return err
	}
	f.put(path, next.Data, next.Mode, next.Immutable)
	f.metadata[path] = next
	return nil
}
func (f *dnsFixture) command(ctx context.Context, name string, args ...string) *exec.Cmd {
	output, ok := "", false
	joined := name + " " + strings.Join(args, " ")
	switch joined {
	case "systemctl is-active --quiet NetworkManager":
		ok = false
	case "systemctl is-active --quiet systemd-resolved":
		ok = f.resolved && !f.resolvedInactive
	case "systemctl restart systemd-resolved":
		ok = !f.restartFailure
	case "ip -6 route show default":
		ok = true
		if f.ipv6 {
			output = "default via 2001:db8::1 dev eth0"
		}
	case "resolvectl dns --no-pager":
		ok = true
		s, _ := f.read(f.paths.DropIn, true)
		if s.Exists {
			for _, line := range strings.Split(string(s.Data), "\n") {
				if strings.HasPrefix(line, "DNS=") {
					output = strings.TrimPrefix(line, "DNS=")
				}
			}
		} else {
			output = "8.8.8.8"
		}
	default:
		f.t.Fatalf("unexpected external DNS fixture command: %s", joined)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDNSCommandFixtureProcess$", "--")
	cmd.Env = append(os.Environ(), "OLS_DNS_FIXTURE_PROCESS=1", "OLS_DNS_FIXTURE_OK="+fmt.Sprint(ok), "OLS_DNS_FIXTURE_OUTPUT="+base64.StdEncoding.EncodeToString([]byte(output)))
	return cmd
}

func TestDNSCommandFixtureProcess(t *testing.T) {
	if os.Getenv("OLS_DNS_FIXTURE_PROCESS") != "1" {
		return
	}
	data, _ := base64.StdEncoding.DecodeString(os.Getenv("OLS_DNS_FIXTURE_OUTPUT"))
	fmt.Print(string(data))
	if os.Getenv("OLS_DNS_FIXTURE_OK") == "true" {
		os.Exit(0)
	}
	os.Exit(1)
}

func TestDNSStaticTakeoverPreservesNonNameserverLinesAndOriginalAttributes(t *testing.T) {
	f := newDNSFixture(t)
	f.metadata[f.paths.ResolvConf] = func() dnsFileSnapshot { s := f.metadata[f.paths.ResolvConf]; s.Immutable = true; return s }()
	original, _ := f.read(f.paths.ResolvConf, false)
	status := GetDNSStatus()
	if status.Manager != "static-resolv.conf" || !status.Configurable || !status.TakeoverRequired || !status.Immutable {
		t.Fatalf("static file not available for explicit takeover: %+v", status)
	}
	status, err := ApplyCustomDNS(context.Background(), "1.1.1.1,2606:4700:4700::1111")
	if err != nil {
		t.Fatal(err)
	}
	if status.Manager != "ols-resolv.conf" || !status.Managed || !status.RestoreAvailable || status.TakeoverRequired {
		t.Fatalf("managed status wrong: %+v", status)
	}
	actual, _ := f.read(f.paths.ResolvConf, false)
	for _, retained := range []string{"# administrator comment", "search example.internal", "options timeout:2 attempts:3"} {
		if !strings.Contains(string(actual.Data), retained) {
			t.Fatal("lost " + retained)
		}
	}
	if strings.Contains(string(actual.Data), "8.8.8.8") || actual.Mode != original.Mode || actual.UID != original.UID || actual.GID != original.GID || !actual.Immutable {
		t.Fatalf("state not preserved: %+v", actual)
	}
	backup, err := readDNSBackup(f.paths, f.paths.ResolvConf)
	if err != nil || !sameDNSSnapshot(backup.Original, original) {
		t.Fatalf("original not backed up: %+v %v", backup, err)
	}
	// A second edit must retain the first takeover's original, not replace it
	// with the first managed configuration.
	if _, err := ApplyDNSPreset(context.Background(), "mainland_china"); err != nil {
		t.Fatal(err)
	}
	backup, err = readDNSBackup(f.paths, f.paths.ResolvConf)
	if err != nil || !sameDNSSnapshot(backup.Original, original) {
		t.Fatal("repeated edit replaced original backup")
	}
	status, err = RestoreAutomaticDNS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	restored, _ := f.read(f.paths.ResolvConf, false)
	if !sameDNSSnapshot(original, restored) || status.Managed || status.Manager != "static-resolv.conf" {
		t.Fatalf("original not restored exactly: %+v %+v", restored, status)
	}
}

func TestDNSRejectedCustomAddressesAndUnreachableSelectionNeverWrite(t *testing.T) {
	for _, value := range []string{"", "1.1.1.1,", "example.com", "1.1.1.1:53", "1.1.1.1,$(id)", "0.0.0.0", "::", "ff02::1", "fe80::1%eth0", "1.1.1.1,1.1.1.1", "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5"} {
		t.Run(value, func(t *testing.T) {
			f := newDNSFixture(t)
			if _, err := ApplyCustomDNS(context.Background(), value); err == nil {
				t.Fatal("invalid value accepted")
			}
			if len(f.writes) != 0 {
				t.Fatal("invalid input wrote files")
			}
		})
	}
	t.Run("one unreachable custom", func(t *testing.T) {
		f := newDNSFixture(t)
		f.denied["8.8.8.8"] = true
		if _, err := ApplyCustomDNS(context.Background(), "1.1.1.1,8.8.8.8"); err == nil {
			t.Fatal("partially failing custom selection accepted")
		}
		if len(f.writes) != 0 {
			t.Fatal("failed DNS probe wrote files")
		}
	})
	t.Run("missing IPv6 route", func(t *testing.T) {
		f := newDNSFixture(t)
		f.ipv6 = false
		if _, err := ApplyCustomDNS(context.Background(), "2606:4700:4700::1111"); err == nil {
			t.Fatal("IPv6 without route accepted")
		}
		if len(f.writes) != 0 {
			t.Fatal("unsupported IPv6 selection wrote files")
		}
	})
	t.Run("all preset candidates unreachable", func(t *testing.T) {
		f := newDNSFixture(t)
		p, _ := findDNSPreset("international")
		for _, ip := range append(p.IPv4, p.IPv6...) {
			f.denied[ip] = true
		}
		if _, err := ApplyDNSPreset(context.Background(), p.ID); err == nil {
			t.Fatal("failed preset accepted")
		}
		if len(f.writes) != 0 {
			t.Fatal("failed preset wrote files")
		}
	})
}

func TestDNSPresetsWriteOnlyIndividuallyVerifiedAddresses(t *testing.T) {
	f := newDNSFixture(t)
	f.denied["1.0.0.1"] = true
	f.denied["2606:4700:4700::1001"] = true
	status, err := ApplyDNSPreset(context.Background(), "international")
	if err != nil {
		t.Fatal(err)
	}
	if !status.IPv4ProbeOK || !status.IPv6ProbeOK {
		t.Fatal("probe outcomes lost")
	}
	actual, _ := f.read(f.paths.ResolvConf, false)
	if strings.Join(parseResolvConf(string(actual.Data)), ",") != "1.1.1.1,2606:4700:4700::1111" {
		t.Fatal("unverified server written")
	}
}

func TestDNSCustomAddressesPreserveConfiguredPriority(t *testing.T) {
	f := newDNSFixture(t)
	value := "2606:4700:4700::1111,1.1.1.1,2606:4700:4700::1001"
	if _, err := ApplyCustomDNS(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	actual, _ := f.read(f.paths.ResolvConf, false)
	if strings.Join(parseResolvConf(string(actual.Data)), ",") != value {
		t.Fatal("custom priority changed by grouping address families")
	}
	preset, err := ParseCustomDNS(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(renderResolvedDNSConfig(preset, true), "DNS="+strings.ReplaceAll(value, ",", " ")) {
		t.Fatal("resolved custom priority changed")
	}
}

func TestDNSBackendLimitsMatchOrdinaryResolverAndResolved(t *testing.T) {
	t.Run("static rejects fourth custom server", func(t *testing.T) {
		f := newDNSFixture(t)
		status := GetDNSStatus()
		if status.MaxServers != 3 || status.Warning == "" {
			t.Fatalf("ordinary resolver limit missing: %+v", status)
		}
		value := "1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001"
		if _, err := ProbeCustomDNS(context.Background(), value); err == nil || !strings.Contains(err.Error(), "3 台") {
			t.Fatalf("four-address probe accepted: %v", err)
		}
		if _, err := ApplyCustomDNS(context.Background(), value); err == nil || !strings.Contains(err.Error(), "3 台") {
			t.Fatalf("four-address custom write accepted: %v", err)
		}
		if len(f.writes) != 0 || len(f.probes) != 0 {
			t.Fatal("over-limit custom selection wrote or probed")
		}
	})
	t.Run("static preset keeps first three verified servers", func(t *testing.T) {
		f := newDNSFixture(t)
		status, err := ApplyDNSPreset(context.Background(), "international")
		if err != nil {
			t.Fatal(err)
		}
		actual, _ := f.read(f.paths.ResolvConf, false)
		if got := strings.Join(parseResolvConf(string(actual.Data)), ","); got != "1.1.1.1,1.0.0.1,2606:4700:4700::1111" {
			t.Fatalf("preset priority or limit wrong: %s", got)
		}
		if status.MaxServers != 3 || status.Warning == "" || !status.IPv6ProbeOK || len(f.probes) != 4 {
			t.Fatalf("limit/probe outcome not visible: %+v %v", status, f.probes)
		}
	})
	t.Run("resolved preserves four custom servers", func(t *testing.T) {
		f := newDNSFixture(t)
		f.resolved = true
		value := "2606:4700:4700::1111,1.1.1.1,2606:4700:4700::1001,1.0.0.1"
		status, err := ApplyCustomDNS(context.Background(), value)
		if err != nil {
			t.Fatal(err)
		}
		actual, _ := f.read(f.paths.DropIn, false)
		if status.MaxServers != 4 || !strings.Contains(string(actual.Data), "DNS="+strings.ReplaceAll(value, ",", " ")) {
			t.Fatalf("resolved four-address configuration changed: %+v %s", status, actual.Data)
		}
	})
}

func TestDNSGeneratedManagersRemainReadOnly(t *testing.T) {
	for _, tc := range []struct{ header, manager string }{{"# Generated by NetworkManager", "NetworkManager"}, {"# Generated by resolvconf", "resolvconf"}, {"# Generated by cloud-init", "cloud-init"}, {"# Generated by dhclient", "dhcp"}, {"# Generated by netplan", "netplan"}, {"# Automatically generated DNS configuration", "auto-generated"}, {"# Generated file\n# NetworkManager", "NetworkManager"}} {
		t.Run(tc.manager, func(t *testing.T) {
			f := newDNSFixture(t)
			f.put(f.paths.ResolvConf, []byte(tc.header+"\nnameserver 8.8.8.8\n"), 0o644, false)
			status := GetDNSStatus()
			if status.Manager != tc.manager || status.Configurable || strings.Contains(status.Reason, "云厂商") {
				t.Fatalf("wrong manager or assumed vendor: %+v", status)
			}
			if _, err := ApplyDNSPreset(context.Background(), "international"); err == nil {
				t.Fatal("generated file modified")
			}
			if len(f.writes) != 0 {
				t.Fatal("generated DNS file wrote files")
			}
		})
	}
}

func TestDNSVerificationFailureRollsBackAndReportsFailedRollback(t *testing.T) {
	t.Run("successful verified rollback", func(t *testing.T) {
		f := newDNSFixture(t)
		original, _ := f.read(f.paths.ResolvConf, false)
		calls := 0
		f.verify = func(context.Context) error {
			calls++
			if calls == 1 {
				return errors.New("synthetic lookup failure")
			}
			return nil
		}
		status, err := ApplyDNSPreset(context.Background(), "international")
		if err == nil || !strings.Contains(err.Error(), "已恢复修改前") || strings.Contains(err.Error(), "回滚未验证成功") {
			t.Fatalf("wrong rollback result: %v", err)
		}
		actual, _ := f.read(f.paths.ResolvConf, false)
		if !sameDNSSnapshot(actual, original) || status.Managed {
			t.Fatal("rollback not reflected in returned status")
		}
	})
	t.Run("rollback lookup also fails", func(t *testing.T) {
		f := newDNSFixture(t)
		f.verify = func(context.Context) error { return errors.New("synthetic lookup failure") }
		_, err := ApplyDNSPreset(context.Background(), "international")
		if err == nil || !strings.Contains(err.Error(), "自动回滚未验证成功") || !strings.Contains(err.Error(), f.paths.Backup) {
			t.Fatalf("failed rollback hidden or recovery path missing: %v", err)
		}
	})
	t.Run("rollback file cannot be written", func(t *testing.T) {
		f := newDNSFixture(t)
		original, _ := f.read(f.paths.ResolvConf, false)
		f.verify = func(context.Context) error { return errors.New("synthetic lookup failure") }
		f.writeFailure = func(path string, next dnsFileSnapshot) error {
			if path == f.paths.ResolvConf && sameDNSSnapshot(next, original) {
				return errors.New("synthetic restoration failure")
			}
			return nil
		}
		_, err := ApplyDNSPreset(context.Background(), "international")
		if err == nil || !strings.Contains(err.Error(), "自动回滚未验证成功") {
			t.Fatalf("write rollback failure hidden: %v", err)
		}
	})
	t.Run("outside writer preserved", func(t *testing.T) {
		f := newDNSFixture(t)
		f.verify = func(context.Context) error {
			os.WriteFile(f.paths.ResolvConf, []byte("# Changed outside OLS\nnameserver 9.9.9.9\n"), 0o600)
			return errors.New("synthetic lookup failure")
		}
		_, err := ApplyDNSPreset(context.Background(), "international")
		actual, _ := f.read(f.paths.ResolvConf, false)
		if err == nil || !strings.Contains(err.Error(), "未知 DNS 文件内容") || !strings.Contains(string(actual.Data), "9.9.9.9") {
			t.Fatalf("outside writer overwritten: %s %v", actual.Data, err)
		}
	})
}

func TestDNSRestoreFailureReturnsToManagedConfiguration(t *testing.T) {
	f := newDNSFixture(t)
	if _, err := ApplyCustomDNS(context.Background(), "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	managed, _ := f.read(f.paths.ResolvConf, false)
	calls := 0
	f.verify = func(context.Context) error {
		calls++
		if calls == 1 {
			return errors.New("old upstream unavailable")
		}
		return nil
	}
	status, err := RestoreAutomaticDNS(context.Background())
	actual, _ := f.read(f.paths.ResolvConf, false)
	if err == nil || !sameDNSSnapshot(actual, managed) || !status.Managed || !status.RestoreAvailable {
		t.Fatalf("failed restore lost working managed state: %+v %v", status, err)
	}
}

func TestDNSManagedChangesAndCorruptBackupsAreRejected(t *testing.T) {
	t.Run("outside managed edit", func(t *testing.T) {
		f := newDNSFixture(t)
		if _, err := ApplyCustomDNS(context.Background(), "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
		s, _ := f.read(f.paths.ResolvConf, false)
		f.put(f.paths.ResolvConf, append(s.Data, []byte("nameserver 9.9.9.9\n")...), s.Mode, s.Immutable)
		before := len(f.writes)
		status := GetDNSStatus()
		if status.Configurable || status.RestoreAvailable {
			t.Fatal("foreign edit accepted")
		}
		if _, err := RestoreAutomaticDNS(context.Background()); err == nil {
			t.Fatal("foreign edit overwritten")
		}
		if len(f.writes) != before {
			t.Fatal("foreign edit caused writes")
		}
	})
	t.Run("missing backup", func(t *testing.T) {
		f := newDNSFixture(t)
		f.put(f.paths.ResolvConf, []byte(dnsManagedMarker+"\nnameserver 1.1.1.1\n"), 0o644, false)
		if status := GetDNSStatus(); status.Configurable || status.ReasonCode != "backup_unavailable" {
			t.Fatalf("missing original accepted: %+v", status)
		}
	})
	t.Run("invalid backup", func(t *testing.T) {
		f := newDNSFixture(t)
		if _, err := ApplyCustomDNS(context.Background(), "1.1.1.1"); err != nil {
			t.Fatal(err)
		}
		s, _ := f.read(f.paths.Backup, false)
		var backup map[string]any
		json.Unmarshal(s.Data, &backup)
		backup["target"] = "/etc/passwd"
		data, _ := json.Marshal(backup)
		f.put(f.paths.Backup, data, 0o600, false)
		before := len(f.writes)
		if _, err := RestoreAutomaticDNS(context.Background()); err == nil {
			t.Fatal("wrong-target backup accepted")
		}
		if len(f.writes) != before {
			t.Fatal("wrong-target backup caused writes")
		}
	})
}

func TestDNSResolvedDropInAndLegacyRestoreAreCompatible(t *testing.T) {
	t.Run("new resolved override restores absence", func(t *testing.T) {
		f := newDNSFixture(t)
		f.resolved = true
		original, _ := f.read(f.paths.ResolvConf, false)
		status := GetDNSStatus()
		if !status.Configurable || status.Managed || status.TakeoverRequired {
			t.Fatalf("resolved status wrong: %+v", status)
		}
		if _, err := ApplyCustomDNS(context.Background(), "1.1.1.1,2606:4700:4700::1111"); err != nil {
			t.Fatal(err)
		}
		managed, _ := f.read(f.paths.DropIn, false)
		if !strings.Contains(string(managed.Data), "DNS=1.1.1.1 2606:4700:4700::1111") {
			t.Fatal("resolved override not written")
		}
		if _, err := RestoreAutomaticDNS(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(f.paths.DropIn); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("drop-in was not removed")
		}
		actual, _ := f.read(f.paths.ResolvConf, false)
		if !sameDNSSnapshot(original, actual) {
			t.Fatal("resolved operation altered resolv.conf")
		}
	})
	t.Run("old release marker without backup", func(t *testing.T) {
		f := newDNSFixture(t)
		f.resolved = true
		preset, _ := findDNSPreset("international")
		f.put(f.paths.DropIn, []byte(renderResolvedDNSConfig(preset, false)), 0o644, false)
		status := GetDNSStatus()
		if !status.Configurable || !status.RestoreAvailable {
			t.Fatalf("legacy override blocked: %+v", status)
		}
		if _, err := RestoreAutomaticDNS(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(f.paths.DropIn); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("legacy drop-in not removed")
		}
	})
	t.Run("unmanaged same-name override", func(t *testing.T) {
		f := newDNSFixture(t)
		f.resolved = true
		f.put(f.paths.DropIn, []byte("[Resolve]\nDNS=9.9.9.9\n"), 0o644, false)
		if status := GetDNSStatus(); status.Configurable || status.ReasonCode != "foreign_config" {
			t.Fatalf("foreign override accepted: %+v", status)
		}
		if _, err := ApplyDNSPreset(context.Background(), "international"); err == nil {
			t.Fatal("foreign resolved override overwritten")
		}
		if len(f.writes) != 0 {
			t.Fatal("foreign override wrote files")
		}
	})
	t.Run("resolved inactive", func(t *testing.T) {
		f := newDNSFixture(t)
		f.resolved = true
		f.resolvedInactive = true
		if status := GetDNSStatus(); status.Configurable || status.ReasonCode != "resolved_inactive" {
			t.Fatalf("inactive resolved accepted: %+v", status)
		}
	})
	t.Run("restart and rollback restart both fail", func(t *testing.T) {
		f := newDNSFixture(t)
		f.resolved = true
		f.restartFailure = true
		_, err := ApplyCustomDNS(context.Background(), "1.1.1.1")
		if err == nil || !strings.Contains(err.Error(), "自动回滚未验证成功") {
			t.Fatalf("restart failure hidden: %v", err)
		}
		if _, err := os.Lstat(f.paths.DropIn); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed restart left new drop-in")
		}
	})
}

func TestDNSProbeDetectsConcurrentFileChangesBeforeWriting(t *testing.T) {
	f := newDNSFixture(t)
	dnsProbeAddress = func(context.Context, string, string) bool {
		os.WriteFile(f.paths.ResolvConf, []byte("nameserver 9.9.9.9\n"), 0o600)
		return true
	}
	if _, err := ApplyDNSPreset(context.Background(), "international"); err == nil || !strings.Contains(err.Error(), "发生变化") {
		t.Fatalf("probe race not rejected: %v", err)
	}
	if len(f.writes) != 0 {
		t.Fatal("external change caused a write")
	}
	actual, _ := os.ReadFile(f.paths.ResolvConf)
	if string(actual) != "nameserver 9.9.9.9\n" {
		t.Fatal("external DNS configuration lost")
	}
}

func TestDNSCanceledProbeCannotWriteConfiguration(t *testing.T) {
	f := newDNSFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ApplyDNSPreset(ctx, "international"); err == nil {
		t.Fatal("canceled action accepted")
	}
	if len(f.writes) != 0 {
		t.Fatal("canceled action wrote files")
	}
}
