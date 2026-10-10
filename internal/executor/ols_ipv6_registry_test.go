package executor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

type olsIPv6RegistryFixture struct {
	paths   olsRuntimePaths
	enabled string
	site    string
	content string
}

func newOLSIPv6RegistryFixture(t *testing.T) olsIPv6RegistryFixture {
	t.Helper()
	root := t.TempDir()
	available, enabled := filepath.Join(root, "sites-available"), filepath.Join(root, "sites-enabled")
	for _, directory := range []string{available, enabled} {
		if err := os.MkdirAll(directory, 0750); err != nil {
			t.Fatal(err)
		}
	}
	oldConfig, oldIPv6, oldRun, oldCommand := config.AppConfig, olsIPv6Available, runOLSCommand, olsIPv6Command
	oldUpgradeCommand, oldPaused := olsIPv6UpgradeCommand, olsIPv6UpgradePaused
	config.AppConfig = &config.Config{Paths: config.PathsConfig{
		OLSRoot: root, OLSManagedConfig: filepath.Join(root, "sites.conf"),
		OLSVHostsAvailable: available, OLSVHostsEnabled: enabled,
		OLSBinary:       filepath.Join(root, "openlitespeed"),
		OLSListenerCert: filepath.Join(root, "default.crt"), OLSListenerKey: filepath.Join(root, "default.key"),
	}}
	olsIPv6Available = func() bool { return true }
	olsIPv6UpgradePaused = func() bool { return false }
	olsIPv6Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok || name != "ss" || len(args) != 6 || strings.Join(args[:5], " ") != "-H -l -t -n -p" {
			t.Fatalf("unexpected listener verification command: %s %v", name, args)
		}
		host := "0.0.0.0"
		if args[5] == "-6" {
			host = "[::]"
		} else if args[5] != "-4" {
			t.Fatalf("unexpected socket family: %s", args[5])
		}
		return olsTestOwnedListeners("LISTEN 0 4096 " + host + ":80 *:*\nLISTEN 0 4096 " + host + ":443 *:*\n"), nil
	}
	t.Cleanup(func() {
		config.AppConfig, olsIPv6Available, runOLSCommand = oldConfig, oldIPv6, oldRun
		olsIPv6Command = oldCommand
		olsIPv6UpgradeCommand, olsIPv6UpgradePaused = oldUpgradeCommand, oldPaused
	})
	stubOLSDefaultVHostOwnership(t)
	stubOLSListenerOwnership(t)
	site := filepath.Join(available, "example.com.conf")
	content := olsMetadataFormatPrefix + "1\n" + olsMetadataVHostPrefix + "olsw_example\n" +
		olsMetadataDomainsPrefix + "example.com,www.example.com\n" + olsMetadataRootPrefix + filepath.Join(root, "www", "example.com") + "\n" +
		"vhssl {\n  certFile " + filepath.Join(root, "site.crt") + "\n  keyFile " + filepath.Join(root, "site.key") + "\n}\n"
	if err := os.WriteFile(site, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(site, filepath.Join(enabled, "example.com.conf")); err != nil {
		t.Fatal(err)
	}
	return olsIPv6RegistryFixture{paths: currentOLSRuntimePaths(), enabled: enabled, site: site, content: content}
}

func readOLSIPv6Registry(t *testing.T, fixture olsIPv6RegistryFixture) string {
	t.Helper()
	content, err := os.ReadFile(fixture.paths.managed)
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func TestOLSIPv6RegistryPreservesIPv4VHostsAliasesAndCertificates(t *testing.T) {
	fixture := newOLSIPv6RegistryFixture(t)
	ipv4, err := renderOLSManagedRegistryWithIPv6(fixture.enabled, false)
	if err != nil {
		t.Fatal(err)
	}
	dual, err := renderOLSManagedRegistry(fixture.enabled)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(dual, ipv4) || strings.Count(ipv4, "listener ") != 2 || strings.Count(dual, "listener ") != 4 {
		t.Fatal("IPv6 must append two independent listeners while leaving IPv4 bytes unchanged")
	}
	for _, listener := range []struct{ name, address string }{
		{"OLSWPanelHTTP", "*:80"}, {"OLSWPanelHTTPS", "*:443"},
		{"OLSWPanelHTTPIPv6", "[ANY]:80"}, {"OLSWPanelHTTPSIPv6", "[ANY]:443"},
	} {
		start := strings.Index(dual, "listener "+listener.name+" {\n")
		if start < 0 {
			t.Fatalf("missing listener %s", listener.name)
		}
		block := strings.SplitN(dual[start:], "}\n", 2)[0]
		for _, want := range []string{
			"address                 " + listener.address,
			"map                    olsw_example example.com,www.example.com",
			"map                    olsw_default *",
		} {
			if !strings.Contains(block, want) {
				t.Fatalf("listener %s missing %q", listener.name, want)
			}
		}
		if strings.Contains(listener.name, "HTTPS") {
			for _, want := range []string{"secure                  1", "certFile                " + filepath.ToSlash(fixture.paths.listenerCert), "keyFile                 " + filepath.ToSlash(fixture.paths.listenerKey), "sslProtocol             24\n"} {
				if !strings.Contains(block, want) {
					t.Fatalf("TLS listener %s missing %q", listener.name, want)
				}
			}
		} else if strings.Contains(block, "sslProtocol") {
			t.Fatalf("HTTP listener %s unexpectedly contains TLS settings", listener.name)
		}
	}
	if strings.Count(dual, "virtualHost olsw_example {") != 1 || strings.Count(dual, "configFile             "+filepath.ToSlash(fixture.site)) != 1 {
		t.Fatal("both address families must use the same vhost configuration and SNI certificate")
	}
	if content, err := os.ReadFile(fixture.site); err != nil || string(content) != fixture.content {
		t.Fatalf("per-site SSL configuration changed: %v", err)
	}
	olsIPv6Available = func() bool { return false }
	withoutIPv6, err := renderOLSManagedRegistry(fixture.enabled)
	if err != nil || withoutIPv6 != ipv4 {
		t.Fatalf("unavailable IPv6 must retain exact IPv4 registry: %v", err)
	}
}

func TestOLSIPv6EmptyRegistryKeepsDefaultMapsOnBothFamilies(t *testing.T) {
	fixture := newOLSIPv6RegistryFixture(t)
	if err := os.Remove(filepath.Join(fixture.enabled, "example.com.conf")); err != nil {
		t.Fatal(err)
	}
	content, err := renderOLSManagedRegistryWithIPv6(fixture.enabled, true)
	if err != nil || strings.Count(content, "map                    olsw_default *") != 4 || strings.Contains(content, "virtualHost olsw_example {") {
		t.Fatalf("empty dual-stack registry did not preserve default catch-all: %v\n%s", err, content)
	}
}

func TestOLSIPv6ReloadFallsBackWithoutLosingNewIPv4Site(t *testing.T) {
	for _, failure := range []string{"validation", "restart", "missing IPv6 listener", "IPv4 startup recovers"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newOLSIPv6RegistryFixture(t)
			if err := os.WriteFile(fixture.paths.managed, []byte("old registry\n"), 0640); err != nil {
				t.Fatal(err)
			}
			var tests, restarts, ipv4Queries int
			validListeners := olsIPv6Command
			olsIPv6Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if args[len(args)-1] == "-4" {
					ipv4Queries++
				}
				dual := strings.Contains(readOLSIPv6Registry(t, fixture), "listener OLSWPanelHTTPIPv6 {")
				if (failure == "missing IPv6 listener" && args[len(args)-1] == "-6") || (failure == "IPv4 startup recovers" && dual && args[len(args)-1] == "-4") {
					return nil, nil
				}
				return validListeners(ctx, name, args...)
			}
			runOLSCommand = func(name string, args ...string) ([]byte, error) {
				dual := strings.Contains(readOLSIPv6Registry(t, fixture), "listener OLSWPanelHTTPIPv6 {")
				if name == fixture.paths.binary && len(args) == 1 && args[0] == "-t" {
					tests++
					if dual && failure == "validation" {
						return []byte("IPv6 listener unsupported"), errors.New("exit 1")
					}
				} else if name == "systemctl" && strings.Join(args, " ") == "restart lshttpd" {
					restarts++
					if dual && failure == "restart" {
						return []byte("IPv6 listener cannot bind"), errors.New("exit 1")
					}
				} else {
					t.Fatalf("unexpected command: %s %v", name, args)
				}
				return []byte("ok"), nil
			}
			if _, err := reloadOLSManagedRegistry(fixture.enabled); err != nil {
				t.Fatalf("optional IPv6 failure blocked site configuration: %v", err)
			}
			final := readOLSIPv6Registry(t, fixture)
			if strings.Contains(final, "HTTPIPv6") || strings.Count(final, "map                    olsw_example example.com,www.example.com") != 2 {
				t.Fatal("fallback must keep complete new IPv4 mappings and omit only IPv6 listeners")
			}
			wantRestarts := 1
			if failure != "validation" {
				wantRestarts = 2
			}
			if tests != 2 || restarts != wantRestarts {
				t.Fatalf("validation/restart count = %d/%d", tests, restarts)
			}
			if ipv4Queries == 0 {
				t.Fatal("IPv4 fallback reported success without reading its listeners")
			}
		})
	}
}

func TestOLSIPv6ReloadRestoresOldRegistryWhenIPv4FallbackNotListening(t *testing.T) {
	for _, failure := range []string{"IPv4 remains missing", "ss unavailable", "ss partial output with failure"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newOLSIPv6RegistryFixture(t)
			old := "old registry\n"
			if err := os.WriteFile(fixture.paths.managed, []byte(old), 0640); err != nil {
				t.Fatal(err)
			}
			var tests, restarts int
			runOLSCommand = func(name string, args ...string) ([]byte, error) {
				if name == fixture.paths.binary && len(args) == 1 && args[0] == "-t" {
					tests++
				} else if name == "systemctl" && strings.Join(args, " ") == "restart lshttpd" {
					restarts++
				} else {
					t.Fatalf("unexpected command: %s %v", name, args)
				}
				return []byte("ok"), nil
			}
			validListeners := olsIPv6Command
			olsIPv6Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if failure == "ss unavailable" {
					return nil, errors.New("ss unavailable")
				}
				if failure == "ss partial output with failure" {
					output, _ := validListeners(ctx, name, args...)
					return output, errors.New("ss failed after output")
				}
				if args[len(args)-1] == "-4" {
					return nil, nil
				}
				return validListeners(ctx, name, args...)
			}
			_, err := reloadOLSManagedRegistry(fixture.enabled)
			if err == nil || !strings.Contains(err.Error(), "IPv4 配置回退也未通过") || !strings.Contains(err.Error(), "旧 OpenLiteSpeed 注册表已恢复") {
				t.Fatalf("unverified IPv4 fallback must fail after restoring the old registry: %v", err)
			}
			if readOLSIPv6Registry(t, fixture) != old || tests != 3 || restarts != 3 {
				t.Fatalf("failed fallback was not restored: tests=%d restarts=%d", tests, restarts)
			}
		})
	}
}

func TestOLSIPv6ReloadRestoresOldRegistryWhenIPv4AlsoInvalid(t *testing.T) {
	fixture := newOLSIPv6RegistryFixture(t)
	old := "old registry\n"
	if err := os.WriteFile(fixture.paths.managed, []byte(old), 0640); err != nil {
		t.Fatal(err)
	}
	var tests, restarts int
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name == fixture.paths.binary {
			tests++
			if readOLSIPv6Registry(t, fixture) != old {
				return []byte("invalid per-site configuration"), errors.New("exit 1")
			}
		} else if name == "systemctl" && strings.Join(args, " ") == "restart lshttpd" {
			restarts++
		} else {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		return []byte("ok"), nil
	}
	_, err := reloadOLSManagedRegistry(fixture.enabled)
	if err == nil || !strings.Contains(err.Error(), "invalid per-site configuration") {
		t.Fatalf("vhost failure must be reported after IPv4 fallback: %v", err)
	}
	if readOLSIPv6Registry(t, fixture) != old || tests != 3 || restarts != 1 {
		t.Fatalf("old registry restore or command sequence failed: tests=%d restarts=%d", tests, restarts)
	}
}

func TestOLSIPv6ReloadRejectsInvalidMetadataBeforeAnyServiceCommand(t *testing.T) {
	fixture := newOLSIPv6RegistryFixture(t)
	if err := os.WriteFile(fixture.paths.managed, []byte("old registry\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.site, []byte("invalid metadata\n"), 0640); err != nil {
		t.Fatal(err)
	}
	runOLSCommand = func(string, ...string) ([]byte, error) {
		t.Fatal("metadata errors must not trigger validation, restart, or IPv4 fallback")
		return nil, nil
	}
	if _, err := reloadOLSManagedRegistry(fixture.enabled); err == nil || !strings.Contains(err.Error(), "元数据") {
		t.Fatalf("invalid metadata accepted: %v", err)
	}
	if readOLSIPv6Registry(t, fixture) != "old registry\n" {
		t.Fatal("invalid metadata replaced the original registry")
	}
}

func TestOLSIPv6UpgradeAddsListenersOnceForRunningManagedServer(t *testing.T) {
	fixture := newOLSIPv6RegistryFixture(t)
	old, err := renderOLSManagedRegistryWithIPv6(fixture.enabled, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.paths.managed, []byte(old), 0640); err != nil {
		t.Fatal(err)
	}
	var activeChecks, serviceCommands int
	olsIPv6UpgradeCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok || name != "systemctl" || strings.Join(args, " ") != "is-active --quiet lshttpd" {
			t.Fatalf("unbounded or unexpected upgrade command: %s %v", name, args)
		}
		activeChecks++
		return nil, nil
	}
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if !(name == fixture.paths.binary && strings.Join(args, " ") == "-t") && !(name == "systemctl" && strings.Join(args, " ") == "restart lshttpd") {
			t.Fatalf("unexpected service command: %s %v", name, args)
		}
		serviceCommands++
		return []byte("ok"), nil
	}
	for i := 0; i < 2; i++ {
		if err := ensureManagedOLSIPv6Listeners(); err != nil {
			t.Fatal(err)
		}
	}
	if activeChecks != 1 || serviceCommands != 2 || strings.Count(readOLSIPv6Registry(t, fixture), "listener ") != 4 {
		t.Fatalf("upgrade must be idempotent: active=%d service=%d", activeChecks, serviceCommands)
	}
}

func TestOLSIPv6UpgradeSkipsForeignInactiveOrUnavailableServers(t *testing.T) {
	for _, state := range []string{"unavailable", "paused", "foreign", "missing", "symlink", "inactive", "invalid metadata"} {
		t.Run(state, func(t *testing.T) {
			fixture := newOLSIPv6RegistryFixture(t)
			old, err := renderOLSManagedRegistryWithIPv6(fixture.enabled, false)
			if err != nil {
				t.Fatal(err)
			}
			if state == "foreign" {
				old = "# third-party server configuration\n"
			}
			if state != "missing" {
				if err := os.WriteFile(fixture.paths.managed, []byte(old), 0640); err != nil {
					t.Fatal(err)
				}
			}
			switch state {
			case "unavailable":
				olsIPv6Available = func() bool { return false }
			case "paused":
				olsIPv6UpgradePaused = func() bool { return true }
			case "symlink":
				foreign := fixture.paths.managed + ".foreign"
				if err := os.Rename(fixture.paths.managed, foreign); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(foreign, fixture.paths.managed); err != nil {
					t.Fatal(err)
				}
			case "invalid metadata":
				if err := os.WriteFile(fixture.site, []byte("invalid metadata\n"), 0640); err != nil {
					t.Fatal(err)
				}
			}
			var activeChecks int
			olsIPv6UpgradeCommand = func(context.Context, string, ...string) ([]byte, error) {
				activeChecks++
				return nil, errors.New("inactive")
			}
			runOLSCommand = func(string, ...string) ([]byte, error) {
				t.Fatal("upgrade must not validate, restart, or start a skipped server")
				return nil, nil
			}
			if err := ensureManagedOLSIPv6Listeners(); err != nil {
				t.Fatal(err)
			}
			wantChecks := 0
			if state == "inactive" {
				wantChecks = 1
			}
			if activeChecks != wantChecks {
				t.Fatalf("active checks = %d, want %d", activeChecks, wantChecks)
			}
			if state == "missing" {
				if _, err := os.Lstat(fixture.paths.managed); !os.IsNotExist(err) {
					t.Fatal("upgrade created a registry for an unmanaged server")
				}
			} else if readOLSIPv6Registry(t, fixture) != old {
				t.Fatal("upgrade changed a skipped server's registry")
			}
		})
	}
}

func TestOLSIPv6UpgradeFailurePreservesRegistryAndDoesNotBlockPanelStartup(t *testing.T) {
	fixture := newOLSIPv6RegistryFixture(t)
	old, err := renderOLSManagedRegistryWithIPv6(fixture.enabled, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.paths.managed, []byte(old), 0640); err != nil {
		t.Fatal(err)
	}
	olsIPv6UpgradeCommand = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	var tests int
	runOLSCommand = func(name string, args ...string) ([]byte, error) {
		if name != fixture.paths.binary || strings.Join(args, " ") != "-t" {
			t.Fatalf("failed validation must not restart a server: %s %v", name, args)
		}
		tests++
		return []byte("configuration invalid"), errors.New("exit 1")
	}
	if err := ensureManagedOLSIPv6Listeners(); err != nil {
		t.Fatalf("optional IPv6 upgrade blocked panel startup: %v", err)
	}
	if readOLSIPv6Registry(t, fixture) != old || tests != 3 {
		t.Fatalf("failed candidate/fallback/recovery did not preserve old registry: tests=%d", tests)
	}
}
