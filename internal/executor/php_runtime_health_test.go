package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func lsphpHealthFixture(version, iniPath, scanDir string, exclude ...string) []byte {
	omit := make(map[string]bool)
	for _, name := range exclude {
		omit[name] = true
	}
	var fixture strings.Builder
	fmt.Fprintf(&fixture, "phpinfo()\nPHP Version => %s.4\nServer API => LiteSpeed V8.3\nLoaded Configuration File => %s\nScan this dir for additional .ini files => %s\nAdditional .ini files parsed => %s/99-ols-wpanel.ini\n\nConfiguration\n\nCore\n\nPHP Version => %s.4\n\nstandard\n\n", version, iniPath, scanDir, scanDir, version)
	for _, extension := range lsphpHealthExtensions {
		if omit[extension.Name] {
			continue
		}
		name := extension.Name
		if name == "opcache" {
			name = "Zend OPcache"
		}
		fmt.Fprintf(&fixture, "%s\n\n%s support => enabled\n\n", name, name)
	}
	fixture.WriteString("opcache.enable => On => On\nopcache.memory_consumption => 256 => 256\nopcache.max_accelerated_files => 20000 => 20000\nCache hits => 999999\nCache misses => 1\nUsed memory => 999999\n\nPHP Variables\n\n$_SERVER['SECRET'] => sensitive-value\n\nPHP License\nThis program is free software\n")
	return []byte(fixture.String())
}

func lsphpHealthFixturePaths() (string, string) {
	ini := filepath.Join("/usr/local/lsws/lsphp85/etc/php/8.5/litespeed", "php.ini")
	return ini, filepath.Join(filepath.Dir(filepath.Dir(ini)), "mods-available")
}

func assertLSPHPHealthUnknown(t *testing.T, health LSPHPRuntimeHealth) {
	t.Helper()
	if health.State != "unknown" && health.State != "not_installed" {
		t.Fatalf("expected unknown health, got %+v", health)
	}
	if health.MissingRequired != 0 || health.MissingRecommended != 0 {
		t.Fatalf("failed probe must not classify modules as missing: %+v", health)
	}
	for _, extension := range health.Extensions {
		if extension.State != "unknown" {
			t.Fatalf("failed probe classified module: %+v", extension)
		}
	}
}

func TestLSPHPHealthParsesOnlyCuratedConfiguration(t *testing.T) {
	ini, scan := lsphpHealthFixturePaths()
	health := parseLSPHPHealthOutput("8.5", ini, scan, lsphpHealthFixture("8.5", ini, scan))
	if health.State != "ok" || health.Reason != "" || health.MissingRequired != 0 || health.MissingRecommended != 0 {
		t.Fatalf("healthy runtime = %+v", health)
	}
	for _, extension := range health.Extensions {
		if extension.State != "loaded" {
			t.Fatalf("expected loaded module: %+v", extension)
		}
	}
	opcache := health.OPcache
	if opcache.ConfigurationState != "known" || opcache.Enabled == nil || !*opcache.Enabled || opcache.MemoryMB == nil || *opcache.MemoryMB != 256 || opcache.MaxFiles == nil || *opcache.MaxFiles != 20000 {
		t.Fatalf("OPcache configuration = %+v", opcache)
	}
	if opcache.MetricsState != "unavailable" || opcache.MetricsReason != "web_worker_probe_unavailable" {
		t.Fatalf("CLI result must not claim to observe web workers: %+v", opcache)
	}
	encoded, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sensitive-value", "999999", "Cache hits", "Used memory", "php.ini"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("health exposed raw phpinfo value %q: %s", secret, encoded)
		}
	}
}

func TestLSPHPHealthMissingModulesRequireSuccessfulCompleteProbe(t *testing.T) {
	ini, scan := lsphpHealthFixturePaths()
	output := lsphpHealthFixture("8.5", ini, scan, "mysqli", "redis", "opcache")
	// A configure flag or environment value naming a module is not proof it loaded.
	output = bytes.Replace(output, []byte("Server API =>"), []byte("Configure Command => --with-mysqli\nServer API =>"), 1)
	output = bytes.Replace(output, []byte("$_SERVER['SECRET']"), []byte("mysqli\nredis\nZend OPcache\n$_SERVER['SECRET']"), 1)
	health := parseLSPHPHealthOutput("8.5", ini, scan, output)
	if health.State != "warning" || health.Reason != "extensions_missing" || health.MissingRequired != 1 || health.MissingRecommended != 2 {
		t.Fatalf("missing runtime modules = %+v", health)
	}
	for _, extension := range health.Extensions {
		if extension.Name == "mysqli" || extension.Name == "redis" || extension.Name == "opcache" {
			if extension.State != "missing" {
				t.Errorf("module outside module section counted loaded: %+v", extension)
			}
		}
	}
	if health.OPcache.ConfigurationState != "unknown" || health.OPcache.Enabled != nil {
		t.Fatalf("unloaded OPcache cannot have known configuration: %+v", health.OPcache)
	}
}

func TestLSPHPHealthRejectsFailedTruncatedOrWrongRuntimeOutput(t *testing.T) {
	ini, scan := lsphpHealthFixturePaths()
	valid := lsphpHealthFixture("8.5", ini, scan)
	cases := []struct {
		name   string
		output []byte
		reason string
	}{
		{"empty", nil, "invalid_output"},
		{"usage", []byte("Usage: php -[b|c|n|h|i|q|s|v|?]"), "invalid_output"},
		{"truncated", bytes.Split(valid, []byte("PHP License"))[0], "invalid_output"},
		{"oversized", bytes.Repeat([]byte("a"), lsphpHealthOutputLimit+1), "invalid_output"},
		{"nul", append(append([]byte(nil), valid...), 0), "invalid_output"},
		{"startup warning", bytes.Replace(valid, []byte("\nConfiguration"), []byte("\nPHP Warning: Unable to load dynamic library\nConfiguration"), 1), "probe_failed"},
		{"opcache startup failed", bytes.Replace(valid, []byte("Cache hits"), []byte("Startup Failed => shared memory unavailable\nCache hits"), 1), "probe_failed"},
		{"different branch", lsphpHealthFixture("8.4", ini, scan), "runtime_mismatch"},
		{"CLI SAPI", bytes.Replace(valid, []byte("LiteSpeed V8.3"), []byte("Command Line Interface"), 1), "runtime_mismatch"},
		{"different ini", bytes.ReplaceAll(valid, []byte(ini), []byte("/tmp/site/php.ini")), "configuration_mismatch"},
		{"different scan dir", bytes.ReplaceAll(valid, []byte(scan), []byte("/tmp/site/conf.d")), "configuration_mismatch"},
		{"missing modules section", bytes.Replace(valid, []byte("\nConfiguration\n"), []byte("\nOther\n"), 1), "invalid_output"},
		{"missing variables delimiter", bytes.Replace(valid, []byte("\nPHP Variables\n"), []byte("\nOther\n"), 1), "invalid_output"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			health := parseLSPHPHealthOutput("8.5", ini, scan, test.output)
			assertLSPHPHealthUnknown(t, health)
			if health.Reason != test.reason {
				t.Fatalf("reason = %q, want %q", health.Reason, test.reason)
			}
		})
	}
}

func TestLSPHPHealthDistinguishesDisabledOrUnknownOpcacheConfiguration(t *testing.T) {
	ini, scan := lsphpHealthFixturePaths()
	valid := lsphpHealthFixture("8.5", ini, scan)
	disabled := bytes.Replace(valid, []byte("opcache.enable => On => On"), []byte("opcache.enable => Off => Off"), 1)
	health := parseLSPHPHealthOutput("8.5", ini, scan, disabled)
	if health.State != "warning" || health.Reason != "opcache_disabled" || health.OPcache.Enabled == nil || *health.OPcache.Enabled {
		t.Fatalf("disabled OPcache = %+v", health)
	}
	invalid := bytes.Replace(valid, []byte("opcache.memory_consumption => 256"), []byte("opcache.memory_consumption => 99999999999999999999"), 1)
	health = parseLSPHPHealthOutput("8.5", ini, scan, invalid)
	if health.OPcache.ConfigurationState != "unknown" || health.OPcache.MemoryMB != nil {
		t.Fatalf("malformed OPcache config must not become a numeric default: %+v", health.OPcache)
	}
}

func TestLSPHPHealthUsesOnlyValidatedLSAPIAndServerIni(t *testing.T) {
	ini, scan := lsphpHealthFixturePaths()
	runtime := LSPHPRuntime{Version: "8.5", Installed: true, LSAPIBinary: filepath.Join("/usr/local/lsws/lsphp85/bin", "lsphp"), CLIBinary: "should-not-run"}
	validate := func(got LSPHPRuntime) (string, string, string) {
		if got != runtime {
			t.Fatal("runtime changed before validation")
		}
		return ini, scan, ""
	}
	called := 0
	probe := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		called++
		if name != "/usr/bin/env" || strings.Join(args, "|") != strings.Join([]string{"-i", "PATH=/usr/bin:/bin", "PHP_INI_SCAN_DIR=" + scan, runtime.LSAPIBinary, "-c", ini, "-i"}, "|") {
			t.Fatalf("unexpected health command: %s %q", name, args)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > lsphpHealthTimeout {
			t.Fatal("health probe has no bounded deadline")
		}
		return lsphpHealthFixture("8.5", ini, scan), nil
	}
	health := readLSPHPRuntimeHealth(context.Background(), runtime, probe, validate)
	if health.State != "ok" || called != 1 {
		t.Fatalf("health = %+v; calls = %d", health, called)
	}
}

func TestLSPHPHealthNeverRunsUninstalledUnsupportedOrUntrustedRuntime(t *testing.T) {
	probe := func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("unsafe or unavailable runtime must not be invoked")
		return nil, nil
	}
	for _, test := range []struct {
		runtime LSPHPRuntime
		reason  string
	}{
		{LSPHPRuntime{Version: "8.5"}, "not_installed"},
		{LSPHPRuntime{Version: "8.6", Installed: true}, "unsupported_runtime"},
		{LSPHPRuntime{Version: "8.5;id", Installed: true}, "unsupported_runtime"},
		{LSPHPRuntime{Version: "", Installed: true}, "unsupported_runtime"},
		{LSPHPRuntime{Version: "8.5", Installed: true, LSAPIBinary: "/tmp/lsphp"}, "untrusted_runtime"},
	} {
		health := ReadLSPHPRuntimeHealthWithProbe(context.Background(), test.runtime, probe)
		assertLSPHPHealthUnknown(t, health)
		if health.Reason != test.reason {
			t.Fatalf("%+v: reason = %q, want %q", test.runtime, health.Reason, test.reason)
		}
	}
}

func TestLSPHPHealthFailedProbeDoesNotConsumePartialOutput(t *testing.T) {
	ini, scan := lsphpHealthFixturePaths()
	runtime := LSPHPRuntime{Version: "8.5", Installed: true}
	validate := func(LSPHPRuntime) (string, string, string) { return ini, scan, "" }
	for _, test := range []struct {
		err    error
		reason string
	}{
		{errors.New("failed command"), "probe_failed"},
		{context.DeadlineExceeded, "probe_timeout"},
		{context.Canceled, "probe_canceled"},
	} {
		health := readLSPHPRuntimeHealth(context.Background(), runtime, func(context.Context, string, ...string) ([]byte, error) {
			return lsphpHealthFixture("8.5", ini, scan, "mysqli"), test.err
		}, validate)
		assertLSPHPHealthUnknown(t, health)
		if health.Reason != test.reason {
			t.Fatalf("reason = %q, want %q", health.Reason, test.reason)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	health := readLSPHPRuntimeHealth(ctx, runtime, func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("canceled caller must not start a probe")
		return nil, nil
	}, validate)
	assertLSPHPHealthUnknown(t, health)
	if health.Reason != "probe_canceled" {
		t.Fatalf("canceled result = %+v", health)
	}
}

type lsphpHealthTestFileInfo struct{ mode os.FileMode }

func (info lsphpHealthTestFileInfo) Name() string       { return "fixture" }
func (info lsphpHealthTestFileInfo) Size() int64        { return 0 }
func (info lsphpHealthTestFileInfo) Mode() os.FileMode  { return info.mode }
func (info lsphpHealthTestFileInfo) ModTime() time.Time { return time.Time{} }
func (info lsphpHealthTestFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info lsphpHealthTestFileInfo) Sys() any           { return nil }

func TestLSPHPHealthRootTrustChecksOwnerModeAndKind(t *testing.T) {
	for _, test := range []struct {
		name  string
		mode  os.FileMode
		kind  string
		uid   int
		err   error
		trust bool
	}{
		{"root executable", 0755, "executable", 0, nil, true},
		{"root config", 0644, "file", 0, nil, true},
		{"root directory", os.ModeDir | 0755, "directory", 0, nil, true},
		{"root symlink", os.ModeSymlink | 0777, "executable", 0, nil, true},
		{"user executable", 0755, "executable", 1000, nil, false},
		{"group writable", 0775, "executable", 0, nil, false},
		{"world writable", 0777, "executable", 0, nil, false},
		{"non executable", 0644, "executable", 0, nil, false},
		{"wrong file kind", os.ModeDir | 0755, "file", 0, nil, false},
		{"wrong directory kind", 0644, "directory", 0, nil, false},
		{"user symlink", os.ModeSymlink | 0777, "file", 1000, nil, false},
		{"unknown ownership", 0755, "executable", 0, errors.New("unavailable"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := lsphpHealthSafeInfo(lsphpHealthTestFileInfo{mode: test.mode}, test.kind, test.uid, test.err); got != test.trust {
				t.Fatalf("trusted = %v, want %v", got, test.trust)
			}
		})
	}
	scope := filepath.Join(string(filepath.Separator), "usr", "local", "lsws", "lsphp85")
	for _, path := range []string{scope + "-attacker/bin/lsphp", filepath.Join(filepath.Dir(scope), "lsphp84", "bin", "lsphp"), filepath.Join(scope, "..", "other", "lsphp")} {
		if lsphpHealthPathWithin(filepath.Clean(path), scope) {
			t.Fatalf("branch escape accepted: %q", path)
		}
	}
	if !lsphpHealthPathWithin(filepath.Join(scope, "bin", "lsphp"), scope) {
		t.Fatal("valid branch path was rejected")
	}
}

// This helper is a harmless short-lived local process, selected only by an
// explicit test argument. It proves output/cancellation behavior end to end.
func TestLSPHPHealthHelperProcess(t *testing.T) {
	args := os.Args
	if len(args) < 3 || args[len(args)-2] != "lsphp-health-helper" {
		return
	}
	switch args[len(args)-1] {
	case "normal":
		fmt.Fprint(os.Stdout, "bounded-output")
	case "overflow":
		fmt.Fprint(os.Stdout, strings.Repeat("x", lsphpHealthOutputLimit+1))
	case "stderr":
		fmt.Fprint(os.Stderr, "PHP Warning: startup diagnostic")
	case "sleep":
		time.Sleep(2 * time.Second)
	case "fail":
		fmt.Fprint(os.Stdout, "partial-result")
		os.Exit(2)
	default:
		os.Exit(3)
	}
	os.Exit(0)
}

func TestLSPHPHealthDefaultProbeBoundsOutputAndCancellation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"normal", "overflow", "stderr", "fail", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if mode == "sleep" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 40*time.Millisecond)
			}
			defer cancel()
			started := time.Now()
			output, err := boundedLSPHPHealthRead(ctx, executable, "-test.run=^TestLSPHPHealthHelperProcess$", "--", "lsphp-health-helper", mode)
			if mode == "normal" {
				if err != nil || string(output) != "bounded-output" {
					t.Fatalf("successful probe = %q, %v", output, err)
				}
				return
			}
			if err == nil || len(output) != 0 {
				t.Fatalf("failed probe returned output: %q, %v", output, err)
			}
			if mode == "sleep" && (!errors.Is(err, context.DeadlineExceeded) || time.Since(started) >= time.Second) {
				t.Fatalf("probe did not honor deadline: %v after %v", err, time.Since(started))
			}
		})
	}
}
