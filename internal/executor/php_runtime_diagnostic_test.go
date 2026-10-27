package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const lsphpOPcacheABIFailure = "Failed loading /usr/local/lsws/lsphp83/lib/php/20230831/opcache.so: /usr/local/lsws/lsphp83/lib/php/20230831/opcache.so: undefined symbol: zend_handle_delayed_oom\n"

func assertLSPHPStartupABIFailure(t *testing.T, health LSPHPRuntimeHealth) {
	t.Helper()
	if health.State != "error" || health.Reason != "extension_abi_mismatch" || health.Diagnostic == nil ||
		health.Diagnostic.Code != health.Reason || health.Diagnostic.Extension != "opcache" || health.Diagnostic.Symbol != "zend_handle_delayed_oom" {
		t.Fatalf("startup diagnosis=%+v", health)
	}
	if health.MissingRequired != 0 || health.MissingRecommended != 0 || health.OPcache.ConfigurationState != "unknown" || health.OPcache.Enabled != nil {
		t.Fatalf("failed startup was classified as usable configuration: %+v", health)
	}
	for _, extension := range health.Extensions {
		if extension.State != "unknown" {
			t.Fatalf("failed startup claimed an extension state: %+v", extension)
		}
	}
	encoded, err := json.Marshal(health)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"/usr/local/lsws", "20230831", "sensitive-value", "PHP Variables", "php.ini", "user:secret"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("startup diagnosis exposed raw output %q: %s", secret, encoded)
		}
	}
}

func TestLSPHPHealthUndefinedSymbolReportsSafeDiagnosticAndKeepsUnknown(t *testing.T) {
	ini, scan := lsphpHealthFixturePaths()
	valid := lsphpHealthFixture("8.3", ini, scan)
	valid = bytes.ReplaceAll(valid, []byte("8.3.4"), []byte("8.3.35"))
	for _, output := range [][]byte{
		[]byte(lsphpOPcacheABIFailure),
		append([]byte(lsphpOPcacheABIFailure), valid...),
		bytes.Replace(valid, []byte("\nConfiguration\n"), []byte("\n"+lsphpOPcacheABIFailure+"\nConfiguration\n"), 1),
	} {
		assertLSPHPStartupABIFailure(t, parseLSPHPHealthOutput("8.3", ini, scan, output))
	}
}

func TestLSPHPHealthDiagnosticIgnoresVariablesThirdPartySymbolsAndInvalidOutput(t *testing.T) {
	ini, scan := lsphpHealthFixturePaths()
	valid := lsphpHealthFixture("8.3", ini, scan)
	for _, test := range []struct {
		name   string
		output []byte
	}{
		{"PHP variables", append(valid, []byte(lsphpOPcacheABIFailure)...)},
		{"environment", []byte("Environment\n" + lsphpOPcacheABIFailure)},
		{"module configuration", []byte("Configuration\n" + lsphpOPcacheABIFailure)},
		{"third-party symbol", []byte(strings.ReplaceAll(lsphpOPcacheABIFailure, "zend_handle_delayed_oom", "OPENSSL_3_0_0"))},
		{"missing library", []byte("Failed loading /opcache.so: libpcre2-8.so: cannot open shared object file\n")},
		{"unrelated filename", []byte(strings.ReplaceAll(lsphpOPcacheABIFailure, "opcache.so", "notopcache.so"))},
		{"filename suffix", []byte(strings.ReplaceAll(lsphpOPcacheABIFailure, "opcache.so", "opcache.so.attacker"))},
		{"not a startup warning", []byte("$_SERVER['SECRET'] => " + lsphpOPcacheABIFailure)},
		{"oversized symbol", []byte(strings.ReplaceAll(lsphpOPcacheABIFailure, "zend_handle_delayed_oom", "zend_"+strings.Repeat("x", 123)))},
		{"nul", append([]byte(lsphpOPcacheABIFailure), 0)},
		{"oversized output", append([]byte(lsphpOPcacheABIFailure), bytes.Repeat([]byte("x"), lsphpHealthOutputLimit)...)},
		{"beyond startup scan", append(bytes.Repeat([]byte("x\n"), lsphpStartupDiagnosticLimit), []byte(lsphpOPcacheABIFailure)...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if diagnostic := lsphpStartupDiagnostic(test.output); diagnostic != nil {
				t.Fatalf("unrecognized/unsafe output classified as ABI mismatch: %+v", diagnostic)
			}
		})
	}
}

func TestLSPHPHealthDiagnosticErrorContainsOnlyCuratedFields(t *testing.T) {
	failure := errors.New("original exit failure")
	warning := strings.ReplaceAll(lsphpOPcacheABIFailure, "/usr/local/lsws/lsphp83/lib/php/20230831/", "https://user:secret@example.test/private/")
	err := WrapLSPHPHealthProbeError(failure, []byte(warning))
	if !errors.Is(err, failure) || !strings.Contains(err.Error(), "zend_handle_delayed_oom") {
		t.Fatalf("typed startup error lost its cause or useful identifier: %v", err)
	}
	for _, secret := range []string{"user:secret", "https://", "example.test", "private", "original exit failure"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("typed startup error exposed raw information %q: %v", secret, err)
		}
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		if result := WrapLSPHPHealthProbeError(cause, []byte(lsphpOPcacheABIFailure)); result != cause || lsphpHealthDiagnosticFromError(result) != nil {
			t.Fatalf("cancellation was replaced by a partial startup diagnosis: %v", result)
		}
	}
}

func TestLSPHPStartupDiagnosticHelperProcess(t *testing.T) {
	args := os.Args
	if len(args) < 3 || args[len(args)-2] != "lsphp-startup-diagnostic-helper" {
		return
	}
	fmt.Fprint(os.Stderr, lsphpOPcacheABIFailure)
	switch args[len(args)-1] {
	case "stderr":
		fmt.Fprint(os.Stdout, "partial sensitive-value phpinfo")
	case "fail":
		os.Exit(2)
	case "stdout overflow":
		fmt.Fprint(os.Stdout, strings.Repeat("x", lsphpHealthOutputLimit+1))
	case "stderr overflow":
		fmt.Fprint(os.Stderr, strings.Repeat("x", lsphpStartupDiagnosticLimit+1))
	case "sleep":
		time.Sleep(2 * time.Second)
	default:
		os.Exit(3)
	}
	os.Exit(0)
}

func TestLSPHPHealthDirectStderrCarriesOnlyStructuredStartupDiagnostic(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ini, scan := lsphpHealthFixturePaths()
	for _, mode := range []string{"stderr", "fail"} {
		t.Run(mode, func(t *testing.T) {
			var probeErr error
			probe := func(ctx context.Context, _ string, _ ...string) ([]byte, error) {
				output, err := boundedLSPHPHealthRead(ctx, executable, "-test.run=^TestLSPHPStartupDiagnosticHelperProcess$", "--", "lsphp-startup-diagnostic-helper", mode)
				probeErr = err
				if err == nil || len(output) != 0 {
					t.Fatalf("startup failure returned raw partial output: %q, %v", output, err)
				}
				return output, err
			}
			health := readLSPHPRuntimeHealth(t.Context(), LSPHPRuntime{Version: "8.3", Installed: true}, probe,
				func(LSPHPRuntime) (string, string, string) { return ini, scan, "" })
			assertLSPHPStartupABIFailure(t, health)
			if mode == "fail" {
				var exitErr *exec.ExitError
				if !errors.As(probeErr, &exitErr) || exitErr.ExitCode() != 2 {
					t.Fatalf("startup diagnosis lost the command exit status: %v", probeErr)
				}
			}
		})
	}
}

func TestLSPHPHealthDiagnosticDoesNotOverrideOutputLimitOrTimeout(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"stdout overflow", "stderr overflow", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			if mode == "sleep" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 40*time.Millisecond)
			}
			defer cancel()
			output, err := boundedLSPHPHealthRead(ctx, executable, "-test.run=^TestLSPHPStartupDiagnosticHelperProcess$", "--", "lsphp-startup-diagnostic-helper", mode)
			if err == nil || len(output) != 0 || lsphpHealthDiagnosticFromError(err) != nil {
				t.Fatalf("partial startup failure replaced output/timeout failure: output=%q error=%v", output, err)
			}
			if mode == "sleep" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout priority lost: %v", err)
			}
		})
	}
}

func TestLSPHPHealthGateIncludesStartupDiagnosticWithoutClaimingReady(t *testing.T) {
	previous := lsphpRuntimeHealthRead
	t.Cleanup(func() { lsphpRuntimeHealthRead = previous })
	lsphpRuntimeHealthRead = func(context.Context, LSPHPRuntime) LSPHPRuntimeHealth {
		return withLSPHPHealthDiagnostic(newLSPHPRuntimeHealth("8.3"), lsphpStartupDiagnostic([]byte(lsphpOPcacheABIFailure)))
	}
	err := requireLSPHPRuntimeHealth(t.Context(), LSPHPRuntime{Version: "8.3", Installed: true})
	if !errors.Is(err, ErrLSPHPRuntimeNotReady) || !strings.Contains(err.Error(), "OPcache") || !strings.Contains(err.Error(), "zend_handle_delayed_oom") || strings.Contains(err.Error(), "/usr/local/") {
		t.Fatalf("runtime gate lost useful safe diagnostic or reported success: %v", err)
	}
}
