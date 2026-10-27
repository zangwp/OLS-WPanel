package handlers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const softwareOPcacheStartupWarning = "Failed loading /usr/local/lsws/lsphp83/lib/php/20230831/opcache.so: undefined symbol: zend_handle_delayed_oom\n"

func TestSoftwareStartupDiagnosticHelperProcess(t *testing.T) {
	args := os.Args
	if len(args) < 3 || args[len(args)-2] != "software-startup-diagnostic-helper" {
		return
	}
	fmt.Fprint(os.Stderr, softwareOPcacheStartupWarning)
	switch args[len(args)-1] {
	case "success":
		fmt.Fprint(os.Stdout, "phpinfo()\npartial sensitive-value\n")
	case "fail":
		os.Exit(2)
	case "overflow":
		fmt.Fprint(os.Stdout, strings.Repeat("x", softwareProbeOutputLimit+1))
		os.Exit(2)
	case "sleep":
		time.Sleep(2 * time.Second)
	default:
		os.Exit(3)
	}
	os.Exit(0)
}

func TestSoftwareHealthCachePreservesTypedStartupFailureWithoutRawOutput(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	cache := newSoftwareProbeCache(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls.Add(1)
		return boundedSoftwareRead(ctx, name, args...)
	})
	var first error
	for attempt := 0; attempt < 2; attempt++ {
		output, err := cache.read(t.Context(), false, executable, "-test.run=^TestSoftwareStartupDiagnosticHelperProcess$", "--", "software-startup-diagnostic-helper", "fail")
		if err == nil || output != "" || !strings.Contains(err.Error(), "OPcache") || !strings.Contains(err.Error(), "zend_handle_delayed_oom") || strings.Contains(err.Error(), "/usr/local/") {
			t.Fatalf("cached startup failure lost safe information or exposed raw output: %q, %v", output, err)
		}
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
			t.Fatalf("cached diagnosis lost underlying command failure: %v", err)
		}
		if first == nil {
			first = err
		} else if err != first {
			t.Fatal("cache did not preserve the typed error instance")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("startup failures were not coalesced: calls=%d", calls.Load())
	}
}

func TestSoftwareHealthProbeKeepsSuccessfulStartupWarningForHealthClassification(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output, err := boundedSoftwareRead(t.Context(), executable, "-test.run=^TestSoftwareStartupDiagnosticHelperProcess$", "--", "software-startup-diagnostic-helper", "success")
	if err != nil || !strings.Contains(string(output), softwareOPcacheStartupWarning) || !strings.Contains(string(output), "phpinfo()") {
		t.Fatalf("successful merged probe lost startup warning before health parser: %q, %v", output, err)
	}
}

func TestSoftwareHealthProbeStartupDiagnosticNeverOverridesOverflowOrTimeout(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"overflow", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			if mode == "sleep" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 40*time.Millisecond)
			}
			defer cancel()
			output, err := boundedSoftwareRead(ctx, executable, "-test.run=^TestSoftwareStartupDiagnosticHelperProcess$", "--", "software-startup-diagnostic-helper", mode)
			want := errSoftwareProbeOutputLimit
			if mode == "sleep" {
				want = context.DeadlineExceeded
			}
			if len(output) != 0 || !errors.Is(err, want) || strings.Contains(err.Error(), "zend_handle_delayed_oom") {
				t.Fatalf("startup diagnosis replaced higher-priority failure: %q, %v", output, err)
			}
		})
	}
}
