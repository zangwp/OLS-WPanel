package executor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOLSRegistrationRecoversMissingUnitAndPreservesCustomServices(t *testing.T) {
	for _, tc := range []struct {
		name, native, legacy, fail      string
		custom, wantError, wantRecovery bool
	}{
		{name: "missing native", wantRecovery: true},
		{name: "Debian generated service", legacy: "/run/systemd/generator.late/lsws.service", wantRecovery: true},
		{name: "existing stopped native", native: "existing"},
		{name: "custom legacy", legacy: "/etc/systemd/system/custom.service", wantError: true},
		{name: "custom policy", custom: true},
		{name: "invalid OLS configuration", fail: "/usr/local/lsws/bin/openlitespeed -t", wantError: true},
		{name: "enable fails", legacy: "/run/systemd/generator.late/lsws.service", fail: "systemctl enable --now lshttpd.service", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && (tc.wantRecovery || tc.fail == "systemctl enable --now lshttpd.service") {
				t.Skip("Linux systemd recovery requires native symlink support")
			}
			root := t.TempDir()
			vendor := filepath.Join(root, "vendor.service")
			if err := os.Mkdir(filepath.Join(root, "lshttpd.service.d"), 0700); err != nil {
				t.Fatal(err)
			}
			policy := managedOLSServiceDropInContent
			if tc.custom {
				policy = "[Service]\nRestart=no\n"
			}
			if err := os.WriteFile(filepath.Join(root, "lshttpd.service.d", "ols-wpanel.conf"), []byte(policy), 0600); err != nil {
				t.Fatal(err)
			}
			content := []byte("[Service]\nExecStart=/usr/local/lsws/bin/lswsctrl start\n")
			if err := os.WriteFile(vendor, content, 0600); err != nil {
				t.Fatal(err)
			}
			native := tc.native
			if native != "" {
				native = filepath.Join(root, "custom-native.service")
				if err := os.WriteFile(native, []byte("custom"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			var calls []string
			command := func(name string, args ...string) ([]byte, error) {
				call := name + " " + strings.Join(args, " ")
				calls = append(calls, call)
				if call == tc.fail {
					return nil, errors.New("fixture failure")
				}
				if call == "systemctl show lshttpd.service --property=FragmentPath --value" {
					return []byte(native), nil
				}
				if call == "systemctl show lsws.service --property=FragmentPath --value" {
					return []byte(tc.legacy), nil
				}
				return nil, nil
			}
			err := restoreOLSServiceRegistration(root, vendor, command)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v calls=%v", err, calls)
			}
			_, statErr := os.Stat(filepath.Join(root, "lshttpd.service"))
			if (statErr == nil) != tc.wantRecovery {
				t.Fatalf("unit presence mismatch: %v", statErr)
			}
			joined := strings.Join(calls, "\n")
			if tc.wantRecovery && !strings.Contains(joined, "systemctl is-active --quiet lshttpd.service") {
				t.Fatal("recovery did not verify service")
			}
			if tc.native != "" || tc.custom {
				if strings.Contains(joined, "enable") || strings.Contains(joined, "stop") {
					t.Fatal("existing service was modified")
				}
			}
			if tc.fail == "systemctl enable --now lshttpd.service" && !strings.Contains(joined, "systemctl start lsws.service") {
				t.Fatal("legacy service was not restored")
			}
		})
	}
}
