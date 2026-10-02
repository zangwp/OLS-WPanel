package handlers

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestStartSystemTimeSync(t *testing.T) {
	for _, tc := range []struct {
		name, unit, fail, state string
		install, wantError      bool
	}{
		{name: "preserve chrony", unit: "chrony.service"},
		{name: "preserve ntpsec", unit: "ntpsec.service"},
		{name: "install missing provider", install: true},
		{name: "preserve mask", state: "masked", wantError: true},
		{name: "install failure", fail: "apt-get", install: true, wantError: true},
		{name: "enable failure", unit: "chrony.service", fail: "enable", wantError: true},
		{name: "ntp failure", unit: "chrony.service", fail: "timedatectl", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldUnit, oldCommand := ntpTimeSyncUnit, timeSyncCommand
			t.Cleanup(func() { ntpTimeSyncUnit, timeSyncCommand = oldUnit, oldCommand })
			ntpTimeSyncUnit = func() string { return tc.unit }
			var mutations []string
			timeSyncCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("time sync commands must have a bounded timeout")
				}
				if name == "systemctl" && args[0] == "show" {
					return []byte(tc.state), nil
				}
				mutations = append(mutations, name+" "+strings.Join(args, " "))
				if name == tc.fail || (len(args) > 0 && args[0] == tc.fail) {
					return []byte("failed"), errors.New("failed")
				}
				return nil, nil
			}
			err := startSystemTimeSync()
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v, wantError=%v", err, tc.wantError)
			}
			if tc.state == "masked" && len(mutations) != 0 {
				t.Fatalf("masked provider was changed: %v", mutations)
			}
			if tc.install && !strings.HasPrefix(mutations[0], "apt-get install -y --no-install-recommends systemd-timesyncd") {
				t.Fatalf("missing provider was not installed: %v", mutations)
			}
			if !tc.install && strings.Contains(strings.Join(mutations, "\n"), "apt-get") {
				t.Fatalf("existing provider was replaced: %v", mutations)
			}
			if !tc.wantError {
				unit := tc.unit
				if unit == "" {
					unit = "systemd-timesyncd.service"
				}
				want := []string{"systemctl enable --now " + unit, "timedatectl set-ntp true", "systemctl restart " + unit}
				if tc.install {
					want = append([]string{"apt-get install -y --no-install-recommends systemd-timesyncd"}, want...)
				}
				if !reflect.DeepEqual(mutations, want) {
					t.Fatalf("commands=%v, want %v", mutations, want)
				}
			}
		})
	}
}
