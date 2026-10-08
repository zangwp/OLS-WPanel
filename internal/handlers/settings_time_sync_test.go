package handlers

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestStartSystemTimeSync(t *testing.T) {
	for _, tc := range []struct {
		name, unit, fail, state string
		providers               map[string]string
		install, wantError      bool
	}{
		{name: "preserve chrony", unit: "chrony.service"},
		{name: "preserve ntpsec", unit: "ntpsec.service"},
		{name: "preserve openntpd", unit: "openntpd.service"},
		{name: "install missing provider", install: true},
		{name: "preserve mask", state: "masked", wantError: true},
		{name: "install failure", fail: "apt-get", install: true, wantError: true},
		{name: "enable failure", unit: "chrony.service", fail: "enable", wantError: true},
		{name: "restart failure", unit: "chrony.service", fail: "restart", wantError: true},
		{name: "verification failure", unit: "chrony.service", fail: "is-active", wantError: true},
		{name: "preserve active timesyncd over disabled chrony", unit: "systemd-timesyncd.service", providers: map[string]string{"chrony.service": "LoadState=loaded\nActiveState=inactive", "systemd-timesyncd.service": "LoadState=loaded\nActiveState=active"}},
		{name: "multiple active providers", providers: map[string]string{"chrony.service": "LoadState=loaded\nActiveState=active", "systemd-timesyncd.service": "LoadState=loaded\nActiveState=active"}, wantError: true},
		{name: "same active daemon aliases", unit: "ntpsec.service", providers: map[string]string{"ntpsec.service": "Id=ntpsec.service\nLoadState=loaded\nActiveState=active", "ntp.service": "Id=ntpsec.service\nLoadState=loaded\nActiveState=active"}},
		{name: "state unavailable", fail: "show", wantError: true},
		{name: "unknown active state", providers: map[string]string{"chrony.service": "LoadState=loaded"}, wantError: true},
		{name: "masked active provider prevents second daemon", providers: map[string]string{"chrony.service": "LoadState=masked\nActiveState=active", "systemd-timesyncd.service": "LoadState=loaded\nActiveState=inactive"}, wantError: true},
		{name: "masked provider state unknown", providers: map[string]string{"chrony.service": "LoadState=masked"}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldCommand := timeSyncCommand
			t.Cleanup(func() { timeSyncCommand = oldCommand })
			var mutations []string
			timeSyncCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("time sync commands must have a bounded timeout")
				}
				if name == "systemctl" && args[0] == "show" {
					if tc.fail == "show" {
						return nil, errors.New("systemd unavailable")
					}
					if tc.providers != nil {
						if properties, ok := tc.providers[args[1]]; ok {
							return []byte(properties), nil
						}
					} else if args[1] == tc.unit && tc.unit != "" {
						return []byte("LoadState=loaded\nActiveState=active"), nil
					}
					if tc.state == "masked" && args[1] == "systemd-timesyncd.service" {
						return []byte("LoadState=masked\nActiveState=inactive"), nil
					}
					return []byte("LoadState=not-found\nActiveState=inactive"), nil
				}
				mutations = append(mutations, name+" "+strings.Join(args, " "))
				if name == tc.fail || (len(args) > 0 && args[0] == tc.fail) {
					return []byte("failed"), fmt.Errorf("injected %s failure", tc.fail)
				}
				return nil, nil
			}
			err := startSystemTimeSync()
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v, wantError=%v", err, tc.wantError)
			}
			if tc.wantError && tc.unit == "" && !tc.install && len(mutations) != 0 {
				t.Fatalf("uncertain/conflicting provider was changed: %v", mutations)
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
				want := []string{"systemctl enable --now " + unit, "systemctl restart " + unit, "systemctl is-active --quiet " + unit}
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
