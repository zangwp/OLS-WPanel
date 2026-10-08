package handlers

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// Provider selection reads systemctl show rather than list-unit-files so it
// can preserve the daemon already running, including aliased or masked units.
func withFakeNTPSystemctlProperties(t *testing.T, units map[string]string) {
	t.Helper()
	previous := timeSyncCommand
	t.Cleanup(func() { timeSyncCommand = previous })
	timeSyncCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("NTP detection commands must have a bounded timeout")
		}
		if name != "systemctl" || len(args) != 6 || !reflect.DeepEqual(args, []string{"show", args[1], "--property=Id", "--property=LoadState", "--property=ActiveState", "--no-pager"}) {
			t.Fatalf("unexpected command during read-only NTP detection: %s %q", name, args)
		}
		if properties, ok := units[args[1]]; ok {
			return []byte(properties), nil
		}
		return []byte("Id=" + args[1] + "\nLoadState=not-found\nActiveState=inactive"), nil
	}
}

func withFakeSystemctlUnits(t *testing.T, units string) {
	t.Helper()
	properties := make(map[string]string)
	for _, unit := range strings.Fields(units) {
		properties[unit] = "Id=" + unit + "\nLoadState=loaded\nActiveState=inactive"
	}
	withFakeNTPSystemctlProperties(t, properties)
}

func TestDetectNTPTimeSyncUnitPrefersChrony(t *testing.T) {
	withFakeSystemctlUnits(t, "chrony.service systemd-timesyncd.service")
	if unit := detectNTPTimeSyncUnit(); unit != "chrony.service" {
		t.Fatalf("unit=%q, want chrony.service", unit)
	}
}

func TestDetectNTPTimeSyncUnitFallsBackToTimesyncd(t *testing.T) {
	withFakeSystemctlUnits(t, "systemd-timesyncd.service")
	if unit := detectNTPTimeSyncUnit(); unit != "systemd-timesyncd.service" {
		t.Fatalf("unit=%q, want systemd-timesyncd.service", unit)
	}
}

func TestDetectNTPTimeSyncUnitReturnsEmptyWhenNeitherExists(t *testing.T) {
	withFakeSystemctlUnits(t, "")
	if unit := detectNTPTimeSyncUnit(); unit != "" {
		t.Fatalf("unit=%q, want empty", unit)
	}
}

func TestDetectNTPTimeSyncUnitSkipsMaskedChrony(t *testing.T) {
	withFakeNTPSystemctlProperties(t, map[string]string{
		"chrony.service":            "Id=chrony.service\nLoadState=masked\nActiveState=inactive",
		"systemd-timesyncd.service": "Id=systemd-timesyncd.service\nLoadState=loaded\nActiveState=inactive",
	})
	if unit := detectNTPTimeSyncUnit(); unit != "systemd-timesyncd.service" {
		t.Fatalf("unit=%q, want systemd-timesyncd.service (chrony is masked)", unit)
	}
}

func TestDetectNTPTimeSyncUnitPreservesActiveProvider(t *testing.T) {
	withFakeNTPSystemctlProperties(t, map[string]string{
		"chrony.service":            "Id=chrony.service\nLoadState=loaded\nActiveState=inactive",
		"systemd-timesyncd.service": "Id=systemd-timesyncd.service\nLoadState=loaded\nActiveState=active",
	})
	if unit := detectNTPTimeSyncUnit(); unit != "systemd-timesyncd.service" {
		t.Fatalf("unit=%q, want active systemd-timesyncd.service", unit)
	}
}

func TestDetectNTPTimeSyncUnitDeduplicatesActiveAliases(t *testing.T) {
	withFakeNTPSystemctlProperties(t, map[string]string{
		"ntpsec.service": "Id=ntpsec.service\nLoadState=loaded\nActiveState=active",
		"ntp.service":    "Id=ntpsec.service\nLoadState=loaded\nActiveState=active",
	})
	if unit := detectNTPTimeSyncUnit(); unit != "ntpsec.service" {
		t.Fatalf("unit=%q, want single ntpsec.service behind both aliases", unit)
	}
}

func TestDetectNTPTimeSyncUnitDoesNotSelectConflictingProviders(t *testing.T) {
	withFakeNTPSystemctlProperties(t, map[string]string{
		"chrony.service":            "Id=chrony.service\nLoadState=loaded\nActiveState=active",
		"systemd-timesyncd.service": "Id=systemd-timesyncd.service\nLoadState=loaded\nActiveState=active",
	})
	if unit := detectNTPTimeSyncUnit(); unit != "" {
		t.Fatalf("unit=%q, want empty for conflicting active providers", unit)
	}
}

func TestDetectNTPTimeSyncUnitDoesNotSelectUncertainProvider(t *testing.T) {
	for _, properties := range []string{
		"Id=chrony.service\nLoadState=loaded",
		"Id=chrony.service\nLoadState=masked\nActiveState=active",
	} {
		t.Run(properties, func(t *testing.T) {
			withFakeNTPSystemctlProperties(t, map[string]string{
				"chrony.service":            properties,
				"systemd-timesyncd.service": "Id=systemd-timesyncd.service\nLoadState=loaded\nActiveState=inactive",
			})
			if unit := detectNTPTimeSyncUnit(); unit != "" {
				t.Fatalf("unit=%q, want empty while chrony activity is uncertain", unit)
			}
		})
	}
}
