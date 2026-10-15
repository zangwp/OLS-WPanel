package executor

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirewallRollbackStateRequiresNoQueuedJob(t *testing.T) {
	old := portCommand
	t.Cleanup(func() { portCommand = old })
	for _, sample := range []struct {
		name, output string
		readError    bool
		inactive     bool
		wantError    bool
	}{
		{name: "actual absent unit with empty Job", output: "LoadState=not-found\nActiveState=inactive\nSubState=dead\nResult=success\nJob=", inactive: true},
		{name: "zero Job", output: "LoadState=loaded\nActiveState=inactive\nResult=success\nJob=0", inactive: true},
		{name: "queued rollback", output: "LoadState=loaded\nActiveState=inactive\nResult=success\nJob=123"},
		{name: "missing Job", output: "LoadState=not-found\nActiveState=inactive", wantError: true},
		{name: "malformed Job", output: "LoadState=loaded\nActiveState=inactive\nResult=success\nJob=unknown", wantError: true},
		{name: "read failure despite plausible output", output: "LoadState=not-found\nActiveState=inactive\nJob=", readError: true, wantError: true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			portCommand = func(context.Context, string, ...string) (string, error) {
				if sample.readError {
					return sample.output, errors.New("fixture D-Bus read failed")
				}
				return sample.output, nil
			}
			inactive, err := firewallAccessRollbackInactive(context.Background(), accessRollbackUnit+".service")
			if inactive != sample.inactive || (err != nil) != sample.wantError {
				t.Fatalf("unsafe unit interpretation: inactive=%t err=%v", inactive, err)
			}
		})
	}
}

type accessWatchdogFixture struct {
	state         *accessFingerprintState
	units         map[string]string
	stuck, unread string
	stopMissing   bool
	failRestore   bool
	stops         int
}

func newAccessWatchdogFixture(t *testing.T) *accessWatchdogFixture {
	t.Helper()
	fixture := &accessWatchdogFixture{state: newAccessFingerprintFixture(t, false), units: map[string]string{}}
	boundary := portCommand
	absent := "LoadState=not-found\nActiveState=inactive\nResult=success\nJob="
	portCommand = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && len(args) > 1 {
			unit := args[1]
			if args[0] == "show" && strings.Contains(strings.Join(args, " "), "--property=LoadState") {
				if unit == fixture.unread {
					return "", errors.New("fixture unreadable unit")
				}
				if output, ok := fixture.units[unit]; ok {
					return output, nil
				}
				return absent, nil
			}
			if args[0] == "stop" {
				fixture.stops++
				if unit != fixture.stuck {
					fixture.units[unit] = absent
				}
				if fixture.stopMissing && strings.HasSuffix(unit, ".service") {
					return "Unit not loaded", errors.New("fixture stop returned nonzero")
				}
				return "", nil
			}
			if args[0] == "reset-failed" {
				return "", nil
			}
		}
		if name == "nft" && len(args) == 2 && args[0] == "--file" && filepath.Base(args[1]) == "rollback.nft" {
			if fixture.failRestore {
				return "fixture nft restore failed", errors.New("restore failed")
			}
			record, err := readFirewallAccessChange()
			if err != nil {
				t.Fatal(err)
			}
			fixture.state.owned = record.Previous
			fixture.state.writes++
			return "", nil
		}
		out, err := boundary(ctx, name, args...)
		if name == "systemd-run" && err == nil {
			fixture.units[accessRollbackUnit+".timer"] = "LoadState=loaded\nActiveState=active\nResult=success\nJob="
		}
		return out, err
	}
	return fixture
}

func beginAccessWatchdogFixture(t *testing.T) FirewallProtectionResult {
	t.Helper()
	_, request := accessPreviewRoundTrip(t, []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 2212}})
	result, err := ApplyFirewallAccess(request, "203.0.113.5")
	if err != nil || !result.RequiresConfirmation {
		t.Fatalf("could not stage first-use confirmation: %+v %v", result, err)
	}
	return result
}

func TestAccessConfirmationAcceptsProvenAbsentTransientService(t *testing.T) {
	fixture := newAccessWatchdogFixture(t)
	change := beginAccessWatchdogFixture(t)
	fixture.stopMissing = true
	if err := ConfirmFirewallAccess(change.ConfirmationToken); err != nil || !fixture.state.saved || fixture.stops != 2 || pendingAccess.token != "" {
		t.Fatalf("proven cancellation failed: %v %+v", err, fixture)
	}
	if status := inspectFirewallAccessChange(context.Background()); status.State != "confirmed" {
		t.Fatalf("confirmed state was not durable: %+v", status)
	}
}

func TestAccessConfirmationFailureReconcilesBeforeRetry(t *testing.T) {
	for _, sample := range []struct {
		name, unitState string
		unread          bool
		failRestore     bool
	}{
		{name: "running timer", unitState: "LoadState=loaded\nActiveState=active\nResult=success\nJob="},
		{name: "queued rollback", unitState: "LoadState=loaded\nActiveState=inactive\nResult=success\nJob=123"},
		{name: "unreadable cancellation", unread: true},
		{name: "restore failure preserves protection", unitState: "LoadState=loaded\nActiveState=active\nResult=success\nJob=", failRestore: true},
	} {
		t.Run(sample.name, func(t *testing.T) {
			fixture := newAccessWatchdogFixture(t)
			change := beginAccessWatchdogFixture(t)
			unit := accessRollbackUnit + ".timer"
			fixture.stuck, fixture.failRestore = unit, sample.failRestore
			fixture.units[unit] = sample.unitState
			if sample.unread {
				fixture.unread = unit
			}
			if err := ConfirmFirewallAccess(change.ConfirmationToken); err == nil || fixture.state.saved || pendingAccess.token != "" {
				t.Fatalf("unsafe confirmation survived: %v %+v", err, fixture)
			}
			if status := inspectFirewallAccessChange(context.Background()); status.State != "pending" && status.State != "error" {
				t.Fatalf("unknown recovery was declared terminal: %+v", status)
			}
			fixture.state.writes = 0
			_, request := accessPreviewRoundTrip(t, []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 2212}})
			beforeStops := fixture.stops
			if _, err := ApplyFirewallAccess(request, "203.0.113.5"); err == nil || fixture.state.writes != 0 {
				t.Fatalf("unresolved recovery permitted another write: %v %+v", err, fixture)
			}
			if sample.failRestore && fixture.stops != beforeStops {
				t.Fatal("still-applied pending policy had its watchdog automatically stopped")
			}
			if !sample.failRestore {
				fixture.stuck, fixture.unread = "", ""
				if _, err := ApplyFirewallAccess(request, "203.0.113.5"); err != nil || fixture.state.writes != 1 {
					t.Fatalf("observed restoration could not clear stale jobs and retry: %v %+v", err, fixture)
				}
			}
		})
	}
}

func TestFirewallRollbackGuardIncludesLegacyService(t *testing.T) {
	fixture := newAccessWatchdogFixture(t)
	fixture.units[firewallRollbackUnit+".service"] = "LoadState=loaded\nActiveState=active\nResult=success\nJob="
	if err := checkFirewallRollbackUnits(context.Background(), firewallRollbackUnit+".timer", firewallRollbackUnit+".service"); err == nil || fixture.stops != 0 {
		t.Fatalf("running legacy service was ignored or stopped: %v", err)
	}
	fixture.units[firewallRollbackUnit+".service"] = "LoadState=loaded\nActiveState=inactive\nResult=success\nJob=321"
	if err := checkFirewallRollbackUnits(context.Background(), firewallRollbackUnit+".timer", firewallRollbackUnit+".service"); err == nil {
		t.Fatal("queued legacy rollback was ignored")
	}
}

func TestAccessRestoredSnapshotClearsFailedResidualJob(t *testing.T) {
	fixture := newAccessWatchdogFixture(t)
	beginAccessWatchdogFixture(t)
	fixture.state.owned, fixture.state.writes, pendingAccess.token = "", 0, ""
	fixture.units[accessRollbackUnit+".service"] = "LoadState=loaded\nActiveState=failed\nResult=exit-code\nJob="
	_, request := accessPreviewRoundTrip(t, []FirewallAccessRule{{Protocol: "tcp", Port: 22}, {Protocol: "tcp", Port: 8443}, {Protocol: "tcp", Port: 2212}})
	if _, err := ApplyFirewallAccess(request, "203.0.113.5"); err != nil || fixture.stops != 2 || fixture.state.writes != 1 {
		t.Fatalf("known restored snapshot stayed blocked by a failed residual job: %v %+v", err, fixture)
	}
}

func TestAccessConfirmationRechecksPolicyAfterCancellation(t *testing.T) {
	fixture := newAccessWatchdogFixture(t)
	change := beginAccessWatchdogFixture(t)
	boundary := portCommand
	portCommand = func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := boundary(ctx, name, args...)
		if name == "systemctl" && len(args) == 2 && args[0] == "stop" && args[1] == accessRollbackUnit+".service" {
			fixture.state.owned = ""
		}
		return out, err
	}
	if err := ConfirmFirewallAccess(change.ConfirmationToken); err == nil || fixture.state.saved || pendingAccess.token != "" {
		t.Fatalf("policy changed during cancellation was persisted: %v %+v", err, fixture)
	}
	if status := inspectFirewallAccessChange(context.Background()); status.State != "rolled_back" {
		t.Fatalf("observed original policy was not recorded after cancellation: %+v", status)
	}
}

func TestAccessPersistenceFailureRecordsObservedRollback(t *testing.T) {
	fixture := newAccessWatchdogFixture(t)
	change := beginAccessWatchdogFixture(t)
	persistAccessRules = func(context.Context) error { return errors.New("fixture disk full") }
	if err := ConfirmFirewallAccess(change.ConfirmationToken); err == nil || fixture.state.saved || pendingAccess.token != "" {
		t.Fatalf("failed save remained confirmable: %v %+v", err, fixture)
	}
	if status := inspectFirewallAccessChange(context.Background()); status.State != "rolled_back" {
		t.Fatalf("completed immediate rollback was not recorded: %+v", status)
	}
}

func TestAccessRecoveryIsExplicitAndMatchesTheReceipt(t *testing.T) {
	fixture := newAccessWatchdogFixture(t)
	change := beginAccessWatchdogFixture(t)
	changeID := change.ChangeID
	for _, invalid := range []string{"", "invalid", strings.Repeat("f", 32)} {
		if err := RecoverFirewallAccess(invalid); err == nil || fixture.stops != 0 || fixture.state.writes != 1 {
			t.Fatalf("unmatched recovery mutated tasks or rules: %q %v", invalid, err)
		}
	}
	if err := RecoverFirewallAccess(changeID); err == nil || fixture.stops != 0 || fixture.state.writes != 1 {
		t.Fatalf("still-applied temporary policy lost its watchdog: %v", err)
	}
	fixture.state.owned, pendingAccess.token = "", ""
	if status := inspectFirewallAccessChange(context.Background()); status.State != "pending" || fixture.stops != 0 {
		t.Fatalf("GET-style inspection cancelled stale tasks: %+v", status)
	}
	if err := RecoverFirewallAccess(changeID); err != nil || fixture.stops != 2 || fixture.state.writes != 1 {
		t.Fatalf("explicit recovery did not finish known restored state: %v %+v", err, fixture)
	}
	if status := inspectFirewallAccessChange(context.Background()); status.State != "rolled_back" {
		t.Fatalf("explicit recovery did not unlock terminal receipt: %+v", status)
	}
	if err := RecoverFirewallAccess(changeID); err != nil || fixture.stops != 2 || fixture.state.writes != 1 {
		t.Fatalf("terminal recovery was not idempotent: %v", err)
	}
}

func TestAccessRecoveryRejectsUnknownReceiptWithoutCommands(t *testing.T) {
	newAccessFingerprintFixture(t, false)
	portCommand = func(context.Context, string, ...string) (string, error) {
		t.Fatal("unknown recovery inspected or modified tasks")
		return "", errors.New("unexpected")
	}
	if err := RecoverFirewallAccess(strings.Repeat("a", 32)); err == nil {
		t.Fatal("unknown recovery was accepted")
	}
}
