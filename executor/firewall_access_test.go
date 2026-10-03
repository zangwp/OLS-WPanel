package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAccessStateDistinguishesReadFailure(t *testing.T) {
	old := portCommand
	defer func() { portCommand = old }()
	portCommand = func(context.Context, string, ...string) (string, error) { return "", errors.New("permission denied") }
	if _, _, err := readAccessState(context.Background()); err == nil {
		t.Fatal("read failure treated as absent policy")
	}
	portCommand = func(_ context.Context, _ string, args ...string) (string, error) {
		if strings.Join(args, " ") == "--stateless list tables" {
			return "table inet ols_wpanel_access", nil
		}
		return `tcp dport 22 counter accept comment "ols-access:tcp:22:2001:db8::1/128"`, nil
	}
	enabled, rules, err := readAccessState(context.Background())
	if err != nil || !enabled || len(rules) != 1 || rules[0].Source != "2001:db8::1/128" {
		t.Fatalf("bad state: %v %+v %v", enabled, rules, err)
	}
}

func TestAccessConfirmationFailureRestoresRuntimeAndBoot(t *testing.T) {
	oldCmd, oldPersist, oldPending := portCommand, persistAccessRules, pendingAccess
	defer func() { portCommand = oldCmd; persistAccessRules = oldPersist; pendingAccess = oldPending }()
	pendingAccess.token = "test-token"
	pendingAccess.expected = "expected table"
	pendingAccess.rollback = "/test/rollback.nft"
	pendingAccess.deadline = time.Now().Add(time.Minute)
	var calls []string
	portCommand = func(_ context.Context, name string, args ...string) (string, error) {
		cmd := name + " " + strings.Join(args, " ")
		calls = append(calls, cmd)
		if strings.Contains(cmd, "is-active") {
			return "inactive", errors.New("inactive")
		}
		if strings.Contains(cmd, "is-enabled") {
			return "disabled", errors.New("disabled")
		}
		if strings.Contains(cmd, "list table") {
			return "expected table", nil
		}
		return "", nil
	}
	persistAccessRules = func(context.Context) error { calls = append(calls, "persist"); return errors.New("disk full") }
	if err := ConfirmFirewallAccess("test-token"); err == nil {
		t.Fatal("save failure ignored")
	}
	all := strings.Join(calls, "\n")
	stop := strings.Index(all, "systemctl stop")
	save := strings.Index(all, "persist")
	restore := strings.Index(all, "nft --file /test/rollback.nft")
	if stop < 0 || save < stop || restore < save || !strings.Contains(all, "systemctl disable nftables") {
		t.Fatalf("unsafe failure ordering: %s", all)
	}
	if pendingAccess.token != "" {
		t.Fatal("failed transaction remains confirmable")
	}
}

func TestAccessExpiredConfirmationDoesNotMutate(t *testing.T) {
	oldCmd, oldPending := portCommand, pendingAccess
	defer func() { portCommand = oldCmd; pendingAccess = oldPending }()
	pendingAccess.token = "expired"
	pendingAccess.deadline = time.Now().Add(5 * time.Second)
	portCommand = func(context.Context, string, ...string) (string, error) {
		t.Fatal("expired confirmation ran a command")
		return "", nil
	}
	if err := ConfirmFirewallAccess("expired"); err == nil {
		t.Fatal("late confirmation accepted")
	}
}
