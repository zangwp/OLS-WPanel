package handlers

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestVPSCommandHelper(t *testing.T) {
	if os.Getenv("WPANEL_VPS_PROBE_HELPER") != "1" {
		return
	}
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "inactive", "disabled":
		_, _ = os.Stdout.WriteString(mode + "\n")
		os.Exit(3)
	case "stderr":
		_, _ = os.Stderr.WriteString("failed\n")
		os.Exit(1)
	case "blocked":
		_, _ = os.Stdout.WriteString("active\n")
		time.Sleep(10 * time.Second)
	default:
		_, _ = os.Stdout.WriteString(mode + "\n")
	}
	os.Exit(0)
}

func stubVPSCommand(t *testing.T, mode string) *int {
	t.Helper()
	old := hostCommandContext
	calls := 0
	hostCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 2*time.Second {
			t.Fatal("missing host command deadline")
		}
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestVPSCommandHelper", "--", mode)
		cmd.Env = append(os.Environ(), "WPANEL_VPS_PROBE_HELPER=1")
		return cmd
	}
	t.Cleanup(func() { hostCommandContext = old })
	return &calls
}

func TestVPSServiceStateKeepsValidNonzeroStdoutAndRejectsStderr(t *testing.T) {
	for _, mode := range []string{"inactive", "disabled", "stderr", "not-a-state"} {
		t.Run(mode, func(t *testing.T) {
			stubVPSCommand(t, mode)
			want := mode
			if mode == "stderr" || mode == "not-a-state" {
				want = "unknown"
			}
			if state := systemctlState(context.Background(), "is-active", "fixture"); state != want {
				t.Fatalf("state=%q want=%q", state, want)
			}
		})
	}
}

func TestVPSSharedContextDoesNotRestartTwoSecondBudgets(t *testing.T) {
	calls := stubVPSCommand(t, "blocked")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	started := time.Now()
	for i := 0; i < 12; i++ {
		if state := systemctlState(ctx, "is-active", "fixture"); state != "unknown" {
			t.Fatalf("cancelled output treated as real state: %q", state)
		}
	}
	if *calls != 1 || time.Since(started) > 2*time.Second {
		t.Fatalf("expired context launched subsequent probes: calls=%d elapsed=%v", *calls, time.Since(started))
	}
}

func TestVPSNTPUnknownIsNotFalse(t *testing.T) {
	for _, mode := range []string{"yes", "no", "stderr", "unexpected"} {
		t.Run(mode, func(t *testing.T) {
			stubVPSCommand(t, mode)
			state := readNTPSynchronized(context.Background())
			if mode == "yes" || mode == "no" {
				if state == nil || *state != (mode == "yes") {
					t.Fatalf("NTP state=%v for %q", state, mode)
				}
			} else if state != nil {
				t.Fatal("unavailable NTP reported false")
			}
			payload, _ := json.Marshal(struct {
				State *bool `json:"ntp_synchronized"`
			}{state})
			if state == nil && string(payload) != `{"ntp_synchronized":null}` {
				t.Fatalf("unknown JSON=%s", payload)
			}
		})
	}
}
