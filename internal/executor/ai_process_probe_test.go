package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestAIProcessProbeHelper(t *testing.T) {
	if os.Getenv("WPANEL_AI_PROBE_HELPER") != "1" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "success":
		_, _ = os.Stdout.WriteString("wp_demo 12.0 1.5 lsphp83\n")
	case "overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), aiProcessOutputLimit+1))
	case "blocked":
		time.Sleep(10 * time.Second)
	}
	os.Exit(0)
}

func stubAIProcessCommand(t *testing.T, mode string) *int {
	t.Helper()
	old := aiProcessCommandContext
	calls := 0
	aiProcessCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls++
		if name != "ps" || len(args) != 2 || args[0] != "-eo" || args[1] != "user:32,%cpu,%mem,comm" {
			t.Fatalf("unexpected process command %s %v", name, args)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > aiProcessProbeTimeout {
			t.Fatal("missing process deadline")
		}
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestAIProcessProbeHelper", "--", mode)
		cmd.Env = append(os.Environ(), "WPANEL_AI_PROBE_HELPER=1")
		return cmd
	}
	t.Cleanup(func() { aiProcessCommandContext = old })
	return &calls
}

func TestAIProcessProbePreservesOutput(t *testing.T) {
	stubAIProcessCommand(t, "success")
	output, err := runAIProcessList(context.Background())
	if err != nil || string(output) != "wp_demo 12.0 1.5 lsphp83\n" {
		t.Fatalf("output=%q err=%v", output, err)
	}
}

func TestAIProcessProbeRejectsExcessOutput(t *testing.T) {
	stubAIProcessCommand(t, "overflow")
	output, err := runAIProcessList(context.Background())
	if !errors.Is(err, errAIProcessOutputLimit) || output != nil {
		t.Fatalf("excess output must be unavailable: size=%d err=%v", len(output), err)
	}
	w := &aiProcessOutput{limit: 4, cancel: func() {}}
	if _, bypass := any(w).(io.ReaderFrom); bypass {
		t.Fatal("ReadFrom would bypass Write budget")
	}
	_, err = io.Copy(w, bytes.NewReader([]byte("12345")))
	if !errors.Is(err, errAIProcessOutputLimit) || w.buffer.Len() != 4 {
		t.Fatalf("copy bypassed limit: size=%d err=%v", w.buffer.Len(), err)
	}
}

func TestAIProcessProbeCancellationStopsChildAndFurtherCommands(t *testing.T) {
	calls := stubAIProcessCommand(t, "blocked")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	started := time.Now()
	output, err := runAIProcessList(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || output != nil || time.Since(started) > 2*time.Second {
		t.Fatalf("cancelled probe output=%q err=%v elapsed=%v", output, err, time.Since(started))
	}
	_, err = runAIProcessList(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || *calls != 1 {
		t.Fatalf("expired context launched another command: calls=%d err=%v", *calls, err)
	}
}
