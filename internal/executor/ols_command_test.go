package executor

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// The test binary supplies a real local child process without a shell or a
// platform-specific sleep command. It never contacts the network or a service.
func TestOLSBoundedCommandChild(t *testing.T) {
	switch os.Args[len(os.Args)-1] {
	case "ols-command-sleep":
		time.Sleep(5 * time.Second)
	case "ols-command-output":
		_, _ = os.Stdout.WriteString("ols-command-completed\n")
	}
}

func TestRunOLSCommandBoundedCancelsHungChild(t *testing.T) {
	start := time.Now()
	_, err := runOLSCommandBounded(100*time.Millisecond, os.Args[0], "-test.run=^TestOLSBoundedCommandChild$", "--", "ols-command-sleep")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung command error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("hung command did not stop within bounded budget: %v", elapsed)
	}
}

func TestRunOLSCommandBoundedRetainsSuccessfulOutput(t *testing.T) {
	output, err := runOLSCommandBounded(5*time.Second, os.Args[0], "-test.run=^TestOLSBoundedCommandChild$", "--", "ols-command-output")
	if err != nil || !strings.Contains(string(output), "ols-command-completed") {
		t.Fatalf("successful command output = %q, error = %v", output, err)
	}
}
