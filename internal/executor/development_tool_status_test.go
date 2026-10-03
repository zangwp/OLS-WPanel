package executor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestToolVersionHelper(t *testing.T) {
	if os.Args[len(os.Args)-1] == "tool-version-success" {
		fmt.Print("v1.2.3")
		os.Exit(0)
	}
	if os.Args[len(os.Args)-1] == "tool-version-failure" {
		os.Exit(1)
	}
	if os.Args[len(os.Args)-1] == "tool-version-empty" {
		os.Exit(0)
	}
}

func TestDevelopmentToolDetectionStates(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, state := inspectDevelopmentCommand(context.Background(), filepath.Join(t.TempDir(), "missing")); state != "missing" {
		t.Fatal(state)
	}
	if version, state := inspectDevelopmentCommand(context.Background(), binary, "-test.run=^TestToolVersionHelper$", "--", "tool-version-success"); state != "installed" || version != "v1.2.3" {
		t.Fatalf("%q %q", version, state)
	}
	if _, state := inspectDevelopmentCommand(context.Background(), binary, "-test.run=^TestToolVersionHelper$", "--", "tool-version-failure"); state != "error" {
		t.Fatal(state)
	}
	if _, state := inspectDevelopmentCommand(context.Background(), binary, "-test.run=^TestToolVersionHelper$", "--", "tool-version-empty"); state != "error" {
		t.Fatalf("an empty version must not count as an installed tool: %s", state)
	}
	if state := combinedDevelopmentState("installed", "missing"); state != "partial" {
		t.Fatal(state)
	}
	if state := combinedDevelopmentState("installed", "error"); state != "error" {
		t.Fatal(state)
	}
	if state := combinedDevelopmentState("missing", "missing"); state != "missing" {
		t.Fatal(state)
	}
}
