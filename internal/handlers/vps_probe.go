package handlers

import (
	"context"
	"strings"
	"time"
)

func hostCommandOutput(parent context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	command := hostCommandContext(ctx, name, args...)
	command.WaitDelay = 250 * time.Millisecond
	output, err := command.Output()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return strings.TrimSpace(string(output)), err
}

func runHostCommand(ctx context.Context, name string, args ...string) string {
	output, _ := hostCommandOutput(ctx, name, args...)
	return output
}

func systemctlState(ctx context.Context, operation, unit string) string {
	// systemctl reports inactive/disabled with a nonzero exit status. Accept
	// only its recognized stdout state, never stderr or cancellation as state.
	state := strings.SplitN(runHostCommand(ctx, "systemctl", operation, unit), "\n", 2)[0]
	switch state {
	case "active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance",
		"enabled", "enabled-runtime", "disabled", "static", "indirect", "generated", "transient",
		"alias", "linked", "linked-runtime", "masked", "masked-runtime", "not-found":
		return state
	default:
		return "unknown"
	}
}

func readNTPSynchronized(ctx context.Context) *bool {
	output, err := hostCommandOutput(ctx, "timedatectl", "show", "--property=NTPSynchronized", "--value")
	if err != nil || (output != "yes" && output != "no") {
		return nil
	}
	synchronized := output == "yes"
	return &synchronized
}
