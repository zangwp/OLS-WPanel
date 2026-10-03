package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func inspectDevelopmentCommand(ctx context.Context, binary string, args ...string) (string, string) {
	path := binary
	if !filepath.IsAbs(path) {
		resolved, err := exec.LookPath(binary)
		if err != nil {
			if errors.Is(err, exec.ErrNotFound) {
				return "", "missing"
			}
			return "", "error"
		}
		path = resolved
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", "missing"
		}
		return "", "error"
	}
	if info.IsDir() {
		return "", "error"
	}
	out, err := exec.CommandContext(ctx, path, args...).Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		return "", "error"
	}
	return strings.TrimSpace(string(out)), "installed"
}

func combinedDevelopmentState(first, second string) string {
	if first == "error" || second == "error" {
		return "error"
	}
	if first == second {
		return first
	}
	return "partial"
}
