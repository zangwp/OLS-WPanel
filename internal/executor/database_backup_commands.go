package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
)

func backupCommandCandidates(name string) []string {
	switch name {
	case "mysql":
		return []string{"mysql", "mariadb"}
	case "mysqldump":
		return []string{"mysqldump", "mariadb-dump"}
	default:
		return []string{name}
	}
}

// Detection and execution must select the same alternatives. Only a missing
// command permits fallback; other lookup errors must remain visible.
func findBackupCommand(names []string, lookPath func(string) (string, error)) (string, error) {
	var lastErr error
	for _, name := range names {
		path, err := lookPath(name)
		if err == nil {
			return path, nil
		}
		if !errors.Is(err, exec.ErrNotFound) && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		lastErr = err
	}
	return "", lastErr
}

func newDatabaseBackupCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	path, err := findBackupCommand(backupCommandCandidates(name), backupDependencyLookPath)
	if err != nil {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Err = err
		return cmd
	}
	return exec.CommandContext(ctx, path, args...)
}
