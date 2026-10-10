//go:build !linux

package executor

import "errors"

func exchangeFileRestoreDirectories(string, string) error {
	return errors.New("atomic directory exchange is only supported on Linux")
}

func availableFileRestoreBytes(string) (int64, error) {
	return 0, errors.New("restore filesystem space verification is only supported on Linux")
}
