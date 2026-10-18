//go:build !linux

package executor

import "os"

func prepareOLSWebAdminReplacement(string, *os.File, []byte) error { return nil }

func EnsureOLSWebAdminConfigReadAccess() error { return nil }
