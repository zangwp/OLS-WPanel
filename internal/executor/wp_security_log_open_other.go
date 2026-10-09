//go:build !linux

package executor

import "os"

func openWPSecurityLogReadOnly(path string) (*os.File, error) { return os.Open(path) }
