//go:build windows

package config

import "os"

// Windows is a development/test platform only. Production installation is
// Linux-only, where repair_owner_unix.go enforces UID and hard-link identity.
func repairConfigOwnerSafe(os.FileInfo) bool { return true }
