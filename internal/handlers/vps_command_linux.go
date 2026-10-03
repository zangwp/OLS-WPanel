//go:build linux

package handlers

import (
	"os/exec"
)

var hostCommandContext = exec.CommandContext
