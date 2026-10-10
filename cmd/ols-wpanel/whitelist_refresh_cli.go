package main

import (
	"fmt"
	"io"
)

// A failed refresh must fail the oneshot, so systemd does not report success
// just because the executable could print the task's diagnostic message.
func writeWhitelistRefreshCLIResult(output io.Writer, success bool, message string) int {
	if !success {
		fmt.Fprintf(output, "白名单刷新失败: %s\n", message)
		return 1
	}
	fmt.Fprintf(output, "白名单刷新结果: %s\n", message)
	return 0
}
