package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWhitelistRefreshCLIReportsFailureToSystemd(t *testing.T) {
	for _, scenario := range []struct {
		name     string
		success  bool
		message  string
		exitCode int
		prefix   string
	}{
		{"success", true, "完整网段已应用", 0, "白名单刷新结果:"},
		{"failed-recovered", false, "应用失败，原配置已恢复", 1, "白名单刷新失败:"},
		{"failed-incomplete-recovery", false, "恢复未完成，请人工检查", 1, "白名单刷新失败:"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var output bytes.Buffer
			if got := writeWhitelistRefreshCLIResult(&output, scenario.success, scenario.message); got != scenario.exitCode {
				t.Fatalf("CLI exit=%d, want %d", got, scenario.exitCode)
			}
			if !strings.HasPrefix(output.String(), scenario.prefix) || !strings.Contains(output.String(), scenario.message) {
				t.Fatalf("refresh diagnostic lost: %q", output.String())
			}
		})
	}
}
