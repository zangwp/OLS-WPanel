package executor

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

func cleanFail2banWebsiteLogRoot(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, "\x00\r\n\t *?[]{}%#;") || (!filepath.IsAbs(raw) && !strings.HasPrefix(raw, "/")) {
		return "", fmt.Errorf("Fail2ban 网站日志根目录必须是安全绝对路径，不能包含空白、通配符或 INI 控制字符")
	}
	root := filepath.ToSlash(filepath.Clean(raw))
	if root == "/" || root == "." {
		return "", fmt.Errorf("Fail2ban 网站日志根目录不能是文件系统根目录")
	}
	return root, nil
}

func fail2banWebsiteLogRoot() (string, error) {
	root := siteLogRoot
	if cfg := config.AppConfig; cfg != nil && cfg.Paths.WWWLogs != "" {
		root = cfg.Paths.WWWLogs
	}
	return cleanFail2banWebsiteLogRoot(root)
}

func renderFail2banWebsiteLogPaths(content, rawRoot string) (string, error) {
	root, err := cleanFail2banWebsiteLogRoot(rawRoot)
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(content, siteLogRoot+"/", root+"/"), nil
}

var readFail2banLoginLogPaths = func(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "fail2ban-client", "get", "olswpanel-login", "logpath").CombinedOutput()
	return string(out), err
}

func fail2banMonitorsExactLogPath(output, logPath string) bool {
	expected := filepath.ToSlash(filepath.Clean(logPath))
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|- ") && !strings.HasPrefix(line, "`- ") {
			continue
		}
		candidate := strings.TrimSpace(line[3:])
		if filepath.ToSlash(filepath.Clean(candidate)) == expected {
			return true
		}
	}
	return false
}

// Query the live jail's expanded file list. Its existence alone does not prove
// a newly created site or a custom log root is currently being watched.
func WPLoginFailureJailMatches(ctx context.Context, logPath string) bool {
	root, err := fail2banWebsiteLogRoot()
	if err != nil || strings.ContainsAny(logPath, "\x00\r\n\t *?[]{}%#;") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(logPath))
	if !strings.HasPrefix(clean, root+"/") || filepath.Base(clean) != wpLoginFailureLogName {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	readCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	if readCtx.Err() != nil {
		return false
	}
	output, err := readFail2banLoginLogPaths(readCtx)
	return err == nil && readCtx.Err() == nil && fail2banMonitorsExactLogPath(output, clean)
}
