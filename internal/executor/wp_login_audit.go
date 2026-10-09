package executor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/config"
)

const wpLoginFailureLogName = "wp-login-security.log"
const wpLoginFailureLogLimit = 8 * 1024 * 1024

var wpLoginAuditBlock = regexp.MustCompile(`(?s)/\* OLS-WPANEL-LOGIN-AUDIT-BEGIN \*/.*?/\* OLS-WPANEL-LOGIN-AUDIT-END \*/\r?\n?`)

// This is independent of update/application-password settings: changing either
// must not disable real authentication-failure reporting. WordPress converts
// preinitialized hooks while loading its plugin API. XML-RPC uses the same
// wp_authenticate/wp_login_failed path, so a second XML-RPC hook would double count.
func renderWPLoginFailureLogging(content, logPath string) string {
	content = wpLoginAuditBlock.ReplaceAllString(content, "")
	if logPath == "" {
		return content
	}
	body := fmt.Sprintf(`/* OLS-WPANEL-LOGIN-AUDIT-BEGIN */
if (!function_exists('ols_wpanel_log_login_failure')) {
 function ols_wpanel_log_login_failure($unused_username, $error = null) {
  static $recorded = false;
  if ($recorded || !($error instanceof WP_Error)) return;
  if (!in_array($error->get_error_code(), array('invalid_username', 'invalid_email', 'incorrect_password'), true)) return;
  $ip = $_SERVER['REMOTE_ADDR'] ?? '';
  if (!is_string($ip)) return;
  $packed = @inet_pton($ip);
  if ($packed === false) return;
  if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") $packed = substr($packed, 12);
  $ip = inet_ntop($packed);
  if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) return;
  $path = '%s';
  clearstatcache(true, $path);
  if (is_link($path) || !is_file($path)) return;
  $before = @lstat($path);
  $log = @fopen($path, 'ab');
  if ($log === false) return;
  $opened = @fstat($log);
  if (!is_array($before) || !is_array($opened) || $before['dev'] !== $opened['dev'] || $before['ino'] !== $opened['ino'] || ($opened['mode'] & 0170000) !== 0100000 || $opened['nlink'] !== 1) { fclose($log); return; }
  if (!flock($log, LOCK_EX | LOCK_NB)) { fclose($log); return; }
  $stat = fstat($log);
  $line = $ip . ' [' . gmdate('Y-m-d\TH:i:s\Z') . "] OLS_WPANEL_LOGIN_FAILED\n";
  if (is_array($stat) && $stat['size'] + strlen($line) <= %d) $recorded = fwrite($log, $line) === strlen($line);
  flock($log, LOCK_UN);
  fclose($log);
 }
}
if (PHP_SAPI !== 'cli') {
 $GLOBALS['wp_filter']['wp_login_failed'][PHP_INT_MAX][] = array('function' => 'ols_wpanel_log_login_failure', 'accepted_args' => 2);
}
/* OLS-WPANEL-LOGIN-AUDIT-END */
`, phpSingleQuoteEscape(filepath.ToSlash(logPath)), wpLoginFailureLogLimit)
	return insertBeforeMarker(content, body)
}

// ConfigureWPLoginFailureLogging installs a bounded, site-writable audit log
// without changing WordPress settings or running WordPress/plugin code.
// PHP's per-site open_basedir must also include this site's log directory.
func ConfigureWPLoginFailureLogging(webRoot, logDir, systemUser string) error {
	configPath, err := managedWordPressPath(webRoot, "wp-config.php")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	logPath, err := prepareWPLoginFailureLog(logDir, systemUser)
	if err != nil {
		return fmt.Errorf("登录失败审计日志不可安全写入: %w", err)
	}
	next := renderWPLoginFailureLogging(string(data), logPath)
	if next == string(data) {
		return nil
	}
	return writeManagedPHPFile(webRoot, configPath, []byte(next), 0600)
}

func migrateWPLoginFailureLogging(webRoot, logDir, systemUser string) (func() error, error) {
	noop := func() error { return nil }
	configPath, err := managedWordPressPath(webRoot, "wp-config.php")
	if err != nil {
		return nil, err
	}
	before, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		return noop, nil
	}
	if err != nil {
		return nil, err
	}
	// Pre-upgrade/custom sites without the managed audit block are repaired by
	// startup baseline. Renaming alone does not introduce an unrelated policy.
	if !wpLoginAuditBlock.Match(before) {
		return noop, nil
	}
	after := []byte(renderWPLoginFailureLogging(string(before), filepath.Join(filepath.Clean(logDir), wpLoginFailureLogName)))
	restore := func() error {
		current, err := os.ReadFile(configPath)
		if err != nil {
			return err
		}
		if bytes.Equal(current, before) {
			return nil
		}
		if !bytes.Equal(current, after) {
			return fmt.Errorf("WordPress 配置已变化，拒绝覆盖并发修改")
		}
		return writeManagedPHPFile(webRoot, configPath, before, 0600)
	}
	if err := ConfigureWPLoginFailureLogging(webRoot, logDir, systemUser); err != nil {
		return restore, err
	}
	return restore, nil
}

func wpLoginAuditLogPath(logDir string) (string, error) {
	logRoot := siteLogRoot
	if cfg := config.AppConfig; cfg != nil && strings.TrimSpace(cfg.Paths.WWWLogs) != "" {
		logRoot = cfg.Paths.WWWLogs
	}
	logRoot, logDir = filepath.Clean(logRoot), filepath.Clean(strings.TrimSpace(logDir))
	if !filepath.IsAbs(logRoot) || !filepath.IsAbs(logDir) || strings.ContainsAny(logDir, "\r\n\x00") {
		return "", fmt.Errorf("日志目录必须是绝对路径")
	}
	rel, err := filepath.Rel(logRoot, logDir)
	if err != nil || rel == "." || rel == ".." || strings.ContainsAny(rel, `/\`) {
		return "", fmt.Errorf("日志目录必须是日志根目录下的独立站点目录")
	}
	// Inspect every parent, including the configured root. Only root may rename
	// the log file or its parents; never make configuration directories public.
	for current := logDir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		owner, _, ownerErr := fileOwnerIDs(info)
		stickyParent := current != logDir && current != logRoot && info.Mode()&os.ModeSticky != 0
		if ownerErr != nil || owner != 0 || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (info.Mode().Perm()&0022 != 0 && !stickyParent) {
			return "", fmt.Errorf("日志目录不安全: %s", current)
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return filepath.Join(logDir, wpLoginFailureLogName), nil
}

func prepareWPLoginFailureLog(logDir, systemUser string) (string, error) {
	logPath, err := wpLoginAuditLogPath(logDir)
	if err != nil {
		return "", err
	}
	uid, gid, err := siteUserIDs(strings.TrimSpace(systemUser))
	if err != nil || uid <= 0 || gid <= 0 {
		return "", fmt.Errorf("站点用户或用户组无效")
	}
	if err := wpLoginAuditTraversal(logDir, gid); err != nil {
		return "", err
	}
	info, statErr := os.Lstat(logPath)
	flags := os.O_WRONLY | os.O_APPEND
	if os.IsNotExist(statErr) {
		flags |= os.O_CREATE | os.O_EXCL
	} else if statErr != nil {
		return "", statErr
	} else if err := validateOwnedRegularFile(logPath, 0, 0002); err != nil {
		return "", err
	}
	f, err := os.OpenFile(logPath, flags, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || (info != nil && !os.SameFile(info, opened)) {
		return "", fmt.Errorf("打开日志时文件身份发生变化")
	}
	if err := f.Chown(0, gid); err != nil {
		return "", err
	}
	if err := f.Chmod(0660); err != nil {
		return "", err
	}
	return logPath, nil
}

func wpLoginAuditTraversal(logDir string, gid int) error {
	// fopen is performed by the isolated site PHP worker, not the panel/root.
	// Check traversal without making a private parent directory world-readable.
	for current := logDir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		_, ownerGID, err := fileOwnerIDs(info)
		if err != nil || (info.Mode().Perm()&0001 == 0 && (ownerGID != gid || info.Mode().Perm()&0010 == 0)) {
			return fmt.Errorf("站点 PHP 用户不能遍历日志目录: %s", current)
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

// This reports installation, not recent traffic or proof that a ban occurred.
func WPLoginFailureLoggingConfigured(webRoot, logDir string, systemUser ...string) bool {
	configPath, err := managedWordPressPath(webRoot, "wp-config.php")
	if err != nil {
		return false
	}
	logPath, err := wpLoginAuditLogPath(logDir)
	if err != nil || validateOwnedRegularFile(logPath, 0, 0002) != nil {
		return false
	}
	info, err := os.Lstat(logPath)
	if err != nil || info.Mode().Perm() != 0660 || info.Size() >= wpLoginFailureLogLimit {
		return false
	}
	_, logGID, ownerErr := fileOwnerIDs(info)
	if ownerErr != nil || logGID <= 0 || wpLoginAuditTraversal(logDir, logGID) != nil {
		return false
	}
	if len(systemUser) > 0 {
		_, gid, err := siteUserIDs(systemUser[0])
		if err != nil || gid <= 0 || gid != logGID {
			return false
		}
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	block := wpLoginAuditBlock.FindString(string(data))
	return block != "" && block == wpLoginAuditBlock.FindString(renderWPLoginFailureLogging("<?php\n", logPath))
}
