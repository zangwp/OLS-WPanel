package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WordPress password reset protection modes:
//   - allow: default; allow all users to reset passwords.
//   - all: disable resets for everyone and hide the login page's reset link.
//   - admin: disable resets only for administrators.
const (
	PasswordResetModeAllow = "allow"
	PasswordResetModeAll   = "all"
	PasswordResetModeAdmin = "admin"
)

// olsWPanelPasswordResetMarker identifies the panel-managed mu-plugin.
// The panel deletes it in allow mode and overwrites it otherwise; do not edit it manually.
const olsWPanelPasswordResetMarker = "OLS-WPANEL-MANAGED:password-reset"

const wpPasswordResetPluginFile = "ols-wpanel-password-reset.php"

// ValidatePasswordResetMode returns a valid password reset mode or an error.
func ValidatePasswordResetMode(mode string) (string, error) {
	switch mode {
	case PasswordResetModeAllow, PasswordResetModeAll, PasswordResetModeAdmin:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid password reset mode: %q", mode)
	}
}

// ApplyWPPasswordResetMode manages the site's password reset mu-plugin:
//   - allow: remove the managed file to restore WordPress defaults.
//   - all/admin: write the mode's plugin and assign it to the site user.
//
// Create mu-plugins when needed. webRoot must be absolute, nonempty, and not a filesystem root;
// the derived path must remain inside it to prevent tampered database paths from redirecting writes.
func ApplyWPPasswordResetMode(webRoot, systemUser, mode string) error {
	webRoot = strings.TrimSpace(webRoot)
	if webRoot == "" {
		return fmt.Errorf("web root is empty")
	}
	webRoot = filepath.Clean(webRoot)
	if !filepath.IsAbs(webRoot) {
		return fmt.Errorf("web root must be an absolute path: %s", webRoot)
	}
	if webRoot == string(filepath.Separator) {
		return fmt.Errorf("web root cannot be filesystem root")
	}
	mode, err := ValidatePasswordResetMode(mode)
	if err != nil {
		return err
	}

	muDir, err := managedWordPressPath(webRoot, "wp-content", "mu-plugins")
	if err != nil {
		return fmt.Errorf("password reset mu-plugin path: %w", err)
	}
	pluginPath, err := managedWordPressPath(webRoot, "wp-content", "mu-plugins", wpPasswordResetPluginFile)
	if err != nil {
		return fmt.Errorf("password reset mu-plugin path: %w", err)
	}
	if mode == PasswordResetModeAllow {
		if _, statErr := os.Lstat(pluginPath); statErr == nil {
			if rmErr := os.Remove(pluginPath); rmErr != nil {
				return fmt.Errorf("remove password reset mu-plugin: %w", rmErr)
			}
		}
		return nil
	}

	if err := os.MkdirAll(muDir, 0755); err != nil {
		return fmt.Errorf("create mu-plugins dir: %w", err)
	}
	content := renderWPPasswordResetPlugin(mode)
	if err := writeManagedPHPFile(webRoot, pluginPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("write password reset mu-plugin: %w", err)
	}

	systemUser = strings.TrimSpace(systemUser)
	if systemUser != "" {
		// The site user running LSPHP must own the mu-plugin to read it.
		// Report chown failures so a successful save cannot silently leave the policy ineffective.
		if chErr := ChownSitePath(pluginPath, webRoot, systemUser); chErr != nil {
			return fmt.Errorf("chown password reset mu-plugin to %s: %w", systemUser, chErr)
		}
		if chErr := ChownSitePath(muDir, webRoot, systemUser); chErr != nil {
			return fmt.Errorf("chown mu-plugins dir to %s: %w", systemUser, chErr)
		}
	}
	return nil
}

func WPPasswordResetModeMatches(webRoot, mode string) (bool, error) {
	mode, err := ValidatePasswordResetMode(mode)
	if err != nil {
		return false, err
	}
	pluginPath, err := managedWordPressPath(webRoot, "wp-content", "mu-plugins", wpPasswordResetPluginFile)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(pluginPath)
	if mode == PasswordResetModeAllow {
		if os.IsNotExist(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return string(data) == renderWPPasswordResetPlugin(mode), nil
}

// renderWPPasswordResetPlugin generates the managed mu-plugin.
// In all mode, CSS hides p#nav, including its reset and back-to-site links.
func renderWPPasswordResetPlugin(mode string) string {
	var body string
	switch mode {
	case PasswordResetModeAll:
		body = `// 禁止所有用户通过“忘记密码”找回/重置密码（retrieve_password 在发邮件前即中止）。
add_filter('allow_password_reset', '__return_false');

// 隐藏登录页“忘记密码？”链接，避免暴露该功能入口。
add_action('login_head', function () {
    echo '<style>p#nav { display:none !important; }</style>';
});`
	case PasswordResetModeAdmin:
		body = `// 仅禁止具有 administrator 角色的用户找回/重置密码；其余用户不受影响。
add_filter('allow_password_reset', function ($allow, $user_id) {
    $user = get_userdata($user_id);
    if ($user && $user->has_cap('administrator')) {
        return false;
    }
    return $allow;
}, 10, 2);`
	}
	return fmt.Sprintf(`<?php
// %s
// 由 OLS WPanel 托管：密码找回保护（mode: %s）。请勿手动修改，面板会覆盖本文件。

%s
`, olsWPanelPasswordResetMarker, mode, body)
}
