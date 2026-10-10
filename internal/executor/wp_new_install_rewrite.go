package executor

import (
	"fmt"
	"os"
)

// WordPress core's non-verbose, single-site root-directory rules, as emitted by
// WP_Rewrite::mod_rewrite_rules(). A new managed WordPress site installs in the
// document root. Real files/directories (including login/admin and uploads)
// keep their normal handlers; virtual permalinks route through index.php.
const newWordPressRootRewrite = `# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
# END WordPress
`

// prepareNewWordPressRewrite is called only by the new-site deployment wrapper,
// before its first OLS configuration load. O_EXCL preserves package-supplied
// and other existing rules, including empty files. It never edits a live site
// or intercepts user/plugin rewrite rules in the generated vhost.
func prepareNewWordPressRewrite(webRoot string) (err error) {
	path, err := managedWordPressPath(webRoot, ".htaccess")
	if err != nil {
		return fmt.Errorf("准备 WordPress 固定链接规则失败: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if os.IsExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("创建 WordPress 固定链接规则失败: %w", err)
	}
	defer func() {
		file.Close()
		if err != nil {
			os.Remove(path)
		}
	}()
	if _, err = file.WriteString(newWordPressRootRewrite); err != nil {
		return fmt.Errorf("写入 WordPress 固定链接规则失败: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("保存 WordPress 固定链接规则失败: %w", err)
	}
	if err = file.Close(); err != nil {
		return fmt.Errorf("关闭 WordPress 固定链接规则文件失败: %w", err)
	}
	return nil
}
