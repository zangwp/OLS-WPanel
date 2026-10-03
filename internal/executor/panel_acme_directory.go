package executor

import (
	"fmt"
	"os"
	"path/filepath"
)

// The ACME context is present before a certificate is requested. Its public
// challenge directories must therefore exist before OLS validates the vhost.
// Never follow a replacement symlink or relax permissions on config parents.
func ensurePanelACMEChallengeDirectory(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("读取 ACME 根目录失败: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("ACME 根目录不是安全目录: %s", root)
	}
	for _, dir := range []string{filepath.Join(root, ".well-known"), filepath.Join(root, ".well-known", "acme-challenge")} {
		info, err := os.Lstat(dir)
		if os.IsNotExist(err) {
			if err = os.Mkdir(dir, 0755); err != nil {
				return fmt.Errorf("创建 ACME 验证目录失败: %w", err)
			}
		} else if err != nil {
			return err
		} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("ACME 验证路径不是安全目录: %s", dir)
		}
		if err := os.Chmod(dir, 0755); err != nil {
			return fmt.Errorf("修复 ACME 验证目录权限失败: %w", err)
		}
	}
	return nil
}
