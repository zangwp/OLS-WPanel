package executor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const opcacheClearTimeout = 30 * time.Second

// ClearOPcache 清空 PHP 的 OPcache 字节码缓存。
//
// OPcache 由 OpenLiteSpeed 管理的 LSPHP worker 共享，不区分站点，所以这是一个
// 全局操作。先校验服务器配置，再重启 lsws 以替换 worker 并重建 OPcache。
func ClearOPcache() error {
	ctx, cancel := context.WithTimeout(context.Background(), opcacheClearTimeout)
	defer cancel()
	paths := currentOLSRuntimePaths()
	if out, err := exec.CommandContext(ctx, paths.binary, "-t").CombinedOutput(); err != nil {
		return fmt.Errorf("OpenLiteSpeed 配置检查失败: %s", strings.TrimSpace(string(out)))
	}
	out, err := exec.CommandContext(ctx, "systemctl", "restart", "lsws").CombinedOutput()
	if err != nil {
		return fmt.Errorf("重启 OpenLiteSpeed/LSPHP 失败: %s", strings.TrimSpace(string(out)))
	}
	return nil
}
