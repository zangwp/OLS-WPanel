package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

var nftablesPersistenceCommand = exec.CommandContext

// EnableNftablesBoot validates the packaged persistent ruleset before enabling
// its fixed systemd unit. It intentionally does not reload or replace the
// currently active rules, so the administrator's current connection is not
// disrupted by this action.
func EnableNftablesBoot() error {
	if runtime.GOOS != "linux" {
		return errors.New("nftables 开机加载仅支持 Linux")
	}
	const configPath = "/etc/nftables.conf"
	if err := validateNftablesPersistenceConfig(configPath); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, checkErr := nftablesPersistenceCommand(ctx, "nft", "--check", "--file", configPath).CombinedOutput(); checkErr != nil {
		return fmt.Errorf("nftables 配置验证失败: %s", strings.TrimSpace(string(output)))
	}
	if output, enableErr := nftablesPersistenceCommand(ctx, "systemctl", "enable", "nftables.service").CombinedOutput(); enableErr != nil {
		return fmt.Errorf("启用 nftables 开机加载失败: %s", strings.TrimSpace(string(output)))
	}
	recordOperationLog("nftables_enable_boot", "nftables.service", "success", "validated "+configPath)
	return nil
}

func validateNftablesPersistenceConfig(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("未找到 %s，未更改开机状态", path)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 1024*1024 {
		return errors.New("nftables 持久化配置文件不符合安全要求")
	}
	return nil
}
