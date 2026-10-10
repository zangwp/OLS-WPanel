package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/config"
	"github.com/zangwp/OLS-WPanel/internal/database"
)

var (
	olsIPv6UpgradeCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
	olsIPv6UpgradePaused = func() bool {
		data, err := os.ReadFile("/www/ols-wpanel/guard_paused.json")
		if os.IsNotExist(err) {
			return false
		}
		var paused map[string]bool
		return err != nil || json.Unmarshal(data, &paused) != nil || paused["lshttpd"] || paused["lsws"]
	}
)

func init() {
	database.RegisterUpgrade("1.0.75", ensureManagedOLSIPv6Listeners)
}

// Update only the panel-owned registry of a running server. IPv6 detection or
// service failures remain optional and never prevent the panel from starting.
func ensureManagedOLSIPv6Listeners() error {
	if olsIPv6UpgradePaused() || !olsIPv6Available() {
		return nil
	}
	paths := currentOLSRuntimePaths()
	info, err := os.Lstat(paths.managed)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	old, err := os.ReadFile(paths.managed)
	if err != nil || !bytes.HasPrefix(old, []byte("# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.\n")) {
		return nil
	}
	enabled := filepath.Join(filepath.Dir(paths.managed), "sites-enabled")
	if config.AppConfig != nil && strings.TrimSpace(config.AppConfig.Paths.OLSVHostsEnabled) != "" {
		enabled = filepath.Clean(config.AppConfig.Paths.OLSVHostsEnabled)
	}
	candidate, err := renderOLSManagedRegistryWithIPv6(enabled, true)
	if err != nil {
		log.Printf("[升级] OpenLiteSpeed IPv6 配置检查失败，保留原配置: %v", err)
		return nil
	}
	if bytes.Equal(old, []byte(candidate)) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := olsIPv6UpgradeCommand(ctx, "systemctl", "is-active", "--quiet", "lshttpd"); err != nil {
		return nil
	}
	if _, err := reloadOLSManagedRegistryWithIPv6(enabled, true); err != nil {
		log.Printf("[升级] OpenLiteSpeed IPv6 更新失败，已尝试恢复原配置，不阻止面板启动: %v", err)
		return nil
	}
	log.Printf("[升级] 已同步 OpenLiteSpeed 受管监听配置（IPv4 保留，IPv6 按验证结果启用）")
	return nil
}
