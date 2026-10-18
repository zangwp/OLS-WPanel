package executor

import (
	"bytes"
	"context"
	"log"
	"os/exec"
	"time"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

var olsTrustedProxyUpgradeActive = func() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "lshttpd")
	command.WaitDelay = time.Second
	return command.Run() == nil
}

func init() {
	database.RegisterUpgrade("1.0.76", ensureManagedOLSTrustedProxyACL)
	database.RegisterUpgrade("1.0.80", ensureManagedOLSTrustedProxyACL)
}

// Reconcile automatic Cloudflare and selected CDNs on a running managed OLS.
// A paused/stopped service stays stopped; failures are logged without blocking
// panel startup. Normal settings saves still return a failure to their caller.
func ensureManagedOLSTrustedProxyACL() error {
	if olsIPv6UpgradePaused() || database.GetDB() == nil {
		return nil
	}
	if err := WithFail2banSettingsLock(func(func() error) error {
		return reconcileManagedOLSTrustedProxyACL()
	}); err != nil {
		log.Printf("[升级] OpenLiteSpeed 可信代理配置未更新，延后重试: %v", err)
	}
	return nil
}

func reconcileManagedOLSTrustedProxyACL() error {
	olsTrustedProxyConfigMu.Lock()
	defer olsTrustedProxyConfigMu.Unlock()
	ranges, err := combinedOLSTrustedProxyRanges(database.GetDB())
	if err != nil {
		log.Printf("[升级] OpenLiteSpeed 可信代理配置未更新: %v", err)
		return nil
	}
	if len(ranges) == 0 {
		return nil
	}
	paths := currentOLSRuntimePaths()
	registry, _, err := readOLSTrustedProxyConfig(paths.managed)
	if err != nil || !bytes.HasPrefix(registry, []byte("# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.\n")) {
		return nil
	}
	old, _, err := readOLSTrustedProxyConfig(paths.mainConfig)
	if err != nil {
		return nil
	}
	candidate, err := renderOLSTrustedProxyMainConfig(old, paths.managed, ranges)
	if err != nil {
		log.Printf("[升级] OpenLiteSpeed 可信代理配置未更新，保留原主配置: %v", err)
		return nil
	}
	if string(candidate) == string(old) || !olsTrustedProxyUpgradeActive() {
		return nil
	}
	if err := applyOLSTrustedProxyRanges(paths.mainConfig, paths.managed, ranges); err != nil {
		log.Printf("[升级] OpenLiteSpeed 可信代理 ACL 更新失败，已尝试恢复原主配置: %v", err)
		return nil
	}
	log.Printf("[升级] 已将启用的 CDN 回源网络接入 OpenLiteSpeed 服务器可信代理 ACL")
	return nil
}
