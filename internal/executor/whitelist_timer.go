package executor

import (
	"fmt"
	"os"
)

func DeployWhitelistTimer() error {
	return deployWhitelistTimer(os.WriteFile, executeCommand)
}

// The timer activates the oneshot only when it elapses (or Persistent catches
// a missed run). Requires=service would also start a refresh whenever the
// timer is enabled/started, instead of merely installing the schedule.
func deployWhitelistTimer(writeFile func(string, []byte, os.FileMode) error, run func(string, ...string) (string, error)) error {
	timerUnit := `[Unit]
Description=OLS WPanel Weekly Whitelist Refresh

[Timer]
Unit=olswpanel-whitelist.service
OnCalendar=Mon *-*-* 04:00:00
Persistent=true

[Install]
WantedBy=timers.target
`
	serviceUnit := `[Unit]
Description=OLS WPanel Whitelist Refresh

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ols-wpanel --refresh-whitelist --config=/www/ols-wpanel/config.json
`
	if err := writeFile("/etc/systemd/system/olswpanel-whitelist.timer", []byte(timerUnit), 0644); err != nil {
		return fmt.Errorf("写入白名单定时器失败: %w", err)
	}
	if err := writeFile("/etc/systemd/system/olswpanel-whitelist.service", []byte(serviceUnit), 0644); err != nil {
		return fmt.Errorf("写入白名单刷新服务失败: %w", err)
	}
	if _, err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("重载 systemd 配置失败: %w", err)
	}
	if _, err := run("systemctl", "enable", "olswpanel-whitelist.timer"); err != nil {
		return fmt.Errorf("启用白名单定时器失败: %w", err)
	}
	if _, err := run("systemctl", "start", "olswpanel-whitelist.timer"); err != nil {
		return fmt.Errorf("启动白名单定时器失败: %w", err)
	}
	return nil
}
