package executor

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zangwp/OLS-WPanel/internal/database"
)

const (
	managedServiceDropInLegacyContent  = "[Service]\nRestart=always\nRestartSec=5s\nStartLimitIntervalSec=0\n"
	managedServiceDropInFixedContent   = "[Unit]\nStartLimitIntervalSec=0\n\n[Service]\nRestart=always\nRestartSec=5s\n"
	managedServiceDropInBoundedContent = "[Unit]\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nRestart=on-failure\nRestartSec=5s\n"
	managedOLSServiceDropInContent     = "[Unit]\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nPIDFile=/tmp/lshttpd/lshttpd.pid\nKillMode=mixed\nRestart=on-failure\nRestartSec=5s\n"
)

var (
	managedServiceDropInRoot = "/etc/systemd/system"
	managedSystemctlCommand  = func(args ...string) error {
		output, err := exec.Command("systemctl", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
		}
		return nil
	}
)

func init() {
	database.RegisterUpgrade("1.0.40", ensureManagedServiceDropInStartLimitSections)
	database.RegisterUpgrade("1.0.68", ensureManagedServiceDropInBoundedRestarts)
	database.RegisterUpgrade("1.0.69", ensureManagedOpenLiteSpeedSystemdCompatibility)
}

// ensureManagedServiceDropInStartLimitSections repairs only the exact drop-ins
// produced by old OLS WPanel installers. Custom administrator drop-ins are left
// untouched so an update does not overwrite local service policy.
func ensureManagedServiceDropInStartLimitSections() error {
	changed, err := repairManagedServiceDropIns(managedServiceDropInRoot)
	if err != nil {
		log.Printf("[升级] 修正 systemd drop-in 失败，已跳过且不会阻止面板启动: %v", err)
		return nil
	}
	if !changed {
		log.Printf("[升级] systemd drop-in 无需修正")
		return nil
	}
	if err := managedSystemctlCommand("daemon-reload"); err != nil {
		log.Printf("[升级] systemd daemon-reload 失败，请手动执行 systemctl daemon-reload: %v", err)
		return nil
	}
	log.Printf("[升级] 已修正受管服务 systemd drop-in 的 StartLimitIntervalSec 段落位置")
	return nil
}

func repairManagedServiceDropIns(root string) (bool, error) {
	changed := false
	for _, svc := range []string{"lsws", "mariadb", "redis-server"} {
		path := filepath.Join(root, svc+".service.d", "ols-wpanel.conf")
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return changed, fmt.Errorf("读取 %s: %w", path, err)
		}
		if string(data) == managedServiceDropInFixedContent {
			continue
		}
		if string(data) != managedServiceDropInLegacyContent {
			log.Printf("[升级] 跳过自定义 systemd drop-in: %s", path)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return changed, fmt.Errorf("检查 %s: %w", path, err)
		}
		if err := os.WriteFile(path, []byte(managedServiceDropInFixedContent), info.Mode().Perm()); err != nil {
			return changed, fmt.Errorf("写入 %s: %w", path, err)
		}
		changed = true
	}
	return changed, nil
}

// ensureManagedServiceDropInBoundedRestarts replaces only drop-ins emitted by
// older installers. A broken OpenLiteSpeed configuration must not create an
// unlimited restart loop, while administrator-authored policies remain intact.
func ensureManagedServiceDropInBoundedRestarts() error {
	changed, err := repairManagedServiceDropInsBounded(managedServiceDropInRoot)
	if err != nil {
		log.Printf("[升级] 限制受管服务重启频率失败，已跳过且不会阻止面板启动: %v", err)
		return nil
	}
	if !changed {
		return nil
	}
	if err := managedSystemctlCommand("daemon-reload"); err != nil {
		log.Printf("[升级] systemd daemon-reload 失败，请手动执行 systemctl daemon-reload: %v", err)
		return nil
	}
	log.Printf("[升级] 已为受管服务启用有界的失败重启策略")
	return nil
}

func repairManagedServiceDropInsBounded(root string) (bool, error) {
	changed := false
	for _, svc := range []string{"lsws", "lshttpd", "mariadb", "redis-server"} {
		path := filepath.Join(root, svc+".service.d", "ols-wpanel.conf")
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return changed, fmt.Errorf("读取 %s: %w", path, err)
		}
		content := string(data)
		if content == managedServiceDropInBoundedContent {
			continue
		}
		if content != managedServiceDropInLegacyContent && content != managedServiceDropInFixedContent {
			log.Printf("[升级] 跳过自定义 systemd drop-in: %s", path)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return changed, fmt.Errorf("检查 %s: %w", path, err)
		}
		if err := os.WriteFile(path, []byte(managedServiceDropInBoundedContent), info.Mode().Perm()); err != nil {
			return changed, fmt.Errorf("写入 %s: %w", path, err)
		}
		changed = true
	}
	return changed, nil
}

// ensureManagedOpenLiteSpeedSystemdCompatibility aligns systemd with the PID
// file actually maintained by the upstream lswsctrl script. The vendor unit
// currently points at /var/run/openlitespeed.pid, which can make systemd lose
// the daemon after it forks and eventually time out a successful start.
func ensureManagedOpenLiteSpeedSystemdCompatibility() error {
	changed, err := repairManagedOpenLiteSpeedDropIn(managedServiceDropInRoot)
	if err != nil {
		log.Printf("[升级] 修正 OpenLiteSpeed systemd PID 跟踪失败，已跳过且不会阻止面板启动: %v", err)
		return nil
	}
	if !changed {
		return nil
	}
	if err := managedSystemctlCommand("daemon-reload"); err != nil {
		log.Printf("[升级] systemd daemon-reload 失败，请手动执行 systemctl daemon-reload: %v", err)
		return nil
	}
	log.Printf("[升级] 已修正 OpenLiteSpeed systemd PID 跟踪与停止策略")
	return nil
}

func repairManagedOpenLiteSpeedDropIn(root string) (bool, error) {
	path := filepath.Join(root, "lshttpd.service.d", "ols-wpanel.conf")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("读取 %s: %w", path, err)
	}
	content := string(data)
	if content == managedOLSServiceDropInContent {
		return false, nil
	}
	if content != managedServiceDropInLegacyContent &&
		content != managedServiceDropInFixedContent &&
		content != managedServiceDropInBoundedContent {
		log.Printf("[升级] 跳过自定义 OpenLiteSpeed systemd drop-in: %s", path)
		return false, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("检查 %s: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(managedOLSServiceDropInContent), info.Mode().Perm()); err != nil {
		return false, fmt.Errorf("写入 %s: %w", path, err)
	}
	return true, nil
}
