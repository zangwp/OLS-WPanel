package executor

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const panelCommandScript = `#!/bin/bash
# OLS WPanel CLI — o

set -o pipefail

BIN=/usr/local/bin/ols-wpanel
CFG=/www/ols-wpanel/config.json
SVC=ols-wpanel
ENTRY_URL=https://ols.zangyubin.top/install
ENTRY_MAX_BYTES=$((4 * 1024 * 1024))

red()  { echo -e "\033[31m$*\033[0m"; }
green(){ echo -e "\033[32m$*\033[0m"; }
dim()  { echo -e "\033[2m$*\033[0m"; }

run_lifecycle() {
    local action="$1"
    local entry_file=""
    local entry_size=""
    local status=1

    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        red "此操作需要 root 权限"
        return 1
    fi
    entry_file=$(mktemp /tmp/ols-wpanel-entry.XXXXXXXXXX) || {
        red "无法创建临时文件"
        return 1
    }
    chmod 0600 "$entry_file"
    if command -v curl >/dev/null 2>&1; then
        curl -q -fsSL --proto '=https' --proto-redir '=https' \
            --connect-timeout 15 --max-time 120 --max-filesize "$ENTRY_MAX_BYTES" \
            --retry 3 --retry-delay 2 --retry-all-errors \
            "$ENTRY_URL" -o "$entry_file"
        status=$?
    elif command -v wget >/dev/null 2>&1; then
        wget --no-config -q --https-only --connect-timeout=15 --read-timeout=30 \
            --tries=3 -O "$entry_file" "$ENTRY_URL"
        status=$?
    else
        red "缺少 curl 或 wget，无法下载签名入口"
        rm -f -- "$entry_file"
        return 1
    fi
    if [ "$status" -ne 0 ]; then
        red "下载 OLS WPanel 签名入口失败"
        rm -f -- "$entry_file"
        return "$status"
    fi
    entry_size=$(stat -c '%s' -- "$entry_file" 2>/dev/null || echo 0)
    if ! [[ "$entry_size" =~ ^[0-9]+$ ]] || [ "$entry_size" -le 0 ] || [ "$entry_size" -gt "$ENTRY_MAX_BYTES" ]; then
        red "入口脚本大小异常，已拒绝执行"
        rm -f -- "$entry_file"
        return 1
    fi
    bash "$entry_file" "$action"
    status=$?
    rm -f -- "$entry_file"
    return "$status"
}

diag() {
    local issues=0

    # 1. 二进制
    if [ -x "$BIN" ]; then
        green "✓ 二进制: $BIN"
    elif [ -f "$BIN" ]; then
        red "✗ 二进制无执行权限: $BIN"
        echo "   → 修复: chmod +x $BIN"
        issues=$((issues+1))
    else
        red "✗ 二进制不存在: $BIN"
        echo "   → 面板可能未安装或安装不完整，请重新运行 install.sh"
        issues=$((issues+1))
        return $issues
    fi

    # 2. 配置文件
    if [ -f "$CFG" ]; then
        if python3 -c "import json; json.load(open('$CFG'))" 2>/dev/null; then
            green "✓ 配置文件: $CFG"
        else
            red "✗ 配置文件 JSON 格式错误: $CFG"
            echo "   → 修复: 检查文件内容或从备份恢复"
            issues=$((issues+1))
        fi
    else
        red "✗ 配置文件不存在: $CFG"
        echo "   → 面板可能未安装，请重新运行 install.sh"
        issues=$((issues+1))
        return $issues
    fi

    # 3. 数据库
    DB=$(python3 -c "import json; d=json.load(open('$CFG')); print(d.get('sqlite',{}).get('path',''))" 2>/dev/null)
    if [ -n "$DB" ] && [ -f "$DB" ]; then
        green "✓ 数据库: $DB"
    elif [ -n "$DB" ]; then
        red "✗ 数据库文件不存在: $DB"
        echo "   → 数据库文件丢失，检查磁盘空间或从备份恢复"
        issues=$((issues+1))
    else
        dim "? 未能读取数据库路径"
    fi

    # 4. systemd 服务文件
    if [ -f "/etc/systemd/system/${SVC}.service" ]; then
        green "✓ systemd 服务文件: /etc/systemd/system/${SVC}.service"
    else
        red "✗ systemd 服务文件缺失"
        echo "   → 修复: 重新运行 install.sh"
        issues=$((issues+1))
        return $issues
    fi

    # 5. 端口
    PORT=$(python3 -c "import json; d=json.load(open('$CFG')); print(d['panel'].get('tls_port', d['panel']['port']))" 2>/dev/null)
    if [ -n "$PORT" ]; then
        if ss -tlnp 2>/dev/null | grep -q ":${PORT} "; then
            green "✓ 端口 ${PORT} 已监听"
        else
            dim "? 端口 ${PORT} 未监听（面板未在运行）"
        fi
    fi

    # 6. systemd 状态
    if systemctl is-active --quiet "$SVC"; then
        green "✓ 服务状态: 运行中"
    else
        red "✗ 服务状态: 未运行"
        issues=$((issues+1))
        echo ""
        echo "── 最近的错误日志 ──"
        journalctl -u "$SVC" -n 20 --no-pager --lines=6 2>/dev/null | tail -20
        echo "── 日志结束 ──"
        echo ""
        echo "→ 查看完整日志: journalctl -u $SVC -n 50 --no-pager"
    fi

    if [ $issues -eq 0 ]; then
        echo ""
        green "所有检查通过"
    else
        echo ""
        red "发现 ${issues} 个问题"
    fi
}

case "${1:-}" in
    restart)
        echo "正在重启面板..."
        if systemctl restart "$SVC" 2>/dev/null; then
            sleep 2
            if systemctl is-active --quiet "$SVC"; then
                green "OLS WPanel 已重启，运行中"
            else
                red "OLS WPanel 重启后未能启动"
                echo ""
                echo "── 最近日志 ──"
                journalctl -u "$SVC" -n 20 --no-pager 2>/dev/null | tail -20
                echo "── 结束 ──"
                echo ""
                echo "→ 运行 'o status' 进行完整诊断"
            fi
        else
            red "systemctl restart 失败，服务可能未安装"
            echo "→ 运行 'o status' 进行诊断"
        fi
        ;;
    password)
        $BIN --reset-admin
        ;;
    info)
        $BIN --info
        ;;
    unban)
        $BIN --unban-all
        ;;
    update|upgrade|repair)
        echo "正在通过签名发布链更新/修复 OLS WPanel..."
        run_lifecycle --repair
        ;;
    uninstall)
        echo "普通卸载会保留网站、数据库、站点证书和共享软件。"
        run_lifecycle --uninstall
        ;;
    status|check)
        echo "OLS WPanel 诊断检查"
        echo "=================="
        echo ""
        diag
        ;;
    log)
        journalctl -u "$SVC" -n "${2:-30}" --no-pager 2>/dev/null
        ;;
    *)
        $BIN --info 2>/dev/null
        echo ""
        if [ -f "$CFG" ]; then
            PORT=$(python3 -c "import json; d=json.load(open('$CFG')); print(d['panel']['port'])" 2>/dev/null)
            SUFFIX=$(python3 -c "import json; d=json.load(open('$CFG')); print(d['panel']['random_suffix'])" 2>/dev/null)
            IP=$(hostname -I 2>/dev/null | awk '{print $1}')
            TLS_PORT=$(python3 -c "import json; d=json.load(open('$CFG')); print(d['panel'].get('tls_port', d['panel']['port']))" 2>/dev/null)
            [ -n "$TLS_PORT" ] && [ -n "$SUFFIX" ] && [ -n "$IP" ] && echo "面板地址: https://$IP:$TLS_PORT/$SUFFIX"
        fi
        if systemctl is-active --quiet "$SVC"; then
            green "运行状态: 运行中"
        else
            red "运行状态: 未运行"
            echo ""
            echo "── 自动诊断 ──"
            diag
        fi
        echo ""
        echo "用法: o <命令>（也可使用大写 O）"
        echo "  o restart     重启面板"
        echo "  o status      完整诊断检查"
        echo "  o log [N]     查看最近 N 条日志（默认30）"
        echo "  o password    一键重置管理员账号密码"
        echo "  o unban       一键清空所有IP封禁"
        echo "  o update      通过签名发布链更新/修复面板"
        echo "  o uninstall   普通卸载面板（保留网站与数据库）"
        ;;
esac
`

const (
	panelCommandMarker = "# OLS WPanel CLI — o"
)

// EnsurePanelCommands installs the short lowercase and uppercase CLI entry
// points. Because these are generic one-character names, existing paths are
// replaced only when they already carry OLS WPanel's exact ownership marker.
func EnsurePanelCommands() {
	paths := []string{"/usr/local/bin/o", "/usr/local/bin/O"}
	if err := ensurePanelCommandsAt(paths...); err != nil {
		log.Printf("安装面板 o/O 命令失败: %v", err)
	}
}

func ensurePanelCommandsAt(paths ...string) error {
	if len(paths) == 0 {
		return fmt.Errorf("no panel command paths supplied")
	}
	for _, path := range paths {
		replaceable, err := managedCommandPathReplaceable(path, panelCommandMarker)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", path, err)
		}
		if !replaceable {
			return fmt.Errorf("refusing to replace non-OLS command at %s", path)
		}
	}
	for _, path := range paths {
		if err := writeFileAtomic(path, []byte(panelCommandScript), 0755); err != nil {
			return fmt.Errorf("install %s: %w", path, err)
		}
	}
	return nil
}

func managedCommandPathReplaceable(path, marker string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	lines := strings.SplitN(string(content), "\n", 6)
	for i := 0; i < len(lines) && i < 5; i++ {
		if lines[i] == marker {
			return true, nil
		}
	}
	return false, nil
}

// writeFileAtomic writes data to path via a temp file + rename in the same
// directory, so a concurrent reader (e.g. someone running o mid-upgrade)
// never observes a partially-written script.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ols-wpanel-cli-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
