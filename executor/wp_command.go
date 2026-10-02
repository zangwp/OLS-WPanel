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
blue() { echo -e "\033[1;34m$*\033[0m"; }
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

vps_info() {
    echo "── VPS 信息 ──"
    . /etc/os-release
    echo "系统: ${PRETTY_NAME:-Linux}"
    echo "主机: $(hostname)    内核: $(uname -r)    架构: $(uname -m)"
    echo "CPU: $(getconf _NPROCESSORS_ONLN) 核"
    grep -m1 'model name' /proc/cpuinfo 2>/dev/null || true
    free -h
    df -h /
    echo "IP: $(hostname -I)"
    uptime -p
    date
}
need_root() { [ "${EUID:-$(id -u)}" -eq 0 ] || { red "需要 root 权限"; return 1; }; }
confirm_vps() {
    local answer=""
    echo "$1"
    read -r -p "输入 YES 继续，其他输入取消: " answer < /dev/tty || return 1
    [ "$answer" = "YES" ]
}
vps_choose() {
    local value=""
    read -r -p "$2" value < /dev/tty || return 1
    case "$1:$value" in
      dns:1) value=international;; dns:2) value=mainland_china;; dns:0) value=default;;
      ip-priority:1) value=ipv4;; ip-priority:2) value=ipv6;; ip-priority:0) value=default;;
      tuning:1) value=balanced;; tuning:2) value=website;; tuning:0) value=default;;
      locale:1) value=en_US.UTF-8;; locale:2) value=zh_CN.UTF-8;; locale:3) value=zh_TW.UTF-8;;
      *) echo "已取消"; return 0;;
    esac
    need_root && confirm_vps "将修改 $1 设置: $value" && "$BIN" --vps-tool "$1" --vps-value "$value" --config "$CFG"
}
check_project_update() {
    local current=""
    current=$("$BIN" --info --config "$CFG" | sed -n 's/^版本: \([^ ]*\).*/\1/p')
    python3 - "$current" <<'PYUPDATE'
import json,sys,urllib.request
try:
 request=urllib.request.Request('https://api.github.com/repos/zangwp/OLS-WPanel/releases/latest',headers={'User-Agent':'OLS-WPanel'})
 with urllib.request.urlopen(request,timeout=15) as response: release=json.load(response)
 latest=release['tag_name']; current=sys.argv[1]
 def version(s):return tuple(map(int,s.lstrip('v').split('.')))
 print('当前版本: '+current+'  最新发布: '+latest)
 print('有新版本，使用 o update 更新' if version(latest)>version(current) else '当前版本没有可用更新')
except Exception as error:
 print('检查更新失败: '+str(error),file=sys.stderr);sys.exit(1)
PYUPDATE
}
panel_help() {
    blue "OLS WPanel · 命令帮助"
    echo "用法: o <命令>（也可使用大写 O）"
    echo "  o / o menu       打开管理菜单"
    echo "  o vps            查看 VPS 信息"
    echo "  o info           查看面板详情与安装路径"
    echo "  o status         诊断检查"
    echo "  o log [N]        查看最近日志（默认30条）"
    echo "  o check-update   检查项目更新"
    echo "  o update         签名更新 / 修复面板"
    echo "  o restart        重启面板"
    echo "  o password       重置登录账号密码"
    echo "  o unban          清除面板 IP 封禁"
    echo "  o uninstall      普通卸载（保留网站和数据库）"
    echo "  o advanced       高级操作与完全卸载"
    echo "  o system-update / system-update-status / clean / dns / ip / tuning / language"
    dim "项目: https://github.com/zangwp/OLS-WPanel"
    dim "访问排查: 放行面板端口；运行 o status 或 o log"
}
advanced_menu() {
    local choice=""
    blue "高级操作"
    echo "  1. 普通卸载（保留网站和数据库）"
    echo "  2. 完全卸载（删除网站、数据库和面板）"
    echo "  0. 返回"
    read -r -p "请选择: " choice < /dev/tty || return 0
    case "$choice" in
      1) "$0" uninstall;;
      2) "$0" uninstall --all;;
      0) return 0;;
      *) echo "无效选项";;
    esac
}
vps_menu() {
    local choice=""
    while true; do
      echo ""
      blue "VPS 管理"
      echo "  1. 查看 VPS 信息"
      echo "  2. 更新系统"
      echo "  3. 清理系统缓存"
      echo "  4. 设置 DNS"
      echo "  5. IPv4 / IPv6 优先"
      echo "  6. 网站调优"
      echo "  7. 系统语言"
      echo ""
      blue "面板管理"
      echo "  8. 检查项目更新"
      echo "  9. 更新面板"
      echo " 10. 面板详情"
      echo " 11. 诊断检查"
      echo " 12. 重启面板"
      echo " 13. 命令帮助"
      echo " 14. 高级操作"
      echo "  0. 退出"
      echo ""
      read -r -p "请选择: " choice < /dev/tty || return 0
      case "$choice" in
        1) vps_info;; 2) "$0" system-update;; 3) "$0" clean;;
        4) "$0" dns;; 5) "$0" ip;; 6) "$0" tuning;; 7) "$0" language;;
        8) check_project_update;; 9) "$0" update;; 10) "$0" info;;
        11) "$0" status;; 12) "$0" restart;; 13) panel_help;; 14) advanced_menu;;
        0) return 0;; *) echo "无效选项";;
      esac
    done
}

case "${1:-}" in
    menu) vps_menu ;;
    help|-h|--help) panel_help ;;
    advanced) advanced_menu ;;
    vps) vps_info ;;
    check-update) check_project_update ;;
    system-update)
        need_root && confirm_vps "更新 VPS 软件包，不更新面板、不自动重启服务器。" && "$BIN" --vps-tool system-update --config "$CFG" ;;
    system-update-status) "$BIN" --vps-tool system-update-status --config "$CFG" ;;
    clean)
        need_root || exit 1
        "$BIN" --vps-tool clean-preview --config "$CFG" || exit 1
        confirm_vps "清理 APT 下载缓存和超过14天的归档系统日志；保留网站、数据库、备份，不卸载软件。" && "$BIN" --vps-tool clean --config "$CFG" ;;
    dns) vps_choose dns "1 国外 DNS / 2 国内 DNS / 0 恢复原配置: " ;;
    ip) vps_choose ip-priority "1 IPv4优先 / 2 IPv6优先 / 0 系统默认: " ;;
    tuning) vps_choose tuning "1 均衡 / 2 网站推荐 / 0 恢复原配置: " ;;
    language) vps_choose locale "1 英文 / 2 简体中文 / 3 繁体中文: " ;;
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
        "$BIN" --info --config "$CFG"
        echo "OpenLiteSpeed: /usr/local/lsws/"
        echo "MariaDB: /etc/mysql/    Redis: /etc/redis/"
        ;;
    unban)
        $BIN --unban-all
        ;;
    update|upgrade|repair)
        echo "正在通过签名发布链更新/修复 OLS WPanel..."
        run_lifecycle --repair
        ;;
    uninstall)
        if [ "${2:-}" = "--all" ]; then
            # 完全卸载将删除网站文件、网站数据库与 OLS 面板；备份另行选择。
            red "完全卸载：删除网站、数据库与面板，并移除运行环境。"
            run_lifecycle --purge
        elif [ -z "${2:-}" ]; then
            echo "普通卸载会保留网站、数据库、站点证书和共享软件。"
            run_lifecycle --uninstall
        else
            red "用法: o uninstall [--all]"; exit 1
        fi
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
    "")
        echo ""
        blue "OLS WPanel · VPS 与网站管理"
        dim "管理网站、数据库、缓存、备份和服务器维护。"
        $BIN --info --config "$CFG" 2>/dev/null | sed -n 's/^版本: /版本: /p'
        echo ""
        if [ -f "$CFG" ]; then
            PORT=$(python3 -c "import json; d=json.load(open('$CFG')); print(d['panel']['port'])" 2>/dev/null)
            SUFFIX=$(python3 -c "import json; d=json.load(open('$CFG')); print(d['panel']['random_suffix'])" 2>/dev/null)
            IP=$(hostname -I 2>/dev/null | awk '{print $1}')
            TLS_PORT=$(python3 -c "import json; d=json.load(open('$CFG')); print(d['panel'].get('tls_port', d['panel']['port']))" 2>/dev/null)
            case "$IP" in *:*) IP="[$IP]";; esac
            DOMAIN=$(python3 - "$CFG" <<'PYDOMAIN'
import json,os,re,sys
try:
 cfg=json.load(open(sys.argv[1]));path=os.path.join(os.path.dirname(cfg['panel']['tls_cert_path']),'panel-tls-active.json')
 state=json.load(open(path));domain=state['domain']
 if re.fullmatch(r'[a-zA-Z0-9.-]+',domain):print(domain)
except (OSError,KeyError,ValueError):pass
PYDOMAIN
)
            if [ -n "$DOMAIN" ]; then
                echo "主要地址: https://$DOMAIN:$TLS_PORT/$SUFFIX"
                echo "备用地址: https://$IP:$TLS_PORT/$SUFFIX（IP 访问可能有证书警告）"
            else
                [ -n "$TLS_PORT" ] && [ -n "$SUFFIX" ] && [ -n "$IP" ] && echo "面板地址: https://$IP:$TLS_PORT/$SUFFIX"
            fi
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
        dim "输入 o help 查看命令，o info 查看面板详情。"
        if [ -t 0 ] && [ -t 1 ]; then vps_menu; fi
        ;;
    *) red "未知命令: $1；输入 o help 查看用法"; exit 1 ;;
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
