#!/bin/bash
set -eE
set -o pipefail

# ============================================================
# OLS WPanel 安装脚本 — 适用于 Debian 13 / Ubuntu 24.04、26.04 LTS，建议使用纯净系统
# 自动选择当前架构的已签名二进制，并配置 OpenLiteSpeed/LSPHP 软件源
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/www/ols-wpanel"
CONFIG_FILE="$INSTALL_DIR/config.json"
DB_PATH="$INSTALL_DIR/panel.db"
BIN_PATH="/usr/local/bin/ols-wpanel"
SERVICE_PATH="/etc/systemd/system/ols-wpanel.service"
CRON_PATH="/etc/cron.d/ols_wpanel_cron"
LICENSE_DOC_DIR="/usr/share/doc/ols-wpanel"
PANEL_PORT=8888
MYSQL_PASS=""
GHPROXY="${OLS_WPANEL_GITHUB_PROXY:-}"
PREFER_CN=false
CHECK_PLATFORM_ONLY=false
CHECK_OLS_PACKAGES_ONLY=false
CHECK_MARIADB_PACKAGES_ONLY=false
REQUESTED_ACTION=""
MARIADB_SERIES="11.8"
PLATFORM_ID=""
PLATFORM_VERSION=""
PLATFORM_CODENAME=""
PLATFORM_ARCH=""
PANEL_ASSET_NAME=""
APT_SOURCES_MUTATED=false
REPAIR_MODE=false
REPAIR_BACKUP_DIR=""
REPAIR_SERVICE_WAS_ACTIVE=false
REPAIR_SERVICE_STOPPED_FOR_SNAPSHOT=false
REPAIR_COMMITTED=false
INSTALL_WORKDIR=""
PANEL_CANDIDATE=""
PANEL_SHA256_FILE=""
PANEL_SIGNATURE_FILE=""
LICENSE_ARCHIVE=""
LICENSE_SHA256_FILE=""
LICENSE_SIGNATURE_FILE=""
PROJECT_LICENSE_FILE=""
PROJECT_NOTICE_FILE=""
THIRD_PARTY_NOTICE_FILE=""
LICENSE_RELEASE_VERSION_FILE=""
PANEL_CANDIDATE_VERIFIED=false
REPAIR_BIN_EXISTED=false
REPAIR_UNIT_EXISTED=false
REPAIR_TLS_EXISTED=false
REPAIR_DB_EXISTED=false
REPAIR_LICENSE_DIR_EXISTED=false
REPAIR_MUTATED=false
REPAIR_INACTIVE_HEALTH_VERIFIED=false
FRESH_SERVICE_CLEANUP_REQUIRED=false
VALIDATED_TLS_PORT=""
ATOMIC_STAGE_PATH=""
INSTALL_FAILURE_STATUS=""
INSTALL_FAILURE_LINE=""
UNINSTALL_MODE=false
UNINSTALL_STAGE=""
# The signed bootstrap validates this marker before it delegates execution.
# shellcheck disable=SC2034
RELEASE_PUBLIC_KEY_HEX="e6b66d84c67c8247821d2ab16b6d8e9584a962d4c8458d1f06b52d9cbbd65bd6"
INSTALLER_RELEASE_VERSION="__OLS_WPANEL_RELEASE_VERSION__"
MIN_PANEL_VERSION="v1.0.0"
LITESPEED_DEBIAN_KEY_SHA256="b465f0e857d1574ca9e045282a1b8113eebd7a8d2401bdb204803d0e0a9241aa"
LITESPEED_REPO_KEY_SHA256="186cd78298b9349134c38130f48b015e87fc228b9a9ca9aeb0c65e47630ed2d5"
MARIADB_APT_KEY_FINGERPRINT="177F4010FE56CA3336300305F1656F24C74CD1D8"
REDIS_APT_KEY_SHA256="817b5a78358d00ed6b71884d70ad5d2eab9934badca1a34299fdc6a2e4a8ad20"
MIN_REDIS_PACKAGE_VERSION="6:8.10.2"
PANEL_ASSET_MAX_BYTES=$((256 * 1024 * 1024))
CHECKSUM_ASSET_MAX_BYTES=$((4 * 1024))
SIGNATURE_ASSET_MAX_BYTES=64
LICENSE_ARCHIVE_MAX_BYTES=$((64 * 1024 * 1024))
WORDPRESS_ZIP_MAX_BYTES=$((256 * 1024 * 1024))
PUBLIC_IP_MAX_BYTES=$((4 * 1024))
# SubjectPublicKeyInfo PEM derived from RELEASE_PUBLIC_KEY_HEX. Keeping the raw
# key above makes key rotation and cross-checking with the application explicit.
RELEASE_PUBLIC_KEY_PEM='-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA5rZthMZ8gkeCHSqxa22OlYSpYtTIRY0fBrUtnLvWW9Y=
-----END PUBLIC KEY-----'

if [[ "${OLS_WPANEL_PREFER_CN_MIRROR:-0}" == "1" ]] || [[ "${OLS_WPANEL_PREFER_CN_MIRROR:-}" == "true" ]]; then
    PREFER_CN=true
fi
log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

assert_supported_platform() {
    local os_id=""
    local version_id=""
    local codename=""
    local machine=""
    local dpkg_arch=""
    local platform_cmd=""

    for platform_cmd in dpkg head sed tr uname; do
        command -v "$platform_cmd" >/dev/null 2>&1 || log_error "缺少平台检测命令: ${platform_cmd}"
    done
    [[ -r /etc/os-release ]] || log_error "无法读取 /etc/os-release；仅支持 Debian 13 或 Ubuntu 24.04/26.04 LTS（amd64/arm64）"
    os_id=$(sed -n 's/^ID=//p' /etc/os-release | head -n 1 | tr -d '"')
    version_id=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n 1 | tr -d '"')
    codename=$(sed -n 's/^VERSION_CODENAME=//p' /etc/os-release | head -n 1 | tr -d '"')
    machine=$(uname -m 2>/dev/null || true)
    dpkg_arch=$(dpkg --print-architecture 2>/dev/null || true)

    case "${os_id}:${version_id}:${codename}" in
        debian:13:trixie|ubuntu:24.04:noble|ubuntu:26.04:resolute) ;;
        *) log_error "仅支持 Debian 13 (trixie) 或 Ubuntu 24.04/26.04 LTS (noble/resolute)，当前系统: ${os_id:-unknown} ${version_id:-unknown} ${codename:-unknown}" ;;
    esac
    case "$machine" in
        x86_64|amd64) machine="amd64" ;;
        aarch64|arm64) machine="arm64" ;;
        *) log_error "仅支持 amd64/x86_64 或 arm64/aarch64，检测到架构: ${machine:-unknown}" ;;
    esac
    case "$dpkg_arch" in
        amd64|arm64) ;;
        *) log_error "仅支持 amd64 或 arm64 用户空间，检测到 dpkg 架构: ${dpkg_arch:-unknown}" ;;
    esac
    [[ "$machine" == "$dpkg_arch" ]] || \
        log_error "内核架构 ${machine} 与 dpkg 用户空间架构 ${dpkg_arch} 不一致，拒绝安装"

	if [[ "$dpkg_arch" == "arm64" ]]; then
		local page_size=""
		page_size=$(getconf PAGESIZE 2>/dev/null || true)
		case "$page_size" in
			4096|8192) ;;
			*) log_error "当前 ARM64 内核页大小为 ${page_size:-unknown}；OpenLiteSpeed 官方预编译包目前只在 4K/8K 页内核上受本项目支持" ;;
		esac
	fi

    PLATFORM_ID="$os_id"
    PLATFORM_VERSION="$version_id"
    PLATFORM_CODENAME="$codename"
    PLATFORM_ARCH="$dpkg_arch"
    PANEL_ASSET_NAME="ols-wpanel-linux-${PLATFORM_ARCH}"
}

assert_panel_command_paths_available() {
    local command_path=""

    for command_path in /usr/local/bin/o /usr/local/bin/O; do
        if [[ ! -e "$command_path" ]] && [[ ! -L "$command_path" ]]; then
            continue
        fi
        if [[ -f "$command_path" ]] && [[ ! -L "$command_path" ]] && \
           head -n 5 -- "$command_path" 2>/dev/null | grep -Fqx -- '# OLS WPanel CLI — o'; then
            continue
        fi
        log_error "命令路径 ${command_path} 已被非 OLS WPanel 文件占用；为避免覆盖用户文件，安装已停止"
    done
}

detect_installer_ssh_port() {
    local ssh_port=""
    local sshd_path=""

    sshd_path=$(command -v sshd 2>/dev/null || true)
    if [[ -n "$sshd_path" ]]; then
        ssh_port=$($sshd_path -T 2>/dev/null | awk '$1 == "port" && !found { value=$2; found=1 } END { if (found) print value }' || true)
    fi
    if { [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || (( ssh_port < 1 || ssh_port > 65535 )); } && command -v ss >/dev/null 2>&1; then
        ssh_port=$(ss -H -ltnp 2>/dev/null | awk '/users:\(\("sshd"/ && !found { endpoint=$4; sub(/^.*:/, "", endpoint); value=endpoint; found=1 } END { if (found) print value }' || true)
    fi
    if [[ ! "$ssh_port" =~ ^[0-9]+$ ]] || (( ssh_port < 1 || ssh_port > 65535 )); then
        ssh_port=22
    fi
    printf '%s\n' "$ssh_port"
}

has_existing_nft_input_policy() {
    local ruleset="" line="" table="" managed_fail2ban=false
    ruleset=$(nft list ruleset 2>/dev/null) || log_error "无法读取当前 nftables 规则，拒绝更改防火墙"
    if command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active --quiet fail2ban; then
        managed_fail2ban=true
    fi
    while IFS= read -r line; do
        if [[ "$line" == table\ * ]]; then
            table="$line"
        fi
        if [[ "$line" == *"hook input"* ]]; then
            # Debian starts Fail2ban during package installation. Its ban-only
            # table is not the host's baseline firewall policy.
            if $managed_fail2ban && [[ "$table" == "table inet f2b-table {" && "$line" == *"policy accept;"* ]]; then
                continue
            fi
            return 0
        fi
    done <<< "$ruleset"
    return 1
}

configure_fresh_firewall() {
    local ssh_port=""
    local nft_stage=""
    local nft_snapshot=""
    local create_table_line=""

    if $REPAIR_MODE; then
        log_info "repair模式保留现有防火墙规则和默认策略"
        return 0
    fi

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -F "Status: active" >/dev/null; then
        ufw allow 8443/tcp comment 'OLS WPanel' >/dev/null 2>&1 || \
            log_error "UFW 正在运行，但无法放行面板 8443/TCP"
        log_info "检测到现有 UFW：已放行 8443/TCP，未覆盖其余规则或默认策略"
        return 0
    fi

    command -v nft >/dev/null 2>&1 || \
        log_error "缺少 nft 命令，无法配置本机防火墙"

    if has_existing_nft_input_policy; then
        if nft add rule inet filter input tcp dport 8443 counter accept comment "ols-wpanel-panel" 2>/dev/null || \
           nft add rule ip filter input tcp dport 8443 counter accept comment "ols-wpanel-panel" 2>/dev/null; then
            log_info "检测到现有 nftables 入站策略：仅放行 8443/TCP，未覆盖默认策略"
        else
            log_warn "检测到自定义 nftables 入站链，无法安全定位写入位置；请手动放行 8443/TCP"
        fi
        return 0
    fi

    # A table/chain with these names but no input hook is user-managed state. Do
    # not repurpose it as a base chain because doing so can unexpectedly change
    # packet flow. A genuinely clean host normally has neither object loaded.
    if nft list chain inet filter input >/dev/null 2>&1; then
        log_warn "检测到无 input hook 的 inet filter input 自定义链；为避免覆盖，未启用默认 drop，请手动放行 8443/TCP"
        return 0
    fi
    if ! nft list table inet filter >/dev/null 2>&1; then
        create_table_line="add table inet filter"
    fi

    ssh_port=$(detect_installer_ssh_port)
    nft_stage="$INSTALL_WORKDIR/nftables-fresh.conf"
    nft_snapshot="$INSTALL_WORKDIR/nftables.conf"
    cat > "$nft_stage" << NFTFRESHEOF
${create_table_line}
add chain inet filter input { type filter hook input priority filter; policy drop; }
add rule inet filter input ct state invalid counter drop comment "ols-wpanel-core:invalid"
add rule inet filter input ct state established,related counter accept comment "ols-wpanel-core:established"
add rule inet filter input iifname "lo" counter accept comment "ols-wpanel-core:loopback"
add rule inet filter input meta l4proto ipv6-icmp counter accept comment "ols-wpanel-core:icmpv6"
add rule inet filter input ip protocol icmp counter accept comment "ols-wpanel-core:icmpv4"
add rule inet filter input tcp dport ${ssh_port} ct state new counter accept comment "ols-wpanel-core:ssh"
add rule inet filter input tcp dport 80 ct state new counter accept comment "ols-wpanel-core:http"
add rule inet filter input tcp dport 443 ct state new counter accept comment "ols-wpanel-core:https"
add rule inet filter input udp dport 443 ct state new counter accept comment "ols-wpanel-core:http3"
add rule inet filter input tcp dport 8443 ct state new counter accept comment "ols-wpanel-core:panel"
NFTFRESHEOF
    chmod 0600 "$nft_stage"
    nft --check --file "$nft_stage" || \
        log_error "默认 nftables 安全基线检查失败，未修改防火墙"
    nft --file "$nft_stage" || \
        log_error "默认 nftables 安全基线应用失败"
    printf 'flush ruleset\n' > "$nft_snapshot" || \
        log_error "无法创建 nftables 持久化快照"
    nft list ruleset >> "$nft_snapshot" || \
        log_error "无法导出已验证的 nftables 规则"
    chmod 0600 "$nft_snapshot"
    nft --check --file "$nft_snapshot" || \
        log_error "持久化前 nftables 规则检查失败"
    install -o root -g root -m 0600 "$nft_snapshot" /etc/nftables.conf || \
        log_error "无法安全保存 nftables 规则"
    systemctl enable --now nftables >/dev/null 2>&1 || \
        log_error "无法启用并启动 nftables 服务"
    log_info "已启用 nftables 安全基线：入站默认 drop；放行 SSH ${ssh_port}/TCP、80/TCP、443/TCP+UDP、8443/TCP"
}

init_install_workdir() {
    local required_cmd=""
    local previous_umask=""

    for required_cmd in awk chmod cmp cp dpkg-deb find flock grep head install mktemp mv openssl readlink rm rmdir sed sha256sum sort stat sync systemctl systemd-analyze tar timeout tr uname wc xargs; do
        command -v "$required_cmd" >/dev/null 2>&1 || log_error "缺少安装安全预检命令: ${required_cmd}"
    done
    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        log_error "缺少下载工具：请先安装 curl 或 wget"
    fi

    previous_umask=$(umask)
    umask 077
    INSTALL_WORKDIR=$(mktemp -d /tmp/ols-wpanel-install.XXXXXXXXXX) || \
        log_error "无法创建安装临时工作目录"
    chmod 0700 "$INSTALL_WORKDIR"
    umask "$previous_umask"
    PANEL_CANDIDATE="$INSTALL_WORKDIR/ols-wpanel"
    PANEL_SHA256_FILE="$INSTALL_WORKDIR/ols-wpanel.sha256"
    PANEL_SIGNATURE_FILE="$INSTALL_WORKDIR/ols-wpanel.sha256.sig"
    LICENSE_ARCHIVE="$INSTALL_WORKDIR/ols-wpanel-third-party-licenses.tar.gz"
    LICENSE_SHA256_FILE="$INSTALL_WORKDIR/ols-wpanel-third-party-licenses.tar.gz.sha256"
    LICENSE_SIGNATURE_FILE="$INSTALL_WORKDIR/ols-wpanel-third-party-licenses.tar.gz.sha256.sig"
    PROJECT_LICENSE_FILE="$INSTALL_WORKDIR/LICENSE"
    PROJECT_NOTICE_FILE="$INSTALL_WORKDIR/NOTICE.md"
    THIRD_PARTY_NOTICE_FILE="$INSTALL_WORKDIR/THIRD_PARTY_NOTICES.md"
    LICENSE_RELEASE_VERSION_FILE="$INSTALL_WORKDIR/RELEASE_VERSION"
}

cleanup_install_workdir() {
    [[ -n "$INSTALL_WORKDIR" ]] || return 0
    case "$INSTALL_WORKDIR" in
        /tmp/ols-wpanel-install.??????????)
            [[ -d "$INSTALL_WORKDIR" ]] && rm -rf -- "$INSTALL_WORKDIR"
            ;;
        *)
            log_warn "拒绝清理异常临时目录路径: $INSTALL_WORKDIR"
            ;;
    esac
}

cleanup_atomic_stage_file() {
	[[ -n "$ATOMIC_STAGE_PATH" ]] || return 0
	case "$ATOMIC_STAGE_PATH" in
		/usr/local/bin/.ols-wpanel.ols-install.????????|/www/ols-wpanel/.panel.db.ols-install.????????)
			rm -f -- "$ATOMIC_STAGE_PATH"
			;;
		*)
			log_warn "拒绝清理异常原子暂存文件路径: $ATOMIC_STAGE_PATH"
			;;
	esac
	ATOMIC_STAGE_PATH=""
}

cleanup_failed_fresh_panel_service() {
    [[ "$REPAIR_MODE" == false ]] || return 0
    [[ "$FRESH_SERVICE_CLEANUP_REQUIRED" == true ]] || return 0

    # A fresh install must never leave an unverified panel running now or at
    # the next boot. Both operations are idempotent when the unit was not yet
    # written or enabled.
    systemctl stop ols-wpanel 2>/dev/null || true
    systemctl disable ols-wpanel 2>/dev/null || true
}

installer_exit() {
    local exit_code=$?
    trap - ERR
    set +e
    if [[ $exit_code -ne 0 ]]; then
        repair_rollback
        cleanup_failed_fresh_panel_service
    fi
	cleanup_atomic_stage_file
    if [[ $exit_code -ne 0 ]] && [[ "$APT_SOURCES_MUTATED" == true ]]; then
        restore_managed_apt_sources
    fi
    cleanup_install_workdir
    if [[ $exit_code -ne 0 ]]; then
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        if ${UNINSTALL_MODE:-false}; then
            echo -e "${RED}  卸载未完成 / Uninstallation incomplete${NC}"
            echo "  中断阶段: ${UNINSTALL_STAGE:-检查删除范围}（退出码 $exit_code）"
            echo "  已完成的删除不会自动恢复；请保存输出并核对残留，不要直接重复完全卸载。"
        else
            echo -e "${RED}  安装未完成 / Installation incomplete${NC}"
        fi
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        if [[ -n "$INSTALL_FAILURE_STATUS" ]] && [[ -n "$INSTALL_FAILURE_LINE" ]]; then
            echo -e "  ${RED}失败状态:${NC} exit ${INSTALL_FAILURE_STATUS}，安装脚本第 ${INSTALL_FAILURE_LINE} 行。"
            echo -e "  ${RED}Failure:${NC} exit ${INSTALL_FAILURE_STATUS} at installer line ${INSTALL_FAILURE_LINE}."
        fi
        echo -e "  请先保存本次终端完整输出，不要在未定位原因前直接重装系统。"
        if ${UNINSTALL_MODE:-false}; then
            echo "  请结合上方 APT/dpkg 输出、/var/log/apt/term.log 和服务状态核对已删除与保留的内容。"
        else
            echo -e "  优先检查：网络/DNS 与系统时间、APT 错误、发行包哈希/签名、受支持平台检测，以及现有服务冲突。"
            echo -e "  可结合 ${BOLD}journalctl -u ols-wpanel -n 100 --no-pager${NC} 和 APT 输出排查，再携带已脱敏日志提交 GitHub Issue。"
            echo -e "  Save the complete terminal output first. Check networking/DNS, system time, APT, release hash/signature, platform validation, and existing service conflicts before considering an OS reinstall."
        fi
        echo ""
        echo -e "  GitHub: https://github.com/zangwp/OLS-WPanel/issues"
        echo ""
    fi
    trap - EXIT
    exit "$exit_code"
}

systemctl_enable_best_effort() {
    local svc="$1"
    if ! systemctl enable "$svc"; then
        log_warn "${svc} 开机自启设置失败，继续安装。安装后可手动检查: systemctl enable ${svc}"
    fi
}

systemctl_start_required() {
    local svc="$1"
    if ! systemctl start "$svc"; then
        journalctl -u "$svc" -n 20 --no-pager 2>/dev/null || true
        log_error "${svc} 启动失败，请根据上方日志排查"
    fi
}

ensure_ols_systemd_unit() {
    local fragment="" legacy_fragment=""
    local vendor_unit="/usr/local/lsws/admin/misc/lshttpd.service"
    local target="/etc/systemd/system/lshttpd.service"

    systemctl daemon-reload || log_error "systemd 服务刷新失败"
    fragment=$(systemctl show lshttpd.service --property=FragmentPath --value) || \
        log_error "无法检查 OpenLiteSpeed systemd 服务"
    # Preserve existing native units, including administrator-owned ones.
    if [[ -n "$fragment" ]]; then
        return 0
    fi
    [[ ! -e "$target" && ! -L "$target" ]] || \
        log_error "lshttpd.service 已存在但无法加载，拒绝覆盖"
    [[ -f "$vendor_unit" && ! -L "$vendor_unit" ]] || \
        log_error "OpenLiteSpeed 软件包缺少原生 systemd 服务文件"

    legacy_fragment=$(systemctl show lsws.service --property=FragmentPath --value) || \
        log_error "无法检查旧版 OpenLiteSpeed 服务"
    case "$legacy_fragment" in
        /run/systemd/generator/lsws.service|/run/systemd/generator.late/lsws.service|/run/systemd/generator.early/lsws.service)
            # Debian's vendor rc-inst.sh exits after installing a SysV script.
            # Stop that generated service before registering the native unit,
            # so two independent service managers cannot own the same daemon.
            systemctl stop lsws.service || log_error "旧版 OpenLiteSpeed 服务停止失败"
            systemctl disable lsws.service || log_error "旧版 OpenLiteSpeed 自启关闭失败"
            ;;
        "") ;;
        *) log_error "发现自定义 lsws.service，拒绝自动替换" ;;
    esac
    [[ ! -e /etc/systemd/system/lsws.service && ! -L /etc/systemd/system/lsws.service ]] || \
        log_error "lsws.service 已存在，拒绝覆盖"
    install -o root -g root -m 0644 "$vendor_unit" "$target" || \
        log_error "安装 OpenLiteSpeed 原生 systemd 服务失败"
    ln -s lshttpd.service /etc/systemd/system/lsws.service || \
        log_error "创建 OpenLiteSpeed 兼容服务别名失败"
    systemctl daemon-reload || log_error "systemd 服务刷新失败"
    fragment=$(systemctl show lshttpd.service --property=FragmentPath --value) || \
        log_error "无法检查 OpenLiteSpeed 原生服务"
    [[ "$fragment" == "$target" ]] || log_error "OpenLiteSpeed 原生 systemd 服务未正确加载"
    log_info "已注册 OpenLiteSpeed 原生 systemd 服务及 lsws 兼容别名"
}

systemctl_wait_active_required() {
    local svc="$1"
    local attempt=""
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if systemctl is-active --quiet "$svc"; then
            return 0
        fi
        sleep 1
    done
    journalctl -u "$svc" -n 30 --no-pager 2>/dev/null || true
    log_error "${svc} 未能保持运行状态，请根据上方日志排查"
}

ols_ipv6_available() {
    local ipv6_addresses="" ipv6_routes=""
    local php_cli="/usr/local/lsws/lsphp85/bin/php"
    command -v ip >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1 && [[ -x "$php_cli" ]] || return 1
    # Inspect local state only. A DNS AAAA record or a link-local address does
    # not demonstrate that this VPS has usable public IPv6 connectivity.
    ipv6_addresses=$(timeout 2s ip -6 -j addr show up scope global 2>/dev/null) || return 1
    ipv6_routes=$(timeout 2s ip -6 -j route show default 2>/dev/null) || return 1
    [[ ${#ipv6_addresses} -le 65536 && ${#ipv6_routes} -le 65536 ]] || return 1
    timeout 2s "$php_cli" -n -r '
try {
    $addresses = json_decode($argv[1], true, 64, JSON_THROW_ON_ERROR);
    $routes = json_decode($argv[2], true, 64, JSON_THROW_ON_ERROR);
    if (!is_array($addresses) || !is_array($routes)) exit(1);
    $ready = [];
    foreach ($addresses as $interface) {
        if (!is_array($interface)) continue;
        $name = $interface["ifname"] ?? "";
        $flags = $interface["flags"] ?? [];
        if (!is_string($name) || $name === "" || !is_array($flags) || !in_array("UP", $flags, true) || in_array("LOOPBACK", $flags, true)) continue;
        foreach (($interface["addr_info"] ?? []) as $address) {
            if (!is_array($address) || ($address["family"] ?? "") !== "inet6" || ($address["scope"] ?? "") !== "global") continue;
            $local = $address["local"] ?? "";
            if (!is_string($local)) continue;
            $packed = @inet_pton($local);
            if ($packed === false || strlen($packed) !== 16 || ord($packed[0]) < 0x20 || ord($packed[0]) > 0x3f || substr(bin2hex($packed), 0, 8) === "20010db8") continue;
            $usable = true;
            $addressFlags = $address["flags"] ?? [];
            if (!is_array($addressFlags)) continue;
            foreach (["tentative", "dadfailed", "deprecated"] as $flag) {
                if (($address[$flag] ?? false) === true || in_array($flag, $addressFlags, true)) $usable = false;
            }
            foreach (["preferred_life_time", "valid_life_time"] as $life) {
                $value = $address[$life] ?? null;
                if ((is_int($value) || is_float($value)) && $value == 0) $usable = false;
            }
            if ($usable) $ready[$name] = true;
        }
    }
    foreach ($routes as $route) {
        if (!is_array($route) || !in_array($route["dst"] ?? "", ["default", "::/0"], true) || !in_array($route["type"] ?? "", ["", "unicast"], true)) continue;
        $device = $route["dev"] ?? "";
        $flags = $route["flags"] ?? [];
        if (!is_string($device) || !isset($ready[$device]) || !is_array($flags) || in_array("dead", $flags, true) || in_array("linkdown", $flags, true)) continue;
        exit(0);
    }
} catch (Throwable $error) {}
exit(1);
' "$ipv6_addresses" "$ipv6_routes" >/dev/null 2>&1 || return 1
    # Binding an ephemeral local socket sends no packets and also checks that
    # the kernel actually supports IPv6; close it immediately after probing.
    timeout 2s "$php_cli" -n -r '
$socket = @stream_socket_server("tcp://[::]:0", $errno, $error, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN);
if ($socket === false) exit(1);
fclose($socket);
' >/dev/null 2>&1
}

append_ols_ipv6_listeners() {
    local conf="$1" http_port="$2" https_port="$3" vhost="$4" domains="$5" cert_dir="$6"
    # Append after IPv4 listeners. OpenLiteSpeed retries an IPv6 wildcard bind
    # with IPV6_V6ONLY when the earlier IPv4 listener already owns that port.
    cat >> "$conf" << OLSIPV6EOF
listener OLSWPanelHTTPIPv6 {
  address                 [ANY]:$http_port
  secure                  0
  map                     $vhost $domains
}
listener OLSWPanelHTTPSIPv6 {
  address                 [ANY]:$https_port
  secure                  1
  keyFile                 $cert_dir/default.key
  certFile                $cert_dir/default.crt
  certChain               0
  sslProtocol             24
  map                     $vhost $domains
}
OLSIPV6EOF
}

ols_listener_pid_is_ols() {
    local pid="$1"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    # Compare the kernel's executable identity, not ss's configurable comm.
    # Missing /proc access or another server owning the socket fails closed.
    [[ -f /usr/local/lsws/bin/openlitespeed && -f "/proc/$pid/exe" && "/proc/$pid/exe" -ef /usr/local/lsws/bin/openlitespeed ]]
}

ols_listener_owned_by_ols() {
    local line="$1" users="" char="" next="" pid=""
    local i=0 end=0 owners=0 quoted=false
    [[ "$line" == *'users:('* ]] || return 1
    users="${line#*users:(}"
    for ((i=0; i<${#users}; i++)); do
        char="${users:i:1}"
        if $quoted; then
            if [[ "$char" == '\' ]]; then
                i=$((i + 1))
            elif [[ "$char" == '"' ]]; then
                quoted=false
            fi
            continue
        fi
        if [[ "$char" == '"' ]]; then quoted=true; continue; fi
        [[ "${users:i:5}" == ',pid=' ]] || continue
        end=$((i + 5))
        pid=""
        while [[ "${users:end:1}" == [0-9] ]]; do
            pid+="${users:end:1}"
            end=$((end + 1))
        done
        next="${users:end:1}"
        [[ -n "$pid" && ( "$next" == ',' || "$next" == ')' ) ]] || return 1
        ols_listener_pid_is_ols "$pid" || return 1
        owners=$((owners + 1))
        i=$((end - 1))
    done
    [[ "$owners" -gt 0 && "$quoted" == false ]]
}

ols_owned_listener_addresses() {
    local line=""
    local fields=()
    while IFS= read -r line; do
        read -r -a fields <<< "$line"
        [[ "${#fields[@]}" -ge 5 && "${fields[0]}" == LISTEN ]] || continue
        ols_listener_owned_by_ols "$line" || continue
        printf '%s\n' "${fields[3]}"
    done
}

require_ols_listeners() {
    local attempt=""
    local failure_mode="${1:-fatal}"
    local addresses="" ipv4_addresses="" ipv6_addresses=""
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        if [[ "${OLS_IPV6_ENABLED:-false}" == true ]]; then
            # Family-specific wildcard sockets must be present. Loopback-only
            # or one particular host address cannot satisfy a public listener.
            ipv4_addresses=$(timeout 2s ss -H -l -t -n -p -4 2>/dev/null | ols_owned_listener_addresses) || ipv4_addresses=""
            ipv6_addresses=$(timeout 2s ss -H -l -t -n -p -6 2>/dev/null | ols_owned_listener_addresses) || ipv6_addresses=""
            if grep -Eq '^(0\.0\.0\.0|\*):80$' <<< "$ipv4_addresses" && grep -Eq '^(0\.0\.0\.0|\*):443$' <<< "$ipv4_addresses" && \
               grep -Eq '^(\[::\]|::|\*):80$' <<< "$ipv6_addresses" && grep -Eq '^(\[::\]|::|\*):443$' <<< "$ipv6_addresses"; then
                return 0
            fi
        else
            addresses=$(timeout 2s ss -H -l -t -n -p -4 2>/dev/null | ols_owned_listener_addresses) || addresses=""
            if grep -Eq '^(0\.0\.0\.0|\*):80$' <<< "$addresses" && grep -Eq '^(0\.0\.0\.0|\*):443$' <<< "$addresses"; then return 0; fi
        fi
        sleep 1
    done
    [[ "$failure_mode" != return ]] || return 1
    if [[ "${OLS_IPV6_ENABLED:-false}" == true ]]; then
        log_error "未确认实际 OpenLiteSpeed 进程同时在 IPv4 和 IPv6 监听 80/443 端口"
    fi
    log_error "未确认实际 OpenLiteSpeed 进程同时监听 80/443 端口"
}

# ============================================================
# 系统内核优化（BBR+FQ、TCP 缓冲、连接队列、文件描述符）
# ============================================================
apply_system_tuning() {
    log_info "应用系统内核优化..."

    SYSCTL_FILE="/etc/sysctl.d/99-ols-wpanel.conf"
    CPU_CORES=$(nproc)

    cat > "$SYSCTL_FILE" << 'SYSCTLEOF'
# OLS WPanel — 网络与内核优化

# ── 连接队列 ──
# 连接队列由 VPS 性能菜单独立管理；首次安装沿用系统默认值。
net.core.netdev_max_backlog = 16384

# ── TCP 缓冲区 ──
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# ── TIME-WAIT 优化 ──
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535

# ── Keepalive ──
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5

# ── BBR 辅助参数 ──
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384

# ── 基础安全 ──
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_timestamps = 1
SYSCTLEOF

    # First-install preset; report success only after reading the actual kernel state.
    local bbr_requested=false bbr_actual="" qdisc_actual=""
    if [[ $CPU_CORES -ge 2 ]]; then
        bbr_requested=true
        cat >> "$SYSCTL_FILE" << 'BBREOF'

# ── BBR 拥塞控制 + FQ 调度 ──
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
BBREOF
        modprobe tcp_bbr 2>/dev/null || true
    else
        log_info "单核 CPU，保留当前拥塞控制配置"
    fi

    if ! sysctl --system >/dev/null 2>&1; then
        log_warn "部分 sysctl 配置未能应用，请安装后使用 o bbr 与 o status 检查"
    fi
    if [[ "$bbr_requested" == true ]]; then
        bbr_actual=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null) || bbr_actual=""
        qdisc_actual=$(sysctl -n net.core.default_qdisc 2>/dev/null) || qdisc_actual=""
        if [[ "$bbr_actual" == bbr && "$qdisc_actual" == fq ]]; then
            log_info "BBR + FQ 已启用并核验（${CPU_CORES} 核 CPU）"
        else
            log_warn "BBR + FQ 未确认生效：拥塞控制=${bbr_actual:-未知}，队列=${qdisc_actual:-未知}；请用 o bbr 检查内核支持"
        fi
    fi

    # 文件描述符限制
    if ! grep -q "nofile 65535" /etc/security/limits.conf 2>/dev/null; then
        cat >> /etc/security/limits.conf << 'LIMITSEOF'
* soft nofile 65535
* hard nofile 65535
LIMITSEOF
    fi

    log_info "系统内核优化完成"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefer-cn|--cn)
            PREFER_CN=true
            shift
            ;;
        --check-platform)
            CHECK_PLATFORM_ONLY=true
            shift
            ;;
        --check-ols-packages)
            CHECK_OLS_PACKAGES_ONLY=true
            shift
            ;;
        --check-mariadb-packages)
            CHECK_MARIADB_PACKAGES_ONLY=true
            shift
            ;;
        --repair|--update)
            if [[ -n "$REQUESTED_ACTION" ]] && [[ "$REQUESTED_ACTION" != "repair" ]]; then
                log_error "不能同时请求更新/修复和卸载"
            fi
            REQUESTED_ACTION="repair"
            shift
            ;;
        --purge)
            if [[ -n "$REQUESTED_ACTION" ]] && [[ "$REQUESTED_ACTION" != "purge" ]]; then
                log_error "不能同时请求完全卸载与其他操作"
            fi
            REQUESTED_ACTION="purge"
            shift
            ;;
        --uninstall)
            if [[ -n "$REQUESTED_ACTION" ]] && [[ "$REQUESTED_ACTION" != "uninstall" ]]; then
                log_error "不能同时请求更新/修复和卸载"
            fi
            REQUESTED_ACTION="uninstall"
            shift
            ;;
        *)
            log_warn "未知参数已忽略: $1"
            shift
            ;;
    esac
done

# 异常退出时回滚 repair，并只清理由 mktemp 创建的本次工作目录。
trap 'INSTALL_FAILURE_STATUS=$?; INSTALL_FAILURE_LINE=$LINENO' ERR
trap installer_exit EXIT

file_size_within_limit() {
    local path="$1"
    local max_bytes="$2"
    local actual_bytes=""

    [[ "$max_bytes" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ -f "$path" ]] && [[ ! -L "$path" ]] || return 1
    actual_bytes=$(stat -c '%s' -- "$path" 2>/dev/null) || return 1
    [[ "$actual_bytes" =~ ^[0-9]+$ ]] || return 1
    (( actual_bytes > 0 && actual_bytes <= max_bytes ))
}

download_file() {
    local url="$1"
    local output="$2"
    local total_timeout="${3:-120}"
    local max_bytes="${4:-0}"
    local connect_timeout=15

    [[ "$max_bytes" =~ ^[1-9][0-9]*$ ]] || return 1
    if [[ "$total_timeout" -lt "$connect_timeout" ]]; then
        connect_timeout="$total_timeout"
    fi

    rm -f "$output"
    if command -v curl &>/dev/null; then
        if timeout "${total_timeout}s" curl -q -fsSL \
            --proto '=https' \
            --proto-redir '=https' \
            --connect-timeout "$connect_timeout" \
            --max-time "$total_timeout" \
            --max-filesize "$max_bytes" \
            --speed-limit 1024 \
            --speed-time 30 \
            --retry 3 \
            --retry-delay 2 \
            --retry-all-errors \
            "$url" 2>/dev/null | head -c "$((max_bytes + 1))" > "$output"; then
            file_size_within_limit "$output" "$max_bytes" && return 0
        fi
        rm -f "$output"
    fi
    if command -v wget &>/dev/null; then
        if timeout "${total_timeout}s" wget --no-config -q --https-only --no-hsts \
            --connect-timeout="$connect_timeout" \
            --read-timeout=30 \
            --tries=3 \
            --retry-connrefused \
            --waitretry=2 \
            -O - "$url" 2>/dev/null | head -c "$((max_bytes + 1))" > "$output"; then
            file_size_within_limit "$output" "$max_bytes" && return 0
        fi
        rm -f "$output"
    fi
    rm -f "$output"
    return 1
}

download_official_wordpress_archive() {
    local output="$1"
    local php_cli="/usr/local/lsws/lsphp85/bin/php"
    rm -f -- "$output"
    # Follow only HTTPS redirects to WordPress-controlled package hosts. This
    # receipt records our download source, not official checksum authentication.
    if timeout 60s "$php_cli" -r '
$output = $argv[1];
$limit = (int) $argv[2];
$url = "https://wordpress.org/latest.zip";
for ($redirects = 0; $redirects <= 5; $redirects++) {
    $parts = parse_url($url);
    if (!$parts || ($parts["scheme"] ?? "") !== "https" ||
        !in_array(strtolower($parts["host"] ?? ""), array("wordpress.org", "downloads.wordpress.org"), true) ||
        isset($parts["user"]) || isset($parts["pass"]) || (isset($parts["port"]) && $parts["port"] !== 443)) { exit(1); }
    $file = fopen($output, "wb");
    if (!$file) { exit(1); }
    $location = ""; $bytes = 0;
    $curl = curl_init($url);
    curl_setopt_array($curl, array(CURLOPT_FOLLOWLOCATION => false, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_TIMEOUT => 60, CURLOPT_FAILONERROR => true,
        CURLOPT_HEADERFUNCTION => static function ($curl, $header) use (&$location) {
            if (stripos($header, "HTTP/") === 0) { $location = ""; }
            if (stripos($header, "Location:") === 0) {
                if (strlen($header) > 4096) { return 0; }
                $location = trim(substr($header, 9));
            }
            return strlen($header);
        },
        CURLOPT_WRITEFUNCTION => static function ($curl, $data) use ($file, &$bytes, $limit) {
            $bytes += strlen($data);
            return $bytes <= $limit ? fwrite($file, $data) : 0;
        }));
    $ok = curl_exec($curl); $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    curl_close($curl); fclose($file);
    if (!$ok) { exit(1); }
    if ($status === 200) { exit($bytes > 0 ? 0 : 1); }
    if (!in_array($status, array(301, 302, 303, 307, 308), true) || !$location || preg_match("/[\\x00-\\x20\\x7f]/", $location)) { exit(1); }
    if (strpos($location, "//") === 0) { $url = "https:" . $location; }
    elseif (strpos($location, "/") === 0) { $url = "https://" . $parts["host"] . $location; }
    elseif (parse_url($location, PHP_URL_SCHEME) !== null) { $url = $location; }
    else { $url = "https://" . $parts["host"] . rtrim(dirname($parts["path"] ?? "/"), "/") . "/" . $location; }
}
exit(1);
' "$output" "$WORDPRESS_ZIP_MAX_BYTES" && file_size_within_limit "$output" "$WORDPRESS_ZIP_MAX_BYTES"; then
        return 0
    fi
    rm -f -- "$output"
    return 1
}

validate_installer_wordpress_archive() {
    local archive="$1"
    local php_cli="/usr/local/lsws/lsphp85/bin/php"
    file_size_within_limit "$archive" "$WORDPRESS_ZIP_MAX_BYTES" || return 1
    timeout 15s "$php_cli" -r '
$zip = new ZipArchive();
if ($zip->open($argv[1], ZipArchive::CHECKCONS) !== true || $zip->numFiles < 5 || $zip->numFiles > 20000) { exit(1); }
$required = array_fill_keys(array("wordpress/wp-includes/version.php", "wordpress/wp-settings.php", "wordpress/wp-load.php", "wordpress/wp-admin/index.php", "wordpress/wp-includes/load.php"), false);
$expanded = 0;
for ($index = 0; $index < $zip->numFiles; $index++) {
    $entry = $zip->statIndex($index); $name = $entry["name"] ?? "";
    if (!$name || strpos($name, "\\") !== false || strpos($name, "\0") !== false ||
        ($name !== "wordpress/" && strpos($name, "wordpress/") !== 0) ||
        preg_match("~(?:^|/)(?:\\.\\.?)(?:/|$)~", $name) || strpos($name, "//") !== false) { exit(1); }
    $expanded += $entry["size"];
    if ($expanded > 1024 * 1024 * 1024 || $entry["size"] > 64 * 1024 * 1024) { exit(1); }
    $system = 0; $attributes = 0;
    if (!$zip->getExternalAttributesIndex($index, $system, $attributes)) { exit(1); }
    $type = ($attributes >> 16) & 0170000;
    if ($system === ZipArchive::OPSYS_UNIX && !in_array($type, array(0, 0040000, 0100000), true)) { exit(1); }
    if (isset($required[$name])) {
        if (substr($name, -1) === "/" || $type === 0040000) { exit(1); }
        $required[$name] = true;
    }
}
if (in_array(false, $required, true)) { exit(1); }
$version = $zip->getFromName("wordpress/wp-includes/version.php", 65537);
if (!is_string($version) || strlen($version) > 65536 || !preg_match("~[\\x24]wp_version\\s*=\\s*[\\x27\\x22][0-9]+(?:\\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?[\\x27\\x22]\\s*;~", $version)) { exit(1); }
$zip->close();
' "$archive"
}

write_wordpress_origin_receipt() {
    local archive="$1"
    local receipt_stage=""
    local php_cli="/usr/local/lsws/lsphp85/bin/php"
    [[ -f "$archive" && ! -L "$archive" ]] || return 1
    receipt_stage=$(mktemp "${archive}.origin.json.XXXXXXXX") || return 1
    if chmod 0600 "$receipt_stage" && timeout 15s "$php_cli" -r '
$sha = hash_file("sha256", $argv[1]); $bytes = filesize($argv[1]);
if (!is_string($sha) || !preg_match("/^[0-9a-f]{64}$/D", $sha) || !is_int($bytes) || $bytes <= 0) { exit(1); }
echo json_encode(array("source_url" => "https://wordpress.org/latest.zip", "sha256" => $sha, "archive_bytes" => $bytes), JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
' "$archive" > "$receipt_stage" && mv -fT -- "$receipt_stage" "${archive}.origin.json"; then
        return 0
    fi
    rm -f -- "$receipt_stage"
    return 1
}

verify_signed_release_asset() {
    local asset_file="$1"
    local sha_file="$2"
    local sig_file="$3"
    local expected_name="$4"
    local asset_max_bytes="$5"
    local public_key_file="$INSTALL_WORKDIR/release-public-key.pem"
    local expected_sha=""
    local signed_name=""
    local extra_field=""
    local actual_sha=""
    local nonempty_lines=""

    file_size_within_limit "$asset_file" "$asset_max_bytes" || return 1
    file_size_within_limit "$sha_file" "$CHECKSUM_ASSET_MAX_BYTES" || return 1
    file_size_within_limit "$sig_file" "$SIGNATURE_ASSET_MAX_BYTES" || return 1
    [[ "$(wc -c < "$sig_file" | tr -d '[:space:]')" == "64" ]] || return 1

    printf '%s\n' "$RELEASE_PUBLIC_KEY_PEM" > "$public_key_file"
    chmod 0600 "$public_key_file"
    openssl pkeyutl -verify -pubin -inkey "$public_key_file" -rawin \
        -in "$sha_file" -sigfile "$sig_file" >/dev/null 2>&1 || return 1

    nonempty_lines=$(awk 'NF {count++} END {print count+0}' "$sha_file")
    [[ "$nonempty_lines" == "1" ]] || return 1
    read -r expected_sha signed_name extra_field < "$sha_file" || return 1
    [[ -z "$extra_field" ]] || return 1
    [[ "$expected_sha" =~ ^[0-9a-fA-F]{64}$ ]] || return 1
    [[ "$signed_name" == "$expected_name" ]] || return 1

    actual_sha=$(sha256sum "$asset_file" | awk '{print $1}') || return 1
    [[ "${actual_sha,,}" == "${expected_sha,,}" ]] || return 1
}

verify_panel_release_bundle() {
    verify_signed_release_asset "$1" "$2" "$3" "$PANEL_ASSET_NAME" "$PANEL_ASSET_MAX_BYTES"
}

verify_license_release_bundle() {
    local archive_file="$1"
    local sha_file="$2"
    local sig_file="$3"
    local listing_file="$INSTALL_WORKDIR/license-archive.list"
    local archive_member=""
    local normalized_member=""
    local required_member=""
    local archive_release_version=""

    verify_signed_release_asset \
        "$archive_file" "$sha_file" "$sig_file" \
        "ols-wpanel-third-party-licenses.tar.gz" "$LICENSE_ARCHIVE_MAX_BYTES" || return 1
    tar -tzf "$archive_file" > "$listing_file" 2>/dev/null || return 1
    [[ -s "$listing_file" ]] || return 1
    while IFS= read -r archive_member; do
        [[ -n "$archive_member" ]] || return 1
        [[ "$archive_member" == ./* ]] || return 1
        [[ "$archive_member" != *\\* ]] || return 1
        [[ "$archive_member" == "./" ]] && continue
        normalized_member="${archive_member#./}"
        [[ -n "$normalized_member" ]] || return 1
        [[ ! "/$normalized_member/" =~ /\.\.?/ ]] || return 1
    done < "$listing_file"
    for required_member in \
        ./LICENSE \
        ./NOTICE.md \
        ./THIRD_PARTY_NOTICES.md \
        ./RELEASE_VERSION \
        ./go-toolchain/LICENSE \
        ./go-toolchain/VERSION \
        ./adminer-6.0.1/LICENSE-APACHE-2.0.txt \
        ./adminer-6.0.1/NOTICE.txt; do
        [[ "$(grep -Fxc -- "$required_member" "$listing_file")" == "1" ]] || return 1
    done

    tar -xOzf "$archive_file" ./RELEASE_VERSION > "$LICENSE_RELEASE_VERSION_FILE" 2>/dev/null || return 1
    [[ "$(wc -l < "$LICENSE_RELEASE_VERSION_FILE" | tr -d '[:space:]')" == "1" ]] || return 1
    archive_release_version=$(cat "$LICENSE_RELEASE_VERSION_FILE") || return 1
    [[ "$archive_release_version" == "$INSTALLER_RELEASE_VERSION" ]] || return 1
    tar -xOzf "$archive_file" ./LICENSE > "$PROJECT_LICENSE_FILE" 2>/dev/null || return 1
    tar -xOzf "$archive_file" ./NOTICE.md > "$PROJECT_NOTICE_FILE" 2>/dev/null || return 1
    tar -xOzf "$archive_file" ./THIRD_PARTY_NOTICES.md > "$THIRD_PARTY_NOTICE_FILE" 2>/dev/null || return 1
    [[ -s "$PROJECT_LICENSE_FILE" ]] || return 1
    [[ -s "$PROJECT_NOTICE_FILE" ]] || return 1
    [[ -s "$THIRD_PARTY_NOTICE_FILE" ]] || return 1
    chmod 0600 "$PROJECT_LICENSE_FILE" "$PROJECT_NOTICE_FILE" "$THIRD_PARTY_NOTICE_FILE"
}

verify_complete_release_bundle() {
    verify_panel_release_bundle \
        "$PANEL_CANDIDATE" "$PANEL_SHA256_FILE" "$PANEL_SIGNATURE_FILE" &&
    verify_license_release_bundle \
        "$LICENSE_ARCHIVE" "$LICENSE_SHA256_FILE" "$LICENSE_SIGNATURE_FILE"
}

validate_installer_release_version() {
    [[ "$INSTALLER_RELEASE_VERSION" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] &&
        panel_version_at_least "$INSTALLER_RELEASE_VERSION" "$MIN_PANEL_VERSION"
}

preflight_panel_candidate() {
    local preflight_config="$INSTALL_WORKDIR/preflight-config.json"
    local preflight_output="$INSTALL_WORKDIR/preflight-info.txt"
    local candidate_version=""

    cat > "$preflight_config" << PREFLIGHTEOF
{
  "panel": {
    "port": 8888,
    "tls_port": 8443,
    "random_suffix": "installer-preflight",
    "data_dir": "$INSTALL_WORKDIR",
    "backup_dir": "$INSTALL_WORKDIR",
    "log_dir": "$INSTALL_WORKDIR"
  },
  "sqlite": {"path": "$INSTALL_WORKDIR/preflight.db"},
  "mariadb": {"root_password": "installer-preflight-only"},
  "admin": {"username": "preflight", "password_hash": "preflight"},
  "paths": {"cron_file": "/etc/cron.d/ols_wpanel_cron"},
  "systemd": {
    "service_name": "ols-wpanel",
    "service_path": "/etc/systemd/system/ols-wpanel.service",
    "binary_path": "/usr/local/bin/ols-wpanel"
  }
}
PREFLIGHTEOF
    chmod 0600 "$preflight_config"
    chmod 0700 "$PANEL_CANDIDATE"
    timeout 20s "$PANEL_CANDIDATE" --info --config "$preflight_config" \
        > "$preflight_output" 2>&1 || return 1
    grep -q "OLS WPanel" "$preflight_output" || return 1
    candidate_version=$(sed -n 's/^版本: \(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)\([[:space:]].*\)\{0,1\}$/\1/p' "$preflight_output")
    [[ $(printf '%s\n' "$candidate_version" | awk 'NF {count++} END {print count+0}') == "1" ]] || return 1
    panel_version_at_least "$candidate_version" "$MIN_PANEL_VERSION" || return 1
    [[ "$candidate_version" == "$INSTALLER_RELEASE_VERSION" ]] || return 1
}

panel_version_at_least() {
    [[ "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
    [[ "$2" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
    local actual="${1#v}"
    local minimum="${2#v}"
    local actual_major="" actual_minor="" actual_patch=""
    local minimum_major="" minimum_minor="" minimum_patch=""

    [[ "$actual" =~ ^([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})$ ]] || return 1
    actual_major="${BASH_REMATCH[1]}"
    actual_minor="${BASH_REMATCH[2]}"
    actual_patch="${BASH_REMATCH[3]}"
    [[ "$minimum" =~ ^([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})$ ]] || return 1
    minimum_major="${BASH_REMATCH[1]}"
    minimum_minor="${BASH_REMATCH[2]}"
    minimum_patch="${BASH_REMATCH[3]}"

    (( 10#$actual_major > 10#$minimum_major )) && return 0
    (( 10#$actual_major < 10#$minimum_major )) && return 1
    (( 10#$actual_minor > 10#$minimum_minor )) && return 0
    (( 10#$actual_minor < 10#$minimum_minor )) && return 1
    (( 10#$actual_patch >= 10#$minimum_patch ))
}

write_panel_service_unit() {
    local target="$1"
    local mode="$2"

    cat > "$target" << SYSTEMDEOF
[Unit]
Description=WordPress Server Management Panel
After=network.target mariadb.service redis-server.service

[Service]
Type=simple
User=root
Group=root
ExecStart=$BIN_PATH --config=$CONFIG_FILE
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ols-wpanel
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SYSTEMDEOF
    chmod "$mode" "$target"
}

validate_repair_service_unit() {
    local expected_unit="$INSTALL_WORKDIR/expected-ols-wpanel.service"
    local unit_owner=""
    local unit_mode=""
    local unit_links=""

    [[ -f "$SERVICE_PATH" ]] && [[ ! -L "$SERVICE_PATH" ]] || return 1
    unit_owner=$(stat -c '%u' "$SERVICE_PATH" 2>/dev/null) || return 1
    unit_mode=$(stat -c '%a' "$SERVICE_PATH" 2>/dev/null) || return 1
    unit_links=$(stat -c '%h' "$SERVICE_PATH" 2>/dev/null) || return 1
    [[ "$unit_owner" == "0" ]] || return 1
    [[ "$unit_links" == "1" ]] || return 1
    [[ "$unit_mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$unit_mode & 0022) == 0 )) || return 1

    write_panel_service_unit "$expected_unit" 0600 || return 1
    cmp -s -- "$expected_unit" "$SERVICE_PATH" || return 1

    validate_no_panel_service_dropins || return 1
    systemctl daemon-reload >/dev/null 2>&1 || return 1
    validate_effective_panel_service_unit
}

validate_existing_panel_binary() {
    local binary_owner=""
    local binary_mode=""
    local binary_links=""
    local binary_path=""

    [[ -f "$BIN_PATH" ]] && [[ ! -L "$BIN_PATH" ]] && [[ -s "$BIN_PATH" ]] && [[ -x "$BIN_PATH" ]] || return 1
    binary_owner=$(stat -c '%u' "$BIN_PATH" 2>/dev/null) || return 1
    binary_mode=$(stat -c '%a' "$BIN_PATH" 2>/dev/null) || return 1
    binary_links=$(stat -c '%h' "$BIN_PATH" 2>/dev/null) || return 1
    binary_path=$(readlink -f -- "$BIN_PATH" 2>/dev/null) || return 1
    [[ "$binary_owner" == "0" ]] || return 1
    [[ "$binary_mode" == "755" ]] || return 1
    [[ "$binary_links" == "1" ]] || return 1
    [[ "$binary_path" == "$BIN_PATH" ]]
}

validate_no_panel_service_dropins() {
    local unit_paths=""
    local unit_dir=""
    local dropin_name=""
    local dropin_dir=""

    unit_paths=$(systemd-analyze unit-paths 2>/dev/null) || return 1
    [[ -n "$unit_paths" ]] || return 1

    # systemd applies exact-name, dash-truncated and type-wide drop-ins from
    # every configured unit load path (including *.control, transient and
    # generator paths). Reject any effective source rather than maintaining a
    # hand-written partial directory list.
    while IFS= read -r unit_dir; do
        [[ -n "$unit_dir" ]] || continue
        for dropin_name in ols-wpanel.service.d yub-.service.d service.d; do
            dropin_dir="${unit_dir%/}/${dropin_name}"
            if [[ -e "$dropin_dir" ]] || [[ -L "$dropin_dir" ]]; then
                [[ -d "$dropin_dir" ]] && [[ ! -L "$dropin_dir" ]] || return 1
                if find "$dropin_dir" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | grep -q .; then
                    return 1
                fi
            fi
        done
    done <<< "$unit_paths"
}

validate_effective_panel_service_unit() {
    local load_state=""
    local fragment_path=""
    local dropin_paths=""
    local exec_start=""
    local expected_exec_prefix="{ path=$BIN_PATH ; argv[]=$BIN_PATH --config=$CONFIG_FILE ; "

    load_state=$(systemctl show ols-wpanel.service --property=LoadState --value 2>/dev/null) || return 1
    fragment_path=$(systemctl show ols-wpanel.service --property=FragmentPath --value 2>/dev/null) || return 1
    dropin_paths=$(systemctl show ols-wpanel.service --property=DropInPaths --value 2>/dev/null) || return 1
    exec_start=$(systemctl show ols-wpanel.service --property=ExecStart --value 2>/dev/null) || return 1

    [[ "$load_state" == "loaded" ]] || return 1
    [[ "$fragment_path" == "$SERVICE_PATH" ]] || return 1
    [[ -z "${dropin_paths//[[:space:]]/}" ]] || return 1
    [[ "$exec_start" == "$expected_exec_prefix"* ]] || return 1
    [[ "$exec_start" != *"} {"* ]] || return 1
}

validate_running_panel_service_identity() {
    local main_pid=""
    local running_executable=""
    local installed_executable=""

    [[ -f "$BIN_PATH" ]] && [[ ! -L "$BIN_PATH" ]] || return 1
    installed_executable=$(readlink -f -- "$BIN_PATH" 2>/dev/null) || return 1
    [[ "$installed_executable" == "$BIN_PATH" ]] || return 1

    for _ in 1 2 3 4 5 6 7 8 9 10; do
        main_pid=$(systemctl show ols-wpanel.service --property=MainPID --value 2>/dev/null || true)
        if [[ "$main_pid" =~ ^[1-9][0-9]*$ ]] && [[ -e "/proc/${main_pid}/exe" ]]; then
            running_executable=$(readlink -- "/proc/${main_pid}/exe" 2>/dev/null || true)
            if [[ "$running_executable" == "$BIN_PATH" ]]; then
                return 0
            fi
        fi
        sleep 1
    done
    return 1
}

# A successful systemd start is not enough to commit an install or repair: the
# process must be the deployed binary, own the configured TLS listener, and
# serve the expected release from the database-backed loopback health route.
validate_running_panel_health() {
    local expected_version="$1"
    local panel_info=""
    local reported_version=""
    local tls_port=""
    local main_pid=""
    local running_executable=""
    local confirmed_pid=""
    local listeners=""
    local health_response=""

    [[ "$expected_version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || return 1
    panel_info=$(timeout 20s "$BIN_PATH" --info --config "$CONFIG_FILE" 2>/dev/null) || return 1
    reported_version=$(sed -n 's/^版本: \(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)\([[:space:]].*\)\{0,1\}$/\1/p' <<< "$panel_info")
    tls_port=$(sed -n 's/^HTTPS 端口: \([0-9][0-9]*\)$/\1/p' <<< "$panel_info")
    [[ $(printf '%s\n' "$reported_version" | awk 'NF {count++} END {print count+0}') == "1" ]] || return 1
    [[ $(printf '%s\n' "$tls_port" | awk 'NF {count++} END {print count+0}') == "1" ]] || return 1
    [[ "$reported_version" == "$expected_version" ]] || return 1
    [[ "$tls_port" =~ ^[0-9]{1,5}$ ]] || return 1
    (( 10#$tls_port >= 1 && 10#$tls_port <= 65535 )) || return 1

    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if systemctl is-active --quiet ols-wpanel 2>/dev/null; then
            main_pid=$(systemctl show ols-wpanel.service --property=MainPID --value 2>/dev/null || true)
            if [[ "$main_pid" =~ ^[1-9][0-9]*$ ]] && [[ -e "/proc/${main_pid}/exe" ]]; then
                running_executable=$(readlink -- "/proc/${main_pid}/exe" 2>/dev/null || true)
                listeners=$(ss -H -ltnp "sport = :${tls_port}" 2>/dev/null || true)
                if [[ "$running_executable" == "$BIN_PATH" ]] && \
                   printf '%s\n' "$listeners" | grep -Fq "pid=${main_pid},"; then
                    health_response=$(curl -q --noproxy '*' --insecure --fail --silent --show-error \
                        --connect-timeout 2 --max-time 5 \
                        "https://127.0.0.1:${tls_port}/healthz" 2>/dev/null || true)
                    confirmed_pid=$(systemctl show ols-wpanel.service --property=MainPID --value 2>/dev/null || true)
                    if [[ "$confirmed_pid" == "$main_pid" ]] && \
                       [[ "$health_response" == "{\"ok\":true,\"version\":\"${expected_version}\"}" ]]; then
                        VALIDATED_TLS_PORT="$tls_port"
                        return 0
                    fi
                fi
            fi
        fi
        sleep 2
    done
    return 1
}

validate_existing_panel_cron_file() {
	local cron_parent="${CRON_PATH%/*}"
	local parent_owner=""
	local parent_mode=""
    local cron_owner=""
    local cron_mode=""
    local cron_links=""
    local first_line=""

	[[ -d "$cron_parent" ]] && [[ ! -L "$cron_parent" ]] || return 1
	parent_owner=$(stat -c '%u' "$cron_parent" 2>/dev/null) || return 1
	parent_mode=$(stat -c '%a' "$cron_parent" 2>/dev/null) || return 1
	[[ "$parent_owner" == "0" ]] || return 1
	[[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] || return 1
	(( (8#$parent_mode & 0022) == 0 )) || return 1

    if [[ ! -e "$CRON_PATH" ]] && [[ ! -L "$CRON_PATH" ]]; then
        return 0
    fi
    [[ -f "$CRON_PATH" ]] && [[ ! -L "$CRON_PATH" ]] || return 1
    cron_owner=$(stat -c '%u' "$CRON_PATH" 2>/dev/null) || return 1
    cron_mode=$(stat -c '%a' "$CRON_PATH" 2>/dev/null) || return 1
    cron_links=$(stat -c '%h' "$CRON_PATH" 2>/dev/null) || return 1
    [[ "$cron_owner" == "0" ]] || return 1
    [[ "$cron_links" == "1" ]] || return 1
    [[ "$cron_mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$cron_mode & 0022) == 0 )) || return 1
    IFS= read -r first_line < "$CRON_PATH" || return 1
    [[ "$first_line" == "# OLS WPanel Cron Jobs — DO NOT EDIT MANUALLY" ]]
}

validate_fresh_panel_cron_location() {
	local cron_parent="${CRON_PATH%/*}"
	local nearest_parent="$cron_parent"
	local parent_owner=""
	local parent_mode=""
	local next_parent=""

	if [[ -e "$cron_parent" ]] || [[ -L "$cron_parent" ]]; then
		validate_existing_panel_cron_file
		return
	fi
	# Minimal supported images may not have /etc/cron.d until the cron package is
	# installed. Reject broken links and validate the nearest existing parent;
	# after package installation the exact /etc/cron.d directory is rechecked.
	while [[ ! -e "$nearest_parent" ]]; do
		[[ ! -L "$nearest_parent" ]] || return 1
		next_parent="${nearest_parent%/*}"
		[[ -n "$next_parent" ]] && [[ "$next_parent" != "$nearest_parent" ]] || return 1
		nearest_parent="$next_parent"
	done
	[[ -d "$nearest_parent" ]] && [[ ! -L "$nearest_parent" ]] || return 1
	parent_owner=$(stat -c '%u' "$nearest_parent" 2>/dev/null) || return 1
	parent_mode=$(stat -c '%a' "$nearest_parent" 2>/dev/null) || return 1
	[[ "$parent_owner" == "0" ]] || return 1
	[[ "$parent_mode" =~ ^[0-7]{3,4}$ ]] || return 1
	(( (8#$parent_mode & 0022) == 0 ))
}

copy_local_release_bundle() {
    local script_dir="$1"
    local panel_asset_path="${script_dir}/${PANEL_ASSET_NAME}"

    file_size_within_limit "$panel_asset_path" "$PANEL_ASSET_MAX_BYTES" || return 1
    file_size_within_limit "${panel_asset_path}.sha256" "$CHECKSUM_ASSET_MAX_BYTES" || return 1
    file_size_within_limit "${panel_asset_path}.sha256.sig" "$SIGNATURE_ASSET_MAX_BYTES" || return 1
    file_size_within_limit "$script_dir/ols-wpanel-third-party-licenses.tar.gz" "$LICENSE_ARCHIVE_MAX_BYTES" || return 1
    file_size_within_limit "$script_dir/ols-wpanel-third-party-licenses.tar.gz.sha256" "$CHECKSUM_ASSET_MAX_BYTES" || return 1
    file_size_within_limit "$script_dir/ols-wpanel-third-party-licenses.tar.gz.sha256.sig" "$SIGNATURE_ASSET_MAX_BYTES" || return 1
    install -m 0600 "$panel_asset_path" "$PANEL_CANDIDATE"
    install -m 0600 "${panel_asset_path}.sha256" "$PANEL_SHA256_FILE"
    install -m 0600 "${panel_asset_path}.sha256.sig" "$PANEL_SIGNATURE_FILE"
    install -m 0600 "$script_dir/ols-wpanel-third-party-licenses.tar.gz" "$LICENSE_ARCHIVE"
    install -m 0600 "$script_dir/ols-wpanel-third-party-licenses.tar.gz.sha256" "$LICENSE_SHA256_FILE"
    install -m 0600 "$script_dir/ols-wpanel-third-party-licenses.tar.gz.sha256.sig" "$LICENSE_SIGNATURE_FILE"
}

download_release_bundle() {
    local release_base_url="$1"
    local binary_url="${release_base_url}/${PANEL_ASSET_NAME}"
    local license_url="${release_base_url}/ols-wpanel-third-party-licenses.tar.gz"

    rm -f \
        "$PANEL_CANDIDATE" "$PANEL_SHA256_FILE" "$PANEL_SIGNATURE_FILE" \
        "$LICENSE_ARCHIVE" "$LICENSE_SHA256_FILE" "$LICENSE_SIGNATURE_FILE"
    download_file "$binary_url" "$PANEL_CANDIDATE" 180 "$PANEL_ASSET_MAX_BYTES" || return 1
    download_file "${binary_url}.sha256" "$PANEL_SHA256_FILE" 60 "$CHECKSUM_ASSET_MAX_BYTES" || return 1
    download_file "${binary_url}.sha256.sig" "$PANEL_SIGNATURE_FILE" 60 "$SIGNATURE_ASSET_MAX_BYTES" || return 1
    download_file "$license_url" "$LICENSE_ARCHIVE" 120 "$LICENSE_ARCHIVE_MAX_BYTES" || return 1
    download_file "${license_url}.sha256" "$LICENSE_SHA256_FILE" 60 "$CHECKSUM_ASSET_MAX_BYTES" || return 1
    download_file "${license_url}.sha256.sig" "$LICENSE_SIGNATURE_FILE" 60 "$SIGNATURE_ASSET_MAX_BYTES" || return 1
}

prepare_panel_candidate() {
    local script_dir=""
    local github_release_base=""
    local proxy_release_base=""
    local bundle_source=""

    validate_installer_release_version || \
        log_error "安装器缺少规范、受支持的固定 Release 版本；请使用已签名 GitHub Release 资产"
    github_release_base="https://github.com/zangwp/OLS-WPanel/releases/download/${INSTALLER_RELEASE_VERSION}"
    if [[ -n "$GHPROXY" ]]; then
        proxy_release_base="${GHPROXY%/}/${github_release_base}"
    fi

    if $PANEL_CANDIDATE_VERIFIED && [[ -x "$PANEL_CANDIDATE" ]]; then
        return 0
    fi
    [[ -n "$INSTALL_WORKDIR" ]] && [[ -d "$INSTALL_WORKDIR" ]] || \
        log_error "安装临时工作目录尚未初始化"
    script_dir="$(cd "$(dirname "$0")" && pwd)"

    if copy_local_release_bundle "$script_dir"; then
        bundle_source="同目录离线发布包"
        if ! verify_complete_release_bundle; then
            log_error "同目录面板与许可发布包未通过 Ed25519 签名、SHA256 或内容校验"
        fi
    elif $PREFER_CN && [[ -n "$proxy_release_base" ]]; then
        if download_release_bundle "$proxy_release_base" && \
           verify_complete_release_bundle; then
            bundle_source="自定义 GitHub 反代"
        elif download_release_bundle "$github_release_base" && \
             verify_complete_release_bundle; then
            bundle_source="GitHub Releases"
        else
            log_error "无法获取通过 Ed25519 签名、SHA256 和内容校验的面板与许可发布包"
        fi
    else
        if download_release_bundle "$github_release_base" && \
           verify_complete_release_bundle; then
            bundle_source="GitHub Releases"
        elif [[ -n "$proxy_release_base" ]] && download_release_bundle "$proxy_release_base" && \
             verify_complete_release_bundle; then
            bundle_source="自定义 GitHub 反代"
        else
            log_error "无法获取通过 Ed25519 签名、SHA256 和内容校验的面板与许可发布包"
        fi
    fi

    preflight_panel_candidate || log_error "已验签面板二进制未通过 --info 安全预检"
    PANEL_CANDIDATE_VERIFIED=true
    log_info "安装包 ${INSTALLER_RELEASE_VERSION} 签名与完整性验证通过（${bundle_source}）"
}

create_repair_backup() {
    local timestamp=""
    local license_file=""
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    REPAIR_BACKUP_DIR="$INSTALL_DIR/backups/install-repair/${timestamp}-$$"
    [[ -s "$BIN_PATH" ]] && REPAIR_BIN_EXISTED=true
    [[ -f "$SERVICE_PATH" ]] && REPAIR_UNIT_EXISTED=true
    [[ -f "$DB_PATH" ]] && REPAIR_DB_EXISTED=true
    if [[ -f "$INSTALL_DIR/certs/panel.crt" ]] && [[ -f "$INSTALL_DIR/certs/panel.key" ]]; then
        REPAIR_TLS_EXISTED=true
    fi
    install -d -m 0700 "$REPAIR_BACKUP_DIR"

    install -m 0600 "$CONFIG_FILE" "$REPAIR_BACKUP_DIR/config.json"
    # Preserve the separate MFA encryption key alongside the private repair
    # snapshot. Ordinary downloadable database backups deliberately exclude it.
    local account_mfa_key="${DB_PATH%/*}/account-mfa.key"
    if [[ -e "$account_mfa_key" ]] || [[ -L "$account_mfa_key" ]]; then
        [[ -f "$account_mfa_key" ]] && [[ ! -L "$account_mfa_key" ]] || \
            log_error "repair前双因素认证密钥不是安全常规文件"
        install -m 0600 "$account_mfa_key" "$REPAIR_BACKUP_DIR/account-mfa.key"
    fi
    # Website API credentials use a separate key too. Include it in the
    # private repair snapshot; the downloadable SQLite backup excludes keys.
    local cloudflare_security_key="${DB_PATH%/*}/cloudflare-security.key"
    if [[ -e "$cloudflare_security_key" ]] || [[ -L "$cloudflare_security_key" ]]; then
        [[ -f "$cloudflare_security_key" ]] && [[ ! -L "$cloudflare_security_key" ]] || \
            log_error "repair前Cloudflare凭据密钥不是安全常规文件"
        install -m 0600 "$cloudflare_security_key" "$REPAIR_BACKUP_DIR/cloudflare-security.key"
    fi
    if [[ -f "$DB_PATH" ]]; then
        sqlite3 "$DB_PATH" ".timeout 10000" ".backup $REPAIR_BACKUP_DIR/panel.db"
        [[ "$(sqlite3 "$REPAIR_BACKUP_DIR/panel.db" 'PRAGMA integrity_check;')" == "ok" ]] || \
            log_error "repair备份SQLite完整性检查失败"
    fi
    if $REPAIR_BIN_EXISTED; then
        install -m 0755 "$BIN_PATH" "$REPAIR_BACKUP_DIR/ols-wpanel"
    fi
    if $REPAIR_UNIT_EXISTED; then
        install -m 0644 "$SERVICE_PATH" "$REPAIR_BACKUP_DIR/ols-wpanel.service"
    fi
    if $REPAIR_TLS_EXISTED; then
        install -m 0644 "$INSTALL_DIR/certs/panel.crt" "$REPAIR_BACKUP_DIR/panel.crt"
        install -m 0600 "$INSTALL_DIR/certs/panel.key" "$REPAIR_BACKUP_DIR/panel.key"
    fi
    if [[ -e "$LICENSE_DOC_DIR" ]] || [[ -L "$LICENSE_DOC_DIR" ]]; then
        validate_license_document_directory || \
            log_error "repair前许可文档目录身份不安全"
        for license_file in \
            LICENSE \
            NOTICE.md \
            THIRD_PARTY_NOTICES.md \
            RELEASE_VERSION \
            ols-wpanel-third-party-licenses.tar.gz \
            ols-wpanel-third-party-licenses.tar.gz.sha256 \
            ols-wpanel-third-party-licenses.tar.gz.sha256.sig \
            release-public-key.pem; do
            if [[ -e "$LICENSE_DOC_DIR/$license_file" ]] || [[ -L "$LICENSE_DOC_DIR/$license_file" ]]; then
                [[ -f "$LICENSE_DOC_DIR/$license_file" ]] && [[ ! -L "$LICENSE_DOC_DIR/$license_file" ]] || \
                    log_error "repair前许可文档条目不是安全常规文件: $license_file"
            fi
        done
        REPAIR_LICENSE_DIR_EXISTED=true
        cp -a -- "$LICENSE_DOC_DIR" "$REPAIR_BACKUP_DIR/license-docs" || \
            log_error "repair许可文档目录备份失败"
    fi
    find "$REPAIR_BACKUP_DIR" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > "$REPAIR_BACKUP_DIR/SHA256SUMS"
    sha256sum -c "$REPAIR_BACKUP_DIR/SHA256SUMS" >/dev/null || log_error "repair备份校验失败"
}

prepare_repair_snapshot() {
    if systemctl is-active --quiet ols-wpanel 2>/dev/null; then
        REPAIR_SERVICE_WAS_ACTIVE=true
        # Stop immediately before the snapshot and do not start the candidate
        # until every repair mutation is complete. This closes the window in
        # which a post-snapshot SQLite write could be lost by rollback.
        # Arm active-state restoration before stop: systemctl can report a
        # failure after the stop has already taken effect.
        REPAIR_SERVICE_STOPPED_FOR_SNAPSHOT=true
        if ! systemctl stop ols-wpanel; then
            if systemctl is-active --quiet ols-wpanel 2>/dev/null; then
                log_error "repair快照前无法停止ols-wpanel；未修改服务器状态"
            fi
            log_warn "systemctl stop返回失败，但ols-wpanel已停止；继续创建repair快照"
        fi
        if systemctl is-active --quiet ols-wpanel 2>/dev/null; then
            log_error "repair快照前ols-wpanel仍在运行；未创建快照"
        fi
    fi
    create_repair_backup
}

atomic_install_managed_file() {
	local source_path="$1"
	local target_path="$2"
	local target_mode="$3"
	local target_dir="${target_path%/*}"
	local target_base="${target_path##*/}"
	local dir_owner=""
	local dir_mode=""

	[[ "$target_path" == "$BIN_PATH" ]] || [[ "$target_path" == "$DB_PATH" ]] || return 1
	[[ -f "$source_path" ]] && [[ ! -L "$source_path" ]] || return 1
	[[ -d "$target_dir" ]] && [[ ! -L "$target_dir" ]] || return 1
	dir_owner=$(stat -c '%u' "$target_dir" 2>/dev/null) || return 1
	dir_mode=$(stat -c '%a' "$target_dir" 2>/dev/null) || return 1
	[[ "$dir_owner" == "0" ]] || return 1
	[[ "$dir_mode" =~ ^[0-7]{3,4}$ ]] || return 1
	(( (8#$dir_mode & 0022) == 0 )) || return 1

	cleanup_atomic_stage_file
	ATOMIC_STAGE_PATH=$(mktemp "${target_dir}/.${target_base}.ols-install.XXXXXXXX") || return 1
	if ! install -m "$target_mode" "$source_path" "$ATOMIC_STAGE_PATH" || \
	   ! sync -f "$ATOMIC_STAGE_PATH" || \
	   ! mv -f -- "$ATOMIC_STAGE_PATH" "$target_path"; then
		cleanup_atomic_stage_file
		return 1
	fi
	ATOMIC_STAGE_PATH=""
	sync -f "$target_dir"
}

validate_license_document_directory() {
    local doc_parent="${LICENSE_DOC_DIR%/*}"
    local path_owner=""
    local path_mode=""

    [[ "$doc_parent" == "/usr/share/doc" ]] || return 1
    [[ -d "$doc_parent" ]] && [[ ! -L "$doc_parent" ]] || return 1
    [[ "$(readlink -f -- "$doc_parent" 2>/dev/null)" == "$doc_parent" ]] || return 1
    path_owner=$(stat -c '%u' "$doc_parent" 2>/dev/null) || return 1
    path_mode=$(stat -c '%a' "$doc_parent" 2>/dev/null) || return 1
    [[ "$path_owner" == "0" ]] || return 1
    [[ "$path_mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$path_mode & 0022) == 0 )) || return 1

    if [[ -e "$LICENSE_DOC_DIR" ]] || [[ -L "$LICENSE_DOC_DIR" ]]; then
        [[ -d "$LICENSE_DOC_DIR" ]] && [[ ! -L "$LICENSE_DOC_DIR" ]] || return 1
    else
        install -d -m 0755 "$LICENSE_DOC_DIR" || return 1
    fi
    [[ "$(readlink -f -- "$LICENSE_DOC_DIR" 2>/dev/null)" == "$LICENSE_DOC_DIR" ]] || return 1
    path_owner=$(stat -c '%u' "$LICENSE_DOC_DIR" 2>/dev/null) || return 1
    path_mode=$(stat -c '%a' "$LICENSE_DOC_DIR" 2>/dev/null) || return 1
    [[ "$path_owner" == "0" ]] || return 1
    [[ "$path_mode" =~ ^[0-7]{3,4}$ ]] || return 1
    (( (8#$path_mode & 0022) == 0 ))
}

atomic_install_license_document() {
    local source_path="$1"
    local target_path="$2"
    local target_base="${target_path##*/}"
    local stage_path=""

    [[ -f "$source_path" ]] && [[ ! -L "$source_path" ]] || return 1
    case "$target_path" in
        "$LICENSE_DOC_DIR/LICENSE"|\
        "$LICENSE_DOC_DIR/NOTICE.md"|\
        "$LICENSE_DOC_DIR/THIRD_PARTY_NOTICES.md"|\
        "$LICENSE_DOC_DIR/RELEASE_VERSION"|\
        "$LICENSE_DOC_DIR/ols-wpanel-third-party-licenses.tar.gz"|\
        "$LICENSE_DOC_DIR/ols-wpanel-third-party-licenses.tar.gz.sha256"|\
        "$LICENSE_DOC_DIR/ols-wpanel-third-party-licenses.tar.gz.sha256.sig"|\
        "$LICENSE_DOC_DIR/release-public-key.pem") ;;
        *) return 1 ;;
    esac
    if [[ -e "$target_path" ]] || [[ -L "$target_path" ]]; then
        [[ -f "$target_path" ]] && [[ ! -L "$target_path" ]] || return 1
    fi

    stage_path=$(mktemp "$LICENSE_DOC_DIR/.${target_base}.ols-install.XXXXXXXX") || return 1
    if ! install -m 0644 "$source_path" "$stage_path" || \
       ! sync -f "$stage_path" || \
       ! mv -f -- "$stage_path" "$target_path"; then
        rm -f -- "$stage_path"
        return 1
    fi
    sync -f "$LICENSE_DOC_DIR"
}

install_release_license_documentation() {
    local public_key_file="$INSTALL_WORKDIR/release-public-key.pem"

    validate_license_document_directory || return 1
    atomic_install_license_document "$PROJECT_LICENSE_FILE" "$LICENSE_DOC_DIR/LICENSE" || return 1
    atomic_install_license_document "$PROJECT_NOTICE_FILE" "$LICENSE_DOC_DIR/NOTICE.md" || return 1
    atomic_install_license_document "$THIRD_PARTY_NOTICE_FILE" "$LICENSE_DOC_DIR/THIRD_PARTY_NOTICES.md" || return 1
    atomic_install_license_document "$LICENSE_RELEASE_VERSION_FILE" "$LICENSE_DOC_DIR/RELEASE_VERSION" || return 1
    atomic_install_license_document "$LICENSE_ARCHIVE" \
        "$LICENSE_DOC_DIR/ols-wpanel-third-party-licenses.tar.gz" || return 1
    atomic_install_license_document "$LICENSE_SHA256_FILE" \
        "$LICENSE_DOC_DIR/ols-wpanel-third-party-licenses.tar.gz.sha256" || return 1
    atomic_install_license_document "$LICENSE_SIGNATURE_FILE" \
        "$LICENSE_DOC_DIR/ols-wpanel-third-party-licenses.tar.gz.sha256.sig" || return 1
    atomic_install_license_document "$public_key_file" "$LICENSE_DOC_DIR/release-public-key.pem" || return 1
}

repair_rollback() {
    [[ "$REPAIR_MODE" == true ]] || return 0
    [[ "$REPAIR_COMMITTED" == false ]] || return 0

    if [[ "$REPAIR_MUTATED" != true ]]; then
        # Snapshot preparation may have stopped an originally active service
        # before a backup failure. No persistent repair data changed yet, so
        # restore only the original runtime state.
        if $REPAIR_SERVICE_WAS_ACTIVE && $REPAIR_SERVICE_STOPPED_FOR_SNAPSHOT; then
            systemctl start ols-wpanel 2>/dev/null || \
                log_warn "严重：repair快照失败后无法恢复原active状态，请手动启动ols-wpanel"
        fi
        return 0
    fi
    if [[ -z "$REPAIR_BACKUP_DIR" ]] || [[ ! -d "$REPAIR_BACKUP_DIR" ]]; then
        # A mutated repair without its snapshot cannot be restored safely. Fail
        # closed instead of leaving the candidate service running.
        systemctl stop ols-wpanel 2>/dev/null || \
            log_warn "严重：repair备份目录不可用，且无法确认ols-wpanel已停止，请立即手动停服"
        if systemctl is-active --quiet ols-wpanel 2>/dev/null; then
            log_warn "严重：repair备份目录不可用，ols-wpanel仍在运行；请立即手动停服并从服务器快照恢复"
        else
            log_warn "严重：repair备份目录不可用，已保持ols-wpanel停止；请从服务器快照恢复"
        fi
        return 0
    fi

    local db_rollback_ok=true
    local runtime_rollback_ok=true
    local license_rollback_ok=true
    local license_file=""
    local license_backup_dir="$REPAIR_BACKUP_DIR/license-docs"
    log_warn "repair未完成，正在恢复repair前的面板程序和数据库"
    # 新二进制可能已经升级SQLite结构。必须先停服并恢复同一时间点的数据库，
    # 不能让恢复后的旧二进制继续读取新结构。
    if ! systemctl stop ols-wpanel 2>/dev/null; then
        if systemctl is-active --quiet ols-wpanel 2>/dev/null; then
            log_warn "严重：无法停止ols-wpanel，未恢复面板数据库，保持服务停止后请联系开发者处理"
            db_rollback_ok=false
        else
            log_warn "repair回滚时systemctl stop返回失败，但ols-wpanel已停止；继续恢复"
        fi
    fi
    if systemctl is-active --quiet ols-wpanel 2>/dev/null; then
        log_warn "严重：repair回滚时ols-wpanel仍在运行，未恢复面板数据库，旧面板不会重新启动"
        db_rollback_ok=false
    fi
    if $db_rollback_ok; then
        if $REPAIR_DB_EXISTED; then
            if atomic_install_managed_file "$REPAIR_BACKUP_DIR/panel.db" "$DB_PATH" 0600; then
                if ! rm -f "${DB_PATH}-wal" "${DB_PATH}-shm"; then
                    log_warn "严重：repair数据库恢复后无法移除SQLite sidecar，旧面板不会重新启动，请手动核对"
                    db_rollback_ok=false
                fi
            else
                log_warn "严重：repair前的面板数据库恢复失败，旧面板不会重新启动，请联系开发者处理"
                db_rollback_ok=false
            fi
        elif ! rm -f "$DB_PATH" "${DB_PATH}-wal" "${DB_PATH}-shm"; then
            log_warn "严重：无法移除repair期间创建的面板数据库，旧面板不会重新启动，请手动核对"
            db_rollback_ok=false
        fi
    fi

    if $REPAIR_BIN_EXISTED; then
		if ! atomic_install_managed_file "$REPAIR_BACKUP_DIR/ols-wpanel" "$BIN_PATH" 0755; then
			log_warn "严重：repair前的面板二进制原子恢复失败，旧面板不会重新启动，请联系开发者处理"
			db_rollback_ok=false
		fi
    else
        if ! rm -f "$BIN_PATH"; then
            log_warn "严重：无法移除repair期间创建的面板二进制，旧面板不会重新启动，请手动核对"
            db_rollback_ok=false
        fi
    fi
    if $REPAIR_UNIT_EXISTED; then
        if ! install -m 0644 "$REPAIR_BACKUP_DIR/ols-wpanel.service" "$SERVICE_PATH"; then
            log_warn "严重：repair前的systemd unit恢复失败，旧面板不会重新启动，请手动核对"
            runtime_rollback_ok=false
        fi
    else
        if ! rm -f "$SERVICE_PATH"; then
            log_warn "严重：无法移除repair期间创建的systemd unit，旧面板不会重新启动，请手动核对"
            runtime_rollback_ok=false
        fi
    fi
    if $REPAIR_TLS_EXISTED; then
        if ! install -m 0644 "$REPAIR_BACKUP_DIR/panel.crt" "$INSTALL_DIR/certs/panel.crt" || \
           ! install -m 0600 "$REPAIR_BACKUP_DIR/panel.key" "$INSTALL_DIR/certs/panel.key"; then
            log_warn "严重：repair前的TLS身份恢复失败，旧面板不会重新启动，请手动核对"
            runtime_rollback_ok=false
        fi
    elif [[ "${REPAIR_TLS_ACTION:-}" == "generate" ]]; then
        if ! rm -f "$INSTALL_DIR/certs/panel.crt" "$INSTALL_DIR/certs/panel.key"; then
            log_warn "严重：无法移除repair期间生成的TLS身份，旧面板不会重新启动，请手动核对"
            runtime_rollback_ok=false
        fi
    fi

    # Release documentation is version-bound just like the binary. Remove the
    # files managed by this installer, then restore the exact pre-repair tree;
    # when the directory did not previously exist, remove the now-empty one.
    if [[ -e "$LICENSE_DOC_DIR" ]] || [[ -L "$LICENSE_DOC_DIR" ]]; then
        if [[ ! -d "$LICENSE_DOC_DIR" ]] || [[ -L "$LICENSE_DOC_DIR" ]]; then
            log_warn "严重：repair后的许可文档路径身份异常，拒绝自动恢复"
            license_rollback_ok=false
        else
            for license_file in \
                LICENSE \
                NOTICE.md \
                THIRD_PARTY_NOTICES.md \
                RELEASE_VERSION \
                ols-wpanel-third-party-licenses.tar.gz \
                ols-wpanel-third-party-licenses.tar.gz.sha256 \
                ols-wpanel-third-party-licenses.tar.gz.sha256.sig \
                release-public-key.pem; do
                if [[ -e "$LICENSE_DOC_DIR/$license_file" ]] || [[ -L "$LICENSE_DOC_DIR/$license_file" ]]; then
                    if [[ -d "$LICENSE_DOC_DIR/$license_file" ]] && [[ ! -L "$LICENSE_DOC_DIR/$license_file" ]]; then
                        log_warn "严重：repair后的许可文档条目不是常规文件: $license_file"
                        license_rollback_ok=false
                        continue
                    fi
                    rm -f -- "$LICENSE_DOC_DIR/$license_file" || license_rollback_ok=false
                fi
            done
        fi
    fi
    if $license_rollback_ok && $REPAIR_LICENSE_DIR_EXISTED; then
        if [[ ! -d "$license_backup_dir" ]] || [[ -L "$license_backup_dir" ]]; then
            log_warn "严重：repair前许可文档备份不存在或身份异常"
            license_rollback_ok=false
        elif [[ -e "$LICENSE_DOC_DIR" ]] || [[ -L "$LICENSE_DOC_DIR" ]]; then
            cp -a -- "$license_backup_dir/." "$LICENSE_DOC_DIR/" || license_rollback_ok=false
        else
            cp -a -- "$license_backup_dir" "$LICENSE_DOC_DIR" || license_rollback_ok=false
        fi
    elif $license_rollback_ok && [[ -d "$LICENSE_DOC_DIR" ]] && [[ ! -L "$LICENSE_DOC_DIR" ]]; then
        rmdir "$LICENSE_DOC_DIR" 2>/dev/null || license_rollback_ok=false
    fi
    if ! $license_rollback_ok; then
        log_warn "严重：repair前的许可文档目录未能完整恢复，请使用备份目录手动核对"
    fi
    if ! systemctl daemon-reload 2>/dev/null; then
        log_warn "严重：repair回滚后systemd daemon-reload失败，旧面板不会重新启动，请手动核对"
        runtime_rollback_ok=false
    fi
    if $REPAIR_SERVICE_WAS_ACTIVE && $db_rollback_ok && $runtime_rollback_ok && $license_rollback_ok; then
        systemctl start ols-wpanel 2>/dev/null || \
            log_warn "严重：repair回滚完成但无法恢复原active状态，请手动启动ols-wpanel"
    else
        systemctl stop ols-wpanel 2>/dev/null || \
            log_warn "严重：repair回滚未完整成功且无法确认ols-wpanel保持停止，请立即手动停服并核对"
    fi
}

apt_candidate_version() {
    local pkg="$1"

    # Do not exit awk after the first match. With `set -o pipefail`, an early
    # consumer exit can give apt-cache SIGPIPE and abort the installer even
    # though a valid Candidate line was already produced.
    LC_ALL=C apt-cache policy "$pkg" 2>/dev/null | \
        awk '$1 == "Candidate:" && !found { print $2; found = 1 }'
}

apt_package_available() {
    local pkg="$1"
    local candidate=""

    candidate=$(apt_candidate_version "$pkg" || true)
    if [[ -n "$candidate" ]] && [[ "$candidate" != "(none)" ]]; then
        return 0
    fi

    LC_ALL=C apt-cache show "$pkg" >/dev/null 2>&1
}

assert_managed_source_target() {
    local source_path="$1"

    if [[ ! -e "$source_path" ]] && [[ ! -L "$source_path" ]]; then
        return 0
    fi
    [[ -f "$source_path" ]] && [[ ! -L "$source_path" ]] && \
        head -n 1 -- "$source_path" 2>/dev/null | grep -Fqx -- '# Managed by OLS WPanel' || \
        log_error "APT 源路径已被非 OLS WPanel 文件占用: $source_path"
}

remove_managed_source_file() {
    local source_path="$1"

    [[ -f "$source_path" ]] && [[ ! -L "$source_path" ]] || return 0
    if head -n 1 -- "$source_path" 2>/dev/null | grep -Fqx -- '# Managed by OLS WPanel'; then
        rm -f -- "$source_path"
    else
        log_warn "保留非 OLS WPanel 管理的 APT 源文件: $source_path"
    fi
}

set_debian_source_meta() {
    case "$1" in
        nju)
            DEBIAN_SOURCE_LABEL="南京大学 Debian 镜像"
            DEBIAN_REPO_URL="https://mirror.nju.edu.cn/debian"
            DEBIAN_SECURITY_URL="https://mirror.nju.edu.cn/debian-security"
            ;;
        ustc)
            DEBIAN_SOURCE_LABEL="中科大 Debian 镜像"
            DEBIAN_REPO_URL="https://mirrors.ustc.edu.cn/debian"
            DEBIAN_SECURITY_URL="https://mirrors.ustc.edu.cn/debian-security"
            ;;
        tuna)
            DEBIAN_SOURCE_LABEL="清华大学 Debian 镜像"
            DEBIAN_REPO_URL="https://mirrors.tuna.tsinghua.edu.cn/debian"
            DEBIAN_SECURITY_URL="https://mirrors.tuna.tsinghua.edu.cn/debian-security"
            ;;
        official)
            DEBIAN_SOURCE_LABEL="Debian 官方源"
            DEBIAN_REPO_URL="https://deb.debian.org/debian"
            DEBIAN_SECURITY_URL="https://security.debian.org/debian-security"
            ;;
        *)
            return 1
            ;;
    esac
}

backup_default_distribution_sources() {
    local primary_source="$1"
    local source_pattern="$2"
    local source_file=""
    local backup_path="${primary_source}.ols-wpanel.bak"
    local disabled_path="${primary_source}.ols-wpanel.disabled"

    mkdir -p /etc/apt/sources.list.d
    if [[ -f "$primary_source" ]]; then
        if [[ -e "$backup_path" ]] || [[ -L "$backup_path" ]] || \
           [[ -e "$disabled_path" ]] || [[ -L "$disabled_path" ]]; then
            log_error "发现旧的 APT 源备份/禁用文件，拒绝覆盖: $primary_source"
        fi
        cp -- "$primary_source" "$backup_path"
        APT_SOURCES_MUTATED=true
        mv -- "$primary_source" "$disabled_path"
    fi
    for source_file in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
        [[ -f "$source_file" ]] || continue
        grep -Eq "$source_pattern" "$source_file" || continue
        if [[ -e "${source_file}.ols-wpanel.bak" ]] || [[ -L "${source_file}.ols-wpanel.bak" ]]; then
            log_error "发现旧的 APT 源备份，拒绝覆盖: ${source_file}.ols-wpanel.bak"
        fi
        cp -- "$source_file" "${source_file}.ols-wpanel.bak"
        APT_SOURCES_MUTATED=true
        sed -i -E "\@${source_pattern}@ s@^@# disabled by OLS WPanel: @" "$source_file"
    done
}

backup_default_debian_sources() {
    backup_default_distribution_sources \
        /etc/apt/sources.list.d/debian.sources \
        '^[[:space:]]*deb(-src)?[[:space:]].*(/debian-security|/debian([[:space:]/]|$)|deb\.debian\.org|security\.debian\.org)'
}

write_debian_sources() {
    local codename="$1"

    assert_managed_source_target /etc/apt/sources.list.d/ols-wpanel-debian.sources
    cat > /etc/apt/sources.list.d/ols-wpanel-debian.sources << DEBIANSOURCESEOF
# Managed by OLS WPanel
Types: deb
URIs: ${DEBIAN_REPO_URL}
Suites: ${codename} ${codename}-updates
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: ${DEBIAN_SECURITY_URL}
Suites: ${codename}-security
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
DEBIANSOURCESEOF
    APT_SOURCES_MUTATED=true
}

base_packages_available() {
    local packages=(ca-certificates wget curl gnupg lsb-release iproute2 mariadb-server redis-server)
    local pkg=""

    for pkg in "${packages[@]}"; do
        if ! apt_package_available "$pkg"; then
            log_warn "APT 源缺少关键包候选版本: ${pkg}"
            return 1
        fi
    done
    return 0
}

configure_litespeed_repository() {
	local key1="$INSTALL_WORKDIR/lst_debian_repo.gpg"
	local key2="$INSTALL_WORKDIR/lst_repo.gpg"
	local keyring="/usr/share/keyrings/litespeed-archive-keyring.gpg"
	local keyring_tmp="$INSTALL_WORKDIR/litespeed-archive-keyring.gpg"
	local actual=""

	log_info "配置 LiteSpeed 官方 APT 仓库（HTTPS + 固定公钥哈希）..."
	assert_managed_source_target /etc/apt/sources.list.d/ols-wpanel-litespeed.sources
	download_file "https://rpms.litespeedtech.com/debian/lst_debian_repo.gpg" "$key1" 60 8192 || \
		log_error "下载 LiteSpeed APT 公钥失败"
	actual=$(sha256sum "$key1" | awk '{print $1}')
	[[ "$actual" == "$LITESPEED_DEBIAN_KEY_SHA256" ]] || \
		log_error "LiteSpeed APT 公钥哈希不匹配，拒绝继续"
	download_file "https://rpms.litespeedtech.com/debian/lst_repo.gpg" "$key2" 60 8192 || \
		log_error "下载 LiteSpeed 兼容 APT 公钥失败"
	actual=$(sha256sum "$key2" | awk '{print $1}')
	[[ "$actual" == "$LITESPEED_REPO_KEY_SHA256" ]] || \
		log_error "LiteSpeed 兼容 APT 公钥哈希不匹配，拒绝继续"
	cat "$key1" "$key2" > "$keyring_tmp"
	install -o root -g root -m 0644 "$keyring_tmp" "$keyring"

	cat > /etc/apt/sources.list.d/ols-wpanel-litespeed.sources << LITESPEEDSOURCEEOF
# Managed by OLS WPanel
Types: deb
URIs: https://rpms.litespeedtech.com/debian/
Suites: ${PLATFORM_CODENAME}
Components: main
Signed-By: ${keyring}
LITESPEEDSOURCEEOF
	APT_SOURCES_MUTATED=true
	apt-get update

	local package=""
	# OpenLiteSpeed and all panel-supported LSPHP branches come from LiteSpeed's
	# authenticated repository. The base packages include GD, mbstring, XML and
	# ZIP; those modules are not published as separate Debian packages.
	for package in openlitespeed \
		lsphp83 lsphp83-common lsphp83-mysql lsphp83-curl lsphp83-intl lsphp83-redis lsphp83-opcache lsphp83-imagick \
		lsphp84 lsphp84-common lsphp84-mysql lsphp84-curl lsphp84-intl lsphp84-redis lsphp84-opcache lsphp84-imagick \
		lsphp85 lsphp85-common lsphp85-mysql lsphp85-curl lsphp85-intl lsphp85-redis lsphp85-imagick; do
		apt_package_available "$package" || log_error "LiteSpeed 仓库缺少 ${package}（${PLATFORM_CODENAME}/${PLATFORM_ARCH}）"
	done
	# LiteSpeed currently bundles PHP 8.5 without publishing a separate
	# OPcache Debian package for that branch. Keep the explicit package for 8.3/8.4,
	# but do not reject an otherwise complete 8.5 repository.
}

configure_redis_repository() {
	local key_download="$INSTALL_WORKDIR/redis-archive-keyring.asc"
	local keyring="/usr/share/keyrings/ols-wpanel-redis-archive-keyring.asc"
	local source_file="/etc/apt/sources.list.d/ols-wpanel-redis.sources"
	local actual=""
	local candidate=""

	log_info "配置 Redis 官方 APT 仓库（HTTPS + 固定公钥哈希）..."
	assert_managed_source_target "$source_file"
	download_file "https://packages.redis.io/gpg" "$key_download" 60 16384 || \
		log_error "下载 Redis APT 公钥失败"
	actual=$(sha256sum "$key_download" | awk '{print $1}')
	[[ "$actual" == "$REDIS_APT_KEY_SHA256" ]] || \
		log_error "Redis APT 公钥哈希不匹配，拒绝继续"
	if [[ -L "$keyring" ]] || { [[ -e "$keyring" ]] && [[ ! -f "$keyring" ]]; }; then
		log_error "Redis APT 公钥路径不是普通文件，拒绝覆盖: $keyring"
	fi
	install -o root -g root -m 0644 "$key_download" "$keyring"
	cat > "$source_file" << REDISSOURCEEOF
# Managed by OLS WPanel
Types: deb
URIs: https://packages.redis.io/deb
Suites: ${PLATFORM_CODENAME}
Components: main
Signed-By: ${keyring}
REDISSOURCEEOF
	APT_SOURCES_MUTATED=true
	apt-get update
	apt_package_available redis-server || \
		log_error "Redis 官方仓库缺少 redis-server（${PLATFORM_CODENAME}/${PLATFORM_ARCH}）"
	if ! candidate=$(apt_candidate_version redis-server); then
		log_error "无法读取 Redis APT 候选版本"
	fi
	[[ -n "$candidate" ]] && [[ "$candidate" != "(none)" ]] || \
		log_error "无法解析 Redis APT 候选版本"
	dpkg --compare-versions "$candidate" ge "$MIN_REDIS_PACKAGE_VERSION" || \
		log_error "Redis APT 候选版本 ${candidate} 低于所需稳定版本 8.10.2"
}

configure_mariadb_repository() {
	local key_download="$INSTALL_WORKDIR/mariadb-keyring-2019.gpg"
	local keyring="/usr/share/keyrings/ols-wpanel-mariadb-archive-keyring.gpg"
	local source_file="/etc/apt/sources.list.d/ols-wpanel-mariadb.sources"
	local fingerprints=""
	local candidate=""
	log_info "配置全新安装默认 MariaDB ${MARIADB_SERIES} 官方 APT 仓库..."
	assert_managed_source_target "$source_file"
	download_file "https://supplychain.mariadb.com/mariadb-keyring-2019.gpg" "$key_download" 60 1048576 || \
		log_error "下载 MariaDB APT 公钥失败"
	fingerprints=$(gpg --batch --show-keys --with-colons "$key_download" 2>/dev/null | awk -F: '$1 == "fpr" {print toupper($10)}')
	grep -Fxq "$MARIADB_APT_KEY_FINGERPRINT" <<< "$fingerprints" || \
		log_error "MariaDB APT 公钥指纹不匹配，拒绝继续"
	install -o root -g root -m 0644 "$key_download" "$keyring"
	cat > "$source_file" << MARIADBSOURCEEOF
# Managed by OLS WPanel
Types: deb
URIs: https://mirror.mariadb.org/repo/${MARIADB_SERIES}/${PLATFORM_ID}
Suites: ${PLATFORM_CODENAME}
Components: main
Signed-By: ${keyring}
MARIADBSOURCEEOF
	APT_SOURCES_MUTATED=true
	apt-get update
	if ! candidate=$(apt_candidate_version mariadb-server); then
		log_error "无法读取 MariaDB APT 候选版本"
	fi
	[[ "$candidate" == *"${MARIADB_SERIES}."* ]] || \
		log_error "MariaDB 官方仓库未提供 ${MARIADB_SERIES} 候选包（${PLATFORM_CODENAME}/${PLATFORM_ARCH}）"
	log_info "MariaDB ${MARIADB_SERIES} 官方候选包可用: $candidate"
}

validate_lsphp_wordpress_modules() {
	local modules_file="$INSTALL_WORKDIR/lsphp85-modules.txt"
	local module=""

	/usr/local/lsws/lsphp85/bin/php -m > "$modules_file"
	for module in curl dom exif fileinfo gd imagick igbinary intl mbstring mysqli openssl pdo_mysql redis SimpleXML xml xmlreader xmlwriter zip "Zend OPcache"; do
		grep -Fxq "$module" "$modules_file" || \
			log_error "LSPHP 8.5 缺少 WordPress 所需模块: ${module}（${PLATFORM_CODENAME}/${PLATFORM_ARCH}）"
	done
}

configure_debian_source() {
    local source_id="$1"
    local codename="$2"
    local apt_log="$INSTALL_WORKDIR/debian-apt-update.log"

    set_debian_source_meta "$source_id" || return 1
    log_info "尝试 Debian 源: ${DEBIAN_SOURCE_LABEL}"
    write_debian_sources "$codename"

    if apt-get update > "$apt_log" 2>&1 && base_packages_available; then
        rm -f "$apt_log"
        log_info "Debian 源可用: ${DEBIAN_SOURCE_LABEL}"
        return 0
    fi

    log_warn "${DEBIAN_SOURCE_LABEL} 不可用或同步不完整，准备尝试下一个 Debian 源"
    if [[ -f "$apt_log" ]]; then
        tail -n 8 "$apt_log" 2>/dev/null || true
    fi
    rm -f "$apt_log"
    return 1
}

select_debian_source() {
    local codename="$1"
    local candidates=()
    local source_id=""

    if $PREFER_CN; then
        candidates=(nju ustc tuna official)
        backup_default_debian_sources
    else
        log_info "使用系统默认 Debian APT 源"
        apt-get update
        base_packages_available || log_error "系统默认 APT 源缺少关键包，请检查 /etc/apt/sources.list 或 /etc/apt/sources.list.d/"
        return 0
    fi

    for source_id in "${candidates[@]}"; do
        if configure_debian_source "$source_id" "$codename"; then
            if [[ "$source_id" == "official" ]]; then
                log_warn "国内镜像同步可能延迟，已回退官方源"
            fi
            return 0
        fi
    done

    log_error "所有 Debian APT 源均不可用。请检查网络、DNS、系统时间，或手动配置可用镜像源后重试。"
}

set_ubuntu_source_meta() {
    local source_id="$1"
    local mirror_path="ubuntu"

    [[ "$PLATFORM_ARCH" == "arm64" ]] && mirror_path="ubuntu-ports"
    case "$source_id" in
        ustc)
            UBUNTU_SOURCE_LABEL="中科大 Ubuntu 镜像"
            UBUNTU_REPO_URL="https://mirrors.ustc.edu.cn/${mirror_path}"
            UBUNTU_SECURITY_URL="$UBUNTU_REPO_URL"
            ;;
        tuna)
            UBUNTU_SOURCE_LABEL="清华大学 Ubuntu 镜像"
            UBUNTU_REPO_URL="https://mirrors.tuna.tsinghua.edu.cn/${mirror_path}"
            UBUNTU_SECURITY_URL="$UBUNTU_REPO_URL"
            ;;
        official)
            UBUNTU_SOURCE_LABEL="Ubuntu 官方源"
            if [[ "$PLATFORM_ARCH" == "arm64" ]]; then
                UBUNTU_REPO_URL="https://ports.ubuntu.com/ubuntu-ports"
                UBUNTU_SECURITY_URL="$UBUNTU_REPO_URL"
            else
                UBUNTU_REPO_URL="https://archive.ubuntu.com/ubuntu"
                UBUNTU_SECURITY_URL="https://security.ubuntu.com/ubuntu"
            fi
            ;;
        *) return 1 ;;
    esac
}

backup_default_ubuntu_sources() {
    backup_default_distribution_sources \
        /etc/apt/sources.list.d/ubuntu.sources \
        '^[[:space:]]*deb(-src)?[[:space:]].*(archive\.ubuntu\.com|security\.ubuntu\.com|ports\.ubuntu\.com|/ubuntu([[:space:]/]|$)|/ubuntu-ports([[:space:]/]|$))'
}

write_ubuntu_sources() {
    local codename="$1"

    assert_managed_source_target /etc/apt/sources.list.d/ols-wpanel-ubuntu.sources
    cat > /etc/apt/sources.list.d/ols-wpanel-ubuntu.sources << UBUNTUSOURCESEOF
# Managed by OLS WPanel
Types: deb
URIs: ${UBUNTU_REPO_URL}
Suites: ${codename} ${codename}-updates ${codename}-backports
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: ${UBUNTU_SECURITY_URL}
Suites: ${codename}-security
Components: main universe restricted multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
UBUNTUSOURCESEOF
    APT_SOURCES_MUTATED=true
}

configure_ubuntu_source() {
    local source_id="$1"
    local codename="$2"
    local apt_log="$INSTALL_WORKDIR/ubuntu-apt-update.log"

    set_ubuntu_source_meta "$source_id" || return 1
    log_info "尝试 Ubuntu 源: ${UBUNTU_SOURCE_LABEL}"
    write_ubuntu_sources "$codename"
    if apt-get update > "$apt_log" 2>&1 && base_packages_available; then
        rm -f "$apt_log"
        log_info "Ubuntu 源可用: ${UBUNTU_SOURCE_LABEL}"
        return 0
    fi
    log_warn "${UBUNTU_SOURCE_LABEL} 不可用或同步不完整，准备尝试下一个 Ubuntu 源"
    [[ ! -f "$apt_log" ]] || tail -n 8 "$apt_log" 2>/dev/null || true
    rm -f "$apt_log"
    return 1
}

select_ubuntu_source() {
    local codename="$1"
    local candidates=()
    local source_id=""

    if $PREFER_CN; then
        candidates=(ustc tuna official)
        backup_default_ubuntu_sources
    else
        log_info "使用系统默认 Ubuntu APT 源"
        apt-get update
        base_packages_available || log_error "系统默认 Ubuntu APT 源缺少关键系统包"
        return 0
    fi
    for source_id in "${candidates[@]}"; do
        if configure_ubuntu_source "$source_id" "$codename"; then
            [[ "$source_id" != "official" ]] || log_warn "国内镜像不可用，已回退 Ubuntu 官方源"
            return 0
        fi
    done
    log_error "所有 Ubuntu APT 源均不可用。请检查网络、DNS、系统时间，或恢复系统源后重试。"
}

select_platform_source() {
    case "$PLATFORM_ID" in
        debian) select_debian_source "$PLATFORM_CODENAME" ;;
        ubuntu) select_ubuntu_source "$PLATFORM_CODENAME" ;;
        *) log_error "内部错误：未知平台 ${PLATFORM_ID:-empty}" ;;
    esac
}

restore_managed_apt_sources() {
    # Uninstalling the panel does not necessarily uninstall its runtime. Keep
    # the repositories and verification keys for every retained runtime.
    local runtime_policy="${1:-remove-runtime}"
    local original=""
    local backup=""
    local disabled=""

    case "$runtime_policy" in
        remove-runtime|retain-runtime|retain-redis) ;;
        *) log_error "未知的软件源恢复策略" ;;
    esac
    remove_managed_source_file /etc/apt/sources.list.d/ols-wpanel-debian.sources
    remove_managed_source_file /etc/apt/sources.list.d/ols-wpanel-ubuntu.sources
	if [[ "$runtime_policy" != "retain-runtime" ]]; then
	remove_managed_source_file /etc/apt/sources.list.d/ols-wpanel-litespeed.sources
	remove_managed_source_file /etc/apt/sources.list.d/ols-wpanel-mariadb.sources
	if [[ ! -e /etc/apt/sources.list.d/ols-wpanel-mariadb.sources ]] && [[ ! -L /etc/apt/sources.list.d/ols-wpanel-mariadb.sources ]]; then
		rm -f -- /usr/share/keyrings/ols-wpanel-mariadb-archive-keyring.gpg
	fi
	fi
	if [[ "$runtime_policy" == "remove-runtime" ]]; then
	remove_managed_source_file /etc/apt/sources.list.d/ols-wpanel-redis.sources
	if [[ ! -e /etc/apt/sources.list.d/ols-wpanel-redis.sources ]] && [[ ! -L /etc/apt/sources.list.d/ols-wpanel-redis.sources ]]; then
		rm -f -- /usr/share/keyrings/ols-wpanel-redis-archive-keyring.asc
	fi
	fi
    for original in \
        /etc/apt/sources.list.d/debian.sources \
        /etc/apt/sources.list.d/ubuntu.sources; do
        backup="${original}.ols-wpanel.bak"
        disabled="${original}.ols-wpanel.disabled"
        [[ -f "$backup" ]] || continue
        if [[ -e "$original" ]] || [[ -L "$original" ]]; then
            log_warn "未覆盖后来创建的 APT 源文件: $original；备份保留在 $backup"
            continue
        fi
        rm -f -- "$disabled"
        mv -- "$backup" "$original"
    done

    for backup in /etc/apt/sources.list.ols-wpanel.bak /etc/apt/sources.list.d/*.list.ols-wpanel.bak; do
        [[ -f "$backup" ]] || continue
        original="${backup%.ols-wpanel.bak}"
        if [[ -f "$original" ]] && [[ ! -L "$original" ]]; then
            sed -i 's/^# disabled by OLS WPanel: //' "$original" 2>/dev/null || true
            rm -f -- "$backup"
        elif [[ ! -e "$original" ]] && [[ ! -L "$original" ]]; then
            mv -- "$backup" "$original"
        else
            log_warn "无法安全恢复 APT 源文件: $original；备份保留在 $backup"
        fi
    done
    APT_SOURCES_MUTATED=false
}

# ============================================================
# 卸载函数（定义在前，兼容管道执行）
# ============================================================

is_uninstall_confirmation() {
    [[ "${1:-}" == "Y" || "${1:-}" == "y" ]]
}

cleanup_ols_runtime_integrations() {
    local jail=""
    local logrotate_file=""

    # Stop only fixed OLS units and jails. Every operation is best-effort so a
    # stale or partially installed integration cannot prevent uninstallation.
    systemctl stop olswpanel-whitelist.timer 2>/dev/null || true
    systemctl stop olswpanel-whitelist.service 2>/dev/null || true
    systemctl disable ols-wpanel 2>/dev/null || true
    systemctl disable olswpanel-whitelist.timer 2>/dev/null || true
    systemctl disable olswpanel-whitelist.service 2>/dev/null || true

    if command -v fail2ban-client >/dev/null 2>&1; then
        for jail in olswpanel olswpanel-404 olswpanel-login olswpanel-sshd olswpanel-sqli; do
            fail2ban-client stop "$jail" >/dev/null 2>&1 || true
        done
    fi

    rm -f -- \
        /etc/cron.d/ols_wpanel_cron \
        /etc/systemd/system/ols-wpanel.service \
        /etc/systemd/system/multi-user.target.wants/ols-wpanel.service \
        /run/systemd/transient/ols-wpanel.service \
        /etc/systemd/system/olswpanel-whitelist.timer \
        /etc/systemd/system/olswpanel-whitelist.service \
        /etc/systemd/system/timers.target.wants/olswpanel-whitelist.timer \
        /etc/systemd/system/lsws.service.d/ols-wpanel.conf \
        /etc/systemd/system/lshttpd.service.d/ols-wpanel.conf \
        /etc/systemd/system/mariadb.service.d/ols-wpanel.conf \
        /etc/systemd/system/redis-server.service.d/ols-wpanel.conf \
        /etc/fail2ban/jail.d/olswpanel.conf \
        /etc/fail2ban/action.d/olswpanel-record.conf \
        /etc/fail2ban/filter.d/olswpanel.conf \
        /etc/fail2ban/filter.d/olswpanel-404.conf \
        /etc/fail2ban/filter.d/olswpanel-login.conf \
        /etc/fail2ban/filter.d/olswpanel-sqli.conf \
        2>/dev/null || true

    # Remove only unit-specific overrides owned by this panel. Hierarchical or
    # global drop-ins are never deleted automatically; the installer detects
    # and rejects them before it changes the host.
    rm -rf -- \
        /etc/systemd/system/ols-wpanel.service.d \
        /run/systemd/system/ols-wpanel.service.d \
        /etc/systemd/system.control/ols-wpanel.service.d \
        /run/systemd/system.control/ols-wpanel.service.d \
        2>/dev/null || true

    # Site logrotate names are dynamic. Delete only regular files in the fixed
    # directory whose first line carries OLS WPanel's ownership marker.
    while IFS= read -r -d '' logrotate_file; do
        [[ -f "$logrotate_file" ]] && [[ ! -L "$logrotate_file" ]] || continue
        if head -n 1 -- "$logrotate_file" 2>/dev/null | \
            grep -Eq '^# OLS WPanel Generated - [A-Za-z0-9._-]+$'; then
            rm -f -- "$logrotate_file" 2>/dev/null || true
        fi
    done < <(find /etc/logrotate.d -maxdepth 1 -type f -name 'olswpanel-*' -print0 2>/dev/null)

    systemctl daemon-reload 2>/dev/null || true
}

remove_managed_panel_command() {
    local command_path="$1"
    local ownership_marker="$2"

    [[ -f "$command_path" ]] || return 0
    [[ ! -L "$command_path" ]] || return 0
    if head -n 5 -- "$command_path" 2>/dev/null | grep -Fqx -- "$ownership_marker"; then
        rm -f -- "$command_path"
    fi
}

confirm_ordinary_uninstall() {
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  即将普通卸载 OLS WPanel${NC}"
    echo -e "  将删除面板配置、面板数据库、面板 TLS 身份和面板本地备份。"
    echo -e "${GREEN}  网站文件、网站日志、站点证书、OLS 站点配置、MariaDB 数据库和共享软件会保留。${NC}"
    echo -e "  输入 ${BOLD}Y${NC} 确认卸载（兼容 y）；回车或其他输入取消。"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    local uninstall_confirmation=""
    read -r -p "确认卸载 [y/N]: " uninstall_confirmation < /dev/tty 2>/dev/null || uninstall_confirmation=""
    is_uninstall_confirmation "$uninstall_confirmation"
}

do_uninstall() {
    UNINSTALL_MODE=true
    UNINSTALL_STAGE="停止面板服务"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  普通卸载将永久删除 /www/ols-wpanel 全部内容，包括：${NC}"
    echo -e "  - 面板数据库 panel.db 与 config.json"
    echo -e "  - 面板自身 TLS 证书和私钥"
    echo -e "  - 面板本地备份、共享安装包缓存与该目录内的登录凭据/密钥"
    echo -e "${GREEN}  普通卸载保留站点文件、站点日志、站点证书、OpenLiteSpeed/LSPHP 站点配置、MariaDB 数据库和共享系统软件。${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${BOLD}正在卸载面板，请稍候...${NC}"

    echo -e "  → 停止面板服务..."
    systemctl stop ols-wpanel 2>/dev/null || true
    if systemctl is-active --quiet ols-wpanel; then
        log_error "面板服务仍在运行，停止删除文件；请检查 systemd 日志"
    fi
    systemctl disable ols-wpanel 2>/dev/null || true
    cleanup_ols_runtime_integrations
    echo -e "  ${GREEN}✓${NC} 面板服务已停止"

    echo -e "  → 删除面板文件..."
    UNINSTALL_STAGE="删除面板文件"
    rm -f "$BIN_PATH"
    remove_managed_panel_command /usr/local/bin/o '# OLS WPanel CLI — o'
    remove_managed_panel_command /usr/local/bin/O '# OLS WPanel CLI — o'
    rm -rf "$INSTALL_DIR"
    rm -rf -- "$LICENSE_DOC_DIR"
    restore_managed_apt_sources retain-runtime
    echo -e "  ${GREEN}✓${NC} 面板文件已删除"

    echo -e "  → 重新加载 OpenLiteSpeed..."
    systemctl restart lshttpd 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} OpenLiteSpeed 站点继续运行"

    echo ""
    log_info "面板已卸载。以下内容已保留："
    log_info "  - /www/wwwroot（网站文件）"
    log_info "  - /www/wwwlogs（网站日志）"
    log_info "  - /www/server/certificates（站点 SSL 证书，不包括已删除的面板 TLS 身份）"
    log_info "  - /usr/local/lsws/conf/ols-wpanel（站点 OLS/LSPHP 配置）"
    log_info "  - MariaDB 数据库"
    log_info "  - 系统软件包（openlitespeed/lsphp/mariadb/redis/fail2ban）"
}

# 完全卸载会删除网站文件、网站数据库和 OLS 面板。
# 仅在专用于本面板的服务器上使用；备份默认转移保存，删除备份需单独确认。
# 不执行来自第三方的一键卸载或删除不属于面板的数据库。
purge_inventory_preflight() {
    python3 - "$CONFIG_FILE" "$INSTALL_WORKDIR" <<'PYPURGEPREFLIGHT'
import json,os,pathlib,re,sqlite3,subprocess,sys
cfg=json.load(open(sys.argv[1]));work=pathlib.Path(sys.argv[2])
if cfg['panel'].get('backup_dir','/www/ols-wpanel/backups') != '/www/ols-wpanel/backups':raise SystemExit('自定义备份路径，请手动保留备份并采用普通卸载')
conn=sqlite3.connect('file:'+cfg['sqlite']['path']+'?mode=ro',uri=True)
rows=conn.execute('SELECT web_root,db_name FROM websites').fetchall();conn.close()
roots=set();dbs=set()
for root,db in rows:
 path=pathlib.Path(root)
 if not path.is_absolute() or not path.is_relative_to('/www/wwwroot'):raise SystemExit('拒绝完全卸载：检测到自定义网站路径 '+root)
 roots.add(path.relative_to('/www/wwwroot').parts[0])
 if db:
  if not re.fullmatch(r'[A-Za-z0-9_]+',db):raise SystemExit('数据库名称异常')
  dbs.add(db)
for root in ['/www/wwwroot','/www/wwwlogs','/www/server/certificates','/www/ols-wpanel','/usr/local/lsws/conf/ols-wpanel']:
 path=pathlib.Path(root)
 if path.is_symlink():raise SystemExit('拒绝删除链接目录：'+root)
web=pathlib.Path('/www/wwwroot')
if web.exists():
 unknown=[p.name for p in web.iterdir() if p.name not in roots]
 if unknown:raise SystemExit('检测到未纳入面板的网站目录，保留共享环境：'+', '.join(unknown))
main=pathlib.Path('/usr/local/lsws/conf/httpd_config.conf')
if main.exists():
 for name in re.findall(r'(?im)^\s*virtualHost\s+(\S+)',main.read_text()):
  if name!='olsw_default' and not name.startswith('olsw_'):raise SystemExit('检测到共享 OpenLiteSpeed 虚拟主机：'+name)
client=next((p for p in ['/usr/bin/mariadb','/usr/bin/mysql'] if os.path.isfile(p)),None)
if not client:raise SystemExit('无法确认数据库归属，取消完全卸载')
credentials=cfg.get('mariadb',{})
def option(value):
 if not isinstance(value,str) or '\x00' in value:raise SystemExit('数据库认证配置格式异常')
 return '"'+value.replace('\\','\\\\').replace('"','\\"').replace('\n','\\n').replace('\r','\\r').replace('\t','\\t').replace('\b','\\b')+'"'
client_config=work/'purge-mariadb.cnf'
client_options='[client]\nuser='+option(credentials.get('root_user','root'))+'\npassword='+option(credentials.get('root_password',''))+'\nsocket='+option(credentials.get('socket','/run/mysqld/mysqld.sock'))+'\nprotocol=socket\n'
fd=os.open(client_config,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
with os.fdopen(fd,'w') as output:output.write(client_options)
result=subprocess.run([client,'--defaults-file='+str(client_config),'--protocol=socket','-N','-B','-e','SHOW DATABASES'],capture_output=True,text=True,timeout=15)
if result.returncode:raise SystemExit('无法读取数据库清单，取消完全卸载')
existing=set(result.stdout.splitlines());unknown=existing-dbs-{'mysql','sys','information_schema','performance_schema'}
if unknown:raise SystemExit('检测到其他程序数据库，保留共享环境：'+', '.join(sorted(unknown)))
(work/'purge-databases.sql').write_text(''.join('DROP DATABASE IF EXISTS `'+db+'`;\n' for db in sorted(dbs)))
(work/'purge-client').write_text(client)
print('将删除的网站目录：'+', '.join(sorted(roots)))
print('将删除的数据库：'+', '.join(sorted(dbs)))
PYPURGEPREFLIGHT
}

do_purge() {
    echo ""
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${RED}  高风险警告：彻底清空会删除下列数据和配置：${NC}"
    echo -e "  - /usr/local/lsws/conf/ols-wpanel（全部 OpenLiteSpeed/LSPHP 站点配置）"
    echo -e "  - /www/wwwroot、/www/wwwlogs、/www/server/certificates"
    echo -e "  - /www/ols-wpanel（面板状态、凭据、备份和共享安装包缓存；备份默认另行保留）"
    echo -e "  - 卸载软件：OpenLiteSpeed、LSPHP 8.3/8.4/8.5、MariaDB；保留 Redis、Fail2ban"
    echo -e "${RED}  这些目录和软件可能同时被非 OLS 工作负载使用；操作可能使其停机或永久丢失数据。${NC}"
    echo -e "  Redis、Fail2ban 等可能共享的软件保留，只清理面板自身集成。"
    echo -e "${RED}  此操作不可逆。${NC}"
    echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  请核对以上删除范围，输入 ${BOLD}Y${NC} 确认完全卸载（兼容 y）；回车或其他输入取消。"

    local purge_confirmation=""
    read -r -p "确认完全卸载 [y/N]: " purge_confirmation < /dev/tty 2>/dev/null || purge_confirmation=""
    if ! is_uninstall_confirmation "$purge_confirmation"; then
        log_info "已取消完全卸载"
        return 0
    fi

    echo ""
    UNINSTALL_MODE=true
    UNINSTALL_STAGE="检查删除范围"
    purge_inventory_preflight || { log_warn "无法确认专用环境，已取消；可使用普通卸载保留共享环境"; return 1; }
    local backup_choice="" backup_destination=""
    echo "备份默认保留到 /www/ols-wpanel-preserved-backups；输入 DELETE BACKUPS 才删除备份。"
    read -r -p "备份选择（回车保留）: " backup_choice < /dev/tty || backup_choice=""
    UNINSTALL_STAGE="停止面板服务与保留备份"
    systemctl stop ols-wpanel || log_error "无法停止面板，取消完全卸载"
    if [[ "$backup_choice" != "DELETE BACKUPS" ]] && [[ -d "$INSTALL_DIR/backups" ]]; then
        [[ ! -L "$INSTALL_DIR/backups" ]] || log_error "备份目录是链接，拒绝移动"
        backup_destination=$(mktemp -d /www/ols-wpanel-preserved-backups.XXXXXXXXXX) || log_error "无法创建备份保留目录"
        chmod 0700 "$backup_destination"
        if ! mv -- "$INSTALL_DIR/backups" "$backup_destination/backups"; then
            systemctl start ols-wpanel || true
            log_error "备份保留失败，取消卸载"
        fi
        log_info "备份已保留: $backup_destination/backups"
    fi
    echo -e "${BOLD}正在清空，请耐心等待...${NC}"

    echo -e "  → 停止所有服务..."
    UNINSTALL_STAGE="删除网站数据库与停止运行环境"
    systemctl stop ols-wpanel 2>/dev/null || true
    systemctl stop lshttpd 2>/dev/null || true
    local purge_client=""
    purge_client=$(cat "$INSTALL_WORKDIR/purge-client")
    "$purge_client" --defaults-file="$INSTALL_WORKDIR/purge-mariadb.cnf" --protocol=socket < "$INSTALL_WORKDIR/purge-databases.sql" || log_error "数据库删除失败，停止后续卸载"
    systemctl stop mariadb 2>/dev/null || true
    # Redis 和 Fail2ban 可能被共享工作负载使用，保留其服务与软件包。
    echo -e "  ${GREEN}✓${NC} 服务已停止"

    echo -e "  → 清理 OLS 定时任务、systemd、Fail2ban 和 logrotate 集成..."
    UNINSTALL_STAGE="清理面板运行时集成"
    cleanup_ols_runtime_integrations
    echo -e "  ${GREEN}✓${NC} OLS 运行时集成已清理"

    echo -e "  → 清理 OpenLiteSpeed 和 LSPHP 站点配置..."
    UNINSTALL_STAGE="删除站点配置"
    rm -rf /usr/local/lsws/conf/ols-wpanel
    echo -e "  ${GREEN}✓${NC} 配置已清理"

    echo -e "  → 卸载软件包（可能需要 1-2 分钟）..."
    UNINSTALL_STAGE="卸载 OpenLiteSpeed、LSPHP 与 MariaDB 软件包"
    DEBIAN_FRONTEND=noninteractive apt-get purge -y openlitespeed 'lsphp83*' 'lsphp84*' 'lsphp85*' mariadb-server mariadb-common < /dev/null || log_error "软件包卸载失败，请检查上方 APT/dpkg 输出"
    # 不自动 autoremove，避免连带移除其他应用的依赖。
    echo -e "  ${GREEN}✓${NC} 软件包已卸载"

    echo -e "  → 移除 OLS 系统调优配置..."
    UNINSTALL_STAGE="移除面板系统调优"
    rm -f /etc/sysctl.d/99-ols-wpanel.conf /etc/sysctl.d/99-ols-wpanel-vps.conf /etc/sysctl.d/.ols-wpanel-vps-original.json
    sysctl --system >/dev/null 2>&1 || log_warn "系统其余 sysctl 配置重载失败；面板调优文件已移除，继续清理"
    sed -i '/nofile 65535/d' /etc/security/limits.conf 2>/dev/null || true
    echo -e "  ${GREEN}✓${NC} OLS 系统调优配置已移除"

    echo -e "  → 删除面板文件..."
    UNINSTALL_STAGE="删除面板文件与恢复软件源"
    rm -f "$BIN_PATH"
    remove_managed_panel_command /usr/local/bin/o '# OLS WPanel CLI — o'
    remove_managed_panel_command /usr/local/bin/O '# OLS WPanel CLI — o'
    rm -rf "$INSTALL_DIR"
    rm -rf -- "$LICENSE_DOC_DIR"
    restore_managed_apt_sources retain-redis
    echo -e "  ${GREEN}✓${NC} 面板文件已删除"

    echo -e "  → 删除网站数据..."
    UNINSTALL_STAGE="删除网站文件、日志与证书"
    rm -rf /www/wwwroot /www/wwwlogs /www/server/certificates
    rm -f /etc/apt/sources.list.d/ols-wpanel-litespeed.sources
    rm -f /usr/share/keyrings/litespeed-archive-keyring.gpg
    echo -e "  ${GREEN}✓${NC} 网站数据已删除"

    if awk '$0 == "# OLS WPanel managed swap" {getline; if ($0 == "/swapfile none swap sw 0 0") found=1} END {exit !found}' /etc/fstab 2>/dev/null; then
        echo -e "  → 清理 Swap 文件..."
        UNINSTALL_STAGE="清理面板创建的 Swap"
        swapoff /swapfile 2>/dev/null || true
        rm -f /swapfile
        sed -i '/^# OLS WPanel managed swap$/ {N; /\/swapfile none swap sw 0 0/d;}' /etc/fstab
        rm -f /etc/sysctl.d/99-ols-wpanel-swap.conf
        echo -e "  ${GREEN}✓${NC} Swap 已删除"
    fi

    echo ""
    log_info "彻底清理流程已完成；仅执行了上方明确列出的删除和卸载，不承诺恢复其他系统变更。"
    log_info "Redis、Fail2ban 和共享目录中的剩余文件已保留；o / O 命令已移除，不再提供管理菜单。"
}

# ============================================================
# 权限、平台与发布包安全预检
# ============================================================
if [[ $EUID -ne 0 ]]; then
    log_error "请使用 root 权限运行此脚本"
fi
assert_supported_platform
if $CHECK_PLATFORM_ONLY; then
    log_info "平台检查通过: ${PLATFORM_ID} ${PLATFORM_VERSION} (${PLATFORM_CODENAME}) ${PLATFORM_ARCH}"
    trap - EXIT
    exit 0
fi
if $CHECK_MARIADB_PACKAGES_ONLY; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl wget gnupg coreutils openssl systemd
    init_install_workdir
    configure_mariadb_repository
    log_info "MariaDB ${MARIADB_SERIES} 软件包检查通过: ${PLATFORM_ID} ${PLATFORM_VERSION} ${PLATFORM_ARCH}"
    trap - EXIT
    exit 0
fi
if $CHECK_OLS_PACKAGES_ONLY; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    # Minimal Debian/Ubuntu container images omit systemctl/systemd-analyze,
    # while the production installer deliberately requires both before it
    # creates a private work directory. Install the command package here so
    # the package probe exercises the same fail-closed preflight.
    apt-get install -y --no-install-recommends ca-certificates curl wget gnupg coreutils openssl systemd
    init_install_workdir
    configure_litespeed_repository
	configure_redis_repository
    apt-get install -y --no-install-recommends \
        openlitespeed lsphp85 lsphp85-common lsphp85-mysql lsphp85-curl \
        lsphp85-intl lsphp85-redis lsphp85-imagick \
		redis-server redis-tools
    /usr/local/lsws/bin/openlitespeed -v
    /usr/local/lsws/lsphp85/bin/lsphp -v
    /usr/local/lsws/lsphp85/bin/php --ini
    validate_lsphp_wordpress_modules
    cat "$INSTALL_WORKDIR/lsphp85-modules.txt"
    # Validate the same plain-text constructs emitted by the installer and Go
    # vhost renderer. The container is disposable, so replacing the vendor
    # sample config here cannot affect a user system.
    OLS_CHECK_ROOT="$INSTALL_WORKDIR/ols-config-check"
    install -d -m 0750 "$OLS_CHECK_ROOT/vhosts/example" "$OLS_CHECK_ROOT/www" "$OLS_CHECK_ROOT/logs"
    openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
        -keyout "$OLS_CHECK_ROOT/default.key" -out "$OLS_CHECK_ROOT/default.crt" \
        -subj '/CN=localhost' >/dev/null 2>&1
    cat > "$OLS_CHECK_ROOT/vhosts/example/vhconf.conf" << OLSCHECKVHOSTEOF
docRoot                 $OLS_CHECK_ROOT/www
vhDomain                example.test
adminEmails             root@localhost
enableGzip              1
enableBr                1
errorlog $OLS_CHECK_ROOT/logs/error.log {
  useServer              0
  logLevel               WARN
  rollingSize            20M
  keepDays               14
}
accesslog $OLS_CHECK_ROOT/logs/access.log {
  useServer              0
  rollingSize            20M
  keepDays               14
}
index {
  useServer              0
  indexFiles             index.php,index.html
}
scripthandler {
  add                    lsapi:lsphp_example php
}
extprocessor lsphp_example {
  type                   lsapi
  address                uds://$OLS_CHECK_ROOT/lsphp.sock
  maxConns               2
  env                    PHP_LSAPI_CHILDREN=2
  env                    LSPHP_ENABLE_USER_INI=on
  initTimeout            60
  retryTimeout           0
  persistConn            1
  respBuffer             0
  autoStart              1
  path                   /usr/local/lsws/lsphp85/bin/lsphp
  backlog                100
  instances              1
  extUser                nobody
  extGroup               nogroup
  runOnStartUp           1
}
phpIniOverride {
  php_admin_value memory_limit 256M
  php_admin_flag display_errors Off
}
context / {
  location               $OLS_CHECK_ROOT/www/
  allowBrowse            1
}
rewrite {
  enable                 1
  autoLoadHtaccess       1
}
module cache {
  ls_enabled             1
  storagePath            \$VH_ROOT/.lscache
  checkPrivateCache      1
  checkPublicCache       1
  maxCacheObjSize        10000000
  maxStaleAge            200
  qsCache                1
  reqCookieCache         1
  respCookieCache        0
  ignoreReqCacheCtrl     1
  ignoreRespCacheCtrl    0
  enableCache            1
  expireInSeconds        3600
  enablePrivateCache     0
  privateExpireInSeconds 3600
}
vhssl {
  keyFile                $OLS_CHECK_ROOT/default.key
  certFile               $OLS_CHECK_ROOT/default.crt
  certChain              0
  sslProtocol            24
}
OLSCHECKVHOSTEOF
    cat > /usr/local/lsws/conf/httpd_config.conf << OLSCHECKMAINEOF
serverName               OLS-WPanel-CI
user                     nobody
group                    nogroup
priority                 0
autoFix503               1
gracefulRestartTimeout   300
mime                     conf/mime.properties
showVersionNumber        0
useIpInProxyHeader       2
adminEmails              root@localhost
indexFiles               index.html,index.php
disableWebAdmin          1
errorlog logs/error.log {
  logLevel               WARN
  rollingSize            20M
}
accessControl {
  allow                  ALL
}
module cache {
  ls_enabled             1
  checkPrivateCache      1
  checkPublicCache       1
  enableCache            0
}
virtualHost olsw_example {
  vhRoot                 $OLS_CHECK_ROOT/www/
  allowSymbolLink        1
  enableScript           1
  restrained             1
  setUIDMode             2
  configFile             $OLS_CHECK_ROOT/vhosts/example/vhconf.conf
}
listener OLSWPanelHTTP {
  address                *:8080
  secure                 0
  map                    olsw_example example.test
}
listener OLSWPanelHTTPS {
  address                *:8443
  secure                 1
  keyFile                $OLS_CHECK_ROOT/default.key
  certFile               $OLS_CHECK_ROOT/default.crt
  certChain              0
  sslProtocol            24
  map                    olsw_example example.test
}
OLSCHECKMAINEOF
    # Parse both listener families in the disposable package probe without
    # starting a web server or changing production IPv6/network settings.
    append_ols_ipv6_listeners /usr/local/lsws/conf/httpd_config.conf 8080 8443 olsw_example example.test "$OLS_CHECK_ROOT"
    /usr/local/lsws/bin/openlitespeed -t
    log_info "OpenLiteSpeed/LSPHP 软件包检查通过: ${PLATFORM_ID} ${PLATFORM_VERSION} ${PLATFORM_ARCH}"
    trap - EXIT
    exit 0
fi
init_install_workdir
if [[ "$REQUESTED_ACTION" == "uninstall" ]]; then
    log_info "权限与 ${PLATFORM_ID} ${PLATFORM_VERSION} ${PLATFORM_ARCH} 平台预检通过；普通卸载不下载发布包"
elif [[ "$REQUESTED_ACTION" == "purge" ]]; then
    log_info "完全卸载无需下载完整发布包"
else
    prepare_panel_candidate
    log_info "权限、${PLATFORM_ID} ${PLATFORM_VERSION} ${PLATFORM_ARCH} 平台与发布包安全预检通过"
fi
exec 9>/run/lock/ols-wpanel-install.lock
flock -n 9 || log_error "另一个 OLS WPanel 安装或 repair 进程正在运行"

# Maintenance navigation only selects an action; mutations are dispatched afterwards.
maintenance_read_choice() {
    choice=""
    read -r -p "请选择 [0 返回/退出，回车不执行]: " choice < /dev/tty 2>/dev/null || choice=0
}
maintenance_command_available() {
    [[ -f /usr/local/bin/o && -x /usr/local/bin/o && ! -L /usr/local/bin/o ]] &&
        head -n 5 /usr/local/bin/o | grep -Fqx '# OLS WPanel CLI — o'
}
maintenance_current_version() {
    if ! validate_existing_panel_binary; then return 0; fi
    timeout 5s "$BIN_PATH" --info --config "$CONFIG_FILE" 2>/dev/null |
        sed -n 's/^版本: \(v[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n 1
}
assert_repair_version_compatible() {
    local current=""
    current=$(maintenance_current_version) || current=""
    [[ -n "$current" ]] || log_error "无法确认已安装面板版本，拒绝更新/修复；请检查现有二进制和配置"
    panel_version_at_least "$INSTALLER_RELEASE_VERSION" "$current" || \
        log_error "目标版本 ${INSTALLER_RELEASE_VERSION} 低于当前版本 ${current} 或版本无法比较；未执行降级，请使用最新安装入口"
}

assert_no_retained_sites() {
    local site_dir="" entries=""
    # Also protect a fresh install after ordinary uninstall removed panel.db.
    for site_dir in /www/wwwroot /usr/local/lsws/conf/ols-wpanel/sites-available /usr/local/lsws/conf/ols-wpanel/sites-enabled /usr/local/lsws/conf/ols-wpanel/lsphp-sites; do
        [[ ! -L "$site_dir" ]] || log_error "网站目录是链接，拒绝全新安装或重装；请使用更新/修复"
        [[ -e "$site_dir" ]] || continue
        [[ -d "$site_dir" ]] || log_error "网站目录类型异常，拒绝全新安装或重装"
        entries=$(find "$site_dir" -mindepth 1 -maxdepth 1 -print -quit) || log_error "无法检查保留的网站目录"
        [[ -z "$entries" ]] || log_error "检测到保留的网站文件或运行配置，拒绝全新安装或重装；请使用更新/修复，或先迁移网站"
    done
    local registry=/usr/local/lsws/conf/ols-wpanel/sites.conf
    if [[ -e "$registry" ]] || [[ -L "$registry" ]]; then
        [[ -f "$registry" ]] && [[ ! -L "$registry" ]] || log_error "网站注册配置类型异常，拒绝重装"
        if ! awk '$1 == "virtualHost" && $2 != "olsw_default" {found=1} END {exit found ? 1 : 0}' "$registry"; then
            log_error "检测到保留的网站注册配置，拒绝全新安装或重装；请使用更新/修复"
        fi
    fi
    if [[ -e "$CONFIG_FILE" ]] || [[ -e "$DB_PATH" ]] || [[ -L "$CONFIG_FILE" ]] || [[ -L "$DB_PATH" ]]; then
        command -v python3 >/dev/null 2>&1 || log_error "缺少 python3，无法确认网站登记，拒绝重装"
        python3 - "$CONFIG_FILE" "$DB_PATH" <<'PYREINSTALLCHECK' || log_error "无法确认网站登记为空，拒绝重装；请使用更新/修复，或先迁移网站"
import json,pathlib,sqlite3,sys
config_path=pathlib.Path(sys.argv[1]);db_path=pathlib.Path(sys.argv[2])
if config_path.is_symlink() or db_path.is_symlink():raise SystemExit('拒绝链接形式的面板状态')
if config_path.exists():
 with config_path.open() as source:cfg=json.load(source)
 db_path=pathlib.Path(cfg.get('sqlite',{}).get('path',str(db_path)))
 web_root=pathlib.Path(cfg.get('paths',{}).get('www_root','/www/wwwroot'))
 if not web_root.is_absolute() or web_root.is_symlink():raise SystemExit('网站根目录异常')
 if web_root.exists() and any(web_root.iterdir()):raise SystemExit('检测到保留的网站文件')
if not db_path.is_absolute() or db_path.is_symlink():raise SystemExit('数据库路径异常')
if db_path.exists():
 with sqlite3.connect(db_path.as_uri()+'?mode=ro',uri=True) as conn:
  if conn.execute('SELECT COUNT(*) FROM websites').fetchone()[0]:raise SystemExit('检测到已登记网站')
PYREINSTALLCHECK
    fi
}

installed_maintenance_menu() {
    local choice="" current="" label="" allow_repair=false
    INSTALL_MENU_ACTION=exit
    current=$(maintenance_current_version) || current=""
    label="更新 / 修复面板"
    if [[ -n "$current" && "$current" == "$INSTALLER_RELEASE_VERSION" ]]; then
        label="修复当前版本"
    elif [[ -n "$current" ]] && panel_version_at_least "$INSTALLER_RELEASE_VERSION" "$current"; then
        label="更新面板"
    fi
    [[ -f "$CONFIG_FILE" ]] && allow_repair=true
    while true; do
        echo ""
        echo "OLS WPanel · 安装维护"
        echo "────────────────────────────────────────"
        echo "当前版本：${current:-无法读取（可能存在安装残留）}"
        echo "目标版本：$INSTALLER_RELEASE_VERSION（本次已验证安装包）"
        if systemctl is-active --quiet ols-wpanel; then echo "面板状态：运行中"; else echo "面板状态：未运行"; fi
        if $allow_repair; then
            echo "1. $label"
            echo "   保留网站、数据库、面板配置、登录信息和证书"
        else
            echo "缺少 config.json，无法安全repair；请查看卸载与重装选项。"
        fi
        echo "2. 打开管理菜单"
        echo "3. 查看面板信息与登录地址"
        echo "4. 卸载与重装"
        echo "0. 退出"
        maintenance_read_choice
        case "$choice" in
            0) return ;;
            "") continue ;;
            1)
                if ! $allow_repair; then echo "缺少配置，无法执行修复。"; continue; fi
                if [[ -n "$current" && "$current" != "$INSTALLER_RELEASE_VERSION" ]] &&
                    ! panel_version_at_least "$INSTALLER_RELEASE_VERSION" "$current"; then
                    echo "目标版本低于当前版本或版本无法比较；请使用最新安装入口，未执行降级。"
                    continue
                fi
                INSTALL_MENU_ACTION=repair; return ;;
            2)
                if maintenance_command_available; then INSTALL_MENU_ACTION=menu; return; fi
                echo "管理命令不可用，请先修复面板。" ;;
            3)
                if maintenance_command_available; then /usr/local/bin/o info
                elif validate_existing_panel_binary; then "$BIN_PATH" --info --config "$CONFIG_FILE"
                else echo "面板信息无法读取，请先修复安装。"; fi
                ;;
            4)
                while true; do
                    echo ""
                    echo "OLS WPanel · 卸载与重装"
                    echo "1. 重新安装面板"
                    echo "   仅限无网站环境；删除面板配置、登录信息、证书和本地备份"
                    echo "2. 普通卸载"
                    echo "   删除面板及其本地数据；保留网站、网站数据库和共享软件"
                    echo "3. 完全卸载"
                    echo "   删除网站、网站数据库、面板及相关运行环境；备份另行选择"
                    echo "0. 返回"
                    maintenance_read_choice
                    case "$choice" in
                        0) break ;;
                        "") continue ;;
                        1) INSTALL_MENU_ACTION=reinstall; return ;;
                        2) INSTALL_MENU_ACTION=uninstall; return ;;
                        3) INSTALL_MENU_ACTION=purge; return ;;
                        *) echo "无效选项" ;;
                    esac
                done
                ;;
            *) echo "无效选项" ;;
        esac
    done
}

# ============================================================
# 重复安装/残留安装检测
# ============================================================
INSTALL_COMPLETE=false
INSTALL_TRACES=false

if [[ -f "$CONFIG_FILE" ]] && [[ -s "$BIN_PATH" ]] && [[ -x "$BIN_PATH" ]]; then
    INSTALL_COMPLETE=true
fi

if [[ -e "$CONFIG_FILE" ]] || [[ -L "$CONFIG_FILE" ]] || \
   [[ -e "$BIN_PATH" ]] || [[ -L "$BIN_PATH" ]] || \
   [[ -d "$INSTALL_DIR" ]] || \
   [[ -e "$SERVICE_PATH" ]] || [[ -L "$SERVICE_PATH" ]] || \
   [[ -e "$CRON_PATH" ]] || [[ -L "$CRON_PATH" ]] || \
   [[ -e /etc/systemd/system/ols-wpanel.service.d ]] || [[ -L /etc/systemd/system/ols-wpanel.service.d ]] || \
   [[ -e /run/systemd/system/ols-wpanel.service.d ]] || [[ -L /run/systemd/system/ols-wpanel.service.d ]] || \
   [[ -e /etc/systemd/system.control/ols-wpanel.service.d ]] || [[ -L /etc/systemd/system.control/ols-wpanel.service.d ]] || \
   [[ -e /run/systemd/system.control/ols-wpanel.service.d ]] || [[ -L /run/systemd/system.control/ols-wpanel.service.d ]] || \
   [[ -e /run/systemd/transient/ols-wpanel.service ]] || [[ -L /run/systemd/transient/ols-wpanel.service ]]; then
    INSTALL_TRACES=true
fi

if [[ "$REQUESTED_ACTION" == "repair" ]]; then
    $INSTALL_COMPLETE || log_error "未检测到完整的 OLS WPanel 安装，不能执行更新/修复；请运行普通安装命令处理残留或全新安装"
    REPAIR_MODE=true
    log_info "已进入非交互更新/修复模式：保留现有面板身份、配置和 TLS 证书"
elif [[ "$REQUESTED_ACTION" == "uninstall" ]]; then
    if ! $INSTALL_TRACES; then
        log_info "未检测到 OLS WPanel 安装或残留，无需卸载"
        exit 0
    fi
    if ! confirm_ordinary_uninstall; then
        log_info "已取消普通卸载"
        exit 0
    fi
    do_uninstall
    exit 0
elif [[ "$REQUESTED_ACTION" == "purge" ]]; then
    do_purge
    exit 0
elif $INSTALL_TRACES || $INSTALL_COMPLETE; then
    installed_maintenance_menu
    case "$INSTALL_MENU_ACTION" in
        repair) REPAIR_MODE=true ;;
        reinstall)
            assert_no_retained_sites
            confirm_ordinary_uninstall || { log_info "已取消重新安装"; exit 0; }
            do_uninstall
            log_info "开始重新安装..."
            ;;
        uninstall)
            confirm_ordinary_uninstall || { log_info "已取消普通卸载"; exit 0; }
            do_uninstall
            exit 0
            ;;
        purge) do_purge; exit 0 ;;
        menu)
            # Release the installer lock before handing over to commands that may update.
            flock -u 9
            /usr/local/bin/o menu < /dev/tty
            exit $?
            ;;
        *) log_info "已退出，未执行安装或卸载"; exit 0 ;;
    esac
fi

assert_panel_command_paths_available

if $REPAIR_MODE; then
    prepare_panel_candidate
    verify_complete_release_bundle || \
        log_error "repair执行前面板与许可发布包完整性复核失败"
    repair_check=$($PANEL_CANDIDATE --repair-config-check --config "$CONFIG_FILE") || \
        log_error "现有config.json未通过repair安全校验，未修改服务器状态"
    validate_existing_panel_binary || \
        log_error "现有面板二进制不是root持有的单链接常规0755文件；未修改服务器状态"
    assert_repair_version_compatible
    validate_repair_service_unit || \
        log_error "现有systemd unit不是OLS WPanel生成的精确安全版本，或存在drop-in；未修改服务器状态"
    validate_existing_panel_cron_file || \
        log_error "现有cron文件不是root安全持有的OLS WPanel受管文件；未修改服务器状态"
    command -v curl >/dev/null 2>&1 || \
        log_error "repair缺少curl，无法执行本机HTTPS健康检查；未修改服务器状态"
    command -v ss >/dev/null 2>&1 || \
        log_error "repair缺少ss(iproute2)，无法验证面板监听进程；未修改服务器状态"
    case "$repair_check" in
        *'"tls_action":"preserve"'*) REPAIR_TLS_ACTION="preserve" ;;
        *'"tls_action":"generate"'*) REPAIR_TLS_ACTION="generate" ;;
        *) log_error "repair配置检查返回未知TLS状态" ;;
    esac
    case "$repair_check" in
        *'"tls_certificate_expired"'*) log_warn "现有面板TLS证书已过期；repair将保留证书身份，请另行更新" ;;
        *'"tls_certificate_expires_soon"'*) log_warn "现有面板TLS证书将在30天内到期；repair将保留证书身份" ;;
    esac
    if ! command -v sqlite3 >/dev/null 2>&1; then
        log_warn "repair需要sqlite3创建面板数据库在线备份，正在自动安装"
        command -v apt-get >/dev/null 2>&1 || log_error "repair缺少apt-get，无法自动安装sqlite3"
        DEBIAN_FRONTEND=noninteractive apt-get install -y sqlite3 || \
            log_error "repair自动安装sqlite3失败，请检查APT后重试"
        command -v sqlite3 >/dev/null 2>&1 || log_error "repair安装sqlite3后仍无法找到该命令"
    fi
    prepare_repair_snapshot
    log_info "repair预检与备份完成"
else
    assert_no_retained_sites
    if [[ -e "$SERVICE_PATH" ]] || [[ -L "$SERVICE_PATH" ]]; then
        log_error "fresh安装前仍存在systemd unit或链接，拒绝继续"
    fi
	validate_fresh_panel_cron_location || \
		log_error "fresh安装前cron父目录或现有cron文件身份不安全，拒绝继续"
    if [[ -e "$CRON_PATH" ]] || [[ -L "$CRON_PATH" ]]; then
        log_error "fresh安装前仍存在cron文件或链接，拒绝继续"
    fi
    validate_no_panel_service_dropins || \
        log_error "检测到会影响ols-wpanel.service的遗留、层级或全局systemd drop-in；未修改服务器状态"
fi

# ============================================================
# 系统检测与Swap配置
# ============================================================
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_MEM_MB=$((TOTAL_MEM_KB / 1024))
log_info "物理内存: ${TOTAL_MEM_MB}MB"

if ! $REPAIR_MODE; then
    SWAP_FILE="/swapfile"
    if [[ $TOTAL_MEM_MB -le 1024 ]]; then
        SWAP_SIZE_MB=2048
    else
        SWAP_SIZE_MB=1024
    fi
    SWAP_SIZE_BYTES=$((SWAP_SIZE_MB * 1024 * 1024))
    ROOT_STATS=$(df -P -B1 / | awk 'NR == 2 {print $2, $3, $4}')
    read -r ROOT_TOTAL ROOT_USED ROOT_AVAILABLE <<< "$ROOT_STATS"

    if awk 'NR > 1 && NF {found=1} END {exit !found}' /proc/swaps; then
        log_info "系统已有启用的 Swap，跳过自动创建"
    elif [[ -e "$SWAP_FILE" ]]; then
        log_warn "${SWAP_FILE} 已存在但未启用，跳过自动创建"
    elif [[ -z "$ROOT_TOTAL" || -z "$ROOT_USED" || -z "$ROOT_AVAILABLE" ]]; then
        log_warn "无法读取根分区空间，跳过自动创建 Swap"
    elif [[ $ROOT_TOTAL -le 0 ]]; then
        log_warn "根分区总容量异常，跳过自动创建 Swap"
    elif [[ $ROOT_AVAILABLE -lt $((8 * 1024 * 1024 * 1024)) ]]; then
        log_warn "根分区可用空间不足 8GB，跳过自动创建 Swap"
    elif [[ $(((ROOT_USED + SWAP_SIZE_BYTES) * 100 / ROOT_TOTAL)) -gt 85 ]]; then
        log_warn "创建 Swap 后根分区使用率将超过 85%，跳过自动创建"
    else
        log_info "按物理内存创建 ${SWAP_SIZE_MB}MB Swap 安全缓冲..."
        if dd if=/dev/zero of="$SWAP_FILE" bs=1M count="$SWAP_SIZE_MB" status=progress &&
           chmod 600 "$SWAP_FILE" &&
           mkswap "$SWAP_FILE" &&
           swapon "$SWAP_FILE"; then
            if {
                echo ""
                echo "# OLS WPanel managed swap"
                echo "$SWAP_FILE none swap sw 0 0"
            } >> /etc/fstab; then
                if ! cat > /etc/sysctl.d/99-ols-wpanel-swap.conf << 'SWAPSYSCTLEOF'
# OLS WPanel managed swap
vm.swappiness = 60
SWAPSYSCTLEOF
                then
                    log_warn "Swap 已启用，但写入 vm.swappiness 配置失败"
                else
                    sysctl -p /etc/sysctl.d/99-ols-wpanel-swap.conf >/dev/null 2>&1 || \
                        log_warn "Swap 已启用，但应用 vm.swappiness=60 失败"
                fi
                log_info "${SWAP_SIZE_MB}MB Swap 创建完成"
            else
                swapoff "$SWAP_FILE" 2>/dev/null || true
                rm -f "$SWAP_FILE"
                log_warn "写入 /etc/fstab 失败，已回滚 Swap 并继续安装"
            fi
        else
            swapoff "$SWAP_FILE" 2>/dev/null || true
            rm -f "$SWAP_FILE"
            log_warn "Swap 创建失败，已清理临时文件并继续安装"
        fi
    fi
fi

# ============================================================
# APT 源配置
# ============================================================
log_info "配置 APT 源..."
export DEBIAN_FRONTEND=noninteractive
log_info "检测到平台: ${PLATFORM_ID} ${PLATFORM_VERSION} (${PLATFORM_CODENAME}) ${PLATFORM_ARCH}"

# 国内模式会优先选择对应发行版镜像，并同时覆盖 updates / security。
if ! $REPAIR_MODE; then
select_platform_source

# 安装基础依赖
apt-get install -y curl wget unzip ca-certificates gnupg lsb-release

# OpenLiteSpeed 与 LSPHP 均只从 LiteSpeed 官方仓库安装；仓库公钥通过
# HTTPS 下载并使用本发布内固定的 SHA-256 校验。
configure_litespeed_repository
configure_mariadb_repository
configure_redis_repository

# ============================================================
# 安装基础组件
# ============================================================
log_info "安装系统组件..."

apt-get install -y \
    iproute2 \
    openlitespeed \
    mariadb-server \
    redis-server \
    redis-tools \
    fail2ban \
    nftables \
    sshpass \
    rsyslog \
    cron \
    lsphp85 \
    lsphp85-common \
    lsphp85-mysql \
    lsphp85-curl \
    jpegoptim \
    optipng \
    lsphp85-intl \
    lsphp85-redis \
    lsphp85-imagick

validate_lsphp_wordpress_modules

# Minimal Debian images may omit all time-sync providers. Preserve an existing
# provider rather than installing a competing daemon or replacing its policy.
TIME_SYNC_UNIT=""
for candidate in chrony.service systemd-timesyncd.service ntpsec.service ntp.service; do
    if systemctl list-unit-files "$candidate" --no-legend 2>/dev/null | grep -q "^${candidate} "; then
        TIME_SYNC_UNIT="$candidate"
        break
    fi
done
if [[ -z "$TIME_SYNC_UNIT" ]]; then
    apt-get install -y --no-install-recommends systemd-timesyncd
    systemctl enable --now systemd-timesyncd.service || log_error "时间同步服务启动失败"
fi

log_info "基础组件安装完成"
else
    log_info "repair模式保留APT源和现有软件包，不执行安装或升级"
fi

if ! $REPAIR_MODE; then
	validate_existing_panel_cron_file || \
		log_error "cron安装后 /etc/cron.d 身份不安全，拒绝继续"
fi

# ============================================================
# systemd 进程守护配置
# ============================================================
log_info "配置 systemd 进程守护..."

if ! $REPAIR_MODE; then
ensure_ols_systemd_unit
for svc in mariadb redis-server; do
    DROPDIR="/etc/systemd/system/${svc}.service.d"
    mkdir -p "$DROPDIR"
    cat > "$DROPDIR/ols-wpanel.conf" << SYSTEMDEOF
[Unit]
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Restart=on-failure
RestartSec=5s
SYSTEMDEOF
done

# The upstream unit tracks /var/run/openlitespeed.pid while lswsctrl writes
# /tmp/lshttpd/lshttpd.pid by default.  On current Ubuntu/systemd this can make
# a healthy daemon look like a vanished or zombie main process until startup
# times out.  Keep the vendor unit intact and correct only the panel-owned
# drop-in.  mixed preserves the graceful ExecStop path while allowing systemd
# to clean up remaining children after the stop timeout.
DROPDIR="/etc/systemd/system/lshttpd.service.d"
mkdir -p "$DROPDIR"
cat > "$DROPDIR/ols-wpanel.conf" << 'OLSSYSTEMDEOF'
[Unit]
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
PIDFile=/tmp/lshttpd/lshttpd.pid
KillMode=mixed
Restart=on-failure
RestartSec=5s
OLSSYSTEMDEOF

systemctl daemon-reload
log_info "systemd 进程守护配置完成"

systemctl_enable_best_effort lshttpd
systemctl_enable_best_effort mariadb
systemctl_enable_best_effort redis-server
systemctl_start_required redis-server
else
    log_info "repair模式保留OpenLiteSpeed、MariaDB和Redis的systemd配置与状态"
fi

# ============================================================
# OpenLiteSpeed 基础配置
# ============================================================
log_info "配置 OpenLiteSpeed 基础..."

if ! $REPAIR_MODE; then
OLS_CONF_DIR="/usr/local/lsws/conf/ols-wpanel"
OLS_MAIN_CONF="/usr/local/lsws/conf/httpd_config.conf"
OLS_MANAGED_CONF="$OLS_CONF_DIR/sites.conf"
OLS_DEFAULT_ROOT="/usr/local/lsws/html/ols-wpanel-default"
OLS_DEFAULT_CONF="$OLS_CONF_DIR/default-vhost.conf"
install -d -o root -g root -m 0750 "$OLS_CONF_DIR"
install -d -o root -g root -m 0750 "$OLS_CONF_DIR/sites-available" "$OLS_CONF_DIR/sites-enabled" "$OLS_CONF_DIR/lsphp-sites"
# HTTP-01 files must be reachable by OLS workers; keep private configuration
# permissions unchanged and use only the public static subtree.
if [[ -L /usr/local/lsws/html || ( -e /usr/local/lsws/html && ! -d /usr/local/lsws/html ) || -L "$OLS_DEFAULT_ROOT" || ( -e "$OLS_DEFAULT_ROOT" && ! -d "$OLS_DEFAULT_ROOT" ) ]]; then
    log_error "OpenLiteSpeed 公共验证目录不是安全目录"
fi
if [[ ! -d /usr/local/lsws/html ]]; then
    install -d -o root -g root -m 0755 /usr/local/lsws/html
fi
if ! OLS_DEFAULT_UID="$(id -u www-data 2>/dev/null)" || ! OLS_DEFAULT_GID="$(id -g www-data 2>/dev/null)"; then
    log_error "OpenLiteSpeed 备用虚拟主机需要低权限 www-data 用户"
fi
if (( OLS_DEFAULT_UID < 11 || OLS_DEFAULT_GID < 10 )); then
    log_error "www-data 的 UID/GID 不符合 OpenLiteSpeed 最低安全要求"
fi
install -d -o www-data -g www-data -m 0755 "$OLS_DEFAULT_ROOT"
install -d -o root -g root -m 0755 "$OLS_DEFAULT_ROOT/.well-known" "$OLS_DEFAULT_ROOT/.well-known/acme-challenge"

openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "$OLS_CONF_DIR/default.key" \
    -out "$OLS_CONF_DIR/default.crt" \
    -subj "/C=CN/O=OLS WPanel/OU=OpenLiteSpeed/CN=OLS-WPanel-Default" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
chmod 0600 "$OLS_CONF_DIR/default.key"
chmod 0644 "$OLS_CONF_DIR/default.crt"

cat > "$OLS_DEFAULT_CONF" << 'OLSDEFAULTVHOSTEOF'
docRoot                 /usr/local/lsws/html/ols-wpanel-default/
vhDomain                ols-wpanel.invalid
adminEmails             root@localhost
enableGzip              0
enableBr                0

index {
  useServer              0
  indexFiles             index.html
}

context / {
  location               /usr/local/lsws/html/ols-wpanel-default/
  allowBrowse            0
  addDefaultCharset      off
}
context /.well-known/acme-challenge/ {
  location               /usr/local/lsws/html/ols-wpanel-default/.well-known/acme-challenge/
  allowBrowse            1
  autoIndex              0
  addDefaultCharset      off
}
OLSDEFAULTVHOSTEOF
chmod 0640 "$OLS_DEFAULT_CONF"

cat > "$OLS_MANAGED_CONF" << 'OLSMANAGEDEOF'
# OLS WPanel managed OpenLiteSpeed registry. DO NOT EDIT.
virtualHost olsw_default {
  vhRoot                 /usr/local/lsws/html/ols-wpanel-default/
  allowSymbolLink        0
  enableScript           0
  restrained             1
  setUIDMode             0
  configFile             /usr/local/lsws/conf/ols-wpanel/default-vhost.conf
}
listener OLSWPanelHTTP {
  address                 *:80
  secure                  0
  map                     olsw_default *
}
listener OLSWPanelHTTPS {
  address                 *:443
  secure                  1
  keyFile                 /usr/local/lsws/conf/ols-wpanel/default.key
  certFile                /usr/local/lsws/conf/ols-wpanel/default.crt
  certChain               0
  sslProtocol             24
  map                     olsw_default *
}
OLSMANAGEDEOF
OLS_IPV6_ENABLED=false
if ols_ipv6_available; then
    OLS_IPV4_REGISTRY="$INSTALL_WORKDIR/ols-ipv4-sites.conf"
    cp -- "$OLS_MANAGED_CONF" "$OLS_IPV4_REGISTRY" || log_error "无法保留 OpenLiteSpeed IPv4 备用配置"
    append_ols_ipv6_listeners "$OLS_MANAGED_CONF" 80 443 olsw_default '*' "$OLS_CONF_DIR"
    OLS_IPV6_ENABLED=true
    log_info "检测到可用 VPS IPv6，OpenLiteSpeed 将同时监听 IPv4 和 IPv6 的 80/443 端口"
else
    log_info "未检测到可用 VPS IPv6，保留 OpenLiteSpeed IPv4 监听"
fi
chmod 0640 "$OLS_MANAGED_CONF"

if [[ -f "$OLS_MAIN_CONF" ]]; then
    cp -- "$OLS_MAIN_CONF" "$OLS_MAIN_CONF.ols-wpanel.vendor"
fi
cat > "$OLS_MAIN_CONF" << 'OLSHTTPEOF'
# OLS WPanel managed OpenLiteSpeed server configuration.
serverName               OLS-WPanel
user                     nobody
group                    nogroup
priority                 0
autoRestart              1
chrootPath               /
enableChroot             0
inMemBufSize             60M
swappingDir              /tmp/lshttpd/swap
autoFix503               1
gracefulRestartTimeout   300
mime                     conf/mime.properties
showVersionNumber        0
useIpInProxyHeader       2
adminEmails              root@localhost
indexFiles               index.html,index.php
disableWebAdmin          1

errorlog logs/error.log {
  logLevel               WARN
  debugLevel             0
  rollingSize            20M
  enableStderrLog        1
}
accessLog logs/access.log {
  rollingSize            20M
  keepDays               14
  compressArchive        1
  logReferer             1
  logUserAgent           1
}
expires {
  enableExpires          1
  expiresByType          image/*=A604800,text/css=A604800,application/javascript=A604800,font/*=A604800
}
tuning {
  maxConnections         10000
  maxSSLConnections      10000
  connTimeout            300
  maxKeepAliveReq        10000
  smartKeepAlive         0
  keepAliveTimeout       5
  sndBufSize             0
  rcvBufSize             0
  gzipStaticCompressLevel 6
  gzipMaxFileSize        10M
  eventDispatcher        best
  maxCachedFileSize      4096
  totalInMemCacheSize    20M
  maxMMapFileSize        256K
  totalMMapCacheSize     40M
  useSendfile            1
  fileETag               28
  maxReqURLLen           32768
  maxReqHeaderSize       65536
  maxReqBodySize         2047M
  maxDynRespHeaderSize   32768
  maxDynRespSize         2047M
  enableGzipCompress     1
  enableBrCompress       4
  enableDynGzipCompress  1
  gzipCompressLevel      6
  brStaticCompressLevel  6
  compressibleTypes      default
  gzipAutoUpdateStatic   1
  gzipMinFileSize        300
  quicEnable             1
  quicShmDir             /dev/shm
}
accessDenyDir {
  dir                    /
  dir                    /etc/*
  dir                    /dev/*
  dir                    conf/*
  dir                    admin/conf/*
}
fileAccessControl {
  followSymbolLink       1
  checkSymbolLink        0
  requiredPermissionMask 000
  restrictedPermissionMask 000
}
perClientConnLimit {
  staticReqPerSec        0
  dynReqPerSec           0
  outBandwidth           0
  inBandwidth            0
  softLimit              1000
  hardLimit              2000
  gracePeriod            15
  banPeriod              300
}
CGIRLimit {
  maxCGIInstances        200
  minUID                 11
  minGID                 10
  priority               0
  CPUSoftLimit           10
  CPUHardLimit           50
  memSoftLimit           2047M
  memHardLimit           2047M
  procSoftLimit          400
  procHardLimit          500
}
accessControl {
  allow                  ALL
}
module cache {
  ls_enabled             1
  checkPrivateCache      1
  checkPublicCache       1
  maxCacheObjSize        10000000
  maxStaleAge            200
  qsCache                1
  reqCookieCache         1
  respCookieCache        0
  ignoreReqCacheCtrl     1
  ignoreRespCacheCtrl    0
  enableCache            0
  expireInSeconds        3600
  enablePrivateCache     0
  privateExpireInSeconds 3600
}
include /usr/local/lsws/conf/ols-wpanel/sites.conf
OLSHTTPEOF
chown root:root "$OLS_MAIN_CONF" "$OLS_MANAGED_CONF"
chown root:root "$OLS_DEFAULT_CONF"
chmod 0640 "$OLS_MAIN_CONF" "$OLS_MANAGED_CONF" "$OLS_DEFAULT_CONF"
mkdir -p /tmp/lshttpd/swap
chown -R nobody:nogroup /tmp/lshttpd
OLS_READY=false
if [[ "$OLS_IPV6_ENABLED" == true ]]; then
    # IPv6 is an automatic addition to the known-good IPv4 configuration. If
    # OLS cannot parse, start or retain both families, restore only the exact
    # registry saved before this installer appended the IPv6 listeners.
    systemctl reset-failed lshttpd 2>/dev/null || true
    if /usr/local/lsws/bin/openlitespeed -t && systemctl restart lshttpd && \
       require_ols_listeners return && systemctl is-active --quiet lshttpd; then
        OLS_READY=true
    else
        [[ -f "$OLS_IPV4_REGISTRY" && ! -L "$OLS_IPV4_REGISTRY" ]] || log_error "OpenLiteSpeed IPv4 备用配置不可用，拒绝继续"
        cp -- "$OLS_IPV4_REGISTRY" "$OLS_MANAGED_CONF" || log_error "OpenLiteSpeed IPv4 配置恢复失败"
        chown root:root "$OLS_MANAGED_CONF"
        chmod 0640 "$OLS_MANAGED_CONF"
        OLS_IPV6_ENABLED=false
        log_warn "OpenLiteSpeed 双栈启动未通过验证，已回退到原有 IPv4 配置"
    fi
fi
if ! $OLS_READY; then
    /usr/local/lsws/bin/openlitespeed -t || log_error "OpenLiteSpeed 基础配置检查失败"
    systemctl reset-failed lshttpd 2>/dev/null || true
    systemctl restart lshttpd || log_error "OpenLiteSpeed 重启失败"
    systemctl_wait_active_required lshttpd
    require_ols_listeners
fi
log_info "OpenLiteSpeed 基础配置完成（WebAdmin 已禁用，站点由面板管理）"
else
    log_info "repair模式不改写或重载 OpenLiteSpeed 配置"
fi

# ============================================================
# 本机防火墙安全基线
# ============================================================
log_info "配置本机防火墙安全基线..."
configure_fresh_firewall

# ============================================================
# MariaDB 安全加固
# ============================================================
log_info "配置 MariaDB..."

if ! $REPAIR_MODE; then
    systemctl_start_required mariadb
    systemctl_enable_best_effort mariadb
fi

if $REPAIR_MODE; then
    log_info "repair模式保留现有MariaDB身份与配置"
else
    if [[ -z "$MYSQL_PASS" ]]; then
        MYSQL_PASS=$(head -c 24 /dev/urandom | sha256sum | head -c 32)
    fi

    [[ "$MYSQL_PASS" =~ ^[0-9a-f]{32}$ ]] || log_error "MariaDB root密码格式异常"
    MYSQL_CLIENT_CONFIG="$INSTALL_WORKDIR/mariadb-client.cnf"
    cat > "$MYSQL_CLIENT_CONFIG" << MYSQLCLIENTEOF
[client]
user=root
password=${MYSQL_PASS}
protocol=socket
socket=/run/mysqld/mysqld.sock
MYSQLCLIENTEOF
    chmod 0600 "$MYSQL_CLIENT_CONFIG"

    if mysql --defaults-extra-file="$MYSQL_CLIENT_CONFIG" -e "SELECT 1" 2>/dev/null; then
        log_info "MariaDB root 密码已验证"
    elif mysql --protocol=socket -u root -e "SELECT 1" 2>/dev/null; then
        printf "%s\n" "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_PASS}'; FLUSH PRIVILEGES;" | \
            mysql --protocol=socket -u root 2>/dev/null || \
            log_error "MariaDB root 密码设置失败"
        mysql --defaults-extra-file="$MYSQL_CLIENT_CONFIG" -e "SELECT 1" 2>/dev/null || \
            log_error "MariaDB root 新密码验证失败"
        log_info "MariaDB root 密码已设置"
    else
        log_warn "MariaDB 密码状态异常，面板首次启动时将自动修复"
    fi

    mysql --defaults-extra-file="$MYSQL_CLIENT_CONFIG" << 'MARIADBSECURITYEOF' 2>/dev/null || log_warn "部分安全加固跳过(密码可能已设置)"
        DELETE FROM mysql.user WHERE User='';
        DELETE FROM mysql.user WHERE User='root' AND Host!='localhost';
        DROP DATABASE IF EXISTS test;
        DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
        FLUSH PRIVILEGES;
MARIADBSECURITYEOF

    if [[ $TOTAL_MEM_MB -le 1024 ]]; then
        log_info "低内存环境，优化 MariaDB 配置..."
        cat > /etc/mysql/mariadb.conf.d/99-ols-wpanel.cnf << 'MARIADBEOF'
[mysqld]
innodb_buffer_pool_size = 128M
innodb_log_buffer_size = 8M
table_open_cache = 128
max_connections = 30
performance_schema = OFF
MARIADBEOF
        systemctl restart mariadb || systemctl_start_required mariadb
    fi
fi

# ============================================================
# 目录结构创建
# ============================================================
log_info "创建目录结构..."

mkdir -p "$INSTALL_DIR"/{backups,packages,logs,certs}
mkdir -p /www/wwwroot
mkdir -p /www/wwwlogs
mkdir -p /www/server/certificates
chmod 700 "$INSTALL_DIR"

# ============================================================
# 生成自签名 SSL 证书（有效期 10 年）
# ============================================================
log_info "检查面板 TLS 证书..."

CERT_DIR="$INSTALL_DIR/certs"
CERT_FILE="$CERT_DIR/panel.crt"
KEY_FILE="$CERT_DIR/panel.key"

if $REPAIR_MODE && [[ "$REPAIR_TLS_ACTION" == "preserve" ]]; then
    log_info "repair模式保留现有TLS证书与私钥"
else
    TLS_TMP_DIR="$INSTALL_WORKDIR/tls"
    install -d -m 0700 "$TLS_TMP_DIR"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$TLS_TMP_DIR/panel.key" \
        -out "$TLS_TMP_DIR/panel.crt" \
        -subj "/C=CN/O=OLS WPanel/OU=Panel/CN=OLS-WPanel-SelfSigned" \
        -addext "subjectAltName=IP:127.0.0.1" \
        2>/dev/null
    openssl x509 -in "$TLS_TMP_DIR/panel.crt" -noout >/dev/null
    openssl pkey -in "$TLS_TMP_DIR/panel.key" -noout >/dev/null
    chmod 600 "$TLS_TMP_DIR/panel.key"
    chmod 644 "$TLS_TMP_DIR/panel.crt"
    if $REPAIR_MODE; then REPAIR_MUTATED=true; fi
    mv "$TLS_TMP_DIR/panel.key" "$KEY_FILE"
    mv "$TLS_TMP_DIR/panel.crt" "$CERT_FILE"
    rmdir "$TLS_TMP_DIR"
    log_info "自签名证书已生成（有效期 10 年）"
fi

# ============================================================
# 下载 WordPress 备用包
# ============================================================
log_info "检查 WordPress 备用包..."
WP_ZIP="$INSTALL_DIR/packages/wordpress.zip"
WP_ZIP_TMP="$INSTALL_WORKDIR/wordpress.zip"
if $REPAIR_MODE && file_size_within_limit "$WP_ZIP" "$WORDPRESS_ZIP_MAX_BYTES"; then
    log_info "repair模式保留现有WordPress备用包"
else
    rm -f -- "${WP_ZIP}.origin.json" 2>/dev/null || true
    if [[ -e "$WP_ZIP" ]] || [[ -L "$WP_ZIP" ]]; then
        log_warn "现有WordPress备用包不是安全常规文件或超过大小上限，正在替换"
        rm -f -- "$WP_ZIP"
    fi
    for i in 1 2 3; do
        if download_official_wordpress_archive "$WP_ZIP_TMP" && validate_installer_wordpress_archive "$WP_ZIP_TMP"; then
            mv -fT -- "$WP_ZIP_TMP" "$WP_ZIP"
            if ! write_wordpress_origin_receipt "$WP_ZIP"; then
                rm -f -- "${WP_ZIP}.origin.json" 2>/dev/null || true
                log_warn "WordPress 来源记录未保存，新网站将保留默认内容"
            fi
            log_info "WordPress 下载完成"
            break
        fi
        log_warn "下载失败，重试 ($i/3)..."
        sleep 3
    done
    rm -f "$WP_ZIP_TMP"
    if [[ ! -s "$WP_ZIP" ]]; then
        rm -f "$WP_ZIP"
        log_warn "WordPress 下载失败，将在首次建站时使用联网下载"
    fi
fi

# ============================================================
# 生成面板安全凭证
# ============================================================
log_info "检查安全凭证..."

if ! $REPAIR_MODE; then
PANEL_SUFFIX=$(head -c 20 /dev/urandom | sha256sum | head -c 8)

BASIC_USER="admin"
BASIC_PASS=$(head -c 12 /dev/urandom | base64 | head -c 16)
WEB_USER="wpadmin"
WEB_PASS=$(head -c 12 /dev/urandom | base64 | head -c 16)

BASIC_HASH=""
WEB_HASH=""
generate_bcrypt_hash() {
    local password="$1"
    local hash=""

    if [[ -x /usr/local/lsws/lsphp85/bin/php ]]; then
        hash=$(printf '%s' "$password" | /usr/local/lsws/lsphp85/bin/php -r \
            '$password = stream_get_contents(STDIN); echo password_hash($password, PASSWORD_BCRYPT, ["cost" => 12]);' \
            2>/dev/null || true)
    fi
    if [[ -z "$hash" ]] && command -v python3 &>/dev/null; then
        hash=$(printf '%s' "$password" | python3 -c \
            'import bcrypt, sys; print(bcrypt.hashpw(sys.stdin.buffer.read(), bcrypt.gensalt(12)).decode())' \
            2>/dev/null || true)
    fi
    printf '%s' "$hash"
}
BASIC_HASH=$(generate_bcrypt_hash "$BASIC_PASS")
WEB_HASH=$(generate_bcrypt_hash "$WEB_PASS")
if [[ -z "$BASIC_HASH" || -z "$WEB_HASH" ]]; then
    log_warn "无法生成 bcrypt 哈希，面板首次启动时将自动重置密码"
    # Literal invalid bcrypt fallbacks: dollar signs must not expand.
    # shellcheck disable=SC2016
    BASIC_HASH='$2a$12$00000000000000000000000000000000000000000000000000000'
    # shellcheck disable=SC2016
    WEB_HASH='$2a$12$00000000000000000000000000000000000000000000000000000'
fi
else
    log_info "repair模式保留现有登录凭据和安全入口"
fi

# ============================================================
# 写入 config.json
# ============================================================
log_info "检查配置文件..."

if ! $REPAIR_MODE; then
cat > "$CONFIG_FILE" << CONFIGEOF
{
  "panel": {
    "version": "1.0.0",
    "port": $PANEL_PORT,
    "tls_port": 8443,
    "tls_cert_path": "$CERT_FILE",
    "tls_key_path": "$KEY_FILE",
    "random_suffix": "$PANEL_SUFFIX",
    "data_dir": "$INSTALL_DIR",
    "backup_dir": "$INSTALL_DIR/backups",
    "log_dir": "$INSTALL_DIR/logs"
  },
  "sqlite": {
    "path": "$DB_PATH"
  },
  "mariadb": {
    "host": "localhost",
    "port": 3306,
    "socket": "/run/mysqld/mysqld.sock",
    "root_user": "root",
    "root_password": "$MYSQL_PASS"
  },
  "admin": {
    "username": "$WEB_USER",
    "password_hash": "$WEB_HASH"
  },
  "basic_auth": {
    "username": "$BASIC_USER",
    "password_hash": "$BASIC_HASH"
  },
  "paths": {
    "www_root": "/www/wwwroot",
    "www_logs": "/www/wwwlogs",
    "ols_root": "/usr/local/lsws",
    "ols_main_config": "/usr/local/lsws/conf/httpd_config.conf",
    "ols_managed_config": "/usr/local/lsws/conf/ols-wpanel/sites.conf",
    "ols_binary": "/usr/local/lsws/bin/openlitespeed",
    "lsphp_binary": "/usr/local/lsws/lsphp85/bin/lsphp",
    "lsphp_cli": "/usr/local/lsws/lsphp85/bin/php",
    "ols_listener_cert": "/usr/local/lsws/conf/ols-wpanel/default.crt",
    "ols_listener_key": "/usr/local/lsws/conf/ols-wpanel/default.key",
    "ols_vhosts_available": "/usr/local/lsws/conf/ols-wpanel/sites-available",
    "ols_vhosts_enabled": "/usr/local/lsws/conf/ols-wpanel/sites-enabled",
    "lsphp_socket_dir": "/tmp/lshttpd",
    "certificates": "/www/server/certificates",
    "wordpress_package": "$INSTALL_DIR/packages/wordpress.zip",
    "cron_file": "/etc/cron.d/ols_wpanel_cron"
  },
  "security": {
    "basic_auth_enabled": true,
    "max_login_attempts": 5,
    "attempt_window_minutes": 5,
    "ban_duration_hours": 24,
    "auto_whitelist_enabled": true,
    "core_ports": [22, $PANEL_PORT, 80, 443, 8443]
  },
  "systemd": {
    "service_name": "ols-wpanel",
    "service_path": "$SERVICE_PATH",
    "binary_path": "$BIN_PATH"
  }
}
CONFIGEOF

chmod 600 "$CONFIG_FILE"
else
    log_info "repair模式保持config.json字节不变"
fi

# ============================================================
# 部署 Go 二进制
# ============================================================
log_info "部署面板二进制..."

prepare_panel_candidate
verify_complete_release_bundle || \
    log_error "部署前面板与许可发布包完整性复核失败"
if $REPAIR_MODE; then REPAIR_MUTATED=true; fi
atomic_install_managed_file "$PANEL_CANDIDATE" "$BIN_PATH" 0755 || \
	log_error "面板二进制同目录原子部署失败"
log_info "面板二进制已原子部署"
install_release_license_documentation || \
    log_error "无法安全安装已验签的 OLS WPanel 许可文档"
log_info "许可文档已安装到 $LICENSE_DOC_DIR"

# ============================================================
# 创建 systemd 服务
# ============================================================
log_info "检查 systemd 服务..."

if ! $REPAIR_MODE || [[ ! -f "$SERVICE_PATH" ]]; then
if $REPAIR_MODE; then REPAIR_MUTATED=true; fi
[[ ! -e "$SERVICE_PATH" ]] && [[ ! -L "$SERVICE_PATH" ]] || \
    log_error "写入systemd unit前目标已存在或为链接"
write_panel_service_unit "$SERVICE_PATH" 0644 || log_error "写入ols-wpanel systemd unit失败"
if ! $REPAIR_MODE; then FRESH_SERVICE_CLEANUP_REQUIRED=true; fi
else
    log_info "repair模式保留现有systemd unit"
fi

systemctl daemon-reload
validate_effective_panel_service_unit || \
    log_error "systemd实际加载的unit、drop-in或ExecStart与OLS WPanel不一致"
if $REPAIR_MODE; then
    if $REPAIR_SERVICE_WAS_ACTIVE; then
        systemctl start ols-wpanel || log_error "repair后ols-wpanel启动失败"
        REPAIR_SERVICE_STOPPED_FOR_SNAPSHOT=false
    else
        log_info "repair前ols-wpanel未运行；部署后将临时启动完成健康验证，再恢复inactive状态"
    fi
else
    systemctl_start_required ols-wpanel
    validate_running_panel_service_identity || \
        log_error "ols-wpanel MainPID未运行已部署的OLS WPanel二进制"
    apply_system_tuning
fi

# ============================================================
# 运行时健康、版本与监听归属检测
# ============================================================
PORT_OK=false
if $REPAIR_MODE && ! $REPAIR_SERVICE_WAS_ACTIVE; then
    log_info "临时启动ols-wpanel验证repair后运行时健康"
    systemctl start ols-wpanel || log_error "repair后面板临时启动失败"
    validate_running_panel_health "$INSTALLER_RELEASE_VERSION" || {
        journalctl -u ols-wpanel -n 20 --no-pager 2>/dev/null || true
        log_error "repair后面板未通过/healthz、精确版本或MainPID监听归属验证"
    }
    systemctl stop ols-wpanel || log_error "repair健康验证后无法恢复原inactive状态"
    if systemctl is-active --quiet ols-wpanel 2>/dev/null; then
        log_error "repair健康验证后面板仍在运行，未恢复原inactive状态"
    fi
    REPAIR_INACTIVE_HEALTH_VERIFIED=true
elif systemctl is-active --quiet ols-wpanel; then
    validate_running_panel_health "$INSTALLER_RELEASE_VERSION" || {
        journalctl -u ols-wpanel -n 20 --no-pager 2>/dev/null || true
        log_error "面板未通过/healthz、精确版本或MainPID监听归属验证"
    }
    PORT_OK=true
    if ! $REPAIR_MODE; then
        systemctl enable ols-wpanel || log_error "ols-wpanel健康验证通过，但设置开机自启失败"
    fi
else
    log_error "面板服务未运行，无法完成安装健康验证"
fi

# ============================================================
# 最终输出
# ============================================================
if systemctl is-active --quiet ols-wpanel; then
    STATUS="运行中"
elif $REPAIR_INACTIVE_HEALTH_VERIFIED; then
    STATUS="保持未运行（健康验证已通过）"
else
    STATUS="未运行"
fi

if $REPAIR_MODE; then
    if $REPAIR_SERVICE_WAS_ACTIVE; then
        systemctl is-active --quiet ols-wpanel || log_error "repair后面板服务未运行"
    elif systemctl is-active --quiet ols-wpanel; then
        log_error "repair改变了面板服务原始inactive状态"
    elif ! $REPAIR_INACTIVE_HEALTH_VERIFIED; then
        log_error "repair未完成inactive服务的临时启动健康验证"
    fi
    "$BIN_PATH" --repair-config-check --config "$CONFIG_FILE" >/dev/null || \
        log_error "repair后配置复核失败"
    REPAIR_COMMITTED=true
fi

LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
[[ -z "$LOCAL_IP" ]] && LOCAL_IP="<未知>"

PUBLIC_IP_FILE="$INSTALL_WORKDIR/public-ip.txt"
if download_file "https://ip.sb" "$PUBLIC_IP_FILE" 15 "$PUBLIC_IP_MAX_BYTES" || \
   download_file "https://ifconfig.me/ip" "$PUBLIC_IP_FILE" 15 "$PUBLIC_IP_MAX_BYTES"; then
    PUBLIC_IP=$(tr -d '\r\n' < "$PUBLIC_IP_FILE")
else
    PUBLIC_IP=""
fi
if [[ ${#PUBLIC_IP} -gt 45 ]] || [[ ! "$PUBLIC_IP" =~ ^[0-9A-Fa-f:.]+$ ]]; then
    PUBLIC_IP=""
fi
[[ -z "$PUBLIC_IP" ]] && PUBLIC_IP="<未知>"

# Address labels describe discovery, not private/public reachability.
# Interface addresses may themselves be public; bracket IPv6 for valid URLs.
PUBLIC_HOST="$PUBLIC_IP"
LOCAL_HOST="$LOCAL_IP"
[[ "$PUBLIC_HOST" == *:* ]] && PUBLIC_HOST="[$PUBLIC_HOST]"
[[ "$LOCAL_HOST" == *:* ]] && LOCAL_HOST="[$LOCAL_HOST]"

# Keep values on separate lines: URLs and generated passwords stay easy to copy
# in narrow SSH terminals. Format credentials as data, never as printf escapes.
print_install_summary() {
    local heading="" warning="" reset=""
    local rule="------------------------------------------------------------"
    if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
        heading="$BOLD"
        warning="$YELLOW"
        reset="$NC"
    fi

    printf '\n%b%s%b\n' "$heading" "OLS WPanel / 安装完成" "$reset"
    printf '%s\n' "$rule"
    printf '  版本  %s\n  状态  %s\n' "$INSTALLER_RELEASE_VERSION" "$STATUS"
    printf '\n'
    if $REPAIR_MODE; then
        printf '%s\n' "更新 / 修复完成，登录地址与账号密码保持不变。" "输入 o 查看当前登录地址。"
    else
        printf '%b%s%b\n' "$heading" "登录地址" "$reset"
        if [[ "$PUBLIC_IP" != "<未知>" ]]; then
            printf '  https://%s:%s/%s/\n' "$PUBLIC_HOST" "$VALIDATED_TLS_PORT" "$PANEL_SUFFIX"
            if [[ "$LOCAL_IP" != "<未知>" && "$LOCAL_IP" != "$PUBLIC_IP" ]]; then
                printf '\n%s\n  https://%s:%s/%s/\n' "网卡地址（是否可达取决于网络配置）" "$LOCAL_HOST" "$VALIDATED_TLS_PORT" "$PANEL_SUFFIX"
            fi
        else
            printf '  https://%s:%s/%s/\n' "$LOCAL_HOST" "$VALIDATED_TLS_PORT" "$PANEL_SUFFIX"
        fi
        printf '\n%s\n' "$rule"
        printf '%b%s%b\n' "$heading" "登录凭据 / 仅显示一次，请立即保存" "$reset"
        printf '\n%b%s%b\n' "$heading" "1. 浏览器身份验证" "$reset"
        printf '  用户名\n    %s\n  密码\n    %s\n' "$BASIC_USER" "$BASIC_PASS"
        printf '\n%b%s%b\n' "$heading" "2. 面板账户登录" "$reset"
        printf '  用户名\n    %s\n  密码\n    %s\n' "$WEB_USER" "$WEB_PASS"
        printf '\n%s\n' "打开登录地址后，先完成浏览器身份验证，再登录面板。"
    fi
    if ! $PORT_OK && ! $REPAIR_INACTIVE_HEALTH_VERIFIED; then
        printf '\n%b%s%b\n' "$warning" "端口未监听；输入 o status 检查。" "$reset"
    fi
    printf '\n%s\n' "$rule"
    printf '%b%s%b\n' "$warning" "首次登录 / 核对 TLS 证书" "$reset"
    printf '%s\n' "自签名证书：通过 SSH 核对浏览器显示的 SHA-256 指纹。"
    printf '  openssl x509 -in %s -noout -fingerprint -sha256\n' "$CERT_FILE"
    printf '%b%s%b\n' "$warning" "指纹不一致时立即停止，不要输入任何凭据。" "$reset"
    printf '%s\n' "长期公网使用请替换为由受信任 CA 签发的域名证书，可在面板设置中申请。"
    printf '\n%b%s%b\n' "$heading" "输入 o 打开终端管理菜单；o help 查看帮助。" "$reset"
    printf '%s\n\n' "$rule"
}
print_install_summary
# 可选运行统计 / Optional Runtime Telemetry 默认关闭，详情见项目文档。
