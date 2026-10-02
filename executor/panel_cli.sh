#!/bin/bash
# OLS WPanel CLI — o

set -o pipefail

BIN=/usr/local/bin/ols-wpanel
CFG=/www/ols-wpanel/config.json
SVC=ols-wpanel
ENTRY_URL=https://ols.zangyubin.top/install
ENTRY_MAX_BYTES=$((4 * 1024 * 1024))

color() {
    local code="$1"; shift
    if [ -t 1 ] && [ "${TERM:-dumb}" != dumb ] && [ -z "${NO_COLOR:-}" ]; then
        printf '\033[%sm%s\033[0m\n' "$code" "$*"
    else printf '%s\n' "$*"; fi
}
red() { color 31 "$*"; }
green() { color 32 "$*"; }
blue() { color '1;34' "$*"; }
dim() { color 2 "$*"; }

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

# Read-only views share one formatter so menu pages and shortcuts show the same data.
read_view() {
    python3 - "$1" "$BIN" "$CFG" "${2:-}" <<'PYVIEW'
import datetime, ipaddress, json, os, pathlib, platform, re, shutil, subprocess, sys, time
view, binary, cfg, value = sys.argv[1:]
def run(*args, timeout=8):
    try:
        p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout,env=dict(os.environ,LC_ALL='C'))
        return p.stdout.strip() if p.returncode==0 else None
    except (OSError,subprocess.TimeoutExpired): return None
def text(path):
    try:return pathlib.Path(path).read_text(errors='replace').strip()
    except OSError:return ''
def safe(value):return ''.join(c for c in str(value) if c.isprintable() or c=='\n')
def row(label,value): print('  '+label+'：'+safe(value if value is not None and value!='' else '未检测到'))
def size(n):
    n=float(n)
    for unit in ['B','KiB','MiB','GiB','TiB']:
        if n<1024 or unit=='TiB':return f'{n:.1f} {unit}'
        n/=1024
def usage(used,total):return f'{size(used)} / {size(total)} ({used/total*100:.1f}%)' if total else '未检测到'
def interfaces(family):
    out=run('ip','-j',f'-{family}','address','show','scope','global')
    try:return [a['local'] for i in json.loads(out or '[]') for a in i.get('addr_info',[]) if 'local' in a]
    except (ValueError,TypeError):return []
def addresses(family):
    values=interfaces(family)
    return '、'.join(values) or '未检测到'
def route(family):
    out=run('ip',f'-{family}','route','show','default')
    return '未检测到' if out is None else ('存在' if out else '无')
def properties(*args):
    return dict(line.split('=',1) for line in (run(*args) or '').splitlines() if '=' in line)
def bytes_at(path):
    if not os.path.exists(path):return 0
    out=run('du','-s','-B1',path,timeout=15)
    try:return int(out.split()[0])
    except (ValueError,AttributeError,IndexError):return None
def total_cache():
    values=[bytes_at(p) for p in ['/var/cache/apt/archives','/var/log/journal','/run/log/journal']]
    return sum(values) if all(v is not None for v in values) else None
def cpu_usage():
    def ticks():
        try:
            x=[int(n) for n in text('/proc/stat').splitlines()[0].split()[1:9]]
            return sum(x),x[3]+x[4]
        except (ValueError,IndexError):return None
    a=ticks();time.sleep(.15);b=ticks()
    return f'{100*(1-(b[1]-a[1])/(b[0]-a[0])):.1f}%' if a and b and b[0]>a[0] else None

if view=='info':
    osinfo={}
    for line in text('/etc/os-release').splitlines():
        if '=' in line:
            k,v=line.split('=',1);osinfo[k]=v.strip('"')
    row('系统',osinfo.get('PRETTY_NAME'));row('主机',platform.node());row('内核 / 架构',platform.release()+' / '+platform.machine())
    cpu=re.search(r'(?m)^(?:model name|Hardware)\s*:\s*(.+)$',text('/proc/cpuinfo'))
    row('CPU', (cpu.group(1) if cpu else platform.machine())+f' · {os.cpu_count() or "?"} 核')
    row('负载 1 / 5 / 15 分钟',' / '.join(f'{x:.2f}' for x in os.getloadavg()))
    row('CPU 使用率',cpu_usage())
    m={k:int(v)*1024 for k,v in re.findall(r'(?m)^(\w+):\s+(\d+) kB',text('/proc/meminfo'))}
    total=m.get('MemTotal',0);avail=m.get('MemAvailable',0)
    row('内存',usage(total-avail,total));row('Swap',usage(m.get('SwapTotal',0)-m.get('SwapFree',0),m.get('SwapTotal',0)) if m.get('SwapTotal') else '未配置')
    disk=shutil.disk_usage('/');row('系统盘',usage(disk.used,disk.total))
    row('网卡 IPv4',addresses(4));row('网卡 IPv6',addresses(6))
    row('IPv4 / IPv6 默认路由',route(4)+' / '+route(6))
    dns=run('resolvectl','dns') or text('/etc/resolv.conf')
    row('DNS',dns)
    row('拥塞控制',run('sysctl','-n','net.ipv4.tcp_congestion_control'));row('队列规则',run('sysctl','-n','net.core.default_qdisc'))
    try:
        seconds=int(float(text('/proc/uptime').split()[0]));row('运行时长',f'{seconds//86400} 天 {seconds%86400//3600} 小时 {seconds%3600//60} 分钟')
    except (ValueError,IndexError):row('运行时长',None)
    row('系统时间',run('date','+%Y-%m-%d %H:%M:%S %Z'))
elif view=='dns':
    try:
        result=subprocess.run([binary,'--vps-tool','dns-status','--config',cfg],capture_output=True,text=True,timeout=20)
        if result.returncode:raise ValueError('无法读取面板 DNS 状态，请运行 o status')
        d=json.loads(result.stdout)
        row('配置来源',{'external':'系统或云厂商网络服务'}.get(d.get('manager'),d.get('manager')));row('当前 DNS','、'.join(d.get('current',[])))
        row('IPv6 默认路由','存在（不代表连接测试成功）' if d.get('ipv6_available') else '未检测到')
        row('修改支持','支持' if d.get('configurable') else d.get('reason','当前环境只读'))
        for p in d.get('presets',[]):
            print('\n  '+{'international':'Cloudflare','mainland_china':'阿里云'}.get(p['id'],p['id']))
            row('IPv4',' / '.join(p['ipv4']));row('IPv6',' / '.join(p['ipv6']))
        if not d.get('configurable'):sys.exit(2)
    except (ValueError,OSError,subprocess.TimeoutExpired) as e: print('读取失败：'+safe(e));sys.exit(1)
elif view=='dns-test':
    try:result=subprocess.run([binary,'--vps-tool','dns-test','--vps-value',value,'--config',cfg],capture_output=True,text=True,timeout=70)
    except (OSError,subprocess.TimeoutExpired):print('DNS 检测未完成：命令不可用或超时');sys.exit(1)
    try:
        d=json.loads(result.stdout);row('IPv4 DNS 查询','通过' if d.get('ipv4_probe_ok') else '失败')
        row('IPv6 DNS 查询','未测试：无默认路由' if d.get('ipv6_skipped') else ('通过' if d.get('ipv6_probe_ok') else '失败'))
    except ValueError: row('检测结果','无法读取')
    if result.returncode:print(safe(result.stderr));sys.exit(1)
elif view=='ip':
    content=text('/etc/gai.conf');block=re.search(r'# OLS WPanel IP priority begin\n(.*?)# OLS WPanel IP priority end',content,re.S)
    row('面板优先规则',('IPv6 优先' if 'precedence ::/0 100' in block.group(1) else 'IPv4 优先') if block else '未设置')
    other=re.sub(r'# OLS WPanel IP priority begin\n.*?# OLS WPanel IP priority end','',content,flags=re.S)
    row('其他 precedence 规则','存在，需保留管理员配置' if re.search(r'(?m)^\s*precedence\s+',other) else '无')
    row('网卡 IPv4',addresses(4));row('网卡 IPv6',addresses(6));row('IPv4 / IPv6 默认路由',route(4)+' / '+route(6))
    print('  连通性检测请返回“网络设置”选择。')
elif view=='network':
    print('测试目标：https://www.cloudflare.com/cdn-cgi/trace（仅测试出站 HTTPS）')
    for family in [4,6]:
        row(f'IPv{family} 地址',addresses(family));row(f'IPv{family} 默认路由',route(family))
        out=run('curl','-q',f'-{family}','-fsS','--connect-timeout','4','--max-time','6','https://www.cloudflare.com/cdn-cgi/trace',timeout=8)
        ip=re.search(r'(?m)^ip=(.+)$',out or '')
        row(f'IPv{family} 出站访问','成功' if out is not None else '失败或超时（仅代表此测试目标）');row(f'IPv{family} 出口 IP',ip.group(1) if ip else None)
elif view=='tuning':
    for label,key in [('监听连接队列','net.core.somaxconn'),('TCP SYN 队列','net.ipv4.tcp_max_syn_backlog')]:row(label,run('sysctl','-n',key))
    row('恢复记录','可恢复修改前的值' if os.path.isfile('/etc/sysctl.d/.ols-wpanel-vps-original.json') else '尚未建立')
    row('拥塞控制',run('sysctl','-n','net.ipv4.tcp_congestion_control'));row('队列规则',run('sysctl','-n','net.core.default_qdisc'))
    managed=text('/etc/sysctl.d/99-ols-wpanel-vps.conf')
    legacy=text('/etc/sysctl.d/99-ols-wpanel.conf')
    row('面板队列配置','已保存' if managed else '未设置，沿用现有系统值')
    row('旧版安装配置','存在重复队列项；应用时迁移' if re.search(r'(?m)^net\.(core\.somaxconn|ipv4\.tcp_max_syn_backlog)\s*=',legacy) else '无重复队列项')
    m={k:int(v)*1024 for k,v in re.findall(r'(?m)^(\w+):\s+(\d+) kB',text('/proc/meminfo'))}
    row('CPU 使用率',cpu_usage())
    row('CPU 核数',os.cpu_count());row('负载 1 / 5 / 15 分钟',' / '.join(f'{x:.2f}' for x in os.getloadavg()))
    row('内存',usage(m.get('MemTotal',0)-m.get('MemAvailable',0),m.get('MemTotal',0)))
    row('Swap',usage(m.get('SwapTotal',0)-m.get('SwapFree',0),m.get('SwapTotal',0)) if m.get('SwapTotal') else '未配置')
    print('  以实际读取值为准；应用前记录原值，应用后验证。恢复范围仅限以上两项队列。')
elif view=='locale':
    row('当前 SSH 会话语言',os.environ.get('LC_ALL') or os.environ.get('LANG'))
    defaults=text('/etc/default/locale');match=re.search(r'(?m)^LANG=[\"\']?([^\"\'\n]+)',defaults)
    row('系统默认语言',match.group(1) if match else None)
    row('语言生成工具','已安装' if shutil.which('locale-gen') else '未安装 locales 软件包；设置暂不可用')
elif view=='time':
    d=properties('timedatectl','show');row('时区',d.get('Timezone'));row('本地时间',run('date','+%Y-%m-%d %H:%M:%S %Z'))
    row('自动校时',{'yes':'已开启','no':'未开启'}.get(d.get('NTP'),'未检测到'))
    row('同步状态',{'yes':'已同步','no':'尚未同步'}.get(d.get('NTPSynchronized'),'未检测到'))
    providers=[]
    for unit in ['chrony.service','systemd-timesyncd.service','ntpsec.service','ntp.service']:
        props=properties('systemctl','show',unit,'--property=LoadState,ActiveState')
        if props.get('LoadState')=='loaded':providers.append(unit+'：'+{'active':'运行中','inactive':'未运行','failed':'失败'}.get(props.get('ActiveState'),'未知'))
    row('时间服务','；'.join(providers) or '未检测到')
elif view in ['updates','update-status']:
    if view=='updates':
        out=run('apt','list','--upgradable',timeout=20)
        if out is None:row('软件包列表','读取失败')
        else:
            packages=[x for x in out.splitlines() if '/' in x and '[upgradable' in x]
            row('可更新软件包',len(packages));row('安全源更新',sum('-security' in x.split()[0] for x in packages))
            print('  根据本机 APT 索引；执行更新时会刷新。')
            for x in packages[:12]:print('  '+safe(x))
            if len(packages)>12:print(f'  另有 {len(packages)-12} 项；使用 apt list --upgradable 查看全部。')
    out=run(binary,'--vps-tool','system-update-status','--config',cfg,timeout=15)
    try:
        d=json.loads(out or '{}');status=d.get('status');row('更新任务',{'idle':'尚无任务','running':'执行中','success':'成功','succeeded':'成功','failed':'失败','completed':'已完成'}.get(status,status))
        row('执行阶段',{'queued':'排队中','services_preflight':'更新前服务检查','refresh':'刷新软件包索引','upgrade':'安装软件包更新','services':'更新后服务检查','complete':'完成','interrupted':'任务中断'}.get(d.get('stage'),d.get('stage')))
        if d.get('detail'):row('任务详情',d['detail'])
        if d.get('updated_at'):row('最后更新',d['updated_at'])
    except ValueError:row('更新任务','读取失败')
    row('重启标记','需要重启' if os.path.exists('/var/run/reboot-required') else '系统未报告（不保证无需重启）')
elif view=='clean':
    for label,path in [('APT 下载缓存','/var/cache/apt/archives'),('持久化系统日志','/var/log/journal'),('内存系统日志','/run/log/journal')]:
        n=bytes_at(path);row(label,size(n) if n is not None else None)
    print('  上述是总占用，不代表全部可释放；活动日志及近14天日志会保留。')
elif view=='clean-bytes':
    n=total_cache();print(n if n is not None else '')
PYVIEW
}
vps_info() { read_view info; }
need_root() { [ "${EUID:-$(id -u)}" -eq 0 ] || { red "需要 root 权限"; return 1; }; }
confirm_vps() {
    local answer=""
    echo "$1"
    read -r -p "输入 YES 继续，其他输入取消: " answer < /dev/tty || return 1
    [ "$answer" = "YES" ]
}
interactive() { [ -t 0 ] && [ -t 1 ]; }
page() {
    if interactive && [ "${TERM:-dumb}" != dumb ]; then printf '\033[2J\033[H'; fi
    blue "OLS WPanel › $1"
    dim "────────────────────────────────────────────"
    [ -z "${2:-}" ] || printf '%s\n\n' "$2"
}
pause_page() {
    if interactive; then
        local ignored=""
        read -r -p "按回车返回…" ignored < /dev/tty || return 0
    fi
}
pick() {
    interactive || return 1
    echo ""
    read -r -p "请选择 [0 返回]: " choice < /dev/tty
}
result() {
    if "$@"; then green "操作已完成。"; else red "操作失败，请查看上方原因。"; fi
}
settings_page() {
    local kind="$1" choice="" action="" value="" note="" dns_ready=1
    while true; do
        case "$kind" in
          dns)
            page "DNS 设置" "DNS 将域名解析为 IP 地址。仅修改受面板支持的配置；应用前检测，失败时恢复。"
            dns_ready=1
            read_view dns || dns_ready=0
            echo ""
            if [ "$dns_ready" -eq 1 ]; then
                echo "  1. 使用 Cloudflare"; echo "  2. 使用阿里云"; echo "  3. 恢复系统 DNS（移除面板覆盖）"
            else dim "当前仅支持查看和检测，修改入口不可用。"; fi
            echo "  4. 检测 Cloudflare 双栈 DNS"; echo "  5. 检测阿里云双栈 DNS"
            ;;
          ip)
            page "IPv4 / IPv6 优先级" "影响遵循系统地址选择规则的新连接，不会禁用 IPv4 或 IPv6；部分应用有自己的规则。"
            read_view ip
            echo ""; echo "  1. IPv4 优先"; echo "  2. IPv6 优先"; echo "  3. 恢复系统规则（移除面板覆盖）"
            ;;
          tuning)
            page "高级设置 · 连接队列" "仅调整连接排队上限，不代表访客数量或网站处理能力。"
            read_view tuning
            echo ""; echo "  1. 设为 4096 / 4096"; echo "  2. 设为 8192 / 8192"; echo "  3. 恢复修改前的值"
            ;;
          locale)
            page "系统语言" "影响系统命令提示与新 SSH 会话，网页面板语言单独设置。"
            read_view locale
            echo ""; echo "  1. English · en_US.UTF-8"; echo "  2. 简体中文 · zh_CN.UTF-8"; echo "  3. 繁體中文 · zh_TW.UTF-8"
            ;;
          time)
            page "时区与时间同步" "时区影响日志和定时任务的本地时间；自动校时用于保持服务器时钟准确。"
            read_view time
            echo ""; echo "  1. 时区设为 UTC"; echo "  2. 时区设为 Asia/Shanghai"; echo "  3. 启动自动校时（缺少服务时安装 systemd-timesyncd）"
            ;;
        esac
        echo "  0. 返回"
        pick || return 0
        if [ "$kind" = dns ] && [ "$dns_ready" -eq 0 ] && [[ "$choice" =~ ^[123]$ ]]; then
            echo "当前 DNS 由其他网络服务管理，无法修改。"; pause_page; continue
        fi
        action=""; value=""; note=""
        case "$kind:$choice" in
          *:0) return 0;;
          dns:4|dns:5)
            [ "$choice" = 4 ] && value=international || value=mainland_china
            read_view dns-test "$value"; pause_page; continue;;
          dns:1) action=dns; value=international; note="使用检测通过的 Cloudflare DNS；IPv6 仅在可达时应用。";;
          dns:2) action=dns; value=mainland_china; note="使用检测通过的阿里云 DNS；IPv6 仅在可达时应用。";;
          dns:3) action=dns; value=default; note="移除面板 DNS 覆盖，恢复系统网络服务管理。";;
          ip:1) action=ip-priority; value=ipv4; note="新连接优先选择 IPv4。";;
          ip:2) action=ip-priority; value=ipv6; note="新连接优先选择 IPv6；请先确认 IPv6 连通性。";;
          ip:3) action=ip-priority; value=default; note="移除面板的地址优先级规则，保留其他配置。";;
          tuning:1) action=tuning; value=balanced; note="两项连接队列将设为 4096 / 4096；若当前值更高，本操作会降低上限。不会自动加快网页加载。";;
          tuning:2) action=tuning; value=website; note="两项连接队列将设为 8192 / 8192；仅用于连接高峰评估，若当前值更高会降低上限。";;
          tuning:3) action=tuning; value=default; note="恢复面板首次调整前记录的连接队列值。";;
          locale:1) action=locale; value=en_US.UTF-8; note="系统语言设为英文，重新登录 SSH 后生效。";;
          locale:2) action=locale; value=zh_CN.UTF-8; note="系统语言设为简体中文，重新登录 SSH 后生效。";;
          locale:3) action=locale; value=zh_TW.UTF-8; note="系统语言设为繁体中文，重新登录 SSH 后生效。";;
          time:1) action=timezone; value=UTC; note="时区设为 UTC，会影响按本地时间执行的计划任务。";;
          time:2) action=timezone; value=Asia/Shanghai; note="时区设为 Asia/Shanghai，会影响按本地时间执行的计划任务。";;
          time:3) action=time-sync; note="启用已有校时服务；缺少时安装 systemd-timesyncd，随后检查同步状态。";;
          *) echo "无效选项"; pause_page; continue;;
        esac
        if need_root && confirm_vps "$note"; then
            result "$BIN" --vps-tool "$action" --vps-value "$value" --config "$CFG"
            read_view "$kind"
        else echo "已取消"; fi
        pause_page
    done
}
performance_menu() {
    local choice=""
    while true; do
        page "性能状态" "展示当前实际状态。PHP、数据库和 Redis 参数请在网页的软件管理中设置。"
        read_view tuning
        echo ""; echo "  1. 刷新状态"; echo "  2. 高级设置 · 调整连接队列"; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) continue;; 2) settings_page tuning;;
          *) echo "无效选项"; pause_page;;
        esac
    done
}
updates_page() {
    local choice=""
    while true; do
        page "更新 VPS 软件包" "更新系统软件包，不更新面板或升级发行版。后台任务不会因退出菜单而中断。"
        read_view updates
        echo ""; echo "  1. 开始系统更新"; echo "  2. 重读本机列表与任务状态（不联网刷新索引）"; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 2) continue;;
          1) if need_root && confirm_vps "更新 VPS 软件包，不更新面板、不自动重启服务器。"; then result "$BIN" --vps-tool system-update --config "$CFG"; else echo "已取消"; fi;;
          *) echo "无效选项";;
        esac
        pause_page
    done
}
clean_page() {
    local choice="" before="" after=""
    while true; do
        page "系统清理" "清理 APT 下载缓存及超过14天的归档系统日志；保留网站、数据库、备份和已安装软件。"
        read_view clean
        echo ""; echo "  1. 执行清理"; echo "  2. 刷新占用"; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 2) continue;;
          1)
            if need_root && confirm_vps "清理上述缓存及过期归档日志？"; then
                before=$(read_view clean-bytes)
                result "$BIN" --vps-tool clean --config "$CFG"
                after=$(read_view clean-bytes)
                if [[ "$before" =~ ^[0-9]+$ && "$after" =~ ^[0-9]+$ ]]; then
                    echo "清理前占用: $before 字节；清理后占用: $after 字节"
                    if [ "$before" -ge "$after" ]; then echo "本次占用减少: $((before-after)) 字节（并发日志写入可能影响统计）"; fi
                fi
                read_view clean
            else echo "已取消"; fi;;
          *) echo "无效选项";;
        esac
        pause_page
    done
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
    echo "  o network        双栈网络检测"
    echo "  o time           时区与时间同步"
    dim "项目: https://github.com/zangwp/OLS-WPanel"
    dim "访问排查: 放行面板端口；运行 o status 或 o log"
}
advanced_menu() {
    local choice=""
    while true; do
        page "帮助与高级操作" "卸载前先查看删除范围；完全卸载还会要求专门确认，备份另行选择。"
        echo "  1. 快捷命令帮助"
        echo "  2. 普通卸载（保留网站、数据库和共享软件）"
        echo "  3. 完全卸载（删除网站、数据库、面板及相关运行环境）"; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) page "命令帮助"; panel_help;;
          2) "$0" uninstall; return;; 3) "$0" uninstall --all; return;; *) echo "无效选项";;
        esac
        pause_page
    done
}
panel_summary() {
        echo ""
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
            dim "可在面板管理中运行诊断检查。"
        fi
        echo ""
        dim "输入 o help 查看命令，o info 查看面板详情。"
}
network_menu() {
    local choice=""
    while true; do
        page "网络设置" "管理域名解析、地址选择优先级，或检测服务器出站连接。"
        read_view ip
        echo ""; echo "  1. DNS 设置与检测"; echo "  2. IPv4 / IPv6 优先级"; echo "  3. 网络连通性检测"; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) settings_page dns;; 2) settings_page ip;;
          3) page "网络连通性检测"; read_view network; pause_page;; *) echo "无效选项"; pause_page;;
        esac
    done
}
system_menu() {
    local choice=""
    while true; do
        page "系统设置" "查看时间、同步状态与语言，按需调整。"
        read_view time
        echo ""; echo "  1. 时区与时间同步"; echo "  2. 系统语言"; echo "  0. 返回"
        pick || return 0
        case "$choice" in 0) return 0;; 1) settings_page time;; 2) settings_page locale;; *) echo "无效选项"; pause_page;; esac
    done
}
panel_menu() {
    local choice=""
    while true; do
        page "面板管理"; panel_summary
        echo ""; echo "  1. 检查更新"; echo "  2. 更新 / 修复 OLS WPanel"; echo "  3. 运行诊断"
        echo "  4. 查看日志"; echo "  5. 重启面板"; echo "  6. 重置登录账号密码"; echo "  7. 清除面板 IP 封禁"; echo "  8. 面板详情"; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) page "检查项目更新"; check_project_update;;
          2) if need_root && confirm_vps "通过签名发布链更新或修复面板？"; then "$0" update; fi;;
          3) page "诊断检查"; "$0" status;; 4) page "面板日志"; "$0" log;;
          5) if need_root && confirm_vps "重启面板服务？管理连接会短暂中断。"; then "$0" restart; fi;;
          6) if need_root && confirm_vps "重置面板登录账号密码？"; then "$0" password; fi;;
          7) if need_root && confirm_vps "清除面板管理的 IP 封禁？"; then "$0" unban; fi;;
          8) page "面板详情"; "$0" info;; *) echo "无效选项";;
        esac
        pause_page
    done
}
vps_menu() {
    local choice="" width=""
    while true; do
        page "管理主页"; panel_summary
        width=$(tput cols 2>/dev/null) || width=0
        [[ "$width" =~ ^[0-9]+$ ]] || width=0
        if [ "$width" -ge 68 ]; then
            echo "  1. 系统信息              2. 更新 VPS 软件包"
            echo "  3. 系统清理              4. 网络设置"
            echo "  5. 系统设置              6. 性能状态"
            echo "  7. 面板管理              8. 帮助与高级操作"
        else
            echo "  1. 系统信息"; echo "  2. 更新 VPS 软件包"; echo "  3. 系统清理"; echo "  4. 网络设置"
            echo "  5. 系统设置"; echo "  6. 性能状态"; echo "  7. 面板管理"; echo "  8. 帮助与高级操作"
        fi
        echo "  0. 退出"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) page "系统信息" "服务器资源与网络状态；网卡地址不一定是公网出口地址。"; vps_info; pause_page;;
          2) updates_page;; 3) clean_page;; 4) network_menu;; 5) system_menu;; 6) performance_menu;; 7) panel_menu;; 8) advanced_menu;;
          *) echo "无效选项"; pause_page;;
        esac
    done
}

case "${1:-}" in
    menu) vps_menu ;;
    help|-h|--help) panel_help ;;
    advanced) advanced_menu ;;
    vps) page "系统信息"; vps_info ;;
    network) page "网络连通性检测"; read_view network ;;
    time) settings_page time ;;
    check-update) check_project_update ;;
    system-update) updates_page ;;
    system-update-status) read_view update-status ;;
    clean) clean_page ;;
    dns) settings_page dns ;;
    ip) settings_page ip ;;
    tuning) performance_menu ;;
    language) settings_page locale ;;
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
        if interactive; then vps_menu; else page "面板信息"; panel_summary; fi
        ;;
    *) red "未知命令: $1；输入 o help 查看用法"; exit 1 ;;
esac
