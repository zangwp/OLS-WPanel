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
    local columns
    columns=$(tput cols 2>/dev/null) || columns=72
    export OLS_CLI_WIDTH="${columns:-72}"
    python3 - "$1" "$BIN" "$CFG" "${2:-}" <<'PYVIEW'
import datetime, ipaddress, json, os, pathlib, platform, re, shutil, subprocess, sys, time, unicodedata
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
try: WIDTH=max(32,min(88,int(os.environ.get('OLS_CLI_WIDTH','72'))))
except ValueError: WIDTH=72
def cells(s):return sum(0 if unicodedata.combining(c) else (2 if unicodedata.east_asian_width(c) in 'WF' else 1) for c in s)
def wrapped(s,width):
    lines=[];line=''
    for c in safe(s):
        if c=='\n' or cells(line+c)>width:
            lines.append(line);line=''
            if c=='\n':continue
        line+=c
    if line or not lines:lines.append(line)
    return lines
def note(s):
    for line in wrapped(s,WIDTH-4):print('  '+line)
def section(title):print('\n  '+title+'\n  '+ '─'*min(WIDTH-4,52))
def row(label,value):
    value=value if value is not None and value!='' else '未检测到'
    col=16 if WIDTH>=52 else 12
    if cells(label)>col:note(label);prefix='    '
    else:prefix='  '+label+' '*(col-cells(label))+'  '
    for i,line in enumerate(wrapped(str(value),max(12,WIDTH-cells(prefix)-2))):print((prefix if i==0 else ' '*cells(prefix))+line)
def dns_rows(values):
    for family in [4,6]:
        selected=[]
        for v in values:
            try:ip=ipaddress.ip_address(v.split('%')[0])
            except ValueError:continue
            if ip.version==family:selected.append(v+('（本机转发）' if ip.is_loopback else ''))
        row('IPv'+str(family)+' DNS','\n'.join(selected) or '未读取到该类 DNS 地址')
def dns_status():
    out=run(binary,'--vps-tool','dns-status','--config',cfg,timeout=20)
    if out is None:raise ValueError('DNS 状态读取失败，可使用 o status 排查')
    return json.loads(out)
def dns_current(d):
    section('当前解析服务器')
    dns_rows(d.get('current',[]))
    row('读取来源',d.get('current_source') or '来源未知')
    note('地址按配置顺序显示；不是逐次查询使用记录。')
def memory_rows():
    m={k:int(v)*1024 for k,v in re.findall(r'(?m)^(\w+):\s+(\d+) kB',text('/proc/meminfo'))}
    row('内存',usage(m.get('MemTotal',0)-m.get('MemAvailable',0),m.get('MemTotal',0)))
    row('Swap',usage(m.get('SwapTotal',0)-m.get('SwapFree',0),m.get('SwapTotal',0)) if m.get('SwapTotal') else '未配置')
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
    section('系统')
    osinfo={}
    for line in text('/etc/os-release').splitlines():
        if '=' in line:
            k,v=line.split('=',1);osinfo[k]=v.strip('"')
    row('发行版',osinfo.get('PRETTY_NAME'));row('主机名',platform.node())
    row('内核 / 架构',platform.release()+' / '+platform.machine())
    section('资源')
    cpu=re.search(r'(?m)^(?:model name|Hardware)\s*:\s*(.+)$',text('/proc/cpuinfo'))
    row('处理器',(cpu.group(1) if cpu else platform.machine())+f' · {os.cpu_count() or "?"} 核')
    row('CPU 使用率',cpu_usage());row('负载 1/5/15 分',' / '.join(f'{x:.2f}' for x in os.getloadavg()))
    memory_rows();disk=shutil.disk_usage('/');row('系统盘',usage(disk.used,disk.total))
    section('网络地址')
    row('网卡 IPv4',addresses(4));row('网卡 IPv6',addresses(6))
    try:dns_current(dns_status())
    except ValueError as e:note(str(e))
    section('时间')
    try:
        seconds=int(float(text('/proc/uptime').split()[0]));row('运行时长',f'{seconds//86400} 天 {seconds%86400//3600} 小时 {seconds%3600//60} 分钟')
    except (ValueError,IndexError):row('运行时长',None)
    row('系统时间',run('date','+%Y-%m-%d %H:%M:%S %Z'))
elif view in ['dns','dns-preset']:
    try:
        d=dns_status()
        if view=='dns':
            dns_current(d)
            section('管理状态')
            row('修改权限','可由面板设置' if d.get('configurable') else '只读 · 可检测候选 DNS')
            row('管理方式','systemd-resolved' if d.get('manager')=='systemd-resolved' else '非 systemd-resolved，具体管理者未确认')
            if not d.get('configurable'):note('本页不接管系统 DNS。'+d.get('reason',''))
        else:
            preset=next((p for p in d.get('presets',[]) if p.get('id')==value),None)
            if not preset:raise ValueError('候选方案不存在')
            section({'international':'Cloudflare','mainland_china':'阿里云'}.get(value,value)+' · 候选地址')
            dns_rows(preset['ipv4']+preset['ipv6'])
            note('以上为候选方案，查看或检测不会更换当前 DNS。')
            section('操作条件')
            row('面板修改权限','可用' if d.get('configurable') else '只读，仅可检测')
            row('IPv6 默认路由','存在，仍需检测 DNS' if d.get('ipv6_available') else '未检测到')
        if not d.get('configurable'):sys.exit(2)
    except (ValueError,OSError,subprocess.TimeoutExpired) as e:note('读取失败：'+str(e));sys.exit(1)
elif view=='dns-test':
    try:result=subprocess.run([binary,'--vps-tool','dns-test','--vps-value',value,'--config',cfg],capture_output=True,text=True,timeout=70)
    except (OSError,subprocess.TimeoutExpired):print('DNS 检测未完成：命令不可用或超时');sys.exit(1)
    try:
        d=json.loads(result.stdout);section('候选 DNS 检测结果');row('IPv4 DNS 查询','通过' if d.get('ipv4_probe_ok') else '失败')
        row('IPv6 DNS 查询','未测试：无默认路由' if d.get('ipv6_skipped') else ('通过' if d.get('ipv6_probe_ok') else '失败'))
    except ValueError: row('检测结果','无法读取')
    if result.returncode:print(safe(result.stderr));sys.exit(1)
elif view=='ip':
    content=text('/etc/gai.conf');block=re.search(r'# OLS WPanel IP priority begin\n(.*?)# OLS WPanel IP priority end',content,re.S)
    other=re.sub(r'# OLS WPanel IP priority begin\n.*?# OLS WPanel IP priority end','',content,flags=re.S)
    custom=bool(re.search(r'(?m)^\s*precedence\s+',other))
    section('地址选择规则')
    row('面板设置',('IPv6 优先' if 'precedence ::/0 100' in block.group(1) else 'IPv4 优先') if block else '未设置面板规则')
    row('现有自定义规则','存在，面板不会覆盖' if custom else '未发现')
    if custom:note('不能仅凭面板记录判定当前优先级；请先检查 /etc/gai.conf。')
    section('网卡地址')
    row('IPv4',addresses(4));row('IPv6',addresses(6))
    if custom:sys.exit(2)
elif view=='network':
    note('测试：Cloudflare HTTPS 出站访问，不代表全部网络或入站端口。')
    for family in [4,6]:
        section(f'IPv{family}')
        row('网卡地址',addresses(family));row('默认路由',route(family))
        out=run('curl','-q',f'-{family}','-fsS','--connect-timeout','4','--max-time','6','https://www.cloudflare.com/cdn-cgi/trace',timeout=8)
        ip=re.search(r'(?m)^ip=(.+)$',out or '')
        row('访问结果','成功' if out is not None else '失败或超时');row('出口地址',ip.group(1) if ip else None)
elif view in ['tuning','queues','queue-menu']:
    queue_values=[run('sysctl','-n',k) for k in ['net.core.somaxconn','net.ipv4.tcp_max_syn_backlog']]
    if view=='tuning':
        section('实时资源')
        row('CPU',str(os.cpu_count())+' 核 · '+str(cpu_usage() or '使用率未知'))
        row('负载 1/5/15 分',' / '.join(f'{x:.2f}' for x in os.getloadavg()));memory_rows()
        section('网络参数')
        row('拥塞控制',run('sysctl','-n','net.ipv4.tcp_congestion_control'));row('队列规则',run('sysctl','-n','net.core.default_qdisc'))
    else:section('当前连接配置')
    if view=='queue-menu':
        mode={('4096','4096'):'日常网站配置',('8192','8192'):'连接高峰配置'}.get(tuple(queue_values),'自定义 / 系统配置')
        row('当前模式',mode if all(queue_values) else '未能读取')
        row('两项队列上限',' / '.join(v or '未知' for v in queue_values))
        note('按实际值识别模式；不代表已评估网站性能。')
    else:
        for label,value in zip(['待接收连接上限','半连接队列上限'],queue_values):row(label,value)
    if view in ['queues','queue-menu']:
        managed=text('/etc/sysctl.d/99-ols-wpanel-vps.conf');legacy=text('/etc/sysctl.d/99-ols-wpanel.conf')
        if view=='queues':
            section('配置与恢复')
            row('面板配置文件','存在' if managed else '未建立')
            row('安装器队列项','存在，应用时迁移' if re.search(r'(?m)^net\.(core\.somaxconn|ipv4\.tcp_max_syn_backlog)\s*=',legacy) else '未发现')
        try:
            baseline=json.loads(text('/etc/sysctl.d/.ols-wpanel-vps-original.json'))
            can_restore=all(re.fullmatch(r'[0-9]+',str(baseline.get(k,''))) for k in ['net.core.somaxconn','net.ipv4.tcp_max_syn_backlog'])
        except (ValueError,AttributeError):can_restore=False
        row('恢复记录','已保存有效原值' if can_restore else '无有效记录')
        if view=='queues':note('只调整以上两项上限；数值不代表可接待的访客数量。')
        note('没有连接排队问题时，建议保留当前值。预设低于当前值时会降低上限。')
        if not can_restore:sys.exit(2)
elif view=='locale':
    section('语言环境')
    row('当前 SSH 会话语言',os.environ.get('LC_ALL') or os.environ.get('LANG'))
    defaults=text('/etc/default/locale');match=re.search(r'(?m)^LANG=[\"\']?([^\"\'\n]+)',defaults)
    row('系统默认语言',match.group(1) if match else None)
    row('语言生成工具','已安装' if shutil.which('locale-gen') else '未安装 locales 软件包；设置暂不可用')
elif view=='time':
    section('系统时钟')
    d=properties('timedatectl','show');row('时区',d.get('Timezone'));row('本地时间',run('date','+%Y-%m-%d %H:%M:%S %Z'))
    row('自动校时',{'yes':'已开启','no':'未开启'}.get(d.get('NTP'),'未检测到'))
    row('同步状态',{'yes':'已同步','no':'尚未同步'}.get(d.get('NTPSynchronized'),'未检测到'))
    providers=[]
    for unit in ['chrony.service','systemd-timesyncd.service','ntpsec.service','ntp.service']:
        props=properties('systemctl','show',unit,'--property=LoadState,ActiveState')
        if props.get('LoadState')=='loaded':providers.append(unit+'：'+{'active':'运行中','inactive':'未运行','failed':'失败'}.get(props.get('ActiveState'),'未知'))
    row('时间服务','；'.join(providers) or '未检测到')
elif view in ['updates','update-status','update-details']:
    if view=='updates':
        section('可用软件包更新')
        out=run('apt','list','--upgradable',timeout=20)
        if out is None:row('软件包列表','读取失败')
        else:
            packages=[x for x in out.splitlines() if '/' in x and '[upgradable' in x]
            row('可更新软件包',len(packages));row('安全源更新',sum('-security' in x.split()[0] for x in packages))
            print('  根据本机 APT 索引；执行更新时会刷新。')
            note('包名与版本可在“查看详细记录”中查看。')
    out=run(binary,'--vps-tool','system-update-status','--config',cfg,timeout=15)
    try:
        if out is None:raise ValueError('任务读取失败')
        d=json.loads(out);status=d.get('status');section('正在执行的任务' if status=='running' else '最近一次更新记录（历史）');row('任务结果',{'idle':'尚无任务','running':'执行中','success':'成功','succeeded':'成功','failed':'失败','completed':'已完成'}.get(status,status))
        row('执行阶段',{'queued':'排队中','services_preflight':'更新前服务检查','refresh':'刷新软件包索引','upgrade':'安装软件包更新','services':'更新后服务检查','complete':'完成','interrupted':'任务中断'}.get(d.get('stage'),d.get('stage')))
        if view=='update-details' and d.get('detail'):row('详细信息',d['detail'])
        if d.get('updated_at'):row('最后更新',d['updated_at'])
    except ValueError:row('更新任务','读取失败')
    if view=='update-details':
        section('软件包列表（本机索引）')
        note(run('apt','list','--upgradable',timeout=20) or '读取失败')
    elif view=='updates':note('历史结果不代表当前服务状态；错误原文请查看详细记录。')
    row('重启标记','需要重启' if os.path.exists('/var/run/reboot-required') else '系统未报告（不保证无需重启）')
elif view=='clean':
    section('当前占用')
    for label,path in [('APT 下载缓存','/var/cache/apt/archives'),('持久化系统日志','/var/log/journal'),('内存系统日志','/run/log/journal')]:
        n=bytes_at(path);row(label,size(n) if n is not None else None)
    note('上述是总占用，不代表全部可释放。')
    note('保留活动日志、近 14 天日志、网站、数据库、备份和已安装软件。')
elif view=='clean-bytes':
    n=total_cache();print(n if n is not None else '')
PYVIEW
}
vps_info() { read_view info; }
need_root() { [ "${EUID:-$(id -u)}" -eq 0 ] || { red "需要 root 权限"; return 1; }; }
is_yes() { case "${1,,}" in y|yes) return 0;; *) return 1;; esac; }
confirm_vps() {
    local answer=""
    echo ""
    text_block "$1"
    echo ""
    read -r -p "  确认执行？[y/yes，回车取消]: " answer < /dev/tty || return 1
    is_yes "$answer"
}
interactive() { [ -t 0 ] && [ -t 1 ]; }
text_block() {
    local width
    width=$(tput cols 2>/dev/null) || width=72
    python3 - "$width" "$*" <<'PYTEXT' || printf '  %s\n' "$*"
import sys,unicodedata
try:width=max(28,min(88,int(sys.argv[1])))-4
except ValueError:width=68
line='';used=0
for c in sys.argv[2]:
    if ord(c)<32 and c!='\n':continue
    n=0 if unicodedata.combining(c) else (2 if unicodedata.east_asian_width(c) in 'WF' else 1)
    if c=='\n' or used+n>width:
        print('  '+line);line='';used=0
        if c=='\n':continue
    line+=c;used+=n
if line:print('  '+line)
PYTEXT
}
rule() {
    local width bar
    width=$(tput cols 2>/dev/null) || width=72
    [[ "$width" =~ ^[0-9]+$ ]] || width=72
    [ "$width" -le 76 ] || width=76
    [ "$width" -ge 28 ] || width=28
    printf -v bar '%*s' "$((width-4))" ""
    dim "  ${bar// /─}"
}
page() {
    if interactive && [ "${TERM:-dumb}" != dumb ]; then printf '\033[2J\033[H'; fi
    echo ""
    blue "  OLS WPanel  /  $1"
    rule
    echo ""
    [ -z "${2:-}" ] || text_block "$2"
}
pause_page() {
    if interactive; then
        local ignored=""
        echo ""
        read -r -p "  按回车返回…" ignored < /dev/tty || return 0
    fi
}
pick() {
    interactive || return 1
    echo ""
    rule
    read -r -p "  请选择 [0 ${1:-返回}]: " choice < /dev/tty
}
result() {
    if "$@"; then green "操作已完成。"; else red "操作失败，请查看上方原因。"; fi
}
settings_page() {
    local kind="$1" choice="" action="" value="" note="" dns_ready=1 ip_ready=1 queue_ready=1
    while true; do
        case "$kind" in
          dns)
            page "DNS" "查看当前解析服务器，或检测候选方案。"
            dns_ready=1
            read_view dns || dns_ready=0
            echo ""
            echo "  1. Cloudflare · 查看 / 检测"
            echo "  2. 阿里云     · 查看 / 检测"
            if [ "$dns_ready" -eq 1 ]; then echo "  3. 恢复系统 DNS"; fi
            ;;
          ip)
            page "IPv4 / IPv6 优先级" "设置新连接的地址选择偏好。"
            ip_ready=1
            read_view ip || ip_ready=0
            echo ""
            if [ "$ip_ready" -eq 1 ]; then echo "  1. IPv4 优先"; echo "  2. IPv6 优先"; fi
            echo "  3. 移除面板规则（保留其他规则）"
            ;;
          tuning)
            page "高级设置 · 连接队列" "查看当前值，按需调整。"
            queue_ready=1
            read_view queue-menu || queue_ready=0
            echo ""
            echo "  1. 日常网站配置 · 4096 / 4096"
            echo "     博客、企业站的连接排队预设"
            echo ""
            echo "  2. 连接高峰配置 · 8192 / 8192"
            echo "     用于连接集中到达时的排队评估"
            echo ""
            echo "  3. 查看当前参数与恢复详情"
            if [ "$queue_ready" -eq 1 ]; then echo "  4. 恢复修改前的值"; fi
            ;;
          locale)
            page "系统语言" "影响系统命令提示与新 SSH 会话，网页面板语言单独设置。"
            read_view locale
            echo ""; echo "  1. English · en_US.UTF-8"; echo "  2. 简体中文 · zh_CN.UTF-8"; echo "  3. 繁體中文 · zh_TW.UTF-8"
            ;;
          time)
            page "时区与时间同步" "时区影响日志和定时任务的本地时间；自动校时用于保持服务器时钟准确。"
            read_view time
            echo ""; echo "  1. 时区设为 UTC"; echo "  2. 时区设为 Asia/Shanghai"; echo "  3. 启动自动校时"
            text_block "   缺少服务时安装 systemd-timesyncd"
            ;;
        esac
        echo ""; echo "  0. 返回"
        pick || return 0
        if [ "$kind" = dns ] && [ "$dns_ready" -eq 0 ] && [ "$choice" = 3 ]; then
            echo "当前 DNS 由其他网络服务管理，无法修改。"; pause_page; continue
        fi
        if [ "$kind" = ip ] && [ "$ip_ready" -eq 0 ] && [[ "$choice" =~ ^[12]$ ]]; then
            echo "  已有其他地址选择规则，无法自动覆盖。"; pause_page; continue
        fi
        if [ "$kind" = tuning ] && [ "$queue_ready" -eq 0 ] && [ "$choice" = 4 ]; then
            echo "  无有效恢复记录，未执行修改。"; pause_page; continue
        fi
        action=""; value=""; note=""
        case "$kind:$choice" in
          *:0) return 0;;
          dns:1|dns:2)
            [ "$choice" = 1 ] && value=international || value=mainland_china
            dns_preset_page "$value"; continue;;
          dns:3) action=dns; value=default; note="移除面板 DNS 覆盖，恢复系统网络服务管理。";;
          ip:1) action=ip-priority; value=ipv4; note="新连接优先选择 IPv4。";;
          ip:2) action=ip-priority; value=ipv6; note="新连接优先选择 IPv6；请先确认 IPv6 连通性。";;
          ip:3) action=ip-priority; value=default; note="移除面板的地址优先级规则，保留其他配置。";;
          tuning:1) action=tuning; value=balanced; note="两项连接队列将设为 4096 / 4096；若当前值更高，本操作会降低上限。不会自动加快网页加载。";;
          tuning:2) action=tuning; value=website; note="两项连接队列将设为 8192 / 8192；仅用于连接高峰评估，若当前值更高会降低上限。";;
          tuning:4) action=tuning; value=default; note="恢复面板首次调整前记录的连接队列值。";;
          tuning:3) page "连接队列 · 参数详情"; read_view queues; pause_page; continue;;
          locale:1) action=locale; value=en_US.UTF-8; note="系统语言设为英文，重新登录 SSH 后生效。";;
          locale:2) action=locale; value=zh_CN.UTF-8; note="系统语言设为简体中文，重新登录 SSH 后生效。";;
          locale:3) action=locale; value=zh_TW.UTF-8; note="系统语言设为繁体中文，重新登录 SSH 后生效。";;
          time:1) action=timezone; value=UTC; note="时区设为 UTC，会影响按本地时间执行的计划任务。";;
          time:2) action=timezone; value=Asia/Shanghai; note="时区设为 Asia/Shanghai，会影响按本地时间执行的计划任务。";;
          time:3) action=time-sync; note="启用已有校时服务；缺少时安装 systemd-timesyncd，随后检查同步状态。";;
          *) echo "无效选项"; pause_page; continue;;
        esac
        if [ "$kind" = tuning ]; then
            page "连接队列 · 确认变更"
            read_view queues || true
            echo ""
        fi
        if need_root && confirm_vps "$note"; then
            result "$BIN" --vps-tool "$action" --vps-value "$value" --config "$CFG"
            if [ "$kind" = tuning ]; then read_view queues || true; else read_view "$kind" || true; fi
        else echo "已取消"; fi
        pause_page
    done
}
dns_preset_page() {
    local preset="$1" choice="" ready=1
    while true; do
        page "DNS · 候选方案"
        ready=1
        read_view dns-preset "$preset" || ready=0
        echo ""; echo "  1. 检测候选 DNS"
        if [ "$ready" -eq 1 ]; then echo "  2. 应用此方案（先检测）"; fi
        echo "  0. 返回 DNS"
        pick || return 0
        case "$choice" in
          0) return 0;;
          1) page "DNS · 检测结果"; read_view dns-test "$preset" || true; pause_page;;
          2)
            if [ "$ready" -eq 0 ]; then echo "  当前不支持修改 DNS。"; pause_page; continue; fi
            if need_root && confirm_vps "将替换面板管理的 DNS；仅应用检测通过的地址族。"; then
                result "$BIN" --vps-tool dns --vps-value "$preset" --config "$CFG"
                read_view dns || true
            else echo "  已取消"; fi
            pause_page;;
          *) echo "  无效选项"; pause_page;;
        esac
    done
}
performance_menu() {
    local choice=""
    while true; do
        page "性能状态" "只读查看；刷新不会修改配置。"
        read_view tuning
        echo ""; echo "  1. 刷新状态"; echo "  2. 高级设置 · 调整连接队列"; echo ""; echo "  0. 返回"
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
        page "更新 VPS 软件包" "更新系统软件；面板版本在“面板管理”中更新。"
        read_view updates
        echo ""; echo "  1. 开始系统更新"; echo "  2. 刷新本机状态"; echo "  3. 查看详细记录"; echo ""; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 2) continue;;
          3) page "软件更新 · 详细记录"; read_view update-details; pause_page; continue;;
          1) if need_root && confirm_vps "更新 VPS 软件包，不更新面板、不自动重启服务器。"; then result "$BIN" --vps-tool system-update --config "$CFG"; else echo "已取消"; fi;;
          *) echo "无效选项";;
        esac
        pause_page
    done
}
clean_page() {
    local choice="" before="" after=""
    while true; do
        page "系统清理" "清理软件包缓存与超过 14 天的归档日志。"
        read_view clean
        echo ""; echo "  1. 执行清理"; echo "  2. 刷新占用"; echo ""; echo "  0. 返回"
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
    echo ""
    echo "  o system-update          更新 VPS 软件包"
    echo "  o system-update-status   查看更新任务"
    echo "  o clean                  清理缓存与过期日志"
    echo "  o dns / o ip             DNS / 地址优先级"
    echo "  o tuning                 性能状态与连接设置"
    echo "  o language               系统语言"
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
        echo ""
        echo "  2. 普通卸载"
        text_block "   保留网站、数据库和共享软件"
        echo ""
        echo "  3. 完全卸载"
        text_block "   删除网站、数据库、面板及相关运行环境"
        echo ""; echo "  0. 返回"
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
        dim "  WordPress 建站与 VPS 日常维护"
        $BIN --info --config "$CFG" 2>/dev/null | sed -n 's/^版本: \([^ ]*\).*/  版本      \1/p'
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
                echo "  主要地址: https://$DOMAIN:$TLS_PORT/$SUFFIX"
                echo "  备用地址: https://$IP:$TLS_PORT/$SUFFIX（IP 访问可能有证书警告）"
            else
                [ -n "$TLS_PORT" ] && [ -n "$SUFFIX" ] && [ -n "$IP" ] && echo "  面板地址: https://$IP:$TLS_PORT/$SUFFIX"
            fi
        fi
        if systemctl is-active --quiet "$SVC"; then
            green "  运行状态: 运行中"
        else
            red "  运行状态: 未运行"
            dim "可在面板管理中运行诊断检查。"
        fi
        echo ""

}
network_menu() {
    local choice=""
    while true; do
        page "网络设置" "管理域名解析、地址选择优先级，或检测服务器出站连接。"
        read_view ip
        echo ""; echo "  1. DNS 设置与检测"; echo "  2. IPv4 / IPv6 优先级"; echo "  3. 网络连通性检测"; echo ""; echo "  0. 返回"
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
        echo ""; echo "  1. 时区与时间同步"; echo "  2. 系统语言"; echo ""; echo "  0. 返回"
        pick || return 0
        case "$choice" in 0) return 0;; 1) settings_page time;; 2) settings_page locale;; *) echo "无效选项"; pause_page;; esac
    done
}
panel_menu() {
    local choice=""
    while true; do
        page "面板管理"; panel_summary
        echo ""; echo "  1. 检查更新"; echo "  2. 更新 / 修复 OLS WPanel"; echo "  3. 运行诊断"
        echo "  4. 查看日志"; echo "  5. 重启面板"; echo "  6. 重置登录账号密码"; echo "  7. 清除面板 IP 封禁"; echo "  8. 面板详情"; echo ""; echo "  0. 返回"
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
        echo ""
        blue "  VPS 维护"
        if [ "$width" -ge 68 ]; then
            echo "  1. 系统信息              2. 软件包更新"
            echo ""
            echo "  3. 系统清理              4. 网络设置"
            echo ""
            echo "  5. 系统设置              6. 性能状态"
            echo ""
            blue "  面板与帮助"
            echo "  7. 面板管理              8. 帮助 / 高级操作"
        else
            echo "  1. 系统信息"; echo "  2. 软件包更新"
            echo ""
            echo "  3. 系统清理"; echo "  4. 网络设置"
            echo ""
            echo "  5. 系统设置"; echo "  6. 性能状态"
            echo ""
            blue "  面板与帮助"
            echo "  7. 面板管理"; echo "  8. 帮助 / 高级操作"
        fi
        echo ""
        echo "  0. 退出"
        pick 退出 || return 0
        case "$choice" in
          0) return 0;; 1) page "系统信息" "服务器资源、地址与时间。"; vps_info; pause_page;;
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
