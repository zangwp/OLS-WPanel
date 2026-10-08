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
audit_cli() {
    local outcome=success
    [ "$2" -eq 0 ] || outcome=failed
    if ! "$BIN" --vps-tool cli-audit --vps-value "$1:$outcome" --config "$CFG"; then
        echo "终端维护记录未保存；上述操作结果不变。" >&2
    fi
}

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
    local target current
    target=$(sed -n 's/^BOOTSTRAP_RELEASE_VERSION="\(v[0-9]*\.[0-9]*\.[0-9]*\)"$/\1/p' "$entry_file")
    if ! [[ "$target" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        red "入口目标版本无效，已拒绝执行"
        rm -f -- "$entry_file"; return 1
    fi
    echo "签名入口实际目标版本: $target"
    if [ "$action" = --repair ]; then
        current=$("$BIN" --info --config "$CFG" 2>/dev/null | sed -n 's/^版本: \([^ ]*\).*/\1/p')
        if release_is_newer "$current" "$target"; then
            red "当前版本 $current 高于短入口 $target，已阻止降级；请等待入口同步。"
            rm -f -- "$entry_file"; return 1
        fi
    fi
    bash "$entry_file" "$action"
    status=$?
    rm -f -- "$entry_file"
    [ "$action" != --repair ] || audit_cli update "$status"
    return "$status"
}
release_is_newer() {
    local left="${1#v}" right="${2#v}" a b c x y z
    [[ "$left" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$right" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS=. read -r a b c <<< "$left"; IFS=. read -r x y z <<< "$right"
    # Limit integer width before arithmetic; release tags are untrusted input.
    local part
    for part in "$a" "$b" "$c" "$x" "$y" "$z"; do [ "${#part}" -le 6 ] || return 1; done
    (( 10#$a > 10#$x || (10#$a == 10#$x && 10#$b > 10#$y) || (10#$a == 10#$x && 10#$b == 10#$y && 10#$c > 10#$z) ))
}

diag() {
    local issues=0 db="" endpoint="" port="" config_ready=0

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
    if ! command -v python3 >/dev/null 2>&1; then
        red "✗ 缺少 python3，无法解析配置或显示维护页面"
        issues=$((issues+1))
    elif [ -f "$CFG" ]; then
        if python3 - "$CFG" <<'PYDIAG' 2>/dev/null
import json,sys
with open(sys.argv[1]) as f: json.load(f)
PYDIAG
        then
            green "✓ 配置文件: $CFG"
            config_ready=1
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
    if [ "$config_ready" -eq 1 ]; then
        db=$(python3 - "$CFG" <<'PYDB' 2>/dev/null
import json,sys
with open(sys.argv[1]) as f: print(json.load(f).get('sqlite',{}).get('path',''))
PYDB
)
    if [ -n "$db" ] && [ -f "$db" ]; then
        green "✓ 数据库: $db"
    elif [ -n "$db" ]; then
        red "✗ 数据库文件不存在: $db"
        echo "   → 数据库文件丢失，检查磁盘空间或从备份恢复"
        issues=$((issues+1))
    else
        red "✗ 配置中未能读取数据库路径"
        issues=$((issues+1))
    fi
    fi

    # 4. systemd 服务文件
    if [ -f "/etc/systemd/system/${SVC}.service" ]; then
        green "✓ systemd 服务文件: /etc/systemd/system/${SVC}.service"
    else
        red "✗ systemd 服务文件缺失"
        echo "   → 修复: 重新运行 install.sh"
        issues=$((issues+1))
    fi

    # 5. 端口
    if [ "$config_ready" -eq 1 ]; then
        endpoint=$(python3 - "$CFG" <<'PYPORT' 2>/dev/null
import json,sys
with open(sys.argv[1]) as f: p=json.load(f)['panel']
tls=int(p.get('tls_port',0))>0 and bool(p.get('tls_cert_path')) and bool(p.get('tls_key_path'))
port=int(p.get('tls_port') if tls else p.get('port',0))
if not 1<=port<=65535:sys.exit(1)
print(('https' if tls else 'http')+' '+str(port))
PYPORT
)
        read -r _ port <<< "$endpoint"
        if ! command -v ss >/dev/null 2>&1; then
            red "✗ 缺少 ss（iproute2），无法检查监听端口"; issues=$((issues+1))
        elif [ -n "$port" ] && ss -H -ltn "sport = :$port" 2>/dev/null | grep -q .; then
            green "✓ 端口 ${port} 已监听"
        else
            red "✗ 面板端口 ${port:-未知} 未监听或读取失败"
            issues=$((issues+1))
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
    [ "$issues" -eq 0 ]
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
def section(title):print('\n  '+title+'\n  '+ '─'*min(WIDTH-4,52)+'\n')
def row(label,value):
    label=safe(label).replace('\n',' ')
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
def tool_status(action,value=''):
    out=run(binary,'--vps-tool',action,'--vps-value',value,'--config',cfg,timeout=25)
    if out is None:raise ValueError('状态读取失败，请查看命令错误或运行 o status')
    d=json.loads(out)
    if not isinstance(d,dict):raise ValueError('返回的状态格式无效')
    return d
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

if view=='login-addresses':
    try:
        p=json.loads(text(cfg))['panel']
        tls=int(p.get('tls_port',0))>0 and bool(p.get('tls_cert_path')) and bool(p.get('tls_key_path'))
        port=int(p.get('tls_port') if tls else p.get('port',0));suffix=p.get('random_suffix','')
        if not 1<=port<=65535 or not re.fullmatch(r'[A-Za-z0-9_-]+',suffix):raise ValueError('端口或安全入口无效')
        scheme='https' if tls else 'http';domain=''
        if tls:
            try:
                state=json.loads(text(str(pathlib.Path(p['tls_cert_path']).parent/'panel-tls-active.json')))
                if re.fullmatch(r'[A-Za-z0-9.-]+',state.get('domain','')):domain=state['domain']
            except (ValueError,TypeError):pass
        if domain:row('登录域名',f'{scheme}://{domain}:{port}/{suffix}')
        count=0
        for family in [4,6]:
            for address in interfaces(family):
                try:ip=ipaddress.ip_address(address)
                except ValueError:continue
                if ip.is_loopback or ip.is_link_local:continue
                host='['+address+']' if family==6 else address
                row(f'网卡 IPv{family}',f'{scheme}://{host}:{port}/{suffix}');count+=1
        if not count and not domain:note('未读取到网卡地址；使用服务器公网地址与端口 '+str(port)+' 访问。')
        note('网卡地址可能需要 NAT 映射或放行入站规则；出口地址可用 o network 检测。')
    except (ValueError,TypeError,KeyError):note('登录地址读取失败，请运行 o info / o status 检查。');sys.exit(1)
elif view=='info':
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
elif view in ['dns','dns-preset','dns-restore-ready']:
    try:
        d=dns_status()
        if view=='dns-restore-ready':sys.exit(0 if d.get('configurable') and d.get('restore_available') else 2)
        if view=='dns':
            dns_current(d)
            section('管理状态')
            row('修改权限','可通过终端设置' if d.get('configurable') else '只读 · 可检测候选 DNS')
            row('管理方式',{'static-resolv.conf':'普通 resolv.conf（尚未接管）','ols-resolv.conf':'OLS WPanel 管理的 resolv.conf','systemd-resolved':'systemd-resolved','NetworkManager':'NetworkManager','resolvconf':'resolvconf','cloud-init':'cloud-init','dhcp':'DHCP 客户端','netplan':'netplan','auto-generated':'外部生成的配置','symbolic-link':'其他符号链接','unavailable':'配置不可读取','unknown':'未确认'}.get(d.get('manager'),d.get('manager') or '未确认'))
            if d.get('takeover_required'):note('首次应用将备份当前文件，替换 nameserver 行，保留 search/options。若文件被锁定，修改时临时解除后恢复原锁定状态。')
            if d.get('immutable'):row('文件锁定','immutable；应用前需确认')
            if d.get('restore_available'):row('恢复配置','已保存接管前配置，可在下方恢复')
            if not d.get('configurable'):note('本页不接管系统 DNS。'+d.get('reason',''))
        else:
            preset=next((p for p in d.get('presets',[]) if p.get('id')==value),None)
            if not preset:raise ValueError('候选方案不存在')
            section({'international':'Cloudflare','mainland_china':'阿里云'}.get(value,value)+' · 候选地址')
            dns_rows(preset['ipv4']+preset['ipv6'])
            note('以上为候选方案，查看或检测不会更换当前 DNS。')
            section('操作条件')
            row('终端修改权限','可用' if d.get('configurable') else '只读，仅可检测')
            row('IPv6 默认路由','存在，仍需检测 DNS' if d.get('ipv6_available') else '未检测到')
        if d.get('max_servers'):row('DNS 地址数量上限',d['max_servers'])
        if d.get('warning'):note(d['warning'])
        if not d.get('configurable'):sys.exit(2)
    except (ValueError,OSError,subprocess.TimeoutExpired) as e:note('读取失败：'+str(e));sys.exit(1)
elif view in ['dns-test','dns-custom-test']:
    try:result=subprocess.run([binary,'--vps-tool',view,'--vps-value',value,'--config',cfg],capture_output=True,text=True,timeout=70)
    except (OSError,subprocess.TimeoutExpired):print('DNS 检测未完成：命令不可用或超时');sys.exit(1)
    try:
        d=json.loads(result.stdout);section('候选 DNS 检测结果');row('IPv4 DNS 查询','通过' if d.get('ipv4_probe_ok') else '失败')
        row('IPv6 DNS 查询','未测试：无默认路由' if d.get('ipv6_skipped') else ('通过' if d.get('ipv6_probe_ok') else '失败'))
    except ValueError: row('检测结果','无法读取')
    if result.returncode:print(safe(result.stderr));sys.exit(1)
elif view in ['swap','swap-actions']:
    try:
        out=value or run(binary,'--vps-tool','swap-status','--config',cfg,timeout=20)
        if out is None:raise ValueError('状态命令失败，可使用 o status 排查')
        d=json.loads(out)
        if not isinstance(d,dict) or d.get('supported') is not True:raise ValueError('当前系统不支持 Swap 管理')
        if view=='swap-actions':
            print(int(bool(d.get('recommendation_satisfied') or d.get('can_manage'))),int(bool(d.get('can_manage'))),int(bool(d.get('managed_file'))))
        else:
            section('当前状态')
            row('Swap 使用 / 容量',usage(d.get('used_bytes',0),d.get('total_bytes',0)) if d.get('total_bytes') else '未配置')
            available=d.get('memory_available_bytes',0)
            row('可用内存',size(available) if available>0 else '不可用或不可确认；停用活动 Swap 会被拒绝')
            row('swappiness',d.get('swappiness'))
            section('建议配置')
            row('建议总容量',size(d.get('recommended_bytes',0)))
            row('建议 swappiness',d.get('recommended_swappiness'))
            row('活动 WordPress',str(d.get('active_wordpress_sites',0))+' 个' if d.get('workload_known') else '未知，建议按保守基线计算')
            row('容量建议','已满足' if d.get('recommendation_satisfied') else '未满足')
            note('已有容量满足建议时，只调整 swappiness，不新建文件。')
            section('Swap 来源')
            for entry in d.get('entries') or []:
                row(entry.get('filename') or '未知路径',usage(entry.get('used_bytes',0),entry.get('size_bytes',0)))
                note({'zram':'zram','partition':'分区','file':'文件'}.get(entry.get('type'),'未知类型')+(' · OLS WPanel 管理' if entry.get('managed') else ' · 外部管理'))
            if not d.get('entries'):note('未发现启用的 Swap。')
            row('受管文件',size(d.get('managed_size_bytes',0)) if d.get('managed_file') else '无')
            if not d.get('can_manage'):note(d.get('manage_reason') or '不能创建或调整受管 Swap 文件。')
            print('');note('只管理 OLS WPanel 标记的 /swapfile；保留已有分区、zram 和外部文件。')
    except (ValueError,TypeError,OSError) as e:note('Swap 读取失败：'+str(e));sys.exit(1)
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
    note('分别测试 Cloudflare 和 GitHub 的 HTTPS 出站访问；不能据此判定入站端口已放行。')
    if not shutil.which('curl'):note('缺少 curl，无法执行出站检测。');sys.exit(1)
    successes=0
    for family in [4,6]:
        section(f'IPv{family}')
        row('网卡地址',addresses(family));row('默认路由',route(family))
        out=run('curl','-q',f'-{family}','-fsS','--connect-timeout','4','--max-time','6','https://www.cloudflare.com/cdn-cgi/trace',timeout=8)
        ip=re.search(r'(?m)^ip=(.+)$',out or '')
        row('访问结果','成功' if out is not None else '失败或超时');row('出口地址',ip.group(1) if ip else None)
        second=run('curl','-q',f'-{family}','-fIsS','--connect-timeout','4','--max-time','6','https://github.com',timeout=8)
        row('GitHub HTTPS','成功' if second is not None else '失败或超时')
        successes+=int(out is not None or second is not None)
    if not successes:sys.exit(1)
elif view in ['tuning','queues','queue-menu']:
    queue_values=[run('sysctl','-n',k) for k in ['net.core.somaxconn','net.ipv4.tcp_max_syn_backlog']]
    if view=='tuning':
        section('实时资源')
        row('CPU',str(os.cpu_count())+' 核 · '+str(cpu_usage() or '使用率未知'))
        row('负载 1/5/15 分',' / '.join(f'{x:.2f}' for x in os.getloadavg()));memory_rows()
        section('网络参数')
        row('拥塞控制',run('sysctl','-n','net.ipv4.tcp_congestion_control'));row('队列规则',run('sysctl','-n','net.core.default_qdisc'))
    else:section('当前连接配置')
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
        if view=='queues':
            row('恢复记录','已保存有效原值' if can_restore else '无有效记录')
            print('');note('两项上限不代表在线人数，也不能判断网页快慢。')
        print('');note('默认保留当前值。仅在明确需要调整连接排队时修改。')
        if not can_restore:sys.exit(2)
elif view=='queue-change':
    keys=['net.core.somaxconn','net.ipv4.tcp_max_syn_backlog']
    if value=='default':
        try:targets=json.loads(text('/etc/sysctl.d/.ols-wpanel-vps-original.json'))
        except ValueError:note('无法读取恢复记录，已取消。');sys.exit(1)
    else:targets=dict.fromkeys(keys,{'balanced':'4096','website':'8192'}.get(value,''))
    if not isinstance(targets,dict) or not all(re.fullmatch(r'[0-9]+',str(targets.get(k,''))) for k in keys):
        note('目标值无效，已取消。');sys.exit(1)
    section('当前值 → 将修改为')
    lowered=False
    for label,key in zip(['待接收连接上限','半连接队列上限'],keys):
        current=run('sysctl','-n',key)
        if current is None or not current.isdigit():note('当前值读取失败，已取消。');sys.exit(1)
        row(label,current+' → '+str(targets[key]))
        lowered=lowered or int(targets[key])<int(current)
    print('')
    if lowered:note('注意：本次会降低现有队列上限。')
    note('只修改这两项内核参数，不会自动加快网页加载。')
elif view=='locale':
    section('语言环境')
    row('当前 SSH 会话语言',os.environ.get('LC_ALL') or os.environ.get('LANG'))
    defaults=text('/etc/default/locale');match=re.search(r'(?m)^LANG=[\"\']?([^\"\'\n]+)',defaults)
    row('系统默认语言',match.group(1) if match else None)
    row('语言生成工具','已安装' if shutil.which('locale-gen') else '未安装 locales 软件包；设置暂不可用')
    if not shutil.which('locale-gen') or not shutil.which('update-locale'):sys.exit(2)
elif view=='time':
    section('系统时钟')
    d=properties('timedatectl','show');row('时区',d.get('Timezone'));row('本地时间',run('date','+%Y-%m-%d %H:%M:%S %Z'))
    row('自动校时',{'yes':'已开启','no':'未开启'}.get(d.get('NTP'),'未检测到'))
    row('同步状态',{'yes':'已同步','no':'尚未同步'}.get(d.get('NTPSynchronized'),'未检测到'))
    providers=[];seen=set();active=[]
    for unit in ['chrony.service','systemd-timesyncd.service','ntpsec.service','ntp.service']:
        props=properties('systemctl','show',unit,'--property=Id,LoadState,ActiveState')
        identity=props.get('Id') or unit
        if props.get('LoadState')=='loaded' and identity not in seen:
            seen.add(identity);running=props.get('ActiveState')=='active'
            providers.append((not running,identity+'：'+{'active':'运行中','inactive':'未运行','failed':'失败'}.get(props.get('ActiveState'),'未知')))
            if running:active.append(identity)
    row('当前校时服务','；'.join(active) or '未检测到活动服务')
    row('已安装时间服务','；'.join(item[1] for item in sorted(providers)) or '未检测到')
    if len(active)>1:note('同时运行多套校时服务；请先检查冲突，自动校时操作会拒绝选择。')
elif view=='timezones':
    section('可用时区')
    zones=run('timedatectl','list-timezones',timeout=15)
    if zones is None:note('无法读取系统可用时区。');sys.exit(1)
    note(zones)
elif view=='hostname':
    section('主机名');row('静态主机名',run('hostnamectl','--static'));row('当前主机名',platform.node())
    note('修改静态主机名，不修改 /etc/hosts 或 DNS 记录。')
elif view in ['ports','services','service-log','bbr','history','ssh','ssh-start','ssh-confirm']:
    try:
        actions={'ports':'ports-status','services':'services-status','service-log':'service-log','bbr':'bbr-status','history':'vps-history','ssh':'ssh-port-status'}
        d=json.loads(value) if view in ['ssh-start','ssh-confirm'] else tool_status(actions[view],value)
        if view=='ports':
            section('入站与监听');row('防火墙后端',d.get('backend'));row('入站默认策略',d.get('input_policy'))
            row('SSH / 面板端口',str(d.get('ssh_port','?'))+' / '+str(d.get('panel_port','?')))
            if d.get('warning'):note(d['warning'])
            section('本机监听')
            for item in d.get('listeners') or []:
                row(str(item.get('protocol',''))+' '+str(item.get('port','')),str(item.get('address',''))+' · '+str(item.get('process') or '进程未读取'))
                scope={'local':'本机回环','network':'网络接口'}.get(item.get('bind_scope'),'未知')
                exposure={'local_only':'仅本机','allowed_by_default':'默认允许入站','rule_dependent':'需核对具体规则'}.get(item.get('host_exposure'),'未知')
                note('绑定：'+scope+'；主机策略：'+exposure)
            if not d.get('listeners'):note('未读取到监听端口；请检查 ss 和权限。')
            note('以上是本机状态。云安全组、供应商防火墙和公网可达性需另行检查。')
        elif view=='services':
            section('核心服务')
            for item in d.get('services') or []:
                state={'active':'运行中','inactive':'未运行','failed':'失败','activating':'正在启动'}.get(item.get('active_state'),'未知')
                if item.get('load_state')=='not-found':state='未安装'
                row(item.get('name','服务'),state+' · '+str(item.get('sub_state') or '状态未知'))
                row('开机启动',{'enabled':'已启用','disabled':'未启用','static':'静态服务'}.get(item.get('unit_file_state'),item.get('unit_file_state')))
                if item.get('error'):note(item['error'])
        elif view=='service-log':
            section('最近服务日志 · '+str(d.get('unit','')))
            for line in d.get('lines') or []:note(line)
        elif view=='bbr':
            section('实际内核状态');row('拥塞控制',d.get('algorithm'));row('默认队列',d.get('queue_discipline'))
            row('内核可用算法',' / '.join(d.get('available_algorithms') or []));section('持久配置')
            for item in d.get('persistent') or []:
                note(str(item.get('path',''))+(' · 面板配置' if item.get('managed') else ' · 外部配置'))
                row('配置值',str(item.get('algorithm') or '未设置算法')+' / '+str(item.get('queue_discipline') or '未设置队列'))
            if not d.get('persistent'):note('未发现相关持久配置；当前值不代表重启后仍保持。')
            for error in d.get('errors') or []:note(error)
            note('这里只读检查，不安装内核或自动切换拥塞控制。')
        elif view=='history':
            section('终端维护记录 · 最近 200 条')
            for item in d.get('entries') or []:
                row(item.get('at','时间'),str(item.get('action',''))+' '+str(item.get('value','')))
                note({'success':'成功','failed':'失败','started':'当时已启动后台任务','pending':'发起时等待确认','cancelled':'已取消'}.get(item.get('status'),str(item.get('status','')))+' · '+str(item.get('message','')))
            if not d.get('entries'):note('尚无终端维护记录。')
            note('这是操作时的记录；更新结果请用 o system-update-status，SSH 当前状态请用 o ssh。')
        elif view=='ssh':
            section('SSH 端口');row('当前端口',d.get('port'));row('修改权限','可用' if d.get('available') else '不可用')
            if d.get('reason'):note(d['reason'].replace('请先应用上方端口访问策略','请先在网页安全中心配置端口访问策略，再刷新本页'))
            if d.get('pending'):note('已有待确认的双端口变更，请先确认或等待自动恢复。')
            if not d.get('available') or d.get('pending'):sys.exit(2)
        elif view=='ssh-start':
            section('双端口过渡已启动');row('原端口 → 新端口',str(d.get('old_port'))+' → '+str(d.get('new_port')))
            row('确认截止时间',d.get('deadline'));note('保持本窗口连接，用新端口另开 SSH 窗口，再在新窗口执行：')
            note(d.get('confirm_command') or '确认命令未返回，请等待自动恢复。')
            note('确认成功才关闭旧端口；未确认或失败会由独立守护任务恢复。')
        else:section('SSH 变更确认');row('新端口',d.get('new_port'));note(d.get('message') or '已完成')
    except (ValueError,TypeError,KeyError) as e:note('读取失败：'+str(e));sys.exit(1)
elif view=='disk':
    section('磁盘空间与 inode')
    seen=set();failed=False
    for path in ['/','/www','/var']:
        if path!='/' and not os.path.exists(path):continue
        try:
            device=os.stat(path).st_dev
            if device in seen:continue
            seen.add(device);disk=shutil.disk_usage(path);st=os.statvfs(path)
            row('检查路径',path);row('已用空间',usage(disk.used,disk.total));row('可用空间',size(disk.free))
            row('inode',f'{st.f_files-st.f_ffree} / {st.f_files} ({(1-st.f_ffree/st.f_files)*100:.1f}%)' if st.f_files else '文件系统未提供')
            if disk.total and disk.used/disk.total>=.85:note('空间使用达到 85%，请检查日志、备份和网站文件。')
            if st.f_files and st.f_ffree/st.f_files<=.1:note('inode 剩余不足 10%，大量小文件也可能导致写入失败。')
        except OSError as e:note(path+' 检查失败：'+str(e));failed=True
    if failed:sys.exit(1)
elif view=='apt-health':
    section('APT / dpkg 健康检查')
    failed=False
    for label,args in [('未完成的软件包配置',('dpkg','--audit')),('依赖检查（模拟）',('apt-get','-s','-o','Debug::NoLocking=1','check')),('锁定版本的软件包',('apt-mark','showhold'))]:
        out=run(*args,timeout=20)
        if out is None:row(label,'检查失败，请在 SSH 中查看该命令错误');failed=True
        else:row(label,out or '未发现异常 / 记录')
    section('正在运行的软件包进程')
    processes=run('ps','-eo','pid,comm')
    found=[line.strip() for line in (processes or '').splitlines() if re.search(r'\s(?:apt|apt-get|dpkg|unattended-upgr)$',line)]
    note('\n'.join(found) or '未发现（仅为本次快照）')
    section('软件包索引')
    try:
        stamps=[p.stat().st_mtime for p in pathlib.Path('/var/lib/apt/lists').glob('*_Packages*') if p.is_file()]
        row('最近索引文件',datetime.datetime.fromtimestamp(max(stamps)).astimezone().isoformat(timespec='seconds') if stamps else '未读取到索引')
    except OSError:row('最近索引文件','读取失败')
    note('只读检查；不会结束软件包进程、删除锁文件或自动修复。')
    if failed:sys.exit(1)
elif view=='dependencies':
    section('维护工具依赖')
    missing=[]
    for cmd,package in [('python3','python3'),('ip','iproute2'),('ss','iproute2'),('curl','curl'),('systemctl','systemd'),('timedatectl','systemd'),('sysctl','procps'),('journalctl','systemd'),('locale-gen','locales'),('update-locale','locales')]:
        available=bool(shutil.which(cmd));row(cmd,'已安装' if available else '缺少 · 软件包 '+package)
        if not available:missing.append(package)
    if missing:note('可在系统软件更新前检查这些依赖：'+', '.join(dict.fromkeys(missing)))
    note('本页不会安装软件；locales 可在“系统语言”中确认安装。')
elif view in ['updates','update-status','update-details']:
    if view=='updates':
        section('可用软件包更新')
        out=run('env','LC_ALL=C','apt','list','--upgradable',timeout=20)
        if out is None:row('软件包列表','读取失败')
        else:
            packages=[x for x in out.splitlines() if '/' in x and '[upgradable' in x]
            row('可更新软件包',len(packages));row('安全源更新',sum('-security' in x.split()[0] for x in packages))
            print('');note('根据本机 APT 索引；执行更新时会刷新。')
    out=run(binary,'--vps-tool','system-update-status','--config',cfg,timeout=15)
    try:
        if out is None:raise ValueError('任务读取失败')
        d=json.loads(out);status=d.get('status');remaining=d.get('remaining_count',0);section('正在执行的任务' if status=='running' else '最近一次更新记录（历史）')
        outcome={'idle':'尚无任务','running':'执行中','success':'成功','succeeded':'成功','failed':'失败','completed':'已完成'}.get(status,status)
        if remaining and status=='success':outcome='本轮完成，仍有待更新软件包'
        row('任务结果',outcome)
        if remaining:row('剩余待更新',str(remaining)+' 个')
        row('执行阶段',{'queued':'排队中','services_preflight':'更新前服务检查','refresh':'刷新软件包索引','upgrade':'安装软件包更新','services':'更新后服务检查','remaining':'复查剩余更新','complete':'完成','interrupted':'任务中断'}.get(d.get('stage'),d.get('stage')))
        if d.get('updated_at'):
            try:when=datetime.datetime.fromisoformat(d['updated_at'].replace('Z','+00:00')).astimezone().strftime('%Y-%m-%d %H:%M:%S %z')
            except (ValueError,TypeError):when=d['updated_at']
            row('记录时间',when)
        if status=='failed' and d.get('stage')=='services_preflight':
            print('');note('软件包更新尚未开始：更新前检查未通过。')
        if view=='update-details' and d.get('detail'):
            section('剩余软件包' if remaining else ('错误原因' if status=='failed' else '任务详情'))
            if 'acme-challenge' in d['detail'] and 'not accessible' in d['detail']:
                note('OpenLiteSpeed 无法访问证书验证目录。');print('')
            note(d['detail'])
    except ValueError:row('更新任务','读取失败')
    if view=='update-details':
        section('软件包列表（本机索引）')
        note(run('env','LC_ALL=C','apt','list','--upgradable',timeout=20) or '读取失败')
    elif view=='updates':
        print('');note('这是上次任务的记录。失败原因请选“查看详细记录”。')
    print('')
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
swap_apply() {
    local status=""
    if status=$("$BIN" --vps-tool "$1" --vps-value "${2:-}" --config "$CFG"); then
        if read_view swap "$status"; then green "Swap 设置已完成。"; else red "设置命令已完成，但无法显示更新后的状态；请刷新检查。"; fi
    else
        red "Swap 设置失败，请查看上方原因。"
        return 1
    fi
}
swap_page() {
    local choice="" status="" actions="" recommended_ready=0 custom_ready=0 remove_ready=0
    local size_mb="" swappiness="" confirm=""
    while true; do
        page "Swap 管理" "查看内存交换空间，按需设置；修改前请确认当前容量和来源。"
        if ! status=$("$BIN" --vps-tool swap-status --config "$CFG"); then
            red "Swap 状态读取失败，未提供修改操作。"
            pause_page; return 1
        fi
        if ! read_view swap "$status"; then pause_page; return 1; fi
        actions=$(read_view swap-actions "$status") || return 1
        read -r recommended_ready custom_ready remove_ready <<< "$actions"
        echo ""; echo "  1. 刷新状态"
        [ "$recommended_ready" != 1 ] || echo "  2. 应用建议配置"
        [ "$custom_ready" != 1 ] || echo "  3. 自定义 Swap 文件容量"
        echo "  4. 仅设置 swappiness"
        [ "$remove_ready" != 1 ] || echo "  5. 删除受管 Swap 文件"
        echo ""; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;;
          1) continue;;
          2)
            if [ "$recommended_ready" != 1 ]; then echo "当前不可应用建议配置"; pause_page; continue; fi
            if need_root && confirm_vps "应用上方建议配置？已有 Swap 满足容量时仅调整 swappiness，否则创建或调整受管 /swapfile。"; then
                swap_apply swap-recommended
            else echo "已取消"; fi
            ;;
          3)
            if [ "$custom_ready" != 1 ]; then echo "当前不可创建或调整受管文件"; pause_page; continue; fi
            need_root || { pause_page; continue; }
            text_block "输入 /swapfile 的容量（MB）：512–8192，按 256 递增；已有其他 Swap 不计入此值。"
            read -r -p "  文件容量 MB [回车取消]: " size_mb < /dev/tty || return 0
            if [[ ! "$size_mb" =~ ^[0-9]{3,4}$ ]] || [ "$((10#$size_mb))" -lt 512 ] || [ "$((10#$size_mb))" -gt 8192 ] || [ "$((10#$size_mb % 256))" -ne 0 ]; then
                echo "已取消：容量须为 512–8192 MB，按 256 递增。"; pause_page; continue
            fi
            read -r -p "  swappiness 1–100 [回车取消]: " swappiness < /dev/tty || return 0
            if [[ ! "$swappiness" =~ ^[0-9]{1,3}$ ]] || [ "$((10#$swappiness))" -lt 1 ] || [ "$((10#$swappiness))" -gt 100 ]; then
                echo "已取消：swappiness 须为 1–100。"; pause_page; continue
            fi
            if confirm_vps "将受管 /swapfile 设置为 $size_mb MB，swappiness 设置为 $swappiness？执行时会重新检查磁盘与可用内存。"; then
                swap_apply swap-custom "$size_mb:$swappiness"
            else echo "已取消"; fi
            ;;
          4)
            need_root || { pause_page; continue; }
            text_block "swappiness 影响整个系统使用 Swap 的倾向；本操作不改变容量。"
            read -r -p "  swappiness 1–100 [回车取消]: " swappiness < /dev/tty || return 0
            if [[ ! "$swappiness" =~ ^[0-9]{1,3}$ ]] || [ "$((10#$swappiness))" -lt 1 ] || [ "$((10#$swappiness))" -gt 100 ]; then
                echo "已取消：swappiness 须为 1–100。"; pause_page; continue
            fi
            if confirm_vps "将系统 swappiness 设置为 $swappiness？"; then swap_apply swap-swappiness "$swappiness"; else echo "已取消"; fi
            ;;
          5)
            if [ "$remove_ready" != 1 ]; then echo "没有可删除的受管文件"; pause_page; continue; fi
            need_root || { pause_page; continue; }
            text_block "只删除 OLS WPanel 管理的 /swapfile，并检查可用内存。保留已有分区、zram、外部文件及当前 swappiness。"
            read -r -p "  输入 REMOVE SWAP 确认删除 [回车取消]: " confirm < /dev/tty || return 0
            if [ "$confirm" = 'REMOVE SWAP' ]; then swap_apply swap-remove "$confirm"; else echo "已取消"; fi
            ;;
          *) echo "无效选项";;
        esac
        pause_page
    done
}
result() {
    local status=0
    "$@" || status=$?
    if [ "$status" -eq 0 ]; then green "操作已完成。"; else red "操作失败，请查看上方原因。"; fi
    return "$status"
}
settings_page() {
    local kind="$1" choice="" action="" value="" note="" dns_ready=1 ip_ready=1 queue_ready=1 locale_ready=1
    while true; do
        case "$kind" in
          dns)
            page "DNS" "查看当前解析服务器，或检测候选方案。"
            dns_ready=1
            read_view dns || dns_ready=0
            echo ""
            echo "  1. Cloudflare · 查看 / 检测"
            echo "  2. 阿里云     · 查看 / 检测"
            if [ "$dns_ready" -eq 1 ] && read_view dns-restore-ready; then echo "  3. 恢复系统 / 接管前 DNS 配置"; fi
            echo "  4. 自定义 DNS · 查看 / 检测"
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
            page "高级设置 · 连接队列" "手动调整内核参数，不会自动优化网站。"
            queue_ready=1
            read_view queue-menu || queue_ready=0
            echo ""
            echo "  1. 两项上限设为 4096 / 4096"
            echo ""
            echo "  2. 两项上限设为 8192 / 8192"
            echo ""
            echo "  3. 查看当前参数与恢复详情"
            if [ "$queue_ready" -eq 1 ]; then echo "  4. 恢复修改前的值"; fi
            ;;
          locale)
            page "系统语言" "影响系统命令提示与新 SSH 会话，网页面板语言单独设置。"
            locale_ready=1; read_view locale || locale_ready=0
            if [ "$locale_ready" -eq 1 ]; then
                echo ""; echo "  1. English · en_US.UTF-8"; echo "  2. 简体中文 · zh_CN.UTF-8"; echo "  3. 繁體中文 · zh_TW.UTF-8"
            else echo ""; echo "  4. 安装 locales 语言工具"; fi
            ;;
          time)
            page "时区与时间同步" "时区影响日志和定时任务的本地时间；自动校时用于保持服务器时钟准确。"
            read_view time
            echo ""; echo "  1. 时区设为 UTC"; echo "  2. 时区设为 Asia/Shanghai"; echo "  3. 启动自动校时"
            echo "  4. 输入其他 IANA 时区"; echo "  5. 查看系统可用时区"
            text_block "   缺少服务时安装 systemd-timesyncd"
            ;;
          hostname)
            page "主机名"; read_view hostname
            echo ""; echo "  1. 修改静态主机名"
            ;;
        esac
        echo ""; echo "  0. 返回"
        pick || return 0
        if [ "$kind" = dns ] && [ "$dns_ready" -eq 0 ] && [ "$choice" = 3 ]; then
            echo "当前 DNS 不满足安全修改条件，请查看上方管理方式与原因。"; pause_page; continue
        fi
        if [ "$kind" = ip ] && [ "$ip_ready" -eq 0 ] && [[ "$choice" =~ ^[12]$ ]]; then
            echo "  已有其他地址选择规则，无法自动覆盖。"; pause_page; continue
        fi
        if [ "$kind" = tuning ] && [ "$queue_ready" -eq 0 ] && [ "$choice" = 4 ]; then
            echo "  无有效恢复记录，未执行修改。"; pause_page; continue
        fi
        if [ "$kind" = locale ] && [ "$locale_ready" -eq 0 ] && [[ "$choice" =~ ^[123]$ ]]; then
            echo "缺少语言生成工具，请先确认安装 locales。"; pause_page; continue
        fi
        if [ "$kind" = locale ] && [ "$locale_ready" -eq 1 ] && [ "$choice" = 4 ]; then
            echo "语言工具已可用，无需重复安装。"; pause_page; continue
        fi
        action=""; value=""; note=""
        case "$kind:$choice" in
          *:0) return 0;;
          dns:1|dns:2)
            [ "$choice" = 1 ] && value=international || value=mainland_china
            dns_preset_page "$value"; continue;;
          dns:3)
            if ! read_view dns-restore-ready; then echo "没有可用的恢复记录。"; pause_page; continue; fi
            action=dns; value=default; note="恢复此前保存的 DNS 配置：普通文件恢复接管前内容，systemd-resolved 移除面板覆盖。";;
          dns:4) dns_custom_page; continue;;
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
          locale:4) action=locale-install; note="通过 APT 安装 locales 及必要依赖？仅安装语言工具，随后重新选择语言。";;
          time:1) action=timezone; value=UTC; note="时区设为 UTC，会影响按本地时间执行的计划任务。";;
          time:2) action=timezone; value=Asia/Shanghai; note="时区设为 Asia/Shanghai，会影响按本地时间执行的计划任务。";;
          time:3) action=time-sync; note="启用已有校时服务；缺少时安装 systemd-timesyncd，随后检查同步状态。";;
          time:4)
            read -r -p "  IANA 时区（如 Europe/London）[回车取消]: " value < /dev/tty || return 0
            [ -n "$value" ] || { echo "已取消"; pause_page; continue; }
            action=timezone; note="将时区设为 $value？执行前会校验系统可用时区，会影响日志和按本地时间执行的计划任务。";;
          time:5) page "系统可用时区"; read_view timezones; pause_page; continue;;
          hostname:1)
            read -r -p "  新静态主机名 [回车取消]: " value < /dev/tty || return 0
            [ -n "$value" ] || { echo "已取消"; pause_page; continue; }
            action=hostname; note="将静态主机名设为 $value？不修改 /etc/hosts 或 DNS 记录。";;
          *) echo "无效选项"; pause_page; continue;;
        esac
        if [ "$kind" = tuning ]; then
            page "连接队列 · 确认变更"
            if ! read_view queue-change "$value"; then pause_page; continue; fi
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
            if need_root && confirm_vps "应用候选 DNS？执行前检测地址；首次管理普通 resolv.conf 会备份并替换 nameserver，保留 search/options，临时解除文件锁后恢复原锁定状态。"; then
                result "$BIN" --vps-tool dns --vps-value "$preset" --config "$CFG"
                read_view dns || true
            else echo "  已取消"; fi
            pause_page;;
          *) echo "  无效选项"; pause_page;;
        esac
    done
}
dns_custom_page() {
    local value="" choice="" ready=1
    text_block "输入 DNS IP 地址，以逗号分隔；普通 resolv.conf 最多 3 个，systemd-resolved 最多 4 个。每个指定地址都须通过检测。"
    read -r -p "  DNS 地址 [回车取消]: " value < /dev/tty || return 0
    [ -n "$value" ] || return 0
    while true; do
        page "自定义 DNS"; text_block "$value"
        ready=1; read_view dns || ready=0
        echo ""; echo "  1. 检测指定 DNS"
        [ "$ready" -ne 1 ] || echo "  2. 应用（全部检测通过后）"
        echo "  0. 返回 DNS"; pick || return 0
        case "$choice" in
          0) return 0;;
          1) read_view dns-custom-test "$value"; pause_page;;
          2)
            if [ "$ready" -ne 1 ]; then echo "当前不支持安全修改 DNS。"; pause_page; continue; fi
            if need_root && confirm_vps "将 DNS 设置为 $value？首次管理普通 resolv.conf 会备份原文件，保留 search/options 和原锁定状态；检测失败时不应用。"; then
                result "$BIN" --vps-tool dns-custom --vps-value "$value" --config "$CFG"
                read_view dns || true
            else echo "已取消"; fi
            pause_page;;
          *) echo "无效选项"; pause_page;;
        esac
    done
}
services_page() {
    local choice="" service=""
    while true; do
        page "核心服务检查" "状态与日志均为只读，不会重启服务。"; read_view services
        echo ""; echo "  1. 刷新状态"; echo "  2. 面板日志"; echo "  3. OpenLiteSpeed 日志"
        echo "  4. MariaDB 日志"; echo "  5. Redis 日志"; echo "  6. Fail2ban 日志"; echo "  7. nftables 日志"; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) continue;; 2) service=panel;; 3) service=ols;; 4) service=mariadb;;
          5) service=redis;; 6) service=fail2ban;; 7) service=nftables;; *) echo "无效选项"; pause_page; continue;;
        esac
        page "服务日志"; read_view service-log "$service"; pause_page
    done
}
ssh_page() {
    local choice="" ready=1 port="" client_ip="" client_port="" server_ip="" server_port="" extra="" status=""
    while true; do
        page "SSH 端口" "使用双端口过渡；必须在新 SSH 连接确认，超时自动恢复。"
        ready=1; read_view ssh || ready=0
        echo ""; echo "  1. 刷新状态"; [ "$ready" -ne 1 ] || echo "  2. 发起端口变更"; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) continue;;
          2)
            if [ "$ready" -ne 1 ]; then echo "当前不满足安全变更条件。"; pause_page; continue; fi
            need_root || { pause_page; continue; }
            read -r client_ip client_port server_ip server_port extra <<< "${SSH_CONNECTION:-}"
            if [ -z "$client_ip" ] || [ -z "$server_port" ] || [ -n "$extra" ]; then
                echo "请通过真实 SSH 连接执行，无法从当前会话确认客户端和端口。"; pause_page; continue
            fi
            read -r -p "  新 SSH 端口 1–65535 [回车取消]: " port < /dev/tty || return 0
            if [[ ! "$port" =~ ^[0-9]{1,5}$ ]] || [ "$((10#$port))" -lt 1 ] || [ "$((10#$port))" -gt 65535 ]; then
                echo "已取消：端口须为 1–65535。"; pause_page; continue
            fi
            if confirm_vps "将 SSH 从当前端口过渡到 $port？保持本窗口，另开新端口连接后执行确认命令；未确认会自动恢复。云安全组需先放行新端口。"; then
                if status=$("$BIN" --vps-tool ssh-port-start --vps-value "$port:$client_ip" --config "$CFG"); then read_view ssh-start "$status";
                else red "端口变更未成功启动，请查看上方原因。"; fi
            else echo "已取消"; fi
            pause_page;;
          *) echo "无效选项"; pause_page;;
        esac
    done
}
ssh_confirm() {
    local status=""
    need_root || return 1
    [ -n "${1:-}" ] || { echo "用法：o ssh-confirm 确认令牌（在新端口 SSH 连接中执行）"; return 1; }
    status=$("$BIN" --vps-tool ssh-port-confirm --vps-value "$1" --config "$CFG") || return $?
    read_view ssh-confirm "$status"
}
performance_menu() {
    local choice=""
    while true; do
        page "性能状态" "只读查看；刷新不会修改配置。"
        read_view tuning
        echo ""; echo "  1. 刷新状态"; echo "  2. 高级设置 · 调整连接队列"; echo "  3. 核心服务检查"; echo "  4. 磁盘空间与 inode"; echo ""; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) continue;; 2) settings_page tuning;; 3) services_page;; 4) page "磁盘检查"; read_view disk; pause_page;;
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
          1) if need_root && confirm_vps "更新 VPS 软件包，不更新面板、不自动重启服务器。"; then
                if "$BIN" --vps-tool system-update --config "$CFG"; then green "后台更新任务已启动，完成结果请查看进度。";
                else red "更新任务未成功启动，请查看上方原因。"; fi
             else echo "已取消"; fi;;
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
                if ! result "$BIN" --vps-tool clean --config "$CFG"; then pause_page; continue; fi
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
    python3 - "$current" "$ENTRY_URL" <<'PYUPDATE'
import json,re,sys,urllib.request
def version(s):
 if not isinstance(s,str) or not re.fullmatch(r'v?[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}',s):return None
 return tuple(map(int,s.lstrip('v').split('.')))
current=sys.argv[1];latest=entry=None;errors=[]
try:
 request=urllib.request.Request('https://api.github.com/repos/zangwp/OLS-WPanel/releases/latest',headers={'User-Agent':'OLS-WPanel'})
 with urllib.request.urlopen(request,timeout=15) as response: latest=json.load(response)['tag_name']
 if version(latest) is None:raise ValueError('GitHub 发布版本格式无效')
except Exception as error:errors.append('GitHub 发布读取失败：'+str(error));latest=None
try:
 request=urllib.request.Request(sys.argv[2],method='HEAD',headers={'User-Agent':'OLS-WPanel'})
 with urllib.request.urlopen(request,timeout=15) as response:entry=response.headers.get('X-OLS-WPanel-Release')
 if version(entry) is None:raise ValueError('签名入口未返回有效目标版本')
except Exception as error:errors.append('签名入口版本读取失败：'+str(error));entry=None
print('当前安装版本: '+(current or '未读取到'))
print('GitHub 最新发布: '+(latest or '未读取到'))
print('o update 实际目标: '+(entry or '未确认，请稍后重试'))
if entry and version(current):
 if version(entry)>version(current):print('签名入口有可用更新，可执行 o update。')
 elif version(entry)==version(current):print('入口与当前版本一致；o update 会修复当前版本。')
 else:print('入口落后于当前安装版本；已阻止 o update 降级。')
if entry and latest and version(latest)>version(entry):
 print('GitHub 有更新发布，但短入口尚未同步；o update 暂时无法安装该版本。')
 print('发布记录：https://github.com/zangwp/OLS-WPanel/releases/latest')
for error in errors:print(error,file=sys.stderr)
if errors:sys.exit(1)
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
    echo "  o swap                   Swap 容量与 swappiness 管理"
    echo "  o system-update-status   查看更新任务"
    echo "  o clean                  清理缓存与过期日志"
    echo "  o dns / o ip             DNS / 地址优先级"
    echo "  o tuning                 性能状态与连接设置"
    echo "  o language               系统语言"
    echo "  o network        双栈网络检测"
    echo "  o time           时区与时间同步"
    echo "  o hostname       修改静态主机名"
    echo "  o ports          本机监听与入站规则诊断"
    echo "  o services       核心服务状态与错误日志"
    echo "  o bbr            实际 BBR / 队列与持久配置"
    echo "  o disk           磁盘空间与 inode 检查"
    echo "  o apt-check      APT / dpkg 只读健康检查"
    echo "  o dependencies   维护工具依赖检查"
    echo "  o history        终端维护操作记录"
    echo "  o ssh            SSH 双端口过渡与超时恢复"
    echo "  o ssh-confirm <令牌>  在新端口 SSH 连接中确认"
    dim "项目: https://github.com/zangwp/OLS-WPanel"
    dim "访问排查: 放行面板端口；运行 o status 或 o log"
}
uninstall_panel() {
    local status=0
    run_lifecycle "$1"
    status=$?
    if [ "$status" -ne 0 ]; then
        red "卸载未完成（退出码 $status）。请保存上方日志并核对残留；不要直接重复完全卸载。"
    fi
    # The current Bash process retains its menu functions even after its file
    # is removed. Do not return to that stale menu after self-uninstallation.
    if [ ! -f "$0" ]; then
        echo "o / O 命令已移除，退出当前管理菜单。重新连接后无法再打开，属于卸载后的正常结果。"
        echo "若当前 SSH 提示旧命令路径不存在，可执行 hash -r 清除命令缓存。"
        exit "$status"
    fi
    return "$status"
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
        echo ""; echo "  4. 终端维护记录"; echo "  5. 维护工具依赖"; echo "  6. APT / dpkg 健康检查"
        echo ""; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) page "命令帮助"; panel_help;;
          2) uninstall_panel --uninstall; return;; 3) uninstall_panel --purge; return;;
          4) page "终端维护记录"; read_view history;; 5) page "依赖检查"; read_view dependencies;;
          6) page "APT / dpkg 健康检查"; read_view apt-health;; *) echo "无效选项";;
        esac
        pause_page
    done
}
panel_summary() {
        local version="" state=""
        dim "  VPS 日常维护与 OLS WPanel 管理"
        version=$("$BIN" --info --config "$CFG" 2>/dev/null | sed -n 's/^版本: \([^ ]*\).*/\1/p')
        echo "  面板版本: ${version:-未读取到}"
        state=$(systemctl show "$SVC" --property=ActiveState --value 2>/dev/null)
        case "$state" in
            active) green "  服务状态: 运行中";;
            inactive) dim "  服务状态: 未运行";;
            failed) red "  服务状态: 启动失败";;
            activating) dim "  服务状态: 正在启动";;
            deactivating) dim "  服务状态: 正在停止";;
            *) dim "  服务状态: 未能读取，请用 o status 检查";;
        esac
        echo ""
        read_view login-addresses
}
network_menu() {
    local choice=""
    while true; do
        page "网络设置" "管理域名解析、地址选择优先级，或检测服务器出站连接。"
        read_view ip
        echo ""; echo "  1. DNS 设置与检测"; echo "  2. IPv4 / IPv6 优先级"; echo "  3. 网络连通性检测"
        echo "  4. 端口与进程诊断"; echo "  5. BBR / 队列状态"; echo "  6. SSH 端口管理"; echo ""; echo "  0. 返回"
        pick || return 0
        case "$choice" in
          0) return 0;; 1) settings_page dns;; 2) settings_page ip;;
          3) page "网络连通性检测"; read_view network; pause_page;;
          4) page "端口与进程诊断"; read_view ports; pause_page;; 5) page "BBR / 队列状态"; read_view bbr; pause_page;;
          6) ssh_page;; *) echo "无效选项"; pause_page;;
        esac
    done
}
system_menu() {
    local choice=""
    while true; do
        page "系统设置" "查看时间、同步状态、语言与 Swap，按需调整。"
        read_view time
        echo ""; echo "  1. 时区与时间同步"; echo "  2. 系统语言"; echo "  3. Swap 管理"; echo "  4. 主机名"; echo ""; echo "  0. 返回"
        pick || return 0
        case "$choice" in 0) return 0;; 1) settings_page time;; 2) settings_page locale;; 3) swap_page;; 4) settings_page hostname;; *) echo "无效选项"; pause_page;; esac
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
            echo "  1. 系统信息              2. 系统软件更新"
            echo ""
            echo "  3. 系统清理              4. 网络设置"
            echo ""
            echo "  5. 系统设置              6. 性能状态"
            echo ""
            blue "  面板与帮助"
            echo "  7. 面板管理              8. 帮助 / 高级操作"
        else
            echo "  1. 系统信息"; echo "  2. 系统软件更新"
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
    swap) swap_page ;;
    ip) settings_page ip ;;
    tuning) performance_menu ;;
    language) settings_page locale ;;
    hostname) settings_page hostname ;;
    ports) page "端口与进程诊断"; read_view ports ;;
    services) services_page ;;
    bbr) page "BBR / 队列状态"; read_view bbr ;;
    disk) page "磁盘空间与 inode"; read_view disk ;;
    apt-check) page "APT / dpkg 健康检查"; read_view apt-health ;;
    dependencies) page "维护工具依赖"; read_view dependencies ;;
    history) page "终端维护记录"; read_view history ;;
    ssh) ssh_page ;;
    ssh-confirm) ssh_confirm "${2:-}" ;;
    restart)
        echo "正在重启面板..."
        if systemctl restart "$SVC" 2>/dev/null; then
            sleep 2
            if systemctl is-active --quiet "$SVC"; then
                green "OLS WPanel 已重启，运行中"
                audit_cli restart 0
            else
                red "OLS WPanel 重启后未能启动"
                echo ""
                echo "── 最近日志 ──"
                journalctl -u "$SVC" -n 20 --no-pager 2>/dev/null | tail -20
                echo "── 结束 ──"
                echo ""
                echo "→ 运行 'o status' 进行完整诊断"
                audit_cli restart 1
                exit 1
            fi
        else
            red "systemctl restart 失败，服务可能未安装"
            echo "→ 运行 'o status' 进行诊断"
            audit_cli restart 1
            exit 1
        fi
        ;;
    password)
        "$BIN" --reset-admin --config "$CFG"
        status=$?; audit_cli password "$status"; exit "$status"
        ;;
    info)
        "$BIN" --info --config "$CFG" || exit $?
        echo "OpenLiteSpeed: /usr/local/lsws/"
        echo "MariaDB: /etc/mysql/    Redis: /etc/redis/"
        ;;
    unban)
        "$BIN" --unban-all --config "$CFG"
        status=$?; audit_cli unban "$status"; exit "$status"
        ;;
    update|upgrade|repair)
        echo "正在通过签名发布链更新/修复 OLS WPanel..."
        run_lifecycle --repair
        ;;
    uninstall)
        if [ "${2:-}" = "--all" ]; then
            # 完全卸载将删除网站文件、网站数据库与 OLS 面板；备份另行选择。
            red "完全卸载：删除网站、数据库与面板，并移除运行环境。"
            uninstall_panel --purge
        elif [ -z "${2:-}" ]; then
            echo "普通卸载会保留网站、数据库、站点证书和共享软件。"
            uninstall_panel --uninstall
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
