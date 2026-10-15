# 日常运维与备份恢复

本文档收纳不适合放在项目首页的运维细节。下面的命令都需要 `root` 权限。

## 从终端快速排查

运行 `o` 查看面板版本、服务状态和登录地址；输入 `r` 刷新。主机、运行时长及 CPU、内存、磁盘等详情在“1. 系统信息”中查看。首页保留原有 1–8 项菜单，完整登录地址逐行显示，窄窗口可以复制由终端自动折行的地址；服务异常或版本读取失败时显示诊断入口。

- `o health`：快速汇总服务、磁盘空间与 inode、软件包、本机路由和 DNS 配置。每项显示检查结果和下一步命令；未知表示读取失败或尚未确认，不等于正常。
- `o processes`：查看短时间内 CPU 和内存占用最高的进程。CPU 按单核 100% 计算，多核可超过 100%；常驻内存包含共享页面，不能简单相加当作总内存。只显示进程名称，不显示完整启动参数。
- `o report`：生成可整段复制的纯文本脱敏诊断摘要，也可从“8. 帮助 / 高级操作 → 7. 生成脱敏诊断摘要”进入。只输出白名单中的版本、规范化系统信息与固定检查项状态；不包含主机名、IP、域名、账号、密钥、配置路径或原始日志，不自动写入报告文件。缺失或无法确认的数据会标为未知。
- `o services` / `o log`：查看核心服务状态或面板日志；`o apt-check` 查看更详细的软件包检查；`o network` 主动测试出站网络。

体检和进程列表只读，不自动修复或结束进程。本机网络配置正常不能证明公网访问正常；云安全组、运营商网络和网站实际响应需另外核对。系统更新启动后可在进度页刷新或返回让后台继续；“已启动”与“已完成”分别显示。

## 软件更新边界

- OpenLiteSpeed 和 LSPHP 跟随 LiteSpeed 官方签名软件源。
- MariaDB 全新安装默认 11.8；现有数据库只在当前系列内安装补丁和安全更新。跨系列变更必须先完成全量备份、兼容性检查和恢复演练。
- Redis 跟随已配置的 Redis 官方签名 APT 源。
- nftables 和 Fail2ban 跟随操作系统软件源。上游已发布的源码版本不等于当前系统已有可安全安装的软件包。
- OpenLiteSpeed WebAdmin 7080 默认关闭。OLS WPanel 会生成并维护主配置和站点配置，同时修改两个后台容易互相覆盖。

## 软件环境检查与端口变更

软件管理可按 PHP 版本展开扩展检查。读取的是该版本 LiteSpeed SAPI 的加载与配置结果，不能代替每个网站 PHP 进程的实时统计。检查失败显示“尚未确认”，不会把未能读取的扩展直接判为缺失；OPcache 命中率与实际占用暂未采集。读取有超时、输出上限、并发限制和短暂缓存，“重新检查环境”会刷新查询。

备份工具按当前备份方式检查。本地文件备份需要 tar/gzip，数据库备份与恢复需要 mysqldump/mysql；SSH 远程备份还需要 rsync/SSH 客户端，密码认证额外需要 sshpass。S3 上传由面板实现，不依赖这些 SSH 工具。缺失项可在软件管理中补齐；此操作只安装当前需要的固定软件包，保留现有软件和备份设置，不升级或删除已安装软件。安装由服务器执行，离开页面不会中断安装；失败后先重新检查并核对日志，避免重复提交。更新/修复安装器继续保留原有软件包，精简系统的缺失工具通过该入口补齐。

Cron 状态用于核对计划任务中的网站文件备份、WordPress Cron 和命令任务。面板数据库备份、监控等内部后台计时器由 Go 服务另行调度。Cron 检查不会把该服务加入自动守护，也不会自动改变其启动策略。

“重建 OPcache”先验证 OLS 配置，再写入官方服务器级 PHP 重启标记并重启 OLS。PHP 各进程组可能拥有独立缓存，脱离运行的进程会在下次使用对应处理器时重启；操作成功表示重建请求已发出，不能据此断言每个网站缓存已立即清空。[OLS 脱离运行的 PHP 说明](https://docs.openlitespeed.org/config/php/detached/)

已由面板管理的端口策略中，普通端口新增、删除和访问范围调整，在原有 SSH、面板允许来源保持或扩大时可直接保存。首次启用严格策略、收紧管理入口或无法完整确认原规则时，仍使用临时应用、面板重新连接确认与自动回退。删除自定义入站规则不停止服务，监听进程可能继续显示，但不再获得该策略的外部放行。其他防火墙规则和云安全组仍可能限制连接。

SSH 登录端口可以独立填写。安装器生成的可完整识别严格放行策略可直接用于迁移，无需先在页面另行启用端口策略；未知或自定义防火墙布局会明确拒绝自动迁移。实际迁移仍保留旧端口、云安全组确认、独立新 SSH 会话验证与超时回退，确认后才停用旧端口。并非仅修改上方普通端口就需要验证 SSH。

面板告警连接外部 SMTP 属于出站流量，发送告警无需开放 VPS 的入站邮件端口；端口页面不提供邮件服务快捷区，需要其他入站服务时使用自定义端口。SMTP 服务器地址、加密方式和目标端口在告警通知页面设置。发件邮箱用于 SMTP 登录，管理员通知邮箱用于接收告警，两者可以相同。

## 面板数据库备份

面板使用 SQLite 存储自身数据，每天 02:30 备份到：

```text
/www/ols-wpanel/backups/panel-db/
```

默认保留最近 7 份。面板正常时，请优先在“面板设置”中创建、下载或恢复备份。这些备份不包含网站文件、MariaDB 数据或面板目录之外的系统配置。

## 面板无法启动时恢复

1. 查看可用备份：

   ```bash
   ls -lh /www/ols-wpanel/backups/panel-db/
   ```

2. 选定面板生成的独立备份文件，在同一个 Bash 会话中执行下面的恢复步骤。先将示例文件名替换为真实备份；备份校验失败时保持原数据库不变：

   ```bash
   set -euo pipefail
   umask 077
   backup='/www/ols-wpanel/backups/panel-db/<backup-file>.db'
   test -f "$backup" && test ! -L "$backup"
   recovery_dir=$(mktemp -d /www/ols-wpanel/recovery.XXXXXXXXXX)
   printf '恢复工作目录（请保留）: %s\n' "$recovery_dir"
   install -m 0600 -- "$backup" "$recovery_dir/restored.db"
   python3 - "$recovery_dir/restored.db" <<'PY'
   import pathlib, sqlite3, sys
   path = pathlib.Path(sys.argv[1])
   with sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True) as db:
       if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
           raise SystemExit('备份完整性校验失败；尚未替换数据库')
       db.execute('SELECT COUNT(*) FROM websites').fetchone()
   PY

   systemctl stop ols-wpanel
   test "$(systemctl show ols-wpanel --property=MainPID --value)" = 0
   if systemctl is-active --quiet ols-wpanel; then
       echo '面板仍在运行，停止恢复' >&2
       exit 1
   fi
   # 先整体保存异常数据库及崩溃遗留日志，避免旧 WAL 覆盖恢复的备份。
   for suffix in '' -wal -shm; do
       source="/www/ols-wpanel/panel.db${suffix}"
       test ! -L "$source"
       if test -e "$source"; then
           mv -- "$source" "$recovery_dir/panel.db${suffix}"
       fi
   done
   mv -- "$recovery_dir/restored.db" /www/ols-wpanel/panel.db
   systemctl start ols-wpanel
   systemctl status ols-wpanel --no-pager
   journalctl -u ols-wpanel -n 50 --no-pager
   ```

面板数据库使用 WAL 模式。崩溃后 `panel.db-wal` 可能包含尚未合并的数据，不能只覆盖 `panel.db` 后重启。操作期间应停止其他访问该数据库的工具；不得移动或删除运行中数据库的 WAL/SHM。上面的步骤将旧数据库、WAL 和 SHM 保存在同一个 `recovery.*` 目录，恢复中断时先检查该目录及日志，不要直接重新执行或删除它。

仅恢复同一 OLS WPanel 发布链且仍在支持范围内的备份。恢复前保留现有数据库，并确认系统上已有站点文件和 MariaDB 数据。

启用双因素认证后，数据库备份必须配合数据库同目录的原 `account-mfa.key` 使用。普通数据库备份下载不包含此文件，应通过受控主机管理通道单独加密备份；恢复时保留原文件、所属用户和 `0600` 权限。不要生成替代密钥；恢复码无法代替丢失的加密密钥。恢复旧备份后重新生成恢复码并核对双因素状态，详细流程见 [账户安全中心](account-security.md)。

## 网站数据库和文件恢复

“备份总览”的主要入口是“立即整站备份”。面板短暂关闭该网站的动态请求，暂停受管定时任务、排空网站进程及数据库连接，锁定站点数据库账户和数据表，并核验网站目录只读。在同一段停写期间生成文件和数据库，使用共同编号和 SHA-256 校验保存为一个完整备份点。任何一部分失败都不会标记完整。操作前须停止面板外的部署、脚本及数据库管理员写入；这不是云主机或存储系统的原子快照。

目前支持运行中的根目录 WordPress 网站，需要独立的不可登录系统用户、独立的本地 MariaDB 账户，以及 Linux 的受控只读挂载、进程身份和原子目录交换能力。含外部挂载、链接、特殊文件或数据库视图、触发器、存储程序等无法完整恢复的对象会拒绝整站操作；无法核验停写也会报错，不降级为完整备份。

选择一个完整本地备份点，点击“恢复整站”即可恢复同一编号的文件和数据库。面板先保存当前两部分的安全副本；恢复失败会尝试回滚两部分。无法确认完整回滚或维护清理时，网站继续维护，并保留操作记录和安全副本，不能把解除维护当成恢复成功。页面的“核对并恢复网站访问”仅按本轮维护归属及日志解除可以证明安全的维护状态；未知或部分恢复状态须通过受控主机管理核对。

整站备份存放在 `BackupDir/<domain>/site-sets/<编号>/`，恢复日志及数据库安全副本位于同域名的 `site-operations/<操作编号>/`。原文件安全副本的位置由恢复结果和日志给出。当前整站集合仅保存在本机，不参与单项数据库/文件轮转，也不使用现有远程同步设置。使用“下载完整备份包”导出一个 `.tar`，其中同一个编号目录包含 `files.tar.gz`、`database.sql.gz`、`manifest.json` 和 `SHA256SUMS`。下载前和传输期间会校验组件 SHA-256，大文件需要等待；中断的下载必须重做。不会在服务器另存一份同样大的导出包。

导出清单保留恢复点身份、原站绑定和组件指纹，不导出临时维护归属、原始 vhost 文本、诊断消息或恢复安全副本。网站文件和数据库本身仍可能包含 `wp-config.php`、用户数据和密钥，应加密保存在其他设备。完整包不包含面板 SQLite、MFA/Cloudflare 加密密钥、证书、系统软件或 DNS。单项下载仍保留，但灾难恢复应保存完整包。删除本地完整备份点会一起删除它的数据库和文件。

### 校验完整包，并放回原网站备份库

以下只适用于**原网站仍在当前面板中登记，ID、域名、目录、系统用户、数据库及表前缀均与清单一致**的恢复。不创建新网站，不跨站修改清单，不直接覆盖线上文件或导入 SQL。新 VPS 丢失原面板数据、密钥或系统身份时，先恢复和核对原环境；不能满足绑定时停止，使用经过演练的迁移流程。

先通过受控通道传回完整包。将 `bundle` 改为实际文件名，下面仅向新建的 root 私有目录解包，需要两个组件的额外磁盘空间。校验只证明完整性，应仅使用自己保存的包。

```bash
bundle='/root/example.com_实际编号_site-backup.tar'
workdir=$(mktemp -d /root/ols-backup-check.XXXXXXXX)
chmod 0700 "$workdir"
python3 - "$bundle" "$workdir" <<'PY'
import hashlib, json, os, pathlib, re, shutil, sys, tarfile, uuid
work = pathlib.Path(sys.argv[2])
names = {'files.tar.gz', 'database.sql.gz', 'manifest.json', 'SHA256SUMS'}
with tarfile.open(sys.argv[1], 'r:') as archive:
    members, point = {}, None
    for member in archive:
        parts = member.name.split('/')
        if len(parts) != 2 or parts[1] not in names or not member.isfile() or member.sparse:
            raise SystemExit('拒绝未知路径、链接或特殊成员')
        candidate = str(uuid.UUID(parts[0]))
        if candidate != parts[0] or uuid.UUID(candidate).int == 0 or (point and point != candidate):
            raise SystemExit('编号不一致')
        point = candidate
        limit = 1024**2 if parts[1] in {'manifest.json', 'SHA256SUMS'} else 64 * 1024**3
        if parts[1] in members or len(members) >= 4 or not 0 < member.size <= limit:
            raise SystemExit('重复成员或大小无效')
        members[parts[1]] = member
    if set(members) != names or shutil.disk_usage(work).free < sum(m.size for m in members.values()) + 1024**3:
        raise SystemExit('完整包缺少组件，或解包空间不足')
    expected = {}
    for line in archive.extractfile(members['SHA256SUMS']).read().decode('ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (files\.tar\.gz|database\.sql\.gz|manifest\.json)', line)
        if not match or match[2] in expected:
            raise SystemExit('校验清单格式错误')
        expected[match[2]] = match[1]
    if set(expected) != names - {'SHA256SUMS'}:
        raise SystemExit('校验清单缺少组件')
    destination = work / point
    destination.mkdir(mode=0o700)
    for name, member in members.items():
        digest = hashlib.sha256()
        with archive.extractfile(member) as source, (destination / name).open('xb') as target:
            os.chmod(target.name, 0o600)
            while data := source.read(128 * 1024):
                target.write(data)
                digest.update(data)
        if name in expected and digest.hexdigest() != expected[name]:
            raise SystemExit('SHA-256 不匹配：' + name)
    m = json.loads((destination / 'manifest.json').read_text())
    if m.get('id') != point or m.get('version') != 1 or m.get('state') != 'complete' or m.get('operation') != 'create' or m.get('requires_attention') or m.get('atomic') or m.get('consistency') != 'controlled_quiescence':
        raise SystemExit('不是受支持的完整恢复点')
    for key, name in [('files', 'files.tar.gz'), ('database', 'database.sql.gz')]:
        if m[key].get('name') != name or m[key].get('size') != members[name].size or m[key].get('sha256') != expected[name]:
            raise SystemExit('恢复清单与组件不一致')
(work / 'point-id').write_text(point)
print('校验通过：', destination)
PY
```

只有明确输出“校验通过”才继续。下一步只读核对当前 SQLite 中的原网站绑定，并拒绝覆盖已有编号。自定义配置路径时修改最后一个参数。

```bash
python3 - "$workdir" /www/ols-wpanel/config.json <<'PY'
import json, os, pathlib, sqlite3, sys, urllib.parse
work = pathlib.Path(sys.argv[1])
point = (work / 'point-id').read_text()
m = json.loads((work / point / 'manifest.json').read_text())
cfg = json.loads(pathlib.Path(sys.argv[2]).read_text())
db = sqlite3.connect('file:' + urllib.parse.quote(cfg['sqlite']['path']) + '?mode=ro', uri=True)
columns = ['domain', 'web_root', 'system_user', 'db_name', 'db_user', 'table_prefix']
row = db.execute('SELECT ' + ','.join(columns) + ' FROM websites WHERE id=?', (m['site_id'],)).fetchone()
db.close()
if row != tuple(m[key] for key in columns):
    raise SystemExit('原网站绑定不一致，停止；不能跨站修改清单绕过')
root = pathlib.Path(cfg['panel']['backup_dir'])
if not root.is_absolute() or '/' in m['domain'] or m['domain'] in {'.', '..'}:
    raise SystemExit('备份根路径或域名无效')
target = root / m['domain'] / 'site-sets' / point
for parent in target.parents:
    if parent.is_symlink():
        raise SystemExit('备份祖先路径不能是链接')
    if parent.exists():
        info = parent.stat()
        if not parent.is_dir() or info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit('备份祖先路径不是 root 安全目录')
if os.path.lexists(target):
    raise SystemExit('这个编号已存在，保留现有备份点，不覆盖')
(work / 'target-path').write_text(str(target))
print('原站绑定通过，待放回：', target)
PY
```

只有绑定检查明确通过才复制。保留临时校验目录和现有备份，不将完整包解到网站根目录。完整清单最后复制；任何失败都停止，不恢复不完整集合。

```bash
point=$(cat "$workdir/point-id")
target=$(cat "$workdir/target-path")
if [ -e "$target" ] || [ -L "$target" ]; then echo '目标已存在，停止'; exit 1; fi
install -d -o root -g root -m 0700 -- "$(dirname "$target")"
mkdir -m 0700 -- "$target" || exit 1
for name in files.tar.gz database.sql.gz SHA256SUMS manifest.json; do
    install -o root -g root -m 0600 -- "$workdir/$point/$name" "$target/$name" || exit 1
done
```

刷新面板“备份总览”，选择该编号，确认停止外部写入后点击“恢复整站”。面板仍会重新核对绑定、SHA-256 和停写条件，并保存恢复前双方安全副本。完成后核对首页、后台和关键业务，再单独处理缓存。未知/失败时先核对任务与维护现场，不重复提交，也不删除日志或安全副本。此流程不恢复面板账户、证书、DNS、Cloudflare 规则或历史数据库密码，当前 `wp-config.php` 继续保留。

“单项备份与恢复”保留原有并排显示的数据库、文件备份，各自选择版本、下载、删除或恢复。旧单项备份没有共同编号；时间相近也不能证明属于同一次备份，不自动配成整站备份点。恢复数据库不会恢复文件，恢复文件不会恢复数据库，请核对核心、插件、主题与数据库版本是否兼容。可直接点击“立即全量文件备份”，无需先创建定时任务；单项文件备份仍不保证与独立数据库备份同一时间。

单项数据库自动备份每天按 VPS 本地时区 04:00 启动，并逐站执行。批量创建的文件备份任务会避开 04 点并尝试分配不同 Cron 表达式，旧任务保持原时间；不同周期仍可能落在同一天同一时刻，例如每周日和每月 1 日。多个网站的文件备份、文件恢复及整站操作共用跨进程锁，依次执行，等待锁超过两小时会报错；同一定时任务尚未结束时再次触发会跳过本次。数据库自动备份使用独立执行通道，可能与文件备份同时占用 CPU 和磁盘，不能将这些机制理解为所有备份类型都统一排队，或定时生成的数据库和文件已经组成同一备份点。

首次启用数据库自动备份后有 24 小时 5 分钟宽限；宽限结束仍没有成功的自动备份，也会进入备份过期告警。调整保留数量不会重置宽限，明确关闭后重新启用会开始新宽限。升级时没有成功历史的旧设置获得一次宽限，已有成功历史的过期判断保留；通知仍需启用告警并配置渠道。每日执行按本地日历日期计算，夏令时变化不会把正常 04:00 漂移到经过固定 24 小时后的 05:00；不存在或重复的时刻按时区规则选择有效相邻时刻，UTC 没有此问题。

受管 WordPress Cron 只有 HTTP 2xx 才记录调用成功；301/302 等重定向不会自动跳转并当作已执行。失败时检查主域名、CDN/访问规则及 `/wp-cron.php` 响应，不能仅因浏览器能打开首页就认定计划任务正常。调用成功仍不等于所有插件后台工作已完成。

数据库恢复复用数据库管理页的异步流程，覆盖前会创建当前数据库的安全备份。“数据库备份管理”仍可创建立即备份、上传 SQL 备份并恢复。执行时重新核对网站和数据库绑定，清空前再次核对归属；绑定变化、未结束的更新或迁移、临时维护及未处理的更新结果会阻止普通恢复。更新失败后的专用安全备份回滚保留独立入口。

自 v2.0.0 起，SQL 由每次创建的受限数据库身份导入，面板管理权限仅用于准备、授权核对和清理。需要跨库或服务器级权限的备份会明确失败，不以 root 重试。恢复的 DEFINER 对象会绑定到受限身份；仍被这些对象引用的身份保留并锁定登录。归属凭据存放在 `DataDir/database-import-identities/`（未配置 DataDir 时使用 BackupDir），应随私有面板数据安全保存，不应手工修改或在对象仍使用时删除。

独立手动、自动数据库备份与同站恢复共用网站操作锁；自动备份遇到忙碌网站会跳过并记录，不代表当天已补做。数据库默认保留 7 份、文件任务默认 3 份，均以实际设置为准；数据库列表显示最新 5 份是展示限制。

数据库密码变更使用独立会话保留反斜杠、引号和 `$` 等字符。客户端未启动时恢复旧网站配置；客户端启动后失败或超时不能证明服务器未提交，面板保留请求的新配置并提示结果未确认。此时先通过受控管理通道核对网站与数据库连接，不能把任务失败当作数据库密码已回滚。结果返回固定遮罩，私有配置中的密码仍须按原有权限保护。

文件恢复入口只接受登记在该网站名下、仍保存在本地的全量 `.tar.gz` 包。旧媒体增量只包含变化的上传文件，缺少可验证的完整链和文件删除清单，不能直接恢复整站；仅在远端的文件包也不支持直接网页恢复。文件任务页仍可执行立即备份。

文件恢复目前适用于运行中的、根目录部署的 WordPress 网站。临时维护、文件保护异常、更新、迁移、AI 开发访问或图片优化尚未结束时，恢复会拒绝执行。入队时核对包归属、本地全量文件及重复恢复；执行和切换前再核对当前网站设置、维护与持久任务。同一网站不能同时提交数据库与文件恢复任务。

全量文件恢复先在网站父目录内准备私有目录，验证 gzip/tar、WordPress 必要文件、路径及权限，再用 Linux 原子目录交换切换网站。拒绝路径穿越、重复文件、链接和设备文件；不信任备份中的用户身份或文件权限。内核或文件系统不支持原子交换时会失败，不使用存在目录缺失窗口的两次移动替代。

恢复保留当前 `wp-config.php` 以及面板管理的插件和 MU 代码，避免旧备份覆盖当前数据库连接、登录通道和面板策略，并重新应用当前文件保护权限。普通插件、主题、媒体和 WordPress 核心来自选中的全量包；证书、OLS 配置、DNS 和 Cloudflare 规则不随文件恢复改变。恢复后下一次媒体增量任务会重新建立全量基线。

恢复前的网站文件会留在网站父目录的 `.ols-wpanel-file-restore-*/before` 私有目录中，结果显示具体路径，同目录 `journal.json` 记录恢复状态。这些副本不在普通备份列表中，也不会自动轮转删除。恢复验证失败会尝试交换回原目录；回滚失败会明确报错并保留两个目录。中途断电或面板退出后，不要直接删除这些目录，应结合日志和 `journal.json` 核对当前网站与保留副本；日志状态不能代替线上访问检查。

恢复成功表示磁盘文件切换和权限核验完成。运行中的 PHP 字节码、其他页面缓存和 CDN 缓存可能仍有旧内容，需单独清理和检查；面板不会为单个网站文件恢复自动执行全局 OPcache 清理或重启所有网站。确认网站运行及数据库版本匹配后，再通过受控主机管理清理不再需要的安全副本。

恢复期间页面会显示等待、运行或最终结果。刷新页面可继续查询当前任务；网络错误或任务记录丢失时会明确提示结果未确认，不要把它当作恢复成功后重复提交。

## 常用检查

```bash
o status
systemctl status ols-wpanel lshttpd mariadb redis-server fail2ban
journalctl -u ols-wpanel -n 100 --no-pager
/usr/local/lsws/bin/openlitespeed -t
```

数据库、网站文件、证书和异地备份是不同的恢复对象。生产环境应定期下载或同步备份，并在独立服务器上演练恢复。

## 卸载后的检查

卸载会移除 `o` / `O` 和面板服务。旧菜单退出后无法重新打开属于预期结果，不能仅凭命令消失判断完全清理是否成功。当前 SSH 若仍缓存旧命令路径，可运行 `hash -r`。

以下命令只查看状态，不执行删除：

```bash
systemctl status ols-wpanel --no-pager
ls -ld /usr/local/bin/ols-wpanel /usr/local/bin/o /usr/local/bin/O /www/ols-wpanel
dpkg --audit
dpkg-query -W -f='${binary:Package}\t${db:Status-Abbrev}\n' 'openlitespeed*' 'lsphp*' 'mariadb*'
tail -n 100 /var/log/apt/term.log
```

已移除的服务和文件提示不存在是正常结果。普通卸载保留网站、数据库、运行环境以及对应的签名 APT 软件源和密钥；完全卸载仍保留 Redis、其更新源、Fail2ban 及可能共享的目录残留。检测到网站登记、网站文件或运行配置时，安装器会拒绝全新安装或重装，应使用更新/修复或先迁移网站。出现软件包权限错误或“卸载未完成”时，先核对完整日志，避免盲目删除共享目录或重复完全卸载。
