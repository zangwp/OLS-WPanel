# 日常运维与备份恢复

本文档收纳不适合放在项目首页的运维细节。下面的命令都需要 `root` 权限。

## 软件更新边界

- OpenLiteSpeed 和 LSPHP 跟随 LiteSpeed 官方签名软件源。
- MariaDB 全新安装默认 11.8；现有数据库只在当前系列内安装补丁和安全更新。跨系列变更必须先完成全量备份、兼容性检查和恢复演练。
- Redis 跟随已配置的 Redis 官方签名 APT 源。
- nftables 和 Fail2ban 跟随操作系统软件源。上游已发布的源码版本不等于当前系统已有可安全安装的软件包。
- OpenLiteSpeed WebAdmin 7080 默认关闭。OLS WPanel 会生成并维护主配置和站点配置，同时修改两个后台容易互相覆盖。

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

“备份总览”在同一网站下并排显示数据库与文件备份，各自选择版本、下载、删除或恢复。两类备份分别生成，没有共同的备份点编号；时间相近也不能证明它们属于同一次备份。恢复数据库不会恢复文件，恢复文件不会恢复数据库，请核对核心、插件、主题与数据库版本是否兼容。

数据库恢复复用数据库管理页的异步流程，覆盖前会创建当前数据库的安全备份。“数据库备份管理”仍可创建立即备份、上传 SQL 备份并恢复。执行时重新核对网站和数据库绑定，清空前再次核对归属；绑定变化、未结束的更新或迁移、临时维护及未处理的更新结果会阻止普通恢复。更新失败后的专用安全备份回滚保留独立入口。

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
