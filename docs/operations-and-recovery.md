# 日常运维与面板数据库恢复

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

2. 停止面板并保留当前数据库：

   ```bash
   systemctl stop ols-wpanel
   cp /www/ols-wpanel/panel.db /www/ols-wpanel/panel.db.broken
   ```

3. 用已确认的备份替换数据库，然后启动并检查：

   ```bash
   cp /www/ols-wpanel/backups/panel-db/<backup-file>.db /www/ols-wpanel/panel.db
   systemctl start ols-wpanel
   systemctl status ols-wpanel
   journalctl -u ols-wpanel -n 50 --no-pager
   ```

仅恢复同一 OLS WPanel 发布链且仍在支持范围内的备份。恢复前保留现有数据库，并确认系统上已有站点文件和 MariaDB 数据。

## 常用检查

```bash
o status
systemctl status ols-wpanel openlitespeed mariadb redis-server fail2ban
journalctl -u ols-wpanel -n 100 --no-pager
/usr/local/lsws/bin/openlitespeed -t
```

数据库、网站文件、证书和异地备份是不同的恢复对象。生产环境应定期下载或同步备份，并在独立服务器上演练恢复。
