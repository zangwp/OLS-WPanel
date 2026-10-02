# OLS WPanel

<img src="static/logo.png" alt="OLS WPanel" width="88">

轻量的 VPS 与 WordPress 管理面板。集中管理网站、数据库、SSL 证书、缓存、备份和服务器维护，基于 OpenLiteSpeed、LSPHP、MariaDB 与 Redis。

[English](README.en.md) · [使用文档](docs/operations-and-recovery.md) · [更新记录](CHANGELOG.md) · [问题反馈](https://github.com/zangwp/OLS-WPanel/issues)

## 安装

支持全新的 **Debian 13、Ubuntu 24.04 LTS、Ubuntu 26.04 LTS**，架构为 **amd64 / arm64**。最低 1 核 CPU、1 GiB 内存。使用 root 执行：

```bash
curl -fsSL https://ols.zangyubin.top/install | bash
```

当前稳定版：`v1.15.0`。短链接固定到已发布版本，验证 Ed25519 签名与 SHA-256 后安装。

没有 curl 的精简系统先执行：

```bash
apt-get update && apt-get install -y --no-install-recommends curl wget ca-certificates openssl
```

手动验签、国内网络与离线安装见 [安装指南](docs/verified-install.md)。其他系统版本、已有生产环境及 ARM64 16 KiB 页大小不在自动安装支持范围内。

## 可以做什么

| 功能 | 内容 |
|---|---|
| 网站与 WordPress | 创建 WordPress / PHP 网站，管理域名、PHP 版本、文件、数据库及 WordPress 更新 |
| 证书与缓存 | 网站证书申请与续签；使用官方 LiteSpeed Cache 管理页面及 Redis 对象缓存 |
| 备份与恢复 | 网站、数据库和面板备份，支持 SFTP / S3 异地保存 |
| VPS 维护 | 查看资源与服务状态，管理系统更新、DNS、Swap、时间同步和开放端口 |
| 安全与告警 | 登录保护、文件保护、Fail2ban、nftables、邮件通知和日志分析 |

全新安装默认使用 **LSPHP 8.5、MariaDB 11.8**；可为网站增加 LSPHP 8.4 / 8.3。现有数据库保留当前系列，常规系统更新不会自动跨系列升级。

## SSH 快捷命令

`o` 与大写 `O` 等价，面板信息会显示版本、端口和安全入口。

```text
o                 查看面板信息
o status          诊断面板运行状态
o log [N]         查看最近 N 条面板日志
o restart         重启面板
o password        重置管理员密码
o unban           清空面板管理的 IP 封禁
o update          更新 / 修复面板
o uninstall       卸载面板，保留网站、数据库与共享软件
```

普通卸载要求输入 `UNINSTALL` 确认。更新脚本使用已发布的签名安装入口。

## v1.15.0 更新

本版新增：

- VPS 简单菜单及“服务器概况 / 常用维护”布局。
- 自定义面板域名、证书申请与续期，保留 IP 备用入口。
- PHP 配置批量保存，解除面板对 LiteSpeed Cache 设置的强制覆盖。
- 首页项目更新检查；完全卸载入口与备份保留选项。

新增命令与验证情况见 [开发与验证记录](docs/local-next-version.md)。完全卸载会删除网站文件、网站数据库和面板，需要单独确认；请勿将开发稿中的新命令用于旧发布版。

## 文档

- [安装与验签](docs/verified-install.md)
- [日常维护与恢复](docs/operations-and-recovery.md)
- [升级兼容性](docs/upgrade-compatibility.md)
- [旧 Optimizer 迁移](docs/optimizer-migration.md)：v1.14.0 已停止自动部署旧插件，现有网站可显式迁移并移除。
- [安装安全](docs/security/ols-wpanel-install-security.md) · [运行时安全](docs/security/ols-wpanel-runtime-security.md)
- [仓库目录说明](docs/repository-layout.md)

## 开发目录

应用代码按 Go 包划分；页面放在 templates/ 与 static/，构建源码在 assets/。文档统一在 docs/，独立 Worker 统一在 deploy/。旧插件源码保留用于兼容与迁移验证。

```text
config/ collector/ database/ models/       配置与数据
handlers/ middleware/ router/ executor/   请求处理与系统操作
i18n/ templates/ static/ assets/           界面、翻译与资源
docs/ deploy/                             文档与独立部署组件
scripts/ tests/ third_party/               验证工具、测试与许可材料
```

## 许可证

[GPL-3.0-only](LICENSE)，由 [zangwp](https://github.com/zangwp) 维护。第三方许可见 [NOTICE.md](NOTICE.md) 与 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
