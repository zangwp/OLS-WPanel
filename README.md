# OLS WPanel

<img src="web/logo.png" alt="OLS WPanel" width="88">

轻量的 VPS 与 WordPress 管理面板。集中管理网站、数据库、SSL 证书、缓存、备份和服务器维护，基于 OpenLiteSpeed、LSPHP、MariaDB 与 Redis。

[English](README.en.md) · [使用文档](docs/operations-and-recovery.md) · [版本发布](https://github.com/zangwp/OLS-WPanel/releases) · [问题反馈](https://github.com/zangwp/OLS-WPanel/issues)

## 安装

支持全新的 **Debian 13、Ubuntu 24.04 LTS、Ubuntu 26.04 LTS**，架构为 **amd64 / arm64**。最低 1 核 CPU、1 GiB 内存。使用 root 执行：

```bash
curl -fsSL https://ols.zangyubin.top/install | bash
```

安装入口固定到已发布的稳定版本，验证 Ed25519 签名与 SHA-256 后安装。

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

## 文档

- [安装与验签](docs/verified-install.md)
- [日常维护与恢复](docs/operations-and-recovery.md)
- [升级兼容性](docs/upgrade-compatibility.md)
- [旧 Optimizer 迁移](docs/optimizer-migration.md)：现有网站可显式迁移并移除旧插件。
- [安装安全](docs/security/ols-wpanel-install-security.md) · [运行时安全](docs/security/ols-wpanel-runtime-security.md)
- [仓库目录说明](docs/repository-layout.md)

---

[GPL-3.0-only](LICENSE) · [项目声明](third_party/NOTICE.md) · [第三方许可](third_party/THIRD_PARTY_NOTICES.md) · [zangwp](https://github.com/zangwp)
