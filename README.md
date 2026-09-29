# OLS WPanel

<p><img src="static/logo.png" alt="OLS WPanel" width="120"></p>

面向 WordPress 的轻量服务器管理面板，集成 OpenLiteSpeed、LSPHP、LiteSpeed Cache、MariaDB 和 Redis。支持 Debian 13 / Ubuntu 24.04 LTS 的 amd64 与 arm64 系统。

[English](README.en.md) · [问题反馈](https://github.com/zangwp/OLS-WPanel/issues) · [安全报告](https://github.com/zangwp/OLS-WPanel/security)

[![License](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg)](https://go.dev/)

## 🚀 快速安装

> 仅用于全新的 Debian 13 (Trixie) 或 Ubuntu 24.04 LTS (Noble) 服务器，使用 `root` 执行。

```bash
curl -fsSL https://ols.zangyubin.top/install | bash
```

当前稳定版：`v1.2.4`。短链接固定到已发布 Release，会先验证 Ed25519 签名和 SHA-256，并自动补齐 `curl`、`wget`、`ca-certificates` 和 `openssl` 等引导依赖。

精简镜像如果连 `curl` 都没有，请先执行：

```bash
apt-get update && apt-get install -y --no-install-recommends curl wget ca-certificates openssl
curl -fsSL https://ols.zangyubin.top/install | bash
```

需要手动验签、国内网络或离线安装时，使用 [完整验签安装指南](docs/verified-install.md)。

## 默认运行栈

| 组件 | 默认策略 |
|---|---|
| OpenLiteSpeed | 官方稳定软件源，每站点独立虚拟主机 |
| LSPHP | 默认 8.5；可按需增加 8.4 / 8.3，并逐站点切换 |
| MariaDB | 全新安装默认 11.8；现有数据库仅跟随当前系列的补丁与安全更新 |
| Redis | 官方签名 APT 源，每个 WordPress 站点使用独立缓存前缀 |
| 安全组件 | Fail2ban + nftables，跟随系统软件源更新 |

## 核心能力

| 板块 | 主要能力 |
|---|---|
| 网站 | 创建 WordPress 或通用 PHP 站点，独立系统用户、LSPHP 进程、数据库与日志 |
| WordPress | 核心/主题/插件更新检查，LiteSpeed Cache，Redis 对象缓存，定时任务与临时维护 |
| SSL | Let's Encrypt 申请与自动续签，支持手动证书，失败时保留 HTTP 站点便于排查 |
| 备份 | 站点与数据库备份/恢复，面板 SQLite 自动备份，支持 SFTP / S3 异地保存 |
| 安全 | 登录防爆破、恶意扫描检测、CDN 真实 IP、白名单、Fail2ban 与 nftables 封禁 |
| 运维 | CPU/内存/磁盘监控，文件与数据库管理，计划任务，邮件告警，日志分析与 AI 诊断 |
| 更新 | 面板 Release 验签更新与回滚；系统软件通过已配置的签名 APT 源更新 |

OLS WPanel 不提供邮件服务器、FTP、Docker 编排或通用 Java/Python 应用托管，以减少攻击面和无关依赖。

## 系统要求

| 项目 | 要求 |
|---|---|
| 操作系统 | Debian 13 (Trixie) 或 Ubuntu 24.04 LTS (Noble) |
| 架构 | amd64/x86_64 或 arm64/aarch64 |
| CPU | 1 核及以上 |
| 内存 | 1 GiB 及以上 |
| ARM64 页大小 | 4 KiB 或 8 KiB；16 KiB 会因 OLS 官方二进制不兼容而中止 |

其他 Debian/Ubuntu 大版、非标准云镜像或已有生产环境不在自动安装承诺范围内。

## SSH 管理命令

`o` 与 `O` 完全等价：

```text
o / O             查看面板信息
o restart         重启面板
o password        重置管理员密码
o info            查看版本、端口和入口
o status          查看运行状态
o unban           清空面板管理的 IP 封禁
```

## 安全与文档

- [验签安装指南](docs/verified-install.md)
- [日常运维与面板数据库恢复](docs/operations-and-recovery.md)
- [安装身份与升级兼容性](docs/upgrade-compatibility.md)
- [仓库结构与有意保留的资产](docs/repository-layout.md)
- [安装器安全边界](security/ols-wpanel-install-security.md)
- [运行时多层防护](security/ols-wpanel-runtime-security.md)

面板使用随机入口、BasicAuth 和 Web 登录两层验证。这些措施能提高扫描和口令猜测成本，但不能替代强密码、可信终端、及时更新、端口访问控制和可恢复备份。

## 仓库概览

```text
handlers/ collector/ database/ models/ router/  Go 应用模块
executor/ security/ config/                    系统操作与安全边界
templates/ static/ assets/                     前端模板、嵌入资产与品牌源文件
ols-wpanel-optimizer/                          WordPress 配套插件
deploy/cloudflare/ stats-worker/               独立部署组件
scripts/ tests/ third_party/                   验证脚本、测试与第三方许可材料
```

## 许可证

OLS WPanel 依据 GNU GPL v3.0 only（SPDX：`GPL-3.0-only`）发布，由 [zangwp](https://github.com/zangwp) 维护。详见 [LICENSE](LICENSE)、[NOTICE.md](NOTICE.md) 和 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
