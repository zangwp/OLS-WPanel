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
| 网站与 WordPress | 创建 WordPress 网站，管理域名、PHP 版本、文件、数据库及 WordPress 更新，兼容已有 PHP 网站 |
| 证书与缓存 | 网站证书申请与续签；使用官方 LiteSpeed Cache 管理页面及 Redis 对象缓存 |
| 备份与恢复 | 网站、数据库和面板备份，支持 SFTP / S3 异地保存 |
| VPS 维护 | 网页查看资源、服务器信息与服务状态；通过 SSH `o` 菜单设置 DNS、Swap 和系统参数；开放端口在安全中心管理 |
| 账户安全 | 可选 TOTP 双因素认证、一次性恢复码、在线会话管理、持久登录审计及异常登录通知 |
| 防护与告警 | 文件保护、Fail2ban、nftables、邮件 / Webhook 通知和日志分析 |

全新安装默认使用 **LSPHP 8.5、MariaDB 11.8**；可为网站增加 LSPHP 8.4 / 8.3。现有数据库保留当前系列，常规系统更新不会自动跨系列升级。

新建网站或补装缺失的 LiteSpeed Cache 时，面板查询 WordPress.org 当前稳定版，核对网站实际 WordPress / PHP 版本并校验插件包；失败或不兼容时尝试固定校验的 7.9.2，两者均需能够下载且兼容。已有插件和设置保持原样。详见 [WordPress 新站默认设置](docs/wordpress-new-install-defaults.md)。

在“网站管理 → 创建网站”填写域名和 PHP 版本，即可创建 WordPress 网站。已有的通用 PHP 网站仍可在网站列表和详情中管理。

界面采用浅色工作区与深蓝导航，提供中英文布局和手机端操作；看板集中展示资源指标，网站列表提供分组状态、搜索与筛选。网站详情中的登录地址、授权访问、缓存与安全证据说明见 [WordPress 访问与缓存指南](docs/wordpress-access-and-cache.md)。账户安全入口位于“安全设置 → 账户登录”。双因素认证需要管理员主动绑定；启用前请按 [账户安全指南](docs/account-security.md) 单独备份 `account-mfa.key`，普通面板数据库下载不包含此密钥。

## SSH 快捷命令

`o` 与大写 `O` 等价，面板信息会显示版本、端口和安全入口。

```text
o                 打开管理菜单
o dns             DNS 查看、预设 / 自定义地址检测与设置
o swap            Swap 容量与 swappiness 管理
o ports           本机监听、进程与入站规则诊断
o services        核心服务状态与最近日志
o bbr             当前拥塞控制、内核支持与持久配置
o disk            磁盘空间与 inode 检查
o processes       CPU / 内存占用最高的进程（只读短时采样）
o health          服务、磁盘、软件包与本机网络快速体检
o report          生成可复制的脱敏诊断摘要（只读）
o apt-check       APT / dpkg 只读健康检查
o history         最近 200 条终端维护记录
o ssh             SSH 双端口过渡，超时自动恢复
o status          诊断面板运行状态
o log [N]         查看最近 N 条面板日志
o restart         重启面板
o password        重置管理员密码
o unban           清空面板管理的 IP 封禁
o update          更新 / 修复面板
o uninstall       卸载面板，保留网站、数据库与共享软件
```

维护命令需 root 权限，终端菜单目前使用中文。DNS、Swap、SSH 与更新说明见 [终端维护指南](docs/verified-install.md#first-login-and-server-maintenance)，备份恢复与卸载检查见 [日常维护与恢复](docs/operations-and-recovery.md)。

首页保留面板版本、服务状态、完整登录地址和菜单，输入 `r` 刷新、`h` 运行快速体检；主机和资源详情在“1. 系统信息”中查看。服务异常或版本无法读取时显示对应诊断入口。进程 CPU 按单核 100% 计算，多核进程可以超过 100%；体检显示已确认的状态与下一步命令，无法读取的项目标为未知。

`o report`（或“8. 帮助 / 高级操作 → 7. 生成脱敏诊断摘要”）输出可整段复制的纯文本。摘要只保留版本、规范化系统信息及固定检查项的状态，不包含登录地址、主机名、账号、密钥、配置路径或原始日志。检查不完整时明确标记未知；有警告、未知或采集失败时退出码为 1，已生成的正文仍可复制。命令不自动修复或修改配置。

变更 SSH 端口时请保留当前连接，并在新端口另开 SSH 连接执行返回的 `o ssh-confirm` 命令。

## 文档

- [安装与验签](docs/verified-install.md)
- [日常维护与恢复](docs/operations-and-recovery.md)
- [升级兼容性](docs/upgrade-compatibility.md)
- [账户安全、恢复码与密钥备份](docs/account-security.md)
- [旧 Optimizer 迁移](docs/optimizer-migration.md)：现有网站可显式迁移并移除旧插件。
- [安装安全](docs/security/ols-wpanel-install-security.md) · [运行时安全](docs/security/ols-wpanel-runtime-security.md)
- [仓库目录说明](docs/repository-layout.md)
- [贡献与提交规范](CONTRIBUTING.md)：新提交和 PR 标题使用简短英文，发布说明提供中英文摘要。

---

[GPL-3.0-only](LICENSE) · [项目声明](third_party/NOTICE.md) · [第三方许可](third_party/THIRD_PARTY_NOTICES.md) · [zangwp](https://github.com/zangwp)
