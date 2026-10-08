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
| VPS 维护 | 网页查看资源、服务器信息与服务状态；通过 SSH `o` 菜单设置 DNS、Swap 和系统参数；开放端口在安全中心管理 |
| 账户安全 | 可选 TOTP 双因素认证、一次性恢复码、在线会话管理、持久登录审计及异常登录通知 |
| 防护与告警 | 文件保护、Fail2ban、nftables、邮件 / Webhook 通知和日志分析 |

全新安装默认使用 **LSPHP 8.5、MariaDB 11.8**；可为网站增加 LSPHP 8.4 / 8.3。现有数据库保留当前系列，常规系统更新不会自动跨系列升级。

界面采用浅色工作区与深蓝导航，提供中英文布局和手机端操作；看板集中展示资源指标，网站表格可横向滚动。账户安全入口位于“安全设置 → 账户登录”。双因素认证需要管理员主动绑定；启用前请按 [账户安全指南](docs/account-security.md) 单独备份 `account-mfa.key`，普通面板数据库下载不包含此密钥。

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

Swap 入口为 `o → 5. 系统设置 → 3. Swap 管理`，只管理 OLS WPanel 标记的 `/swapfile`，保留已有分区、zram 和外部文件。调整容量会检查临时新文件的完整磁盘占用，并核验运行状态；失败时恢复原文件与配置。删除受管文件保留当前系统 swappiness。

DNS 入口为 `o → 4. 网络设置 → 1. DNS 设置与检测`，支持运行中的 `systemd-resolved` 和普通 `/etc/resolv.conf` 文件。普通文件首次应用前需确认接管，保存原内容、权限和锁定状态；保留 search/options，支持恢复接管前配置。自定义地址需全部通过检测，普通文件最多 3 个，resolved 最多 4 个。DHCP、cloud-init、NetworkManager、resolvconf 和未识别的符号链接保持只读，页面显示具体原因。

时区菜单支持系统可用的 IANA 时区；系统语言工具缺失时可确认安装 locales。SSH 端口变更保留旧端口，要求通过新端口另开 SSH 连接执行返回的 `o ssh-confirm` 命令；独立守护任务在未确认时自动恢复。`o check-update` 分别显示 GitHub 最新发布与短入口实际目标版本，`o update` 不会降级到落后的入口版本。

卸载前会列出删除范围，输入 `Y`（或 `y`）确认，回车取消。卸载后退出管理菜单并移除 `o` / `O` 命令。更新脚本使用已发布的签名安装入口。

## 文档

- [安装与验签](docs/verified-install.md)
- [日常维护与恢复](docs/operations-and-recovery.md)
- [升级兼容性](docs/upgrade-compatibility.md)
- [账户安全、恢复码与密钥备份](docs/account-security.md)
- [旧 Optimizer 迁移](docs/optimizer-migration.md)：现有网站可显式迁移并移除旧插件。
- [安装安全](docs/security/ols-wpanel-install-security.md) · [运行时安全](docs/security/ols-wpanel-runtime-security.md)
- [仓库目录说明](docs/repository-layout.md)

---

[GPL-3.0-only](LICENSE) · [项目声明](third_party/NOTICE.md) · [第三方许可](third_party/THIRD_PARTY_NOTICES.md) · [zangwp](https://github.com/zangwp)
