# OLS WPanel

<p><img src="static/logo.png" alt="OLS WPanel" width="120"></p>

WordPress 专用服务器管理面板。面向 Debian 13 与 Ubuntu 24.04 LTS 的纯净服务器，支持 amd64 和 arm64。

OLS WPanel 遵循 GNU GPL v3.0 only（SPDX：`GPL-3.0-only`）。源码、安装脚本和已签名发行版位于 [zangwp/OLS-WPanel](https://github.com/zangwp/OLS-WPanel)。

WordPress server management panel for Debian 13 and Ubuntu 24.04 LTS VPS environments on amd64 or arm64, focused on site isolation, SSL, backups, security, and day-to-day WordPress hosting operations.

## English Documentation

The full English project guide is available here: [README.en.md](README.en.md).

[![License](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8.svg)](https://go.dev/)

---

## 🚀 快速安装

> **支持范围：Debian 13 (Trixie) / Ubuntu 24.04 LTS (Noble)，amd64 / arm64。** 使用 `root` 用户执行：

```bash
curl -fsSL https://ols.zangyubin.top/install | bash
```

短域名入口固定到已发布的 Release；Cloudflare Worker 会先验证 `bootstrap.sh` 的 Ed25519 签名和 SHA-256。脚本下载后会自动检查并补装 `wget`、`curl`、`ca-certificates`、`openssl` 等引导依赖，再次验签固定版本的 `install.sh`，最后才启动安装。它不会执行 GitHub `main` 分支上的可变脚本。

当前稳定版本：`v1.2.0`。

### 可选 MariaDB 系列（仅限全新安装）

全新安装默认使用经本版本验证的最新稳定系列 MariaDB `11.8`；Ubuntu 24.04 如需旧应用兼容，可明确选择 `10.11` 或 `11.4`：

```bash
curl -fsSL https://ols.zangyubin.top/install | bash -s -- --mariadb-version 11.8
```

Ubuntu 24.04 可选择 `10.11`、`11.4` 或 `11.8`；MariaDB 官方仓库对 Debian 13/Trixie 仅提供 `11.8`，安装器会在下载软件包前拒绝不受支持的组合。该参数不会对已有数据库执行在线降级；已有服务器的跨系列升级必须先完成全量备份、兼容性检查和恢复演练。兼容官方 `--mariadbver` 参数别名。

### 极简系统 / 下载失败处理

如果系统提示 `curl: command not found`、TLS/证书错误，或使用的是未预装下载与验签工具的精简镜像，请先执行完整兼容命令：

```bash
apt-get update && apt-get install -y --no-install-recommends curl wget ca-certificates openssl && (set -o pipefail; curl -fsSL --proto '=https' --proto-redir '=https' https://ols.zangyubin.top/install | bash)
```

需要在执行任何远程脚本前自行验签，或进行国内网络、离线安装时，请使用 **[完整验签安装指南](docs/verified-install.md)**。

## 定位

通用 Linux 面板臃肿、复杂、与 WordPress 无关的功能太多。

OLS WPanel 只做一件事：**在 VPS 上高效管理 WordPress 网站**。不做 Docker、不做邮件系统、不做 FTP、不做 Java/Python/Node 运行环境。

## 功能模块

| 模块 | 说明 |
|------|------|
| **网站管理** | 一键创建 WordPress 网站，也可暂停、启用、删除或重装；每个网站相互隔离，一个网站出问题时不容易影响其他网站 |
| **WordPress 更新管理** | 在更新核心、插件或主题前先确认内容并自动备份；更新后检查网站是否正常，失败时自动恢复，插件还可批量更新 |
| **WordPress 站点总览** | 在一个页面查看所有 WordPress 网站的版本、插件、主题和待更新项目，不必逐个登录后台检查 |
| **WordPress 维护保护** | 更新或维护网站时自动显示维护页面，结束后恢复访问；临时维护到期后也会自动恢复，减少忘记开启网站的风险 |
| **SSL 证书** | Let's Encrypt 自动申请、到期前 30 天自动续签、手动替换、自签名证书 |
| **网站加速** | 提供页面缓存，并可从 WordPress 后台一键清理；上传图片时也可按设置自动优化，减少图片占用和加载时间 |
| **安全防御** | 自动拦截常见的登录爆破、恶意扫描和高频爬虫，并整理可疑访问记录，方便判断是否需要处理 |
| **密码找回保护** | 可按网站决定是否允许找回密码，也可以只禁止管理员账号通过公开页面找回，降低账号被试探的风险 |
| **数据库管理** | 修改数据库密码，手动或自动备份数据库，并可上传备份进行恢复；需要临时管理时可按需开启管理工具 |
| **计划任务** | 用页面管理定时任务，可用更可靠的系统任务替代 WordPress 自带定时任务，并查看备份等任务是否正常运行 |
| **文件管理器** | 像使用电脑文件管理器一样上传、下载、复制、移动、压缩、解压和搜索文件；大文件支持断点续传 |
| **仪表盘** | CPU/内存/磁盘/负载实时监控、24h/7d/15d 历史趋势图 |
| **系统稳定性防护** | 内存不足时自动增加缓冲空间；重要服务异常、内存耗尽或资源使用异常时保留线索并发出提醒 |
| **网站异常监测** | 关注管理员账号、内容、重要设置、应用密码和异常文件变化，帮助尽早发现网站被篡改的迹象 |
| **AI 诊断** | 一键汇总网站日志和服务状态，用对话方式继续追问问题；只提供分析建议，不会自行修改网站 |
| **告警通知** | 可通过邮件接收资源不足、服务异常、证书到期、网站到期和可用更新等提醒，每类提醒可单独开关 |
| **软件与运行环境** | 管理 OpenLiteSpeed、LSPHP 8.3/8.4/8.5、MariaDB、Redis、nftables 与 Fail2ban，查看版本和候选更新，并按网站生成隔离的虚拟主机与 LSPHP 进程配置 |
| **面板安全** | 使用不公开的登录入口和两次登录验证；连续输错密码或频繁扫描错误地址时会自动限制来源 |
| **安全更新** | 面板和当前 Debian/Ubuntu 系统软件都可检查更新；面板更新会验签并在健康检查失败时尝试回滚 |
| **备份与异地保存** | 自动备份网站和面板数据，并可把网站备份同步到另一台服务器或对象存储，减少单机故障造成的损失 |

## 验签安装说明

生产服务器请从 GitHub Release 下载安装器、SHA-256 清单和 Ed25519 签名，验签成功后再以 root 执行。不要把可变分支脚本直接通过管道交给 shell。国内入口同样必须先验签，并支持管理员明确配置的 HTTPS GitHub 反代。

完整可复制命令、公钥与本地发布包说明见 **[验签安装指南](docs/verified-install.md)**。

安装完成后输出面板地址和两层登录凭据（BasicAuth + Web 登录）。

> 初始自签名证书只能加密连接，不能替你确认服务器身份。首次登录前应通过 SSH 核对证书 SHA-256 指纹；公网长期使用时请换成可信证书并限制管理端口来源。

> 由其他发行身份创建的旧安装不能直接通过改名或 repair 迁移。请先阅读 **[安装身份与升级兼容性](docs/upgrade-compatibility.md)**。

## 安全性

**一句话：随机入口、两层登录和自动限速能明显提高公网扫描与口令猜测的成本，但不能替代可信终端、强密码、及时更新、访问控制和可恢复备份。**

这是因为正常登录必须同时知道每台服务器独有的随机入口，并依次通过浏览器弹窗和网页登录。反复寻找入口或猜测密码还会触发自动限制。没有任何联网软件能承诺绝对不会被攻破，但 OLS WPanel 不会把安全只押在一个密码上。

---

更详细的安全机制：

**访问防护**
- 每台服务器都有独立的随机入口，能提高陌生扫描者找到登录页的难度
- 直接使用扫描工具试探面板，或在一分钟内访问 10 个不同的错误地址，会触发自动限制
- 即使找到入口，仍需依次通过浏览器弹窗和网页登录
- 登录过程使用 HTTPS 加密，错误提示也会尽量避免暴露服务器内部信息

**防爆破**
- 浏览器弹窗或网页登录在短时间内连续失败 5 次，会限制该来源 24 小时
- 网站登录和 SSH 也有独立保护；重复攻击时限制时间会逐步延长，最长 7 天

**站点隔离**
- 每个网站运行在独立系统用户和独立的 LSPHP 外部应用进程下
- 每个网站使用独立的 MariaDB 数据库
- 独立用户和 LSPHP 进程可降低单站故障横向影响；内核、数据库及宿主机资源仍是共享边界

**WordPress 专项防护**
- 自动识别反复尝试登录、批量寻找常见敏感文件和短时间访问大量不存在页面的行为
- 拒绝使用陌生域名访问服务器，减少网站和证书信息被探测的机会
- 将可疑访问按风险高低整理，并给出可疑来源、访问目标和处理建议；默认只分析，不会仅凭分析结果自动封禁
- 监测网站目录中新出现的可疑 PHP 文件和异常高频访问，留下安全事件记录
- 可单独限制高频爬虫，尽量减少对普通访客和日常后台操作的影响

**AI 运维诊断**
- 一次收集与网站故障有关的日志和运行状态，并可继续追问，减少新手来回寻找信息的困难
- 诊断只给出分析和排查建议，不会自动修改文件、数据库或服务器设置

**备份与异地保存**
- 网站备份可同步到另一台服务器或 S3 兼容存储；同步失败时可按设置保留本地副本

**更新安全**
- 更新前会使用 OLS WPanel 的独立 Ed25519 公钥验证安装包，避免使用被替换或损坏的文件
- 候选二进制报告的规范稳定版本必须与 Release 标签一致，避免旧的合法签名包被包装成更高版本重放
- 替换前会备份当前二进制和面板数据库；健康检查失败时会尝试回滚，但回滚并非整机快照，也可能失败

**代码透明**
- 100% 开源（`GPL-3.0-only`），代码可审查
- 运行时遥测默认关闭且没有预设端点；启用自定义端点后发送稳定伪匿名 ID 与版本，不发送业务内容
- 面板自身版本元数据默认来自 GitHub；WordPress 更新及管理员启用的外部功能会连接各自上游
- 无 Web Shell、无在线代码编辑功能
- 面板登录密码使用 bcrypt；运行所需的数据库和第三方服务凭据可能保存在 root-only 配置或数据库中

### 📖 安全深度解读

- **[安装脚本安全透明化报告](security/ols-wpanel-install-security.md)** — 逐段拆解安装、签名验证、软件源与系统变更边界
- **[运行时安全：多层防护机制](security/ols-wpanel-runtime-security.md)** — 源码层面解析六层纵深防御、更新签名校验、软件漏洞管理

## 安全测试

欢迎白帽和安全研究人员对本项目进行安全测试。如果你发现安全漏洞，请通过以下方式反馈：

- **公开反馈**：提交 [GitHub Issue](https://github.com/zangwp/OLS-WPanel/issues)，在标题标注 `[安全]`
- **私下反馈**：通过 GitHub Security 标签页提交 Private Vulnerability Report
- 有效漏洞会在修复后于 Release Notes 中向报告者致谢

## 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Debian 13 (Trixie) 或 Ubuntu 24.04 LTS (Noble)；暂不自动延伸到其他大版本 |
| CPU | 1 核及以上 |
| 内存 | 1 GB 及以上（物理内存不超过 8 GB、未启用 Swap 且磁盘条件满足时，安装器可能创建 2 GB Swap） |
| 架构 | amd64/x86_64 或 arm64/aarch64（内核与 dpkg 用户空间架构必须一致） |

> 各云厂商定制镜像可能带来兼容性差异。请先保存日志并排查网络、APT、签名和系统版本。第三方重装项目不由 OLS WPanel 维护；重装系统会清除数据，只应在新机或已验证完整快照后使用。

## 为什么选择这些技术方案

**为什么锁定 Debian 13 与 Ubuntu 24.04 LTS？**

安装器会配置 LiteSpeed 官方 HTTPS 软件源，并安装 OpenLiteSpeed、LSPHP、MariaDB、Redis、Fail2ban 与 systemd 服务，因此兼容性必须按发行版版本和架构验证。当前只接受 Debian 13/Trixie 和 Ubuntu 24.04/Noble，不会自动放宽到未经测试的旧版或新版。

**PHP 版本如何选择？**

全新安装默认启用本版本已经验证的最新稳定运行时 LSPHP 8.5；软件管理中可按需添加 8.4 或 8.3 兼容运行时，再在创建网站或网站详情中逐站选择。已有服务器保持原主版本，不会因为面板更新自动切换网站。

**为什么是 MariaDB 而非 MySQL？**

WordPress 官方推荐 MariaDB 10.6 或更高版本。全新安装默认使用 MariaDB 11.8 和经签名密钥校验的官方仓库；Ubuntu 24.04 仍可显式选择 10.11 或 11.4，Debian 13 因官方仓库兼容范围仅支持 11.8。MariaDB 是由社区驱动的 GPL 分支并兼容 MySQL。已有数据库只接收当前系列的补丁，不会被面板静默跨系列升级或降级。

**服务版本如何更新？**

“系统更新”安装当前 APT 软件源提供的稳定补丁和安全更新。OpenLiteSpeed 与 LSPHP 来自 LiteSpeed 官方源；MariaDB 使用安装时选定的发行版或 MariaDB 官方系列；Redis 使用经固定公钥哈希校验的 Redis 官方源（v1.1.0 首发基线为 8.10.2）；nftables 与 Fail2ban 使用目标系统仓库。软件管理会同时显示已安装版本、APT 候选版本，以及 Redis 8.10.2、nftables 1.1.7、Fail2ban 1.1.1 的上游稳定版本参考。上游项目发布的最新源码版本不等于当前系统已有可验证的软件包，因此面板不会绕过包管理器直接覆盖生产服务。

**为什么没有开放 OpenLiteSpeed WebAdmin 7080？**

OLS WPanel 会生成并维护服务器级与网站级 OpenLiteSpeed 配置，因此默认关闭 WebAdmin，避免两个后台互相覆盖配置，并减少一个公网管理入口。安装器已启用 Gzip、Brotli、HTTP/3/QUIC，并为 WordPress 网站生成 LiteSpeed Cache 与 Redis 配置；“软件管理”页会直接显示这些能力的实际状态。若确有高级配置需求，应先在面板中实现带校验和回滚的对应选项，而不是同时修改 WebAdmin 与面板管理的文件。

**为什么是自己编的 Go 二进制，不用 Docker/PM2？**

面板应用以单个静态 Go 二进制分发并由 `systemd` 守护，不需要 Docker/PM2。完整功能仍依赖安装器列出的系统服务和命令。它不与 OpenLiteSpeed 共用管理端口，也没有容器运行时开销。

## 运行组件

下表中的服务器栈组件通过 APT 安装；面板二进制来自已签名 GitHub Release，WordPress 与 WP-CLI 使用各自上游分发渠道：

| 组件 | 说明 |
|------|------|
| LSPHP 8.5 / 8.4 / 8.3 | LiteSpeed 官方 HTTPS 软件源；8.5 默认安装，8.4/8.3 作为兼容运行时按需添加；每个网站使用独立 LSAPI socket、系统用户和进程上限 |
| MariaDB 11.8 / 11.4 / 10.11 | 全新安装默认 11.8；Ubuntu 24.04 可显式选择三种系列，Debian 13 支持 11.8；使用经验证的 MariaDB 官方仓库 |
| OpenLiteSpeed | LiteSpeed 官方 HTTPS 软件源；每站点独立虚拟主机，并自动安装官方 LiteSpeed Cache 插件 |
| Redis 8.10.2+ | Redis 官方签名 APT 软件源；支持 Noble/Trixie 与 amd64/arm64 |
| Fail2ban + nftables | 当前发行版系统源；界面同时显示上游稳定版本参考，避免源码覆盖系统防火墙组件 |

## 技术架构

- **后端**：Go + Gin Web 框架，SQLite (WAL 模式)，端口 8443 (HTTPS/TLS)
- **前端**：HTML 模板 + TailwindCSS + Alpine.js + Chart.js
- **分发**：单一二进制文件（前端资源通过 `//go:embed` 编译内嵌），约 20 MB
- **安全**：面板不与 OpenLiteSpeed 共用管理入口，使用独立端口和 TLS

## SSH 管理命令

从 `v1.0.0` 起，安装后面板提供 `o` 命令行工具，并兼容完全相同的大写入口 `O`：

| 命令 | 说明 |
|------|------|
| `o` 或 `O` | 查看面板信息 |
| `o restart` | 重启面板 |
| `o password` | 一键重置管理员账号密码 |
| `o info` | 查看版本/端口/入口 |
| `o status` | 查看运行状态 |
| `o unban` | 清空所有 IP 封禁（管理员被误封时紧急恢复） |

## 面板数据库备份与恢复

面板使用 SQLite 存储数据，每天凌晨 2:30 自动备份到 `/www/ols-wpanel/backups/panel-db/`，保留最近 7 份。

### 面板正常时

在「面板设置」页面可以：
- 手动创建备份
- 下载备份文件到本地
- 从备份恢复（恢复前自动创建安全备份，恢复后面板自动重启）
- 删除备份

### 面板无法启动时的恢复步骤

如果面板恢复数据库后无法启动，或数据库损坏导致面板无法运行，请通过 SSH 手动恢复：

```bash
# 1. 查看可用备份
ls -lh /www/ols-wpanel/backups/panel-db/

# 2. 停止面板
systemctl stop ols-wpanel

# 3. 备份当前损坏的数据库（以防万一）
cp /www/ols-wpanel/panel.db /www/ols-wpanel/panel.db.broken

# 4. 用备份替换当前数据库（替换为实际的备份文件名）
cp /www/ols-wpanel/backups/panel-db/panel_20260107_023000.db /www/ols-wpanel/panel.db

# 5. 启动面板
systemctl start ols-wpanel

# 6. 检查是否正常
systemctl status ols-wpanel
journalctl -u ols-wpanel -n 20
```

### 重装面板后导入备份

如果需要完全重装面板并恢复数据：

```bash
# 1. 先保存备份文件到安全位置
cp -r /www/ols-wpanel/backups/panel-db/ /root/panel-db-backup/

# 2. 重装面板（选择"卸载后重新安装"，保留网站数据）

# 3. 安装完成后停止面板
systemctl stop ols-wpanel

# 4. 用备份替换新数据库
cp /root/panel-db-backup/panel_20260107_023000.db /www/ols-wpanel/panel.db

# 5. 启动面板（自动执行数据库升级）
systemctl start ols-wpanel
```

> **注意**：这里只支持同一 OLS WPanel 分发链且仍在公开支持范围内的 SQLite 备份。其它发行身份的备份不得直接恢复；该数据库备份也不包含网站文件、MariaDB 数据或面板目录外配置。详见[升级兼容性说明](docs/upgrade-compatibility.md)。

## 项目结构

```
├── main.go               # 程序入口
├── config/               # 全局配置管理
├── database/             # SQLite 连接与迁移
├── models/               # 数据结构
├── router/               # 路由 + 页面分发
├── middleware/            # BasicAuth / Session / CSRF / 登录限流
├── handlers/             # HTTP 处理器
├── executor/             # 任务执行器
├── collector/            # 系统指标采集
├── templates/            # HTML 模板
├── static/               # 已生成并嵌入的 CSS / JS / Logo
├── assets/               # 品牌、社区图片与前端源文件
├── deploy/cloudflare/    # 短安装域名的可审计 Worker 配置
├── install.sh            # 一键安装脚本
├── install-cn.sh         # 国内入口及 bootstrap.sh 的共享验签源
├── tests/                # 安装器与跨包约束测试
├── security/             # 安全说明文档
└── ols-wpanel-optimizer/   # WordPress 配套插件
```

为什么部分 Go 测试仍留在根目录、哪些重复资产是有意保留的，见[仓库结构说明](docs/repository-layout.md)。

## OLS WPanel 开源许可

GNU GPL v3.0 only（SPDX：`GPL-3.0-only`）

OLS WPanel 依据 GNU GPL v3.0 only 发布，由 zangwp 维护。完整许可条款见
[`LICENSE`](LICENSE)，项目声明见 [`NOTICE.md`](NOTICE.md)，第三方组件许可见
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) 及每个 Release 附带的签名许可归档。
