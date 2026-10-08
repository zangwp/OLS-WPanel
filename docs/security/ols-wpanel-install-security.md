# OLS WPanel 安装安全边界

本文说明安装器当前实际做什么、信任哪些输入、会修改哪些系统状态，以及失败和卸载时不能保证什么。它不是“绝对安全”承诺；最终行为以同一 Release 中已验签的脚本和源码为准。

## 1. 首先理解 root 安装器的风险

OLS WPanel 要安装和管理 OpenLiteSpeed、LSPHP、MariaDB、Redis、Fail2ban、nftables 与 systemd，因此安装器必须以 root 运行。root 脚本理论上可以修改整台服务器，开源可读不等于下载内容真实，也不等于代码没有缺陷。

生产服务器应使用[验签安装指南](../verified-install.md)：

1. 从 GitHub Release 下载安装器、SHA-256 清单和 Ed25519 签名；
2. 使用独立固定的 OLS WPanel 发布公钥先验证清单签名；
3. 再核对安装器 SHA-256；
4. 阅读脚本后执行。

不要把可变 `main` 分支上的脚本直接通过管道交给 root shell。安装器内部对面板二进制的验签不能反向保护一个已经开始执行的引导脚本。

当前发布公钥原始值为：

```text
e6b66d84c67c8247821d2ab16b6d8e9584a962d4c8458d1f06b52d9cbbd65bd6
```

Release 签名只覆盖以下五组资产及各自的校验清单（共 6 个资产、18 个文件）：

- `ols-wpanel-linux-amd64` / `ols-wpanel-linux-arm64` 及对应 `.sha256`、`.sha256.sig`
- `install.sh`、`install.sh.sha256`、`install.sh.sha256.sig`
- `install-cn.sh`、`install-cn.sh.sha256`、`install-cn.sh.sha256.sig`
- `bootstrap.sh`、`bootstrap.sh.sha256`、`bootstrap.sh.sha256.sig`
- `ols-wpanel-third-party-licenses.tar.gz`、对应 `.sha256` 与 `.sha256.sig`

它不覆盖分支文件或 GitHub 自动生成的源码压缩包。有效签名只证明资产与这把密钥一致，不证明软件无漏洞、构建可复现、一定是最新版本或一定适合你的服务器；第三方反代仍可能返回较旧但签名有效的资产，因此还应核对 Release 版本。正式发布的安装器会把自身固定版本与下载路径、面板版本和许可归档绑定；最低版本门槛仍只是额外的回放下限，不能替代版本核对。

## 2. 执行前的 fail-closed 检查

`install.sh` 在第一次持久化系统写入前执行以下步骤：

1. 要求 root；
2. 严格检查 Debian 13/Trixie、Ubuntu 24.04/Noble 或 Ubuntu 26.04/Resolute，并要求 `amd64`/`arm64` 内核与 dpkg 用户空间架构一致；
3. 创建权限为 `0700` 的随机临时目录，并注册精确清理逻辑；
4. 从与安装器相同的固定 GitHub Release（或同目录离线包）获取面板二进制和许可归档及各自的校验清单与签名；
5. 使用内置 Ed25519 公钥验证两份清单签名；
6. 解析唯一、固定文件名的 SHA-256 记录并核对二进制与许可归档；
7. 用最小临时配置执行已验签候选程序的 `--info` 兼容性预检，并要求候选版本与安装器固定 Release 版本完全一致且不低于最低安全版本；
8. 获取安装锁，避免两个安装/repair 进程并发修改服务器。

任一步失败都会终止安装。安装器通过 curl/wget 显式获取的下列输入使用 HTTPS 限制、连接/总时限、低速时限、有限重试和硬字节上限。安装器同时检查已知的 `Content-Length` 和实际读取长度；分块传输或错误响应即使没有可信长度，也只能写入“上限 + 1”字节用于判定，随后拒绝并删除临时文件。本地发布包也必须在复制或计算哈希前通过相同的常规文件、非符号链接和大小检查。

| 输入 | 硬上限 |
|---|---:|
| 面板二进制 | 256 MiB |
| `install.sh` | 4 MiB |
| 每份 SHA-256 清单 | 4 KiB |
| 每份 Ed25519 签名 | 64 bytes |
| 第三方许可归档 | 64 MiB |
| LiteSpeed / MariaDB 仓库公钥 | 1 MiB |
| WordPress 备用 ZIP | 256 MiB |
| 公网 IP 文本响应 | 4 KiB |

许可归档根目录必须恰好有一个 `RELEASE_VERSION`，其单行内容必须与已发布安装器注入的 `INSTALLER_RELEASE_VERSION` 完全一致。归档即使签名有效，只要来自旧 Release、缺少标记或含重复标记，也会被拒绝；这是防止旧许可归档回放的版本绑定，不替代签名和哈希校验。

`install-cn.sh` 不是免验证跳板。它只会执行来自同一目录或 GitHub Release/管理员指定 HTTPS 反代的 `install.sh` 签名三件套，验签和验哈希通过后才运行主安装器。未签名的分支/CDN 脚本不会被执行。

## 3. 支持范围

安装器面向专用、干净的 Debian 13/Trixie、Ubuntu 24.04/Noble 或 Ubuntu 26.04/Resolute 主机，支持 amd64 与 arm64。它不是通用的“接管任意现有 LEMP 环境”工具，也不会把支持范围自动延伸到其他大版本。

- 现有 MariaDB 已设置未知 root 密码时，fresh install 不会自动导入该密码，可能失败；
- 由不同发行身份创建的面板不能通过手动改名或 repair 安全迁移，见[升级兼容性说明](../upgrade-compatibility.md)；
- 云厂商镜像、自定义 APT 源、现有 OpenLiteSpeed/LSPHP/防火墙策略可能与安装器冲突；
- 建议先使用可丢弃 VM 验证，再在已有完整快照的主机执行。

最低内存要求为 1 GB。物理内存不超过 8 GB、没有已启用 Swap 且磁盘检查通过时，安装器可能创建 2 GB `/swapfile`。

## 4. 安装期间会发生的系统改动

安装器会进行广泛的主机级修改，包括但不限于：

- 配置当前发行版软件源和经验证的 LiteSpeed 官方源；全新安装默认配置 MariaDB 11.8 官方源，Ubuntu 24.04 显式选择兼容系列时使用对应 MariaDB 官方源；
- 写入 sysctl、文件描述符、Swap 与 systemd 配置；
- 安装并配置 OpenLiteSpeed、LSPHP、MariaDB、Redis、Fail2ban 与 nftables/UFW 规则；
- 创建 `/www/ols-wpanel`、网站/日志/证书目录和面板服务；
- 创建面板 SQLite 数据库、配置、TLS 私钥和管理凭据；
- 下载 WordPress 备用包；
- 写入 OLS WPanel 的 cron、timer、Fail2ban、logrotate 和命令行入口。

这意味着安装器可能影响同机已有服务。系统包来自签名 APT 仓库能降低传输篡改风险，但包签名不证明软件没有漏洞，也不消除配置冲突。

### 密码与身份

- 安装器不会主动更改 Linux root/SSH 密码，也不以修改 `/etc/shadow` 或 `sshd_config` 作为安装步骤；
- fresh install 会为 MariaDB root、BasicAuth 和 Web 管理员生成新凭据；
- repair 会保留通过校验的现有配置、登录凭据、MariaDB 身份和 TLS 身份；
- 面板登录密码使用 bcrypt；MariaDB root 密码等运行时秘密必须以可恢复形式保存在 root-only 配置中；
- 安装完成凭据只主动输出到当前 stdout 一次，但 SSH 终端、云串口、CI 或会话记录仍可能捕获输出，应安全保存并清理相关日志。

### 初始 TLS 证书

fresh install 创建自签名证书。它可以加密连接，但浏览器没有可信签发链，且初始证书不能替你确认公网服务器身份。首次登录前应通过 SSH 核对证书指纹：

```bash
openssl x509 -in /www/ols-wpanel/certs/panel.crt -noout -fingerprint -sha256
```

公网长期使用时应换成可信证书，并用防火墙限制 8443 管理端口来源。不要把“点击继续访问证书警告”视为抵抗中间人攻击的方案。

## 5. 预期出站连接

安装过程可能连接以下目的地；抓包时看到这些连接不等于遥测：

| 目的 | 默认目标 | 说明 |
|---|---|---|
| 已签名发布资产 | GitHub Releases | 可使用管理员明确配置的 HTTPS 反代 |
| Debian 包与元数据 | Debian 官方源或所选镜像 | 部分 APT 镜像 URL 使用 HTTP，完整性依赖 APT 签名链 |
| Ubuntu 包与元数据 | Ubuntu 官方源或所选镜像 | amd64 使用 Ubuntu archive，arm64 使用 Ubuntu ports；完整性依赖 APT 签名链 |
| OpenLiteSpeed / LSPHP 仓库 | `rpms.litespeedtech.com` | 两把仓库公钥均使用发布内固定 SHA-256 校验，支持 LSPHP 8.3/8.4/8.5 |
| MariaDB 仓库 | `mirror.mariadb.org`、`supplychain.mariadb.com` | 全新安装统一启用 11.8；公钥完整指纹必须匹配，现有数据库不自动跨系列升级或降级 |
| WordPress 备用包 | wordpress.org | 下载失败时安装可继续，但后续建站仍需网络并可能失败 |
| 公网地址显示 | ip.sb、ifconfig.me | 仅用于安装完成页；服务会看到连接源 IP |

安装器本身不发送安装遥测。运行时遥测是另一项功能：默认关闭、没有预设端点，只有配置自定义端点并启用后才发送稳定伪匿名 ID 与版本。JSON 不含业务数据或 IP 字段，但接收端仍会看到网络源 IP 与时间。

LiteSpeed 仓库的两把公钥分别按发布内固定 SHA-256 验证，随后才写入 OLS WPanel 专用 keyring。MariaDB 官方仓库使用专用 keyring 路径，并要求公钥完整指纹严格等于 `177F4010FE56CA3336300305F1656F24C74CD1D8`。上游轮换密钥时，必须先审计并在新的 OLS WPanel 版本中更新固定值；运行中的安装器不会自动信任新密钥。

## 6. repair 的保护与限制

repair 不是跨发行身份迁移。它只接受当前 OLS WPanel 的固定 cron、service unit、服务名和二进制路径。

repair 预检会：

- 拒绝符号链接、非常规文件、不安全权限/所有权或硬链接配置；
- 拒绝重复 JSON 键、缺失关键身份、异常绝对路径和不匹配的分发身份；
- 要求现有 systemd unit 是 root 安全持有、无硬链接、内容与本发行版生成版本完全一致，并拒绝 service drop-in；
- 只读检查 SQLite 完整性；
- 对全部更新和 repair 入口比较已安装版本与候选版本；读取版本失败或候选版本更旧时拒绝继续；
- 验证现有 TLS 配对并保留有效或已过期身份，不会静默替换自定义证书；
- 在修改前备份关键文件和 SQLite，并记录 SHA-256；已有 `account-mfa.key` 时一并保存到私有 repair 快照，并保持仅 root 可读。

失败时安装器会尝试恢复已备份的二进制、unit、数据库和 TLS 文件，但回滚也可能失败，而且不是整机快照。它不保证恢复面板目录外的所有 OpenLiteSpeed、PHP、Fail2ban、WordPress 插件或站点数据库副作用。repair 前仍应创建主机和业务数据备份。

## 7. 卸载与彻底清理

普通卸载会永久删除 `/www/ols-wpanel`，包括面板数据库、`config.json`、面板 TLS 身份、本地面板/站点备份和远程备份凭据。所需文件必须先复制到该目录之外。

普通卸载的目标是保留 `/www/wwwroot`、`/www/wwwlogs`、站点证书、MariaDB 数据和已安装软件，同时清理已知的 OLS WPanel 服务/任务入口。运行环境保留时，对应 LiteSpeed / MariaDB APT 源与签名密钥也保留，以便继续获取软件更新；仅在彻底清理对应软件后移除带有 OLS 所有权标记的专用源，并恢复它曾禁用且未发生路径冲突的系统源。后来由管理员创建的同名文件不会被覆盖。它不承诺把主机精确恢复到安装前状态，也不替代卸载后审计。

检测到遗留网站时，fresh install 和 reinstall 会拒绝覆盖安装；删除面板并不表示服务器已恢复为干净环境。应保留网站和数据库备份，按[升级兼容性说明](../upgrade-compatibility.md)恢复匹配的面板状态。

“完全卸载”面向专用主机，会删除面板记录的网站数据库、OpenLiteSpeed 站点配置以及指定目录中的网站、日志和证书，卸载 OpenLiteSpeed、LSPHP 和 MariaDB。Redis、Fail2ban 等可能共享的软件保留，只清理面板自身集成。它不是安全擦除，软件包未移除的共享目录、部分用户、防火墙和自定义配置仍可能残留，不等于恢复一台全新 VPS。

两种卸载均先列出删除范围，只有输入 `Y` 或 `y` 才继续，回车或其他输入取消。完全卸载还会检查网站和数据库归属；备份默认转移保留，只有另行输入 `DELETE BACKUPS` 才删除。卸载命令被移除后，当前菜单立即退出，新的 SSH 会话无法再运行 `o` / `O`。当前 shell 的旧命令路径缓存可用 `hash -r` 清除。若卸载失败，会显示中断阶段与退出码；已经完成的删除不会自动恢复，应先核对日志和残留。

## 8. 本地与隔离环境安装

本地提供面板二进制时必须同时提供同一 Release 的六个文件：

```text
ols-wpanel-linux-<arch>
ols-wpanel-linux-<arch>.sha256
ols-wpanel-linux-<arch>.sha256.sig
ols-wpanel-third-party-licenses.tar.gz
ols-wpanel-third-party-licenses.tar.gz.sha256
ols-wpanel-third-party-licenses.tar.gz.sha256.sig
```

任意本地编译产物不会因为与脚本同目录就被信任，也无法在没有发布私钥的情况下伪装成正式资产。六个候选文件均在复制和哈希前执行大小限制；许可归档还必须携带与安装器固定版本完全一致的唯一 `RELEASE_VERSION`。这样只能省去面板和许可资产下载；APT 软件包、仓库密钥和 WordPress 包仍可能需要网络，当前不承诺完整离线安装。

## 9. 建议的管理员验证

安装前：

- 在独立渠道核对发布公钥；
- 验证安装器签名和哈希；
- 阅读脚本、Release Notes 和本页列出的系统改动；
- 创建主机、网站文件、数据库和密钥的可恢复快照。

安装后：

```bash
systemctl status ols-wpanel --no-pager
journalctl -u ols-wpanel -n 100 --no-pager
ss -lntp | grep ':8443'
openssl x509 -in /www/ols-wpanel/certs/panel.crt -noout -fingerprint -sha256
```

同时检查 APT 源、防火墙、OpenLiteSpeed/LSPHP 配置、计划任务和备份恢复流程。发现问题时先保留日志与快照，不要把重装系统作为默认的第一步。
