# 本地安全复核：2026-10-10

范围：本版修改中的面板认证、网站封禁、Cloudflare WAF 同步、CDN 真实 IP、端口回退、SSH 与 OLS 双栈配置，以及相关界面状态和依赖。基于工作区代码和隔离测试，安全复核未读取或修改真实 VPS、Cloudflare 账户与线上规则。用户于 2026-10-10 查看本地预览后明确授权推送发布；发布记录和 Linux CI 结果另行保存在工作区发布验证目录。

## 确认的问题与处理

### SEC-01 · 高：网站登录封禁抑制独立面板封禁

位置：`internal/middleware/login_attempt.go` 的 `banIP`，`internal/middleware/scan_defense.go` 的 `banScanIPForDuration`。

已有 `olswpanel-login` 网站登录封禁时，旧去重逻辑认为 IP 已封禁，不再生成面板登录或扫描封禁；而面板门禁有意排除此类网站封禁。两者组合会削弱面板暴力尝试限制。现在去重与实际面板门禁使用同一判断，分别保留网站与面板封禁记录。回归覆盖 Basic Auth、面板登录与扫描，以及重复请求不重复新增封禁。

### SEC-02 · 中：SSH 监听读取失败被视为旧端口已关闭

位置：`internal/executor/firewall_ports.go`、`internal/executor/ssh_port.go`。

旧逻辑把 `ss` 失败转换成空列表，可能提前确认 SSH 迁移并取消回退。现在迁移验证要求完整、成功的监听查询；命令错误、部分失败及无法解析的数据都进入既有回退流程。测试覆盖配置恢复、持久化边界与 watchdog 保留。

### SEC-03 · 中：网站删除后可能遗留无法管理的 Cloudflare 规则

位置：`internal/cloudflaresecurity/lifecycle.go`、`service.go`、`internal/executor/website_tasks.go`。

旧流程允许删除仍有同步配置的网站。随后令牌失效时，旧规则仍可能存在，而网站接口已经消失。现在在破坏性清理前原子核对同步开关、已保存规则和未确认写入状态，再标记网站正在删除；保存与同步不能在此后创建规则。最终数据库删除事务再次检查。未清理完成时保留网站和可操作的配置入口。

历史孤儿规则的恢复见 [Cloudflare 网站防护](cloudflare-website-protection.md)。本次未自动删除任何线上规则。

### SEC-04 · 中：无效别名阻止解除 Cloudflare 封禁

位置：`internal/cloudflaresecurity/service.go` 的 `Sync`。

旧流程先校验当前域名及别名，再判断黑名单是否为空。新增错误或跨 Zone 别名后，已解封 IP 可能继续被旧规则阻止。现在空黑名单的清理使用原绑定并校验规则归属，不依赖新域名的覆盖校验；非空黑名单仍需完整验证域名范围。管理员修改过的规则不会被覆盖或删除。

### SEC-05 · 中：防火墙回退界面可能提前报告成功

位置：`internal/executor/firewall_access_status.go`、`web/templates/firewall_controller.html`。

旧界面把超时后的普通状态请求成功当作已回退。现在每次变更有独立、不可用于授权的标识；只有同一次变更明确保存成功，或回退任务已停止且实际规则与原快照一致，界面才解除锁定。读取失败、回退任务失败、另一笔变更或新规则残留，都保留待核对状态。恢复记录不保存确认令牌。

### SEC-06 · 中：OLS 监听就绪检查缺少进程归属

位置：`internal/executor/ols_ipv6.go`、`install.sh`。

仅看到 80/443 监听不足以证明 OLS 已绑定，其他服务可能占用其中一个端口。现在同时核对地址族、通配地址和 `/proc/PID/exe` 对应的 OLS 可执行文件身份，不以进程名称作为证据；无法确认时不能报告双栈成功。安装脚本的 IPv4 回退也必须通过这一检查。

### SEC-07 · 低：监控保存中的界面竞争

位置：`web/templates/website_detail.html` 的 `saveMonitoring`。

保存请求期间继续编辑会导致界面把尚未提交的新值写入已保存状态。现在保存使用提交时快照，保留之后修改的草稿，并阻止重复提交；失败时不更新已保存状态。延迟响应回归覆盖这一流程。

### SEC-08 · 高：构建工具链存在已公布安全公告

`govulncheck` 在 Go 1.26.8 上报告标准库可达调用路径，包括 HTTP/2 资源耗尽/崩溃等公告。已将工具链和 CI/发布配置统一升级到 Go 1.26.9，将 `golang.org/x/net` 更新至 0.60.0，并采用其必需依赖版本。依据：[Go 官方公告 GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603)、[GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617)。

升级后在 Linux/amd64 源码模式复扫，没有可达的已知漏洞调用路径。扫描仍提示 `x/crypto` 模块包含已弃用的 `openpgp`，本项目未导入该包、未检测到对应调用路径。符号可达不等于每条公告都能在本项目实际利用，扫描通过也不代表不存在未知漏洞。

### SEC-09 · 低：Bing 官方空响应清空爬虫缓存

位置：`internal/executor/fail2ban.go` 的 Bingbot 网段获取与刷新流程。

HTTP 请求成功但返回空网段列表时，旧逻辑会把有效缓存覆盖为空。现在校验完整 CIDR、地址族及公网范围，拒绝空或非法列表；失败进入原有缓存保留分支。定向回归覆盖空列表、非法条目、正常双栈更新及已有缓存数据的完整保留。

## CDN 区域的取舍

- 保留其他 CDN 的可信回源配置能力，适用于阿里云 ESA 等服务；添加表单默认折叠，已配置项目仍可管理。
- Cloudflare 的官方回源网段单独展示缓存状态，并提供立即更新与每周自动更新。缓存存在不等于某个网站的代理、防护已经验证。
- 深色说明文字区分“识别真实访客 IP”与“通过网站 Cloudflare API 同步封禁”。Google/Bing 数据仅用于爬虫识别，不扩大 SSH 或网站的封禁豁免范围。

## 仍需在线上确认的项目

1. **登录恢复**：管理员是否已启用 MFA，并离线保管恢复码；面板会话免输 WordPress 密码不能替代面板自身的账户恢复。
2. **代理链和源站入口**：实际域名是否启用 Cloudflare 代理；如希望只接受 CDN 回源，应按部署用途另行限制源站 HTTP/HTTPS。仅还原真实 IP 不能阻止绕过 CDN 直连源站。IPv6 的 AAAA、路由和云防火墙需一并验证。
3. **通知和恢复演练**：邮件/Webhook 实际送达、异地备份及一次恢复演练仍需真实环境验证；仅保存配置或生成备份不代表已经验证可恢复。
4. **多网站隔离**：当前 API 凭据、Zone 和 WAF 规则按网站管理，但已启用网站共享网站攻击 IP 黑名单。若要求一个网站触发的封禁完全不影响另一个网站，需要进一步按网站记录攻击来源；本轮没有静默改变这项语义。

## 验证边界

本轮通过：认证与会话、Cloudflare 生命周期、SSH 迁移、防火墙回退、OLS 双栈及安装脚本的定向测试与相关 vet；30 组前端状态测试；44 个中英文页面渲染；Linux amd64/arm64 共 6 个编译目标；依赖校验与升级后的漏洞调用路径复扫。CDN 提示文字实测对比度 10.92:1，390px 手机视口无横向溢出，浏览器无控制台错误。

本次使用真实源码、隔离 SQLite、模拟 Cloudflare/命令执行边界、浏览器模拟接口及 Linux 交叉编译。详细测试结果、源码哈希和截图记录在工作区 `audit-artifacts/security-review`、`audit-artifacts/security-audit` 与 `audit-artifacts/cloudflare-security`。

Windows 上的隔离测试和 Linux 编译不能替代真实 Linux 的 systemd、nftables、SSH、OLS 运行验证；Unix 文件权限/符号链接专用测试也需 Linux 环境执行。发布前需在可回退的测试环境补做这些集成验证。本地预览不会修改线上服务器。
