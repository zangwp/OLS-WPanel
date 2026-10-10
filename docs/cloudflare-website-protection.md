# Cloudflare 网站防护

网站详情 → 网站安全 → **Cloudflare 网站防护** 只需为每个网站填写 **Account ID 和 API Token**。面板根据网站主域名自动查询并核对 Zone，Zone ID 只读展示，无需手填。网站在不同 Cloudflare 账户中时，分别使用所属账户创建的 Token；无需共享全局凭据。

页面常驻展示人可读的域名区域名称；需要核对 Zone ID 时，展开**技术信息**。保护域名来自该网站已登记的主域名、`www` 与其他别名。普通网站若只登记主域名和 `www`，列表就只显示这两个；面板不会额外创建别名或自动覆盖整个 Zone。

## 创建 API Token

1. 在 Cloudflare 控制台打开头像 → My Profile → API Tokens → Create Token → Create Custom Token。
2. 权限选择 **Zone → Zone → Read** 和 **Zone → WAF → Edit**。Rulesets API 文档也将后者称为 Zone WAF Write。
3. Zone Resources 选择 **Include → Specific zone → 当前网站所属域名**。不需要 DNS Edit、Global API Key 或账户级 IP List 权限。
4. 在域名 Overview 页面复制 **Account ID**；不用复制 Zone ID。若网站为 `shop.example.com`，面板会查询并核对它所属的 Zone，例如 `example.com`。面板根据数据库中的网站域名选择目标，不通过请求头或任意手动输入的 Host 选择同步目标。
5. 复制 Token，填入网站详情。面板保存后只显示“已保存”，不会通过配置接口返回 Token。

[Cloudflare Token 创建说明](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/)与[权限列表](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)说明了 Token 的资源范围和权限。

## 保存、测试与同步

- **测试连接**自动识别 Zone，核对此网站的主域名及已配置别名，并读取 WAF 自定义规则，不修改 Cloudflare。读取成功不代表 Token 拥有写入权限；必须授予 WAF Edit，写权限在同步时确认。
- **保存配置**保存当前网站的凭据与启用状态。启用后，后台定期将网站防护黑名单同步至 Cloudflare；**立即同步**可马上执行一次更新。
- 同步创建或更新面板专属的 WAF 自定义规则，匹配此网站**主域名和数据库中已配置的同 Zone 别名／www**及被封禁访客 IP。面板不会猜测添加 `www`，不会放大为整个 Zone 的通配规则，只对橙云代理流量有效。
- 页面分别显示网站配置域名与最近确认写入规则的覆盖域名。若任一别名属于其他 Zone、格式无效或当前 Token 无权访问，同步会明确失败，不会只同步部分域名并报告成功。跨 Zone 域名需要分别配置网站防护；当前单站绑定仅支持一个 Zone。

“覆盖域名”表示规则表达式中的精确 Host 集合。它只对代理经过该 Zone 的 HTTP 请求生效，不表示面板已验证 DNS 代理状态或真实访问效果。Token 只能查询已授权的区域；委派到其他未授权 Zone 的子域名也需要管理员核实其代理归属。

- **停用**需要先取消勾选并保存，再点击**移除同步规则**。规则移除成功前，Cloudflare 上的旧规则仍可能生效。后台不会代替明确的移除操作。
- 同一账户、Zone 与网站域名下可直接更换 API Token，再测试并保存。原 Token 过期或撤销时，可用对同一域名具有所需权限的新 Token 更新或清理原规则，不会因此丢失规则所有权记录。
- 更换账户、Zone 或绑定域名前，必须先移除面板所属的旧规则。即使上一次创建结果不确定，也会先保留清理状态，避免在旧账户留下无法追踪的规则。
- 删除网站前也必须先停用同步并移除面板专属规则；仍启用同步、存在已创建规则或结果不确定的创建计划时，面板会阻止删除。删除状态持久保存后不能再启用同步，因此中断后的删除重试不会留下新的远端规则。
- 网站自动封禁全部解除或过期后，同步使用原账户和规则所有权记录移除旧规则；新增别名无效或不属于同一 Zone，不会阻止空黑名单的清理。仍有封禁 IP 时，当前域名与全部别名须先通过完整覆盖校验。

历史版本或数据库外部操作可能留下已删网站的规则。后台会尝试清理并在服务日志报告失败；如果该孤儿记录的 Token 已失效、账户权限无法恢复，需在 Cloudflare 后台核对面板专属规则的 ID、`olswp_` 开头的 Ref 与网站域名，手动移除这一条规则。不要删除整个规则集或其他管理员规则。当前网站接口不提供已删站点的凭据恢复入口。

面板只管理自己的规则，不覆盖其他 Cloudflare 规则。若规则数量达到套餐限额、表达式超过长度上限、凭据过期或 API 调用失败，状态显示失败并保留错误；不会截断黑名单或域名覆盖范围并报告成功。当前实现将 IP 直接写入规则表达式，无需创建账户级 IP List。

[自定义规则](https://developers.cloudflare.com/waf/custom-rules/)受整个 Zone 的套餐限额约束；[规则表达式](https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/)的长度上限为 4096 个字符。ASCII IP 集合生成时使用对应的字节限制；容量还要包含主域名与规则语法。

## 服务器防护与网站防护

**服务器防护**：SSH、面板登录和服务器手动封禁由服务器与面板原有机制管理，不同步到 Cloudflare 网站规则。

**网站防护**：仅同步网站 Fail2ban 自动封禁。当前版本的网站日志 Jail 与黑名单由已启用网站共享，命中一个网站的 IP 会同步到其他明确启用 Cloudflare 防护的网站。这不是按网站分别生成黑名单；未启用的站点不会创建同步规则。

经 Cloudflare 代理时，VPS 接收到的 TCP 连接来源是 Cloudflare。还原访客 IP 能改善日志和识别，但本机防火墙封禁日志中的访客 IP，不能直接阻断该访客经过 Cloudflare 的连接。Cloudflare WAF 规则在代理侧执行，才可以根据访客 IP 匹配网站请求。

启用前须确认网站 DNS 记录开启橙云代理，并且 OLS 的可信代理网段和真实 IP 还原正常；否则网站 Jail 可能识别不到真实访客。规则追加到当前自定义规则集合，既有的 Skip、允许或其他先执行的规则仍可能影响最终请求处理。同步成功表示规则写入成功，不能替代实际请求验证。

[Cloudflare IP 地址说明](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/)解释了代理与回源连接的区别。

## CDN 网段与爬虫识别数据

- **Cloudflare CDN 网段**用于 OLS 可信代理、真实访客 IP 还原和网站 Fail2ban 的代理免封。它不会自动豁免 SSH 或面板登录。OLS 写入可信代理时添加 `T`，保留公开网站原有 `allow ALL`，并使用 Trusted IP Only。
- **Google、Bing 官方网段**用于验证日志中相应爬虫的身份，不再自动成为 Fail2ban 免封名单，也不加入 OLS 可信代理。
- **网站自定义免封名单**仅放入明确可信的例外；不应为了识别爬虫而把所有爬虫 IP 加入该名单。
- AI 爬虫允许或阻止策略可以在 Cloudflare 管理；识别数据与允许策略是两种不同用途。

相关文档：[OLS 真实访客 IP](https://docs.openlitespeed.org/config/logs/visitorip/)、[Cloudflare AI Crawl Control](https://developers.cloudflare.com/ai-crawl-control/features/manage-ai-crawlers/)。

## 备份与恢复

SQLite 完整数据库备份包含加密后的 API Token，但不包含数据库同目录的 `cloudflare-security.key`。同机恢复且原密钥仍在时可继续解密；跨机迁移必须另外安全保存并恢复**同一份密钥**。密钥必须为权限 `0600` 的普通文件，不接受符号链接。已有加密 Token 而密钥缺失或错误时，面板会明确报错，不会重新生成密钥并假装原凭据可用。

数据库恢复不会恢复或回滚 Cloudflare 远端规则。数据库记录与远端规则的所有权标记、表达式指纹不一致时，同步会保护性报冲突，需要人工核对两边状态。面板恢复成功或健康检查通过，不代表 Cloudflare 凭据与同步规则已经验证；恢复后仍需检查各网站连接和同步状态。

## 本地预览

本地预览页面使用模拟数据，不连接 Cloudflare 或 VPS。真实凭据只能在部署后的受保护面板中填写。发布前须确认界面预览和行为说明；本地修改不代表已经启用线上同步。
