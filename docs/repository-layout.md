# 仓库结构 / Repository layout

根目录只保留构建入口、安装器、许可证、项目说明和 `package main` 的 Go 文件。不要仅为缩短根目录列表而移动 `main.go`、`embed.go` 或根级 `*_test.go`：这些文件属于同一个 Go 主包，拆分后会改变编译与测试边界。

The repository root is limited to build entry points, installers, licenses,
project documentation, and Go files that belong to `package main`. Moving
`main.go`, `embed.go`, or the root `*_test.go` files only to shorten the listing
would change Go package and test boundaries.

| 路径 | 用途 |
|---|---|
| `docs/security/` | 安装与运行时安全说明 |
| `.github/workflows/` | CI、双架构验证、签名与发布 |
| `assets/branding/` | 品牌主图与设计说明 |
| `assets/frontend/` | Tailwind 源码和构建配置；生成结果在 `static/` |
| `collector/`、`database/`、`handlers/`、`middleware/`、`models/`、`router/` | Go 应用分层 |
| `config/`、`executor/` | 配置、系统操作与安全边界 |
| `deploy/cloudflare/` | `ols.zangyubin.top` 的可审计 Worker 源码与部署配置 |
| `templates/`、`static/`、`ols-wpanel-optimizer/` | 由 `embed.go` 打包的运行时资产 |
| `deploy/stats-worker/` | 独立部署的统计 Worker |
| `tests/` | 跨包、安装器与模板约束测试 |
| `third_party/` | 固定版本第三方许可材料 |
| `scripts/` | 开发与隔离验证脚本 |

## 重复内容规则

- 新平台或架构不得复制一套安装流程；应通过平台配置和资产名选择函数分派。
- `install-cn.sh` 是国内入口与全球 `bootstrap.sh` 的共享验签源；发布流程只切换默认镜像策略，避免维护第二份下载与验签实现。它保留独立平台预检，因为必须在下载和执行主安装器之前 fail closed；主安装逻辑仍只维护在 `install.sh`。
- `static/logo.png` 与 `ols-wpanel-optimizer/assets/ols-wpanel-logo.png` 内容相同但用途不同：面板二进制与 WordPress 插件分别打包，保留副本可避免发布物依赖仓库外路径。
- 历史升级文档中的旧资产名属于仍需执行的固定版本迁移说明，不应机械替换成新名称。

## 本次目录整理

- 原 security/ 的两份 Markdown 文档移入 docs/security/，相对链接同步更新。
- 原 stats-worker/ 移入 deploy/stats-worker/，与短链接 Worker 一起归入部署组件；忽略规则同步更新。
- Go 包按现有职责保留，避免更改导入路径和测试边界。前端构建源码 assets/frontend/ 与运行时产物 static/ 也保持分开。
- 旧 Optimizer 仍被嵌入和兼容测试引用，目录暂不删除；它不再自动部署到网站。根级许可证与第三方声明保留，便于分发和查阅。
