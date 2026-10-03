# 仓库结构 / Repository layout

根目录保留构建入口、安装器、许可证与项目说明。Go 业务包保持原有职责；不依赖主包实现的仓库检查集中在 `tests/repository/`。

The root contains build entry points, installers, the license and project documentation. Application packages retain their responsibilities. Source and release contract checks live in `tests/repository/`.

| 路径 | 用途 |
|---|---|
| `static/templates/` | 页面模板，由独立的 TemplatesFS 嵌入，不作为静态文件公开 |
| `static/css/`、`static/js/`、`static/logo.png` | 面板运行时静态资源 |
| `static/source/frontend/` | Tailwind 源码与构建配置，不嵌入静态资源 |
| `static/source/branding/` | 品牌主图与设计说明，不嵌入静态资源 |
| `i18n/` | 翻译及本地化代码 |
| `collector/`、`config/`、`database/`、`models/` | 指标、配置和数据模型 |
| `handlers/`、`middleware/`、`router/`、`executor/` | 请求处理、路由和系统操作 |
| `docs/` | 安装、维护、迁移与安全文档 |
| `deploy/` | 安装入口和统计 Worker 等独立部署组件 |
| `tests/`、`scripts/` | 跨包测试、仓库检查和开发验证工具 |
| `third_party/` | 项目声明、第三方许可和固定版本许可材料 |
| `ols-wpanel-optimizer/` | 仍被嵌入及迁移验证引用的旧插件源码 |
| `.github/workflows/` | CI、双架构验证、签名与发布 |

## 保留的边界

- `main.go`、`embed.go` 及依赖主包实现的测试保留在根目录；独立的源码检查放入 `tests/repository/`。
- 模板、前端构建源文件和公开静态资源虽然归入同一目录，但使用不同嵌入规则，构建源文件及模板不会通过 `/static/` 暴露。
- `install-cn.sh` 是国内入口和发布时 `bootstrap.sh` 的共享验签源；主安装逻辑仍在 `install.sh`。
- 旧插件不再自动部署，但现有兼容与迁移代码仍依赖其源码，因此保留。
- `LICENSE` 保留在根目录。项目声明和第三方声明在 `third_party/`；发布压缩包内的声明文件名与安装路径保持不变。
- 版本详情放在 Releases 和 `CHANGELOG.md`，README 保持常用功能与安装入口说明。
