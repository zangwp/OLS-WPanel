# 仓库结构 / Repository layout

根目录保留安装入口、Go 模块信息、许可证与项目说明；程序入口、后端实现和页面资源分别集中到 `cmd/`、`internal/` 和 `web/`。目录整理不改变已安装服务器的文件路径或发布资产名称。

The root keeps installers, Go module metadata, the license and project documentation. The command entry, backend implementation and web assets live in `cmd/`, `internal/` and `web/`. This layout does not change installed server paths or release asset names.

| 路径 | 用途 |
|---|---|
| `cmd/ols-wpanel/` | 程序入口及依赖主包实现的测试 |
| `internal/collector/`、`internal/config/`、`internal/database/`、`internal/models/` | 指标、配置和数据模型 |
| `internal/handlers/`、`internal/middleware/`、`internal/router/`、`internal/executor/` | 请求处理、路由和系统操作 |
| `internal/i18n/` | 翻译及本地化代码 |
| `web/assets.go` | 独立嵌入模板、公开静态资源和旧插件资源 |
| `web/templates/` | 页面模板，不作为静态文件公开 |
| `web/css/`、`web/js/`、`web/logo.png` | 面板运行时静态资源 |
| `web/source/` | 前端构建源码与品牌素材，不嵌入公开静态资源 |
| `web/plugins/ols-wpanel-optimizer/` | 兼容与迁移验证仍引用的旧插件源码 |
| `deploy/` | Cloudflare 安装入口、统计 Worker 等独立部署组件 |
| `deploy/tools/` | 开发验证、翻译编译及发布辅助工具 |
| `docs/` | 安装、维护、迁移与安全文档 |
| `tests/` | 跨模块测试、前端行为验证及仓库检查 |
| `third_party/` | 项目声明、第三方许可和固定版本许可材料 |
| `.github/workflows/` | CI、双架构验证、签名与发布 |

## 构建与验证

在仓库根目录执行，完整测试应在支持的 Linux 环境运行：

```bash
go test ./...
go vet ./...
go build -o ols-wpanel ./cmd/ols-wpanel
bash deploy/tools/verify.sh
```

Backend modules use Go's `internal` package boundary. Full runtime tests require a supported Linux environment. Release workflows test amd64 and native arm64, then build the command at `./cmd/ols-wpanel`.

## 保留的边界

- 页面和公开静态资源使用不同的嵌入规则；模板、构建源文件和旧插件不会通过 `/static/` 暴露。浏览器资源 URL 保持不变。
- `install-cn.sh` 是国内入口和发布时 `bootstrap.sh` 的共享验签源；主安装逻辑仍在根目录 `install.sh`。
- 旧插件不再自动部署，但现有兼容与迁移代码仍依赖其源码，因此保留在 `web/plugins/`。
- `LICENSE` 保留在根目录。项目声明和第三方声明在 `third_party/`；发布压缩包内的声明文件名与安装路径保持不变。
- 版本详情放在 Releases 和 `CHANGELOG.md`，README 保持常用功能与安装入口说明。
