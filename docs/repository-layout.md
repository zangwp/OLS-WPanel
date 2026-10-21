# 仓库结构 / Repository layout

根目录保留安装入口、Go 模块信息、许可证与项目说明；程序入口、后端实现和页面资源分别集中到 `cmd/`、`internal/` 和 `web/`。目录整理不改变已安装服务器的文件路径或发布资产名称。

The root keeps installers, Go module metadata, the license and project documentation. The command entry, backend implementation and web assets live in `cmd/`, `internal/` and `web/`. This layout does not change installed server paths or release asset names.

| Path | Purpose |
|---|---|
| `cmd/ols-wpanel/` | Command entry point and tests that depend on the main package |
| `internal/collector/`, `internal/config/`, `internal/database/`, `internal/models/` | Metrics, configuration and data models |
| `internal/handlers/`, `internal/middleware/`, `internal/router/`, `internal/executor/` | Request handling, routing and system operations |
| `internal/i18n/` | Translations and localization code |
| `web/assets.go` | Separate embedded filesystems for templates, public assets and legacy plugin assets |
| `web/templates/` | Page templates, excluded from public static files |
| `web/css/`, `web/js/`, `web/logo.png` | Public panel assets |
| `web/source/` | Frontend build sources and brand assets, excluded from public embedded files |
| `web/plugins/ols-wpanel-optimizer/` | Legacy plugin source retained for compatibility and migration checks |
| `deploy/` | Independent deployment components, including Cloudflare installation and statistics Workers |
| `deploy/tools/` | Development checks, translation compilation and release helpers |
| `docs/` | Installation, operations, migration and security documentation |
| `tests/` | Cross-module tests, frontend behavior checks and repository checks |
| `third_party/` | Project notices, third-party licenses and versioned license materials |
| `.github/workflows/` | CI, dual-architecture verification, signing and release workflows |

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
