# Contributing / 贡献指南

## Commits and pull requests

Write new commit subjects and pull request titles in concise English. Use `type: summary` or `type(scope): summary`, with a prefix such as `fix`, `feat`, `docs`, `test`, `refactor`, `chore` or `ci`.

Describe what changed with a direct verb. Keep subjects short, preferably within 72 characters. Examples:

```text
fix: correct login suffix detection and settings reset
docs: document English commit and release note conventions
test: cover clearing login settings under plugin control
```

A pull request should explain the problem, the resulting behavior and relevant validation. State when a check was not run or used simulated services. Use the same English convention for its final squash-merge subject.

新提交、PR 标题及最终合并说明统一使用简短英文，采用 `fix:`、`feat:`、`docs:` 等前缀。说明实际改动及验证结果，区分真实环境检查与模拟检查。现有已发布提交保留原样。

## Documentation and release notes

`README.md` provides the Simplified Chinese introduction; `README.en.md` provides the English introduction. Keep their shared installation and project guidance aligned. `CHANGELOG.md` records changes in English. New release notes provide an English summary and a Simplified Chinese summary, including any required upgrade or recovery steps.

Apply these conventions to new work and preserve published commit hashes. Retain version tags and release assets by default; an explicitly authorized historical cleanup follows the separate policy below. Documentation-only updates retain the application version and do not require a new binary release.

README 保持中英文两份，共同内容同步维护；CHANGELOG 使用英文。新版本发布说明提供中英文摘要，写明必要的升级与恢复步骤。文档更新不单独升级程序版本，也不重写已发布提交。默认保留版本标签及发布包；明确授权的历史清理按下方规则处理。

## Branch cleanup

Use `main` as the stable branch and temporary branches for proposed changes. Delete a temporary branch after confirming that its current head matches a merged pull request, that the merge is included in `main`, and that no open pull request still uses the branch as its source or target. Keep `main` and protected branches.

Squash merges create a different commit hash. Use the merged pull request's head and merge records to verify them; branch ancestry alone is insufficient. Cleaning temporary branches does not authorize deleting version tags or formal Releases.

临时分支仅在确认当前提交已合并、主分支已包含合并结果且没有未完成 PR 引用后清理。压缩合并需要核对 PR 记录；清理分支时保留 `main`、受保护分支。分支清理不代表已获授权删除版本标签或正式发布包。

## Historical release cleanup

Delete historical tags or Releases only with explicit authorization from the repository owner. Before deletion, back up their tag references, release metadata and assets. Keep the current pinned Release, its tag and every signed asset required by the installation endpoint intact. Deleting older Releases removes their download URLs; confirm the retained installation endpoint still verifies and serves the current version after cleanup.

仅在仓库所有者明确授权后清理历史标签或 Releases。删除前备份标签引用、发布信息及附件。保留安装入口当前固定版本的 Release、标签及所需签名附件；旧发布下载链接会随删除失效。清理后检查安装入口仍能验证并提供当前版本。
