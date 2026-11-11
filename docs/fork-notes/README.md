# fork-notes · 自研注释外置库（索引）

> 用途：代码里被我方改动过的位置，只留「一句话结论 + 锚点」，长解释逐字放在本目录。
> 为什么：注释与上游改动落在同一行时必然冲突（`卡-20261110-02` 的 69 个函数级冲突块就是这么来的）。
> 外置后代码内注释量降一个量级，**同行冲突面随之下降，且不损失任何知识**。
>
> 约束（机械可核）：代码内每个 `详见 docs/fork-notes/xxx.md §N` 必须在目标文档里能找到 `## §N` 标题，
> 由 `scripts/check-doc-anchors.sh` 校验（锚点不可跳转 = 红）。

## 文档清单

| 文档 | 覆盖模块 | 对应自研项 |
|---|---|---|
| [`render-chain.md`](render-chain.md) | `internal/services/caddy.go` 渲染链、回源 Host 四态、链式回退、静态响应 handler | 第 1/3/4 项 |
| [`static-response-validation.md`](static-response-validation.md) | `internal/handlers/rule_features.go` 静态响应与链式回退参数校验 | 第 1/3 项 |
| [`db-migrations.md`](db-migrations.md) | 字段搬迁与列登记的**背景**（不是改造方案） | 第 2/4 项 |
| [`tls-file-source.md`](tls-file-source.md) | `certstore.go` + `rules.go` 的文件型证书摄取 | 第 2 项 |
| [`model-fields.md`](model-fields.md) | `internal/models/models.go` 自维护列与结构体字段 | 第 1/2/3/4 项 |
| [`ports-and-config.md`](ports-and-config.md) | `default_ports.go` + `internal/config/config.go` 端口单源与配置 | 第 1/3 项 |
| [`caddygeoip-handler.md`](caddygeoip-handler.md) | `caddygeoip/upstream_host.go` 回源 Host 覆盖处理器本体 | 第 4 项 |
| [`watchdog-and-server.md`](watchdog-and-server.md) | `configwatchdog.go` + `cmd/server/main.go` 启动链 | 第 1/3 项 |
| [`handlers-misc.md`](handlers-misc.md) | `helpers.go` / `system.go` / `rule_write_columns.go` | 第 1/3 项 |
| [`frontend.md`](frontend.md) | `web/src/` 前端校验与规则编辑器 | 第 2/3 项 |

## 写作纪律

1. **逐字搬迁**：搬迁时不允许改写注释内容（只去掉行首注释符号、加章节标题）。要改语义请另开任务。
2. **每节一个主题**：`## §N` 标题后跟一句「是什么」，再跟原文。
3. **锚点稳定**：`§N` 编号一经发布不再重排（新增用新编号），否则代码里的锚点会静默失效。
