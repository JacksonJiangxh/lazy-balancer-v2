# 总台账 · 一行一任务（三省六部体系）

> 本目录为当前 agent 架构（三省六部）的台账；历史任务档案（TASK-2026-1110-01 ~ 1111-04）在 `.npc-teams/tasks/`，保留为历史档案，不再新增。

| 任务编号 | slug | 判级 | 状态 | 承接 | 驳回 | 自愈 | 档案 |
|---|---|---|---|---|---|---|---|
| JJC-20261112-001 | tls-passthrough-plan | XL | S1-b 施工完成（渲染接线，待刑部评审）· S1-a 完成（51b44388）· S0 spike 五项全 CONFIRMED | 兵部（spike + S1-a/S1-b 施工） | 0/3 | 0/3 | `JJC-20261112-001-tls-passthrough-plan.md` |

## JJC-20261112-001 · S1-b 施工记录（2026-11-13，兵部）
- 分支 `feat/JJC-20261112-01-tls-passthrough`，基线 S1-a 51b44388；gate.sh PASS、7 模块 build+vet 全绿。
- 落地：caddy.go 渲染接线（`passthroughRulesByPort` 第三族分组 + `buildPassthroughLayer4Server`/`buildPassthroughProxyHandler`/`passthroughDialAddress` 三函数 + HTTP server 监听迁移 `tcp/127.0.0.1:7443`+`udp/:P` + listener_wrappers proxy_protocol(allow 127.0.0.1/32, fallback reject)→tls 顺序挂载 + 同端口共存时透传规则跳过 HTTP 路由/错误归因/TLS 策略三处循环 + tcp/tls Layer4 端口归属冲突显性报错）；解除 CreateRule/UpdateRule 恒禁用态门（S1-a 门移除，数据完整性由 validatePassthroughRule 单源把守）；v2 备份导入放行（validateRuleFeatures 输入补 Domain/PassthroughUpstream）；v1 导入手造 passthrough 行显性跳过；MCP schema 两处禁用态描述更新；渲染注释卡 §29 落 render-chain.md。
- **钉测**：`caddy_passthrough_render_test.go`（9 项：R5 零回归 sha256 钉测 + Layer4 形态/混合共存/多 SNI 聚合/dial 口径/PROXY+健康检查/分端口零迁移/脏行 fail-closed）。R5 基线 = main@c45efb06 同 fixture 渲染（worktree /tmp/lb-r5-base 实跑取 sha256，证书用固定内嵌 PEM、certDir 归一化——生成方法见测试注释）；变异测试验证断言有分辨力（向 server 加一个键即红）。handler 侧 `rule_features_passthrough_test.go` 改写 2 项 S1-a 门钉测为 S1-b 放行语义 + 新增 3 项导入链钉测。
- **白名单外自裁（1 处）**：`internal/handlers/config_backup.go`（v2 备份校验的 ruleFeatureInput 构造补 Domain/PassthroughUpstream 两字段）——不改则启用态透传行的导出→导入往返必断（与 S1-a cluster_snapshot.go 同性质：唯一事实源校验门的机械伴随输入）。
- 全量回归：`go test ./internal/... ./cmd/...` FAIL 集合与基线 4 项逐条一致（TestCaddyProcessControlAllowedOutsideImportWindow / TestGetClusterWafFiles_409DuringImportWindow / TestApplySnapshot_ruleLogCleanupFailureDoesNotFailSync / TestTaskLogsHousekeeping_countsMetadataFailures，均在基线树 /tmp/lb-r5-base 复现）。
- 遗留：S3 前端、S4 验证收口（端到端真实进程集成测试/镜像/文档登记）；可选加分项（真实 caddy 二进制集成测试）未做——渲染产物可经 `CADDY_PT_FIXTURE_OUT` env 导出供后续接入 caddygeoip 解码链（手法参照 caddy_emit_config_validate_test.go）。

## JJC-20261112-001 · S1-a 施工记录（2026-11-13，兵部）
- 分支 `feat/JJC-20261112-01-tls-passthrough`（自 main c45efb06 切出），commit 51b44388；gate.sh PASS。
- 落地：`lb_rules.passthrough_upstream` 三处登记（fresh DDL/newColumnsRegistry/PK 重建）+ 列钉测；models 三结构体接线；specs/快照/集群触发器/MCP schema 机械伴随同步；protocol 第三值放行保存链（rule_features/handlers 双门）；`validatePassthroughRule` 保存门（SNI 形状/上游 host:port/端口=DefaultHTTPSPort/TLS 字段拒绝/HTTP-only 拒绝）+ 防脏门；冲突双门（同端口同 SNI 含通配重叠、透传↔本地终结双向）；Create/Update/Duplicate 全链接线；钉测 `rule_features_passthrough_test.go` + `db_passthrough_column_test.go`。
- **S1-a 关键裁定**：透传规则恒「禁用态」创建/更新（caddy.go:2496 渲染协议门未放行 passthrough——启用中的透传行会使全量配置生成失败、拖垮全部规则；S1-b 交付渲染后解除）；透传上游存单值列、upstreams 表零行。
- 白名单外自裁（5 处，均为「唯一事实源派生物/机械伴随钉测」：不改即编译或运行期必红）：handlers.go（保存链协议门实址，任务书行号 rules.go:2496 系笔误）、cluster_snapshot.go（specs 派生 SELECT 的 Scan 镜像）、rule_write_columns_test.go（parity 钉测 panic 未覆盖列）、mcpserver/server.go（MCP parity 钉测要求 Agent 可见）、middleware/cluster_version.go（集群触发器列对账钉测——同时是真实功能缺口）。
- 遗留（按阶段归属）：caddy.go 渲染（S1-b）、config_import_v1.go 导入链 passthrough 走「协议无效」跳过（S1-b/S4）、docs 自研登记（S4）。
- 全量回归：`go test ./internal/...` 失败集合与 main 基线逐项一致（4 项既有失败，无我侧独有失败）。

## 状态词表
- 方案定稿 / S0 spike 中 / 施工中 / 评审中 / 合并中 / 已交付 / 已归档

## 体系切换说明（2026-11-12）
- 台账目录由 `.npc-teams/tasks/` 切换为 `.agent_team/`（当前 agent 架构约定：项目根 `.agent_team/`，不预建、需要留痕才建）。
- 历史档案不迁移：`.npc-teams/tasks/` 四份已交付档案 + casebook 原样保留，作为体系演进记录。
