# 总台账 · 一行一任务（三省六部体系）

> 本目录为当前 agent 架构（三省六部）的台账；历史任务档案（TASK-2026-1110-01 ~ 1111-04）在 `.npc-teams/tasks/`，保留为历史档案，不再新增。

| 任务编号 | slug | 判级 | 状态 | 承接 | 驳回 | 自愈 | 档案 |
|---|---|---|---|---|---|---|---|
| JJC-20261112-001 | tls-passthrough-plan | XL | S1-a 施工完成（数据模型+校验层，commit 51b44388，待刑部评审）· S0 spike 五项全 CONFIRMED | 兵部（spike + S1-a 施工） | 0/3 | 0/3 | `JJC-20261112-001-tls-passthrough-plan.md` |

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
