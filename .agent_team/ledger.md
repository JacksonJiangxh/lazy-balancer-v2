# 总台账 · 一行一任务（三省六部体系）

> 本目录为当前 agent 架构（三省六部）的台账；历史任务档案（TASK-2026-1110-01 ~ 1111-04）在 `.npc-teams/tasks/`，保留为历史档案，不再新增。

| 任务编号 | slug | 判级 | 状态 | 承接 | 驳回 | 自愈 | 档案 |
|---|---|---|---|---|---|---|---|
| JJC-20261112-001 | tls-passthrough-plan | XL | S3 前端施工完成（待刑部评审）· S1-b 完成（f27e5579）· S1-a 完成（51b44388）· S0 spike 五项全 CONFIRMED | 兵部（spike + S1-a/S1-b/S3 施工） | 0/3 | 0/3 | `JJC-20261112-001-tls-passthrough-plan.md` |

## JJC-20261112-001 · S3 前端施工记录（2026-11-13，兵部）
- 分支 `feat/JJC-20261112-01-tls-passthrough`，基线 S1-b f27e5579；vue-tsc --noEmit EXIT=0、typecheck:test EXIT=0、`npm test` 1622/1622 全绿（基线 1601 + 新增 21）、go build OK、gate.sh PASS（后端零改动）。
- 落地：
  - `web/src/types/rules.ts`：RuleProtocol 第三值 `passthrough`；Rule/Create 补 `passthrough_upstream`（值字段）；Update 指针三态 `passthrough_upstream?`（nil=保留存量，与后端 *string 合并语义同构）。
  - `web/src/utils/ruleValidation.ts` 新增透传族单源：`normalizeSNIDomain`/`sniDomainError`（与后端 validateSNIDomain 逐条同口径同顺序：空白→控制字符→端口尾缀→尾缀点→IP 字面量→253→通配两级→标签字母表，字节长度口径 TextEncoder 同 Go len）、`passthroughSniError`（必填/单值门先于形状）、`passthroughUpstreamError`（SplitHostPort 形态含 [v6]:port、多冒号串同拒）、`sniDomainsOverlap`（保守多级覆盖）、`passthroughSaveGateError`（三段同序组合）。
  - `web/src/utils/strategyLabels.ts`：卡片/白名单函数签名扩展 passthrough（httpOnly 过滤，与后端 validateStrategyForProtocol passthrough 分支=TCP 五策略同口径）；RuleProtocolFilter 收窄模块私有（exportSurface 门禁）。
  - `web/src/utils/securityStages.ts`：RuleFlowTarget.protocol 扩展 passthrough。
  - `web/src/views/Rules.vue`（照抄 tcp 分支组织方式，全触点）：协议选择器「TLS 透传」；SNI 域名字段（含通配提示+行内红框）；监听端口透传只读（标注跟随部署 HTTPS_PORT）；证书归属提示条 + HTTP/3 降级提示条（证书字段整组不可达：TLS 步仍 http+enable_tls 门）；上游步透传走 passthrough_upstream 单值输入、上游表格整组 v-else 隐藏；健康检查 TCP 块/连接重试/PROXY V2 预览与查看器行扩展透传；策略卡片自动过滤；协议 watch 进入透传清理全部「携带即 400」字段族（TLS 证书族/HTTP-only 七族/代理超时七列）并清空 upstreams、离开补回默认上游行 + 端口快照还原；portWarning 透传端口跟随门；行内校验 computed 族（SNI/上游字段级 + passthroughGateError 三段 + passthroughConflictWarning 冲突双门——只统计启用中规则、排除自身、sniDomainsOverlap 判定，面板数据不可得静默跳过交后端兜底）；nextStep(BASIC/UPSTREAMS) 与 submitWizard 双门镜像；载荷：passthrough_upstream 按协议收敛、upstreams 透传恒 []、TLS 字段族按协议收敛（双保险）、tcp_proxy_protocol 消费面扩展；列表协议列「TLS 透传」+ 上游列透传徽标（悬停上游地址）；单规则配置查看器透传上行；流程弹框上游摘要透传分支。
  - `web/tests/rulePassthrough.spec.ts` 新增 21 用例：SNI 合法/各拒绝形态/通配语义/标签门/253 边界、上游合法/拒绝形态、sniDomainsOverlap、保存门同序组合、策略白名单（含 HTTP/TCP 分支隔离）、跨栈对表（后端 253/端口域/端口跟随/TLS 互斥/SQL 冲突门/upstreams 400 文案）、Rules.vue 分支隔离钉测（选择器/证书隐藏/端口只读/上游表格隔离/行内校验接线/双门镜像/载荷收敛/watch 迁移/列表展示）。
  - 既有钉测 3 处同步更新（钉的是超集扩展非削弱）：feViewsEdgeStates 预览重试行 v-if 超集、rulesWizardContracts 提交门透传豁免前缀、rulesUi 健康检查 TCP 段模板条件扩展。
- **自裁决策（3 项）**：
  1. **「权重」字段不落**：任务书透传表单字段含「权重」，但后端透传上游是单值列、`buildPassthroughProxyHandler` 有意不发射 load_balancing（源码注释「透传上游是单值（无权重/无多上游选择）」），且后端拒绝 upstreams 列表——无处承载即死配置，按「最小改动」纪律不落，台账记录待总监裁定是否需要二期单值上游权重语义。
  2. **Dashboard 协议标签未动**：`web/src/views/Dashboard.vue` 在白名单外，其 `getRuleProtocolLabel` 对透传规则将显示「HTTP」（enable_tls=false 回退）——非阻断（仅历史统计弹框标题），遗留待白名单扩权后补「TLS 透传」标签；RuleFlowDialog.vue 同理透传落入非 TCP 分支显示「HTTP」，已通过 whitelisted 的 securityStages.ts 类型扩展保证类型安全，文案遗留。
  3. **白名单外零改动**：internal/**、Dockerfile、scripts/、AGENTS.md、web/package.json 全程未触碰（gate.sh PASS 佐证后端未被破坏）。
- 遗留：Dashboard/RuleFlowDialog 透传文案标签（自裁 #2）；S4 验证收口（端到端/镜像/文档登记）。
- 经验卡：①`replace_in_file` 并行多编辑同一文件存在竞态（一处载荷行静默丢失，单跑钉测才暴露）——同文件多处编辑应串行落盘；②`web/tests/_helpers.ts` 的 `code()` 剥 HTML 注释——新 spec 切片标记必须用代码锚点（模板注释/Go 行注释均会被剥掉）；③后端裸 IPv6（`::1`）作为 SNI 会被端口尾缀门先拒——跨栈对表断言前先实跑后端门序，勿凭直觉写预期。

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
