# 总台账 · 一行一任务（三省六部体系）

> 本目录为当前 agent 架构（三省六部）的台账；历史任务档案（TASK-2026-1110-01 ~ 1111-04）在 `.npc-teams/tasks/`，保留为历史档案，不再新增。

| 任务编号 | slug | 判级 | 状态 | 承接 | 驳回 | 自愈 | 档案 |
|---|---|---|---|---|---|---|---|
| JJC-20261112-001 | tls-passthrough-plan | XL | S4 完成（S0 五项 spike + S1-a/S1-b/S3/S4-a/S4-b 全绿）已合并 main 并推送（9bf61980） | 兵部（spike + S1-a/S1-b/S3/S4-a 施工） | 0/3 | 0/3 | `JJC-20261112-001-tls-passthrough-plan.md` |
| JJC-20261113-01 | docs-readme-getting-started | S | 完成（README 构建段修正 + fork 锚点/索引 + 快速开始教程；gate PASS，main 直接单提交推送） | 兵部 | 0/0 | 0/0 | — |

## JJC-20261113-01 · 施工记录（2026-11-13，兵部）
- 落地（白名单内三文件）：`README.md`（①68-79 行过时段修正：删「手工 npm build 必选前置」，改「Dockerfile 自带 web-builder 阶段一条 docker build 出镜像」，npm ci 说明移入本地预览语境；②简介段末尾加 fork 身份锚点行；③文档索引表补快速开始/核心自研登记/上游追平手册三行）；`docs/getting-started.zh-CN.md`（新建小白化一站式教程：前置要求→启动→初始化→建规则→TLS 透传→验证→FAQ→延伸阅读）；`.agent_team/ledger.md`（本行）。
- 事实核对：docker run 示例逐字取 README；向导字段名与顺序取 `web/src/views/Rules.vue`（基本配置/TLS/上游/预览保存、SNI 通配、透传端口只读、证书归属与 HTTP/3 降级提示条）；HTTP_PORT/HTTPS_PORT 语义取 `docs/fork-notes/ports-and-config.md` §1/§2；「443 由 Layer4 接管、透传/终结共存」取 `docs/fork-notes/render-chain.md` §29 + 自研登记第 5 项 + spike T-4；「保存即时生效/400 不落库」取 production-tuning 与 rules.go 保存链注释。
- 自裁 1 项：任务令原文「前提：该端口已存在普通 HTTPS 规则」与代码事实不符（`validatePassthroughRule` 无此前置；透传规则自身即令该端口 HTTP server 建立并经兜底路由保本地终结）——教程按事实表述为「443 由 Layer4 接管，现有普通 HTTPS 规则经兜底路由继续工作、无需改动（spike T-4 实证）」，未照抄前置句。
- 验证：`/bin/bash scripts/gate.sh` PASS（五项全过，README 版本锚点 8 处未破坏）；README 新增链接目标 8 个全部存在；`git diff --stat` 仅 README.md + 新文档。

## JJC-20261112-001 · S4-a 施工记录（2026-11-13，兵部）
- 分支 `feat/JJC-20261112-01-tls-passthrough`，基线 S3 5df4685f；vue-tsc --noEmit EXIT=0、`npm test` 全绿、go build OK、gate.sh PASS（后端零改动佐证）。
- 落地：
  - `web/src/views/Dashboard.vue`：`getRuleProtocolLabel`/`getRuleProtocolTagType` 补 passthrough 第三值（「TLS 透传」+ danger 红，参照 Rules.vue 列表写法）——S3 遗留自裁 #2 收口；规则表协议列与历史统计弹框副标题两处使用点同源覆盖。
  - `web/src/components/RuleFlowDialog.vue`：`protocolLabel` 补透传分支（原落入非 TCP 分支显示「HTTP」），头部徽标 danger 对齐 Rules.vue；isPassthrough computed 单源。
  - `docs/self-developed-features.zh-CN.md`：登记第 5 项「TLS 透传 SNI 分流」（一览表行 + 分项详述：能力名/代码位置/裁定出处/关键设计点/防复发约束 5 条/机械判据/不适用面）；最近更新行同步。
  - `docs/upstream-catchup-guide.zh-CN.md`：§十新增 B.7「TLS 透传追平注意事项」（编译产物要素 caddy-l4 + proxyprotocol / layer4 语法语义变动即重验 spike / 机械判据两条）。
- **自裁决策（2 项）**：
  1. **接手前次中断现场**：开工时工作区已有 Dashboard/RuleFlowDialog 未提交改动（注释标 S4，与任务令逐条一致）——逐行核对（单源函数覆盖全部使用点、`RuleFlowTarget.protocol` 三值类型已由 S3 扩展、web/tests 无旧文案钉点）后采纳，未重写。
  2. **spike 证据引用照实改写**：任务令要求写「`spike/evidence/T1-T5.md`」，实际 evidence 目录仅 T1/T2/T4/T5 四份真实进程报告（T-3 系源码走读+编译产物注册表断言类验证，无独立报告，方法见计划档案 §三）——登记文档照实写「T-1/T-2/T-4/T-5 实跑报告 + T-3 走读断言」，不写不存在的文件名。另：`.agent_team/spike/` 目前 untracked 未入库，是否入库待太子裁定（follow-up）。
  3. **钉测契约冲突走 v-else-if 三分支**：采纳现场改动后 `npm test` 红 1 项——`panelUiWiring.spec.ts:657` 钉死 `<el-tag v-else[^>]*type="primary"` 字面量（HTTP 徽标契约），而该测试文件不在白名单禁改。改法：RuleFlowDialog 徽标拆三分支（`v-if isTcp` / `v-else-if isPassthrough` type=danger / `v-else` type=primary 字面量保留）——透传红 + 标签「TLS 透传」照落，钉测契约与 HTTP/HTTPS 徽标零变化，重跑 1622/1622 全绿。
- fork-diff 归属核对：按登记文件维护规则以 `--out-dir /tmp/...` 跑（产物目录不在白名单，不落 docs/fork-diff/）。
- 遗留：S4-b 解码链测试与全回归（另做）。

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

## JJC-20261112-001 · S4-b 施工记录（2026-11-13，兵部）
- 分支 `feat/JJC-20261112-01-tls-passthrough`，基线 S4-a f5f9777e；落地 `caddygeoip/caddy_passthrough_decode_test.go`（三测试：layer4RoutesDecode / httpListenerWrappersDecode / fixtureProvenance）。
- **两棒接力说明**：第一棒写测试 24.3KB 时被切断（文件已完整落盘、未提交）；第二棒接手做判别力自证 + 全回归 + 台账收口 + 提交，未改测试语义。
- **解码降级决策（一句）**：tls listener wrapper 真实解码（caddyhttp 包 init 注册，LoadModuleByID 与 caddy load 同一条模块表查找路）；proxy_protocol wrapper 与 layer4.matchers.tls / layer4.handlers.proxy 系因注册包（caddyhttp/proxyprotocol、mholt/caddy-l4）在本模块依赖树未被 import（引入会增 go.mod/go.sum 条目，不在白名单）降级为结构断言，断言键即真实解码的分派键（"wrapper"/"handler"/matcher 短名），改名即红。
- **判别力自证**：备份后变异 `"handler": "proxy"`→`"proxyx"`（1 处）→ `TestCaddyPassthroughDecodeChain_layer4RoutesDecode` 红（`route[0] handler="proxyx", want proxy`）；还原 diff 逐字一致（RESTORED_IDENTICAL）→ `-count=1` 重跑全绿。
- **全回归矩阵**：
  - `go build ./... && go vet ./...` → BUILD_VET_OK；
  - `scripts/gate.sh` → GATE: PASS；
  - `npx vue-tsc --noEmit` → EXIT=0（无输出）；`npm test` → 1622/1622 全绿；
  - `go test ./internal/...` FAIL 集合 = 基线 4 项逐条一致（TestCaddyProcessControlAllowedOutsideImportWindow / TestGetClusterWafFiles_409DuringImportWindow / TestApplySnapshot_ruleLogCleanupFailureDoesNotFailSync / TestTaskLogsHousekeeping_countsMetadataFailures）；
  - 四项自研钉测 `ChainFallback|UpstreamHost|ReferencedCert|DefaultPort|StaticResponse`：internal/services 侧全 PASS（caddychain 系独立 go.mod 模块，主模块引用报 setup failed 属模块边界非回归；其测试命名不同，模块内全量 `go test ./...` ok）；
  - `git diff main..HEAD --stat -- Dockerfile scripts/` 空输出 → DOCKERFILE_SCRIPTS_CLEAN。
- **S0→S4 全阶段小结一行链**：S0 spike 五项 CONFIRMED → S1-a 51b44388 → S1-b f27e5579 → S3 5df4685f → S4-a f5f9777e → S4-b 本提交。遗留：真实公网 ACME 待部署实测（低风险）。
- 遗留（follow-up）：`internal/services/zz_tmp_pt_fixture_gen_test.go`（fixture 生成临时文件，untracked，env 未设时 skip）仍留在工作区未删——删除需授权，待裁定；`.agent_team/spike/` 入库与否沿用 S4-a 待裁定项。

## JJC-20261112-001 · 交付归档（2026-11-13，兵部最终收口）
- **合并提交号**：`9bf61980`（完整 `9bf619808c2a719af96951ed3a728fa7cf816938`）——`git merge --no-ff feat/JJC-20261112-01-tls-passthrough` 生成，特性分支已 `git branch -d` 删除。
- **推送后远程 main 指针**：`9bf619808c2a719af96951ed3a728fa7cf816938`（`git push origin main` → `c45efb06..9bf61980  main -> main`；`git ls-remote origin main` 复核一致）。
- **收口动作**：S1-b 遗留的 fixture 临时生成器 `internal/services/zz_tmp_pt_fixture_gen_test.go` 本次先核实性质（文件头「临时文件（S4-b 施工过程产物）…生成后立即删除，不入提交」+ `CADDY_PT_DECODE_FIXTURE_OUT` / `os.WriteFile`）后删除；删后 `git status --short` 仅剩 `.agent_team/spike/` 与 `.codebuddy/` 两类 untracked。
- **最终回归矩阵（合并后全绿）**：`MERGE_BUILD_VET_OK`；`scripts/gate.sh` → `GATE: PASS`（EXIT=0）；`caddygeoip` 解码链 3 项 `--- PASS`（独立 go.mod 模块内跑，EXIT=0；根目录 `./caddygeoip/` 写法报 setup failed 属模块边界非回归）；`web npm test` → tests 1622 / pass 1622 / fail 0；`internal/handlers` + `internal/services` Passthrough 双 `ok`。
- **遗留（2 条）**：
  1. 真实公网 ACME 待部署实测（低风险）：本地全绿为渲染产物与解码链级验证，公网证书签发与 443 握手需在部署环境实测。
  2. `.agent_team/spike/`（太子裁定不入库）与 `.codebuddy/`（团队运行时）保持 untracked 为工作档案，本次未 add、不随交付入库。
