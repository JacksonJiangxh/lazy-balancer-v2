# 核心自研能力登记（Self-Developed Features Registry）

> **本文件是本仓库「董事长核心自研」的唯一登记处。**
> 任何一轮上游追平（`docs/upstream-merge.zh-CN.md` 流程）动手前，**必须先读本文件**，
> 按下文每项的「防复发约束」逐条核对，**不得**以「上游有同需求实现」为由把下列
> 能力切回上游版本。
>
> 登记原则：**一能力一条**，写清「能力名 / 代码位置 / 设计裁定出处 / 防复发约束 /
> 机械可核符号」。符号必须能 grep 到，供后续派活直接引用。
>
> 最近更新：2026-11-13 · JJC-20261112-001 S4-a（新增第 5 项 TLS 透传 SNI 分流）
>
> **注释外置后的查找方式**：代码里我方补丁处只留「一句话结论 + `详见 docs/fork-notes/xxx.md §N`」，
> 长解释（设计理由、反例、取舍）**逐字**保存在 `docs/fork-notes/`（索引见其 `README.md`）。
> 锚点可跳转由 `bash scripts/check-doc-anchors.sh` 机械校验（**锚点失效 = 红**）。
> 追平动手前建议先读对应模块的 fork-notes，比读代码里的散注释快。

---

## 〇、构建链契约（**非自研功能，但同属"不得跟上游照抄"的本仓资产**）

> 2026-11-11 TASK-2026-1111-04 教训固化。这几条不是功能，但**跟上游照抄会直接让镜像构建挂掉**，
> 且 Go 测试全绿也拦不住，故与自研能力并列登记。

| 维度 | 上游 v2.4.2 | **本仓必须** | 判据 |
|---|---|---|---|
| 前端产物 `web/dist` | GitHub Actions 预构建，Dockerfile 只 `COPY web/dist` | **Dockerfile 自带 `web-builder` 阶段**（`node:22-alpine`） | `grep -c 'AS web-builder' Dockerfile` = 1 |
| 取前端产物 | `COPY web/dist /app/ui` | `COPY --from=web-builder /app/web/dist /app/ui` | 非注释 `COPY web/dist` 零命中 |
| `.dockerignore` | 排除 `web/src`、`web/package.json` 等 | **放行**（阶段要 `COPY web ./web`）；只排 `web/node_modules/`、`web/tests/` | `awk '!/^#/ && /^web\//' .dockerignore` 仅两行 |
| CI 形态 | 外部 CI 先 build | `.cnb.yml` **一条 `docker build`**，无前置 npm | `grep -c 'npm.*build' .cnb.yml`（无前置步骤） |

**为什么**：本仓 CI 是「点按钮 → 一条 `docker build`」。若 Dockerfile 吃上游形态（只 COPY dist），
干净 checkout 上 `web/dist` 不存在 → `failed to calculate checksum ... "/web/dist": not found`。

**完整方法论**：`docs/upstream-catchup-guide.zh-CN.md` §十 B.6（判据与决策树）+ §十一 C.5（验证命令）。

---

## 一览表

| # | 能力 | 关键符号（grep 可核） | 裁定出处 |
|---|---|---|---|
| 1 | **链式回退**（`chain_fallback`） | `chain_proxy` · `buildChainProxyConfig` · `chain_race_interval_ms` · `ChainRaceIntervalMS` · `caddychain/` | 2026-10-09 |
| 2 | **引用型证书**（`tls_source=file`） | `ResolveReferencedCertPath` · `IngestMissingReferencedCerts` · `tls_cert_path` · `tls_key_path` | — |
| 3 | **默认端口换位** | `DefaultHTTPPort` · `DefaultHTTPSPort` · `default_ports.go` | — |
| 4 | **回源 Host 逐上游自定义** | `resolveUpstreamHostPlan` · `pathUpstreamHostResolver` · `lb_upstream_host` · `lb.upstream_host` · `lb.upstream_sni` | 2026-10-09 / 2026-10-10 / **2026-11-11** |
| 5 | **TLS 透传 SNI 分流**（`protocol='passthrough'`） | `validatePassthroughRule` · `buildPassthroughLayer4Server` · `passthrough_upstream` · `internalTerminatePort` · `passthroughRulesByPort` | 2026-11-12 |

> **本表的第二用途（2026-11-11 TASK-2026-1111-03 增补）**：`scripts/fork-diff.sh`
> 把上文「关键符号」列与下文每项「代码位置」条目**机械解析**成归属判据，用来给
> 差异清单里的每个文件打 `self_dev_feature` 标签。因此：
> ① 每个符号必须能 `grep` 命中真实源码（否则该项永远判不出来）；
> ② 符号要选**本能力独有**的拼写（如 `chain_race_interval_ms`），别选 `manual`、
> `text/plain` 这类通用词——脚本对长度 < 8 或全小写且无下划线的词不作符号处理，
> 正是为避免误命中。
> 变更本表后请重跑 `bash scripts/fork-diff.sh 0cd475ed main` 并核对归属变化。

---

## 第 1 项 · 链式回退（`chain_fallback`）

- **能力名**：链式回退负载策略——上游按权重降序组成回退链，竞速 + 兜底截断 + 失败即切。
- **代码位置**：
  - 模块：`caddychain/`（`chain_proxy` handler，独立 Go 模块，经 `xcaddy --with` 编入）
  - 渲染：`internal/services/caddy.go` → `buildChainProxyConfig`（`strategy=chain_fallback` 分支）
  - 前端：`web/src/views/Rules.vue`（权重即优先级的提示文案）
- **设计裁定出处**：2026-10-09（逐上游回源 Host 同批立项；`chain_fallback` 与回源 Host
  共用「权重降序 + 逐车道 host」的生成侧解析口径）。
- **关键设计点**：`reverse_proxy` 专属的负载均衡 / 健康检查 / transport / headers /
  回源 Host 占位符**全部不发射**；逐上游回源 Host 在**生成侧**解析后随车道下发
  （`entry["host"]`），因此本能力与第 4 项在链式场景下天然同口径。
- **防复发约束**：
  > 上游若出现「竞速式回退」类实现（或把 `try_duration`/`try_interval` 的重试语义
  > 包装成等价物），**不得**据此拆除 `caddychain/`。上游的 `reverse_proxy` 重试是
  > 「同一请求在可用池内换上游」，**没有**「按权重排序的确定性回退链 + 竞速扇出 +
  > 兜底截断」语义；两者不等价。参照比对记录：`docs/upstream-merge.zh-CN.md`。
- **不适用面**：单上游规则、`dynamic_upstreams`（DynamicDNS）规则。

## 第 2 项 · 引用型证书（`tls_source=file`）

- **能力名**：证书来源可选「引用磁盘文件」，而非只能内嵌 PEM 或走 ACME。
- **代码位置**：
  - `internal/services/certstore.go` → `ResolveReferencedCertPath` /
    `LoadReferencedCertificate` / `IngestMissingReferencedCerts`
  - 写侧摄取：`internal/handlers/helpers.go` → `validateReferencedCertificateFiles`
  - DB 列：`lb_rules.tls_cert_path` / `lb_rules.tls_key_path`
  - 前端：规则编辑「证书来源」下拉的 `file` 选项（`web/src/utils/ruleValidation.ts`）
- **设计裁定出处**：`tls_source` 三态（`manual` / `acme_dns` / `file`）为自研扩展；
  `manual` 与 `acme_dns` 跟随上游语义。
- **关键设计点**：引用路径在渲染期解析为 Caddy 可直接加载的 `load_files` 形态，证书
  热更新由文件系统监听承担，不经面板中转；路径解析失败**显性报错**（fail-visible），
  不做静默降级。
- **防复发约束**：
  > 上游只认 `tls_cert` / `tls_key` 两列（内嵌 PEM）。追上游时**不得**因为「上游没有
  > `tls_cert_path`」就把 `file` 源判成「多余分支」删除——它是董事长要求的能力，
  > DB 列与迁移由本仓库自行维护。切回上游形态会导致存量「引用型证书」规则在
  > 保存/启动时报列不存在或渲染空证书。
- **不适用面**：ACME 签发的证书不走本路径。

## 第 3 项 · 默认端口换位

- **能力名**：面板与 Caddy 的默认监听端口可整体换位/自定义，不写死 80/443。
- **代码位置**：
  - `internal/services/default_ports.go` → `DefaultHTTPPort` / `DefaultHTTPSPort`
  - 消费点：渲染层监听端口、面板自访问地址、前端默认值
- **设计裁定出处**：自研扩展（上游硬编码 80/443）。
- **关键设计点**：端口常量单源，渲染层与前端同源消费；不允许各处再写字面量。
- **防复发约束**：
  > 追上游时**不得**把渲染层/前端里出现的 `DefaultHTTPPort` / `DefaultHTTPSPort`
  > 引用替换回上游的 `80` / `443` 字面量。上游没有「端口换位」概念，机械取上游会
  > 把换位能力打回硬编码（存量换位部署的规则监听端口全错）。
- **不适用面**：ACME HTTP-01 challenge 的端口由 ACME 协议规定，不参与换位。

## 第 4 项 · 回源 Host 逐上游自定义

- **能力名**：同一负载池内**逐上游**自定义回源 Host（Host 头与 HTTPS SNI），
  三级回退「上游级 > 规则级 > 上游自身地址」；自定义路由上游的回源 Host 由渲染期
  **内部推导**，前端与子表**零新增字段**。
- **代码位置**：
  - Caddy 模块：`caddygeoip/upstream_host.go` → `UpstreamHostOverride`，注册 ID
    `http.handlers.lb_upstream_host`
  - 三级回退计划：`internal/services/caddy.go` → `upstreamHostPlan`（四态：
    `staticHost` / `usePlaceholder` / `overrideMap` / `sniTarget`）、
    `resolveUpstreamHostPlan`、`fallbackHostPlan`、`hostPlanValueFor`
  - 自定义路由推导：`pathUpstreamHostResolver`、`buildPathUpstreamHostResolver`、
    `decodePathUpstreamsWithResolver`
  - 占位符：`lb.upstream_host`（Host 头）· `lb.upstream_sni`（TLS server_name）
  - 数据：`upstreams.origin_domain`（逐上游，列名保持不改以零迁移）·
    `lb_rules.host_header`（规则级，第二档）· `lb_rules.health_check_host`（probe 专用）
  - 钉测：`internal/services/caddy_upstream_origin_test.go`、
    `internal/services/caddy_path_upstream_host_test.go`、
    `caddygeoip/upstream_host_test.go`
- **设计裁定出处**：
  - 2026-10-09 `e43b1976`：逐上游回源 Host 立项实现
  - 2026-10-10 `0c8ec276`：**自定义路由不新增任何字段**，回源 Host 全程内部逻辑
  - 2026-10-11 `5ee2a96a`：曾按「同需求两实现」临时切上游 map 方案
  - **2026-11-11（董事长裁定）**：「回源 Host 采用我的自研，并记录为我的核心自研」
    ——本项正式登记为第 4 项核心自研，渲染链恢复自研实现
- **关键设计点（也是相对上游的不可替代性）**：
  1. **任何回退态都不用 `{http.request.hostport}`**。上游 map 方案在「纯 http 池 +
     规则级为空」时回退 `{http.request.hostport}` = **客户端 Host**，会把用户域名
     发给未配回源 Host 的上游；自研版全回退恒用
     `{http.reverse_proxy.upstream.hostport}`（该上游自身 dial）。
  2. **自定义路由有推导层**。上游方案无此层：`path_rules.upstreams_json` 里的地址
     不在 `enabledUpstreams` 表中时查表必空，直接落进上条缺陷分支。自研版按
     hoisted（地址在上游表 → 用其三级回退值）/ orphan（不在表 → 只用规则级，空则
     自身地址）分派，**两类都不透传客户端 Host**。
  3. **静态态不发射 handler**。全上游取值一致且非空时直接下发静态值（零额外模块
     开销）；只有混合态才发射 `lb_upstream_host`。
  4. **SNI 语义正确**：Host 头保留端口、SNI 剥端口（RFC 6066 无端口语义）。
- **防复发约束（下次追上游必须逐条核对）**：
  > **不得**以「上游存在同需求实现（`originDomains` + `http.handlers.map`）」为由切回
  > 上游版本。上游实现存在三处实缺陷，实证见
  > `docs/upstream-origin-host-compare.zh-CN.md` §2.4：
  > 1. 纯 http 池 + 规则级空 → 回退 `{http.request.hostport}` = 客户端 Host；
  > 2. 无自定义路由推导层（`path_rules` 外部地址必落缺陷 1）；
  > 3. TLS 回退曾用 `{http.request.hostport}`（`2ba0f2c7`/`872408c2` 引入，
  >    `3f1c3346` 才修）——说明该形态在上游侧反复出问题。
  >
  > 机械判据（可直接照抄执行，任一为红即视为回归）：
  > - `grep -rn "originDomains\|originDialOrder" internal/services/caddy.go` → **无命中**
  > - `grep -rn "http.request.hostport" --include='*.go' --include='*.ts' --include='*.vue' --include='*.yml' --include='*.yaml' .`
  >   → 仅允许出现在**注释**与下列**钉测本体**内：
  >   `internal/services/caddy_upstream_origin_test.go`（H2 扫描器与 needle 常量）、
  >   `internal/services/caddy_emit_config_validate_test.go`（产物层断言）、
  >   `caddygeoip/caddy_decode_generated_config_test.go`（解码链侧断言）、
  >   `internal/services/render_anti_fallback_scan_test.go`（反兜底清单的说明文字）。
  >   注：`.yml`/`.yaml` 在扫描器内**不享受注释豁免**（YAML 块标量内容行不以 `#`
  >   开头，按行首 `#` 豁免会留绕过面）。
  > - `go test -run 'TestUpstreamHost_noClientHostFallbackAnywhere|TestUpstreamHost_mapPlanFullyRemoved' ./internal/services/` → PASS
  > - `go test -run 'TestPathRuleUpstreamHost_' ./internal/services/` → PASS
  > - `/bin/bash scripts/verify-generated-config-decodes.sh` → `VERIFY: PASS`
  >   （生产渲染链产物 → Caddy 真实解码链：`Route.UnmarshalJSON` → `Route.Provision`
  >   → `ctx.LoadModule`；证明配置能被加载，比 `caddy validate` 更贴近根因且不依赖外部二进制）
  >
  > **禁止**删除 `caddygeoip/upstream_host.go` 或 `caddygeoip/go.mod` 里的模块注册；
  > `Dockerfile` 的 `xcaddy --with lazy-balancer-v2/caddygeoip=./caddygeoip` 必须在位
  > （否则 `lb_upstream_host` 模块缺席，caddy validate 直接拒绝混合态配置）。
- **不适用面**：`dynamic_dns` 规则的混合态（保存链强制单启用上游，dial 逐请求变化，
  静态映射永不命中；渲染守卫 + 校验侧 400 双保险）；主动健康检查 probe 的 Host
  只由 `health_check_host` / `host_header` 决定，**不**读逐上游值（probe 为 handler
  级，无法逐上游）。

## 第 5 项 · TLS 透传 SNI 分流（`protocol='passthrough'`）

- **能力名**：TLS 透传 SNI 分流——443 统一入口 · Layer4 混合透传/终结（同一监听端口，
  部分域名按 SNI 字节流转发给上游、其余域名仍走本系统 Caddy TLS 终结）。
- **代码位置**：
  - 协议白名单：`internal/handlers/rule_features.go` → `validateRuleFeatures`
    （`http/tcp/passthrough` 三值放行，`protocol='passthrough'`）
  - 保存门：`internal/handlers/rule_features.go` → `validatePassthroughRule` /
    `validateSNIDomain`；`internal/handlers/rules.go` → `passthroughSNIConflict` /
    `passthroughTerminateConflict`（同端口 SNI 重叠 / 透传↔本地终结 冲突双门）
  - 数据：`internal/db/db.go` → `passthrough_upstream` 列（fresh DDL /
    newColumnsRegistry / PK 重建 DDL 三处登记）
  - 渲染：`internal/services/caddy.go` → `buildPassthroughLayer4Server` /
    `buildPassthroughProxyHandler` / `passthroughDialAddress` /
    `passthroughRulesByPort`（与 http/tcp 并列的第三族按端口分组）；
    内部终结口 7443 常量 `internalTerminatePort` + `internalTerminateAddr`（仅绑 127.0.0.1）
  - 前端：`web/src/views/Rules.vue`（SNI 字段/单值上游/协议分支隔离）、
    `web/src/utils/ruleValidation.ts`（与后端逐条同口径的校验单源）
  - 钉测：`internal/services/caddy_passthrough_render_test.go`（R5 零回归 sha256 钉测族）、
    `internal/handlers/rule_features_passthrough_test.go`、
    `internal/db/db_passthrough_column_test.go`、`web/tests/rulePassthrough.spec.ts`
  - 渲染链注释：`docs/fork-notes/render-chain.md` §29
- **设计裁定出处**：董事长 2026-11-12（需求 + 8 项决策点，计划档案
  `.agent_team/JJC-20261112-001-tls-passthrough-plan.md` §一）；S0 spike 五项验证全
  CONFIRMED（T-1/T-2/T-4/T-5 真实进程实跑报告 `.agent_team/spike/evidence/`；
  T-3 为 caddy-l4 源码走读 + 编译产物注册表断言，方法见计划档案 §三）。
- **关键设计点（也是相对上游的不可替代性）**：
  1. 443/TCP 由 Caddy Layer4（caddy-l4）接管，按 ClientHello 的 SNI 域名分流；
     多条透传规则聚合进同一 `matchers.tls.sni` 集合，同端口可共存。
  2. 透传域名做**字节流转发**：证书由上游自带并终结，本系统不申请、不续期、不监控。
  3. 无 SNI 命中的兜底路由注入 PROXY v2 转发到 `127.0.0.1:7443`（Caddy TLS 终结）——
     本地终结域名的证书/ACME/WAF 链路**零迁移**。
  4. 全库无启用透传规则时渲染产物与改造前**逐字节一致**（R5 sha256 钉测）。
- **防复发约束（下次追上游必须逐条核对）**：
  > ① **上游无同需求实现**——追平时不得以「上游有 TLS 转发能力」为由切换：
  > 本功能是**按 SNI 域名级分流 + 混合终结**（同端口透传/终结并存），上游
  > `reverse_proxy` 无法表达该语义。
  > ② `layer4` 是 Caddyfile **全局选项块** `{ layer4 { :443 {...} } }`，**不可顶层直写**。
  > ③ `servers <addr>` 的 addr 必须与站点 `bind` 监听地址**逐字一致**，否则
  > listener wrapper 静默失效（spike T-5 实证）。
  > ④ 7443 必须仅绑 `127.0.0.1`——全绑存在外部直连绕过面（spike T-5 C 断言实测）。
  > ⑤ 追平新上游时核对 `Dockerfile` 的 `--with caddy-l4` 行与 Caddy
  > `modules/caddyhttp/proxyprotocol` 注册仍在（详见追平手册 §十 B.7）。
  >
  > 机械判据（可直接照抄执行，任一为红即视为回归；grep 通配按本文件维护规则 5 加引号）：
  > - `grep -rn 'func validatePassthroughRule' internal/handlers/` → 命中 `rule_features.go`
  > - `grep -c 'caddy-l4' Dockerfile` ≥ 1
  > - `grep -c 'passthrough_upstream' internal/db/db.go` ≥ 3（fresh DDL / 注册表 / 重建 DDL）
  > - `go test -run 'TestPassthroughRender_' ./internal/services/` → PASS（R5 零回归钉测族）
  > - `go test -run 'TestPassthrough' ./internal/handlers/ ./internal/db/` → PASS
- **不适用面**：HTTP/3（QUIC）——透传域名自动降级 HTTP/2/1.1；透传规则的证书/ACME/
  WAF 面板能力全部不适用（证书归上游管理）。

---

## 维护规则

1. **新增核心自研**：由总经理在任务书里明确「登记为核心自研」后，开发总监在**同一
   任务内**把条目加进本文件（能力名 / 代码位置 / 裁定出处 / 防复发约束 / grep 符号）。
2. **禁止删条目**：能力废弃时保留条目并标注「已退役（时点 + 裁定）」，说明去向。
3. **追上游前必读**：`docs/upstream-merge.zh-CN.md` 的追平流程**第一步**即逐项核对
   本文件的防复发约束；漏核导致能力被切回上游，按红线「假装完成」同族处理。
4. **机械可核**：每条目的「关键符号」必须能被 `grep -rn '<符号>' --include='*.go' .`
   命中；符号改名须同步本条（本仓库 CI 不自动校验，靠评审与 `R3` 类钉测）。
5. **shell 兼容（本仓环境 zsh）**：`grep --include=*.go` 这类**不加引号**的通配在 zsh
   下会被 glob 展开，直接报 `no matches found: --include=*.go` 并**以 0 退出**——
   看起来「无命中 = 通过」，实际命令根本没执行。本文件所有 grep 判据一律写成
   `--include='*.go'`（引号包住通配）或 `rg -g '*.go' '<pattern>' <path>`。
   同理：`*.ts` / `*.vue` / `*.yml` / `*.yaml` 均须加引号。
