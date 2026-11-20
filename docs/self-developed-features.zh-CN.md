# 核心自研能力登记（Self-Developed Features Registry）

> **本文件是本仓库「董事长核心自研」的唯一登记处。**
> 任何一轮上游追平（`docs/upstream-merge.zh-CN.md` 流程）动手前，**必须先读本文件**，
> 按下文每项的「防复发约束」逐条核对，**不得**以「上游有同需求实现」为由把下列
> 能力切回上游版本。
>
> 登记原则：**一能力一条**，写清「能力名 / 代码位置 / 设计裁定出处 / 防复发约束 /
> 机械可核符号」。符号必须能 grep 到，供后续派活直接引用。
>
> 最近更新：2026-11-20 · JJC-20261120-002（第 1 项扩展「chain 被动 5xx 摘除」——passiveMonitor 恒启用/eligibleLanes 单源/网络错误不计数有意差异钉死）
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
| 1 | **链式回退**（`chain_fallback`）+ 混布池 wrr 承载 + 混布池主动健康检查（2026-11-19 扩展）+ 被动 5xx 摘除（2026-11-20 扩展） | `chain_proxy` · `buildChainProxyConfig` · `chain_race_interval_ms` · `ChainRaceIntervalMS` · `chainProxyModeFor` · `caddychain/` · `healthMonitor` · `eligibleLanes` · `health_check` · `passiveMonitor` · `recordPassive` · `passive_health_check` | 2026-10-09 / 2026-11-18 / 2026-11-19 / 2026-11-20 |
| 2 | **引用型证书**（`tls_source=file`） | `ResolveReferencedCertPath` · `IngestMissingReferencedCerts` · `tls_cert_path` · `tls_key_path` | — |
| 3 | **默认端口换位** | `DefaultHTTPPort` · `DefaultHTTPSPort` · `default_ports.go` · `healthcheckPanelPort` | — / 2026-11-15 |
| 4 | **回源 Host 逐上游自定义** | `resolveUpstreamHostPlan` · `pathUpstreamHostResolver` · `lb_upstream_host` · `lb.upstream_host` · `lb.upstream_sni` | 2026-10-09 / 2026-10-10 / **2026-11-11** |
| 5 | **TLS 透传 SNI 分流**（`protocol='passthrough'`） | `validatePassthroughRule` · `buildPassthroughLayer4Server` · `passthrough_upstream` · `internalTerminatePort` · `internalTerminateDefaultPort` · `internalTerminateBind` · `internalTerminateProxyAllow` · `passthroughRulesByPort` | 2026-11-12 / 2026-11-15 |

> **本表的第二用途（2026-11-11 TASK-2026-1111-03 增补）**：`scripts/fork-diff.sh`
> 把上文「关键符号」列与下文每项「代码位置」条目**机械解析**成归属判据，用来给
> 差异清单里的每个文件打 `self_dev_feature` 标签。因此：
> ① 每个符号必须能 `grep` 命中真实源码（否则该项永远判不出来）；
> ② 符号要选**本能力独有**的拼写（如 `chain_race_interval_ms`），别选 `manual`、
> `text/plain` 这类通用词——脚本对长度 < 8 或全小写且无下划线的词不作符号处理，
> 正是为避免误命中。
> 变更本表后请重跑 `bash scripts/fork-diff.sh 0cd475ed main` 并核对归属变化。

---

## 第 1 项 · 链式回退（`chain_fallback`）+ 混布池 wrr 承载 + 混布池主动健康检查（2026-11-19 扩展）

- **能力名**：链式回退负载策略——上游按权重降序组成回退链，竞速 + 兜底截断 + 失败即切。
  **2026-11-18 扩展（JJC-20261118-002）**：HTTP 规则启用上游池支持 http/https 混布，
  混布池由 chain 模块逐上游独立 transport 承载（**绝不落 reverse_proxy**——池级 TLS
  传输会使 http 上游静默 502）；`mode` 分权：`chain_fallback`→`race`（竞速，现状零变化）、
  其余策略（含空串归一 `weighted_round_robin`）→`wrr`（**确定性平滑加权轮询**，逐请求
  精确按权重比例交错选路——与原生 reverse_proxy 随机加权选路长程分布一致、短程形态
  不同，禁等价宣称）。
  **2026-11-19 扩展（JJC-20261119-001，方案 v1.2 门下轮 2 准奏冻结）**：chain 模块
  **主动健康检查（HC）子系统**落地（`caddychain/health.go`）——逐车道探测器（GET，
  复用 `transportFor` 与数据面同池同源）+ 逐车道状态机（初值全 healthy，lag 阈值翻转）
  + 调度 goroutine；选路联动：wrr 跳过 unhealthy（权重视为缺席，恢复无缝回池）、race
  扇出剔除、升级隧道同口径、**全灭不专判**（全部不健康时真实请求照常放行，502/504
  收尾语义不变）；混布+HC 写侧 400 伴随门**整体移除**（原「响亮拒绝」立论失效——
  chain 已真承载 HC），uniform+chain_fallback+HC 的既有「静默忽略」死配置分叉就此
  收口为真探测。
  **2026-11-20 扩展（JJC-20261120-002，方案 v1.1 门下轮 1 准奏冻结）**：chain 模块
  **被动 5xx 摘除子系统**落地（`caddychain/passive.go`）——`passiveMonitor` 逐车道
  5xx 滑动计数（**恒启用、零配置**，对齐 uniform 引擎自带被动 HC；缺省
  fail_duration=90s=uniform 渲染 interval 缺省 30s×3、max_fails=3、
  unhealthy_duration=同 fail_duration 回落语义，S0 读码核销
  `caddy.go:3940-3945/:5469`）；选路单源收敛 `eligibleLanes=HC∩passive`
  （两套注册表独立、任一判摘即摘、恢复条件各自独立：HC=连续探测成功 lag 次、
  passive=摘除期满 half-open 试探；全灭不专判延续，502/504 收尾不变）；
  摘除/恢复各打一行可观测日志。**chain 有意差异（如实钉死）：网络错误不计入
  被动失败**——uniform 原生计入，但 chain 的 wrr/race「失败即切」已覆盖网络
  错误，不双罚；另「计数仅覆盖升级响应的状态码面，升级后字节流天然不计数」。
- **代码位置**：
  - 模块：`caddychain/`（`chain_proxy` handler，独立 Go 模块，经 `xcaddy --with` 编入；
    `Mode` 字段 race/wrr、`serveWRR`/`serveWRRDirect`、`wrrNext` 平滑轮询选路器；
    2026-11-19 扩展：`health.go` 的 `healthMonitor`（调度/探测器/状态机）、
    `hcEligible`/`laneEligible`（选路联动单源）、`parseExpectStatus`（期望状态单一
    语法：单值整数或闭区间串 `200-299`，min>max 拒）、`ChainHealthCheck` 配置面
    （json `health_check`：interval_ms/timeout_ms/expect_status/path/healthy_lag/
    unhealthy_lag/body，缺省 30s/5s/200-299/`/`/2/3/不查体）；
    2026-11-20 扩展：`passive.go` 的 `passiveMonitor`/`recordPassive`（被动 5xx
    滑动计数单源，恒启用零配置）、`eligibleLanes`（HC∩passive 选路单源收敛））
  - 渲染：`internal/services/caddy.go` → `buildChainProxyConfig`（mode 参数 +
    **EnableActiveHealthCheck 时发射 `health_check` 键**，race/wrr 同发射，
    uniform reverse_proxy 路径零触碰）+ `chainProxyModeFor`（mode 单源推导）+
    `httpUpstreamPoolMixed`（混布触发器）
  - 门禁：`internal/handlers/rule_features.go` → `mixedPoolStrategyAllowed`（定向放行
    谓词单源）；`mixedPoolHealthCheckError` 伴随门已于 2026-11-19 整体移除（保存链/
    存量启用门/复制链/v2 导入链四处调用同步移除，聚合 warn 三口径退两口径）
  - 前端：`web/src/views/Rules.vue`（权重即优先级的提示文案；主池门镜像谓词；
    HC 伴随门镜像已同步移除）
- **设计裁定出处**：2026-10-09（逐上游回源 Host 同批立项；`chain_fallback` 与回源 Host
  共用「权重降序 + 逐车道 host」的生成侧解析口径）；2026-11-18（混布池定向放行 +
  mode 分权，JJC-20261118-002 裁决 1-4，方案 v1.2 门下轮 2 准奏冻结）。
- **关键设计点**：`reverse_proxy` 专属的负载均衡 / 健康检查 / transport / headers /
  回源 Host 占位符在 uniform 路径之外**全部不发射**（唯一例外：chain 分支的
  `health_check` 键——HC 标志启用时 chain 模块真承载）；逐上游回源 Host 在**生成侧**
  解析后随车道下发（`entry["host"]`），因此本能力与第 4 项在链式场景下天然同口径。
  混布池渲染触发器**不分策略**（兜存量脏行：直改 DB 的「混布+不允许策略」启用行也
  整池切 chain 承载，绝不落 reverse_proxy）。混布池+主动健康检查=**放行**（2026-11-19
  起经 `health_check` 键真承载；原写侧 400 伴随门移除；存量脏行零值不发射、模块按
  缺省 30s/5s/2,3/"/" 兜底自动获得真探测）。**HC 探测口径**：scheme=车道 Scheme
  （混布核心诉求）、Host=回源 Host 单源（三级回退结果，与数据面严格一致）、UA=
  `chain_proxy-health-check`、连接复用 `transportFor`（与数据面同池，测真实回源路径）；
  **仅主动探测，被动 5xx 摘除不做**（与 uniform 原生 HC 的差异，如实登记，另立项）；
  wrr 404 透传（与 race「干净 404」刻意分叉）；车道恒 HTTP/1.1；`dns_server` 不消费
  （车道走系统解析器）。**2026-11-20 起被动 5xx 摘除已落地**（见上方扩展段与
  `passive_health_check` 键面恒发射），原「本期不做」口径核销。真进程验证：
  `.agent_team/spike/evidence/T6.md`（wrr 分布 2:1:1 精确观测、race 双车道扇出、
  全灭 502/全超时 504、升级隧道 101）+ `evidence/T7.md`（HC 翻转→摘除→恢复真观测、
  探针 Host/UA/TLS 口径、初态全 healthy）+ `evidence/T8.md`（被动 5xx 注入→观测
  摘除→期满恢复真观测、缺省三值实测）。
- **防复发约束**：
  > 上游若出现「竞速式回退」类实现（或把 `try_duration`/`try_interval` 的重试语义
  > 包装成等价物），**不得**据此拆除 `caddychain/`。上游的 `reverse_proxy` 重试是
  > 「同一请求在可用池内换上游」，**没有**「按权重排序的确定性回退链 + 竞速扇出 +
  > 兜底截断」语义；两者不等价。参照比对记录：`docs/upstream-merge.zh-CN.md`。
  > **隧道取连接必须经 `http.NewResponseController(w).Hijack()` 穿透引擎包装层，
  > 禁直接 `w.(http.Hijacker)` 类型断言**——真实 Caddy 引擎把 writer 包装成
  > `*caddyhttp.IdleTimeoutWriter` 等**不实现 Hijacker** 的类型（v2.11.9 实测，
  > 卡-20261118-02），断言失败即隧道 502；httptest 裸 writer 单测测不出该缝隙。
  > **HC 探测连接必须复用 `transportFor`（与数据面同池同源）**——独立 transport 可能
  > 测出不同 SNI/连接形态，违背「测真实回源路径」的目的（JJC-20261119-001 裁决 1，
  > 门下 P1-2 裁决落地）；HC 状态属 handler 实例非规则，**重载即新实例、不持久化**
  > （与 tlsCache/wrrState 生命周期同构）；Cleanup 必须**先等探测协程退出再关连接**
  > （done channel 先等后放，卡-20261118-01 经验）。
- **不适用面**：单上游规则、`dynamic_upstreams`（DynamicDNS）规则；混布池规则另见
  上方 2026-11-18 扩展（单上游 uniform 池维持 reverse_proxy 原生路径零变化）；
  chain HC **不含被动 5xx 摘除**（与 uniform 原生 HC 的差异，另立项）。

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
  **面板口同样可换**：`PANEL_PORT` env 改面板监听口（默认 8000），容器内置健康
  探针跟随该口探测（2026-11-15 起；此前探针硬编码 8000，`PANEL_PORT` 换口部署
  会长期误显 unhealthy，需在 compose 覆盖 healthcheck 才能恢复判定）。
- **代码位置**：
  - `internal/services/default_ports.go` → `DefaultHTTPPort` / `DefaultHTTPSPort`
  - 消费点：渲染层监听端口、面板自访问地址、前端默认值
  - 面板口与健康探针：`internal/config/config.go` → `envPort("PANEL_PORT", ...)`；
    `cmd/server/healthcheck.go` → `healthcheckPanelPort` / `healthcheckURLs`
    （探针每轮按 `PANEL_PORT` 求值，非法值告警回落 8000，与 `envPort` 同口径）
  - 钉测：`cmd/server/healthcheck_test.go`（`TestHealthcheckPanelPort_*` 三条：
    换口跟随 / 未设默认 / 非法回落）
- **设计裁定出处**：自研扩展（上游硬编码 80/443）；面板口探针联动为
  2026-11-15 追加裁定（host 模式下 8000 被占用是真实故障路径，换口 + 探针
  跟随才构成完整能力）。
- **关键设计点**：端口常量单源，渲染层与前端同源消费；不允许各处再写字面量。
  探针端口不 import `internal/config`（main 包引入会拖入 DB 装配依赖，探针
  路径已钉测「不触碰启动依赖」），以常量 `defaultHealthcheckPort` + 注释对齐
  替代单源——两处默认值改动须同步（钉测断言 8000 会拦住漂移）。
- **防复发约束**：
  > 追上游时**不得**把渲染层/前端里出现的 `DefaultHTTPPort` / `DefaultHTTPSPort`
  > 引用替换回上游的 `80` / `443` 字面量。上游没有「端口换位」概念，机械取上游会
  > 把换位能力打回硬编码（存量换位部署的规则监听端口全错）。
  > 同理**不得**把 `healthcheckURLs` 改回硬编码 `:8000`（机械取上游形态会重新
  > 引入「PANEL_PORT 换口 → 容器误显 unhealthy」缺陷）。
  >
  > 机械判据：
  > - `grep -n 'healthcheckPanelPort' cmd/server/healthcheck.go` → 命中
  > - `grep -cn '127\.0\.0\.1:8000' cmd/server/healthcheck.go` → **0 命中**
  >   （探测地址由 `healthcheckURLs` 动态拼出，文件内不得出现硬编码回环 URL）
  > - `go test -run 'TestHealthcheckPanelPort_' ./cmd/server/` → PASS
- **不适用面**：ACME HTTP-01 challenge 的端口由 ACME 协议规定，不参与换位。
  `docker run -config` 通道改 `port`（配置文件键）不影响探针——探针只认
  `PANEL_PORT` env，容器形态经配置文件换面板口的部署仍需覆盖 healthcheck
  （该形态本就不受支持，见部署文档「容器配置用环境变量」）。

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
  **内部终结口的端口与绑定地址均可配，默认收口回环**：host 网络下 7443 虽仅绑
  回环仍可能与宿主其他进程的回环监听冲突（面板口同款故障路径），
  `PASSTHROUGH_INTERNAL_PORT` env 可换口（默认 7443，非法值告警回落）；
  `PASSTHROUGH_INTERNAL_BIND` env 可改绑定地址（**默认 `127.0.0.1` 收口回环**；
  `0.0.0.0` / `::` / 指定 IP 均为**显式选择对外**）。
  2026-11-15 两则追加裁定：① 端口可配（host 模式回环端口占用是真实故障路径）；
  ② 绑定地址可配——家庭网络 / ISP 封禁入站 443 时，可**放弃 Layer4 SNI 分流**，
  把内部终结口绑到对外地址由外部直连入站；**默认值不变**，收口形态零变化。
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
    内部终结口**端口**：`internalTerminatePort()` / `internalTerminateDefaultPort`
    （`PASSTHROUGH_INTERNAL_PORT` env 单源，非法值告警回落 7443）；
    **绑定地址**：`internalTerminateBind()` / `internalTerminateExposed()` /
    `internalTerminateListenHost()` / `internalTerminateDialHost()` /
    `internalTerminateProxyAllow()`（`PASSTHROUGH_INTERNAL_BIND` env 单源，listen /
    dial / allow 三处全部由上述符号派生，**禁止各自读 env**）；
    暴露告警 `warnInternalTerminateExposed()`（每进程一次）；
    整链地址 `internalTerminateAddr` / `internalTerminateListenAddr`；
    规则监听口与内部口同口时渲染显性 generationFailure
  - 前端：`web/src/views/Rules.vue`（SNI 字段/单值上游/协议分支隔离）、
    `web/src/utils/ruleValidation.ts`（与后端逐条同口径的校验单源）
  - 钉测：`internal/services/caddy_passthrough_render_test.go`（R5 零回归 sha256 钉测族 +
    `TestInternalTerminatePort_` 四条：默认/换口整链跟随/非法回落/监听口冲突显性报错）、
    `TestInternalTerminateBind_` 四条：`_defaultsLoopback`（默认收口回环）/
    `_wildcardExposed`（通配 listen + 回环 dial + allow 不变）/
    `_specificIPAddsAllow`（指定 IP 且 allow 追加该 IP）/`_invalidFallsBack`（非法回落）；
    `internal/handlers/rule_features_passthrough_test.go`、
    `internal/db/db_passthrough_column_test.go`、`web/tests/rulePassthrough.spec.ts`
  - 渲染链注释：`docs/fork-notes/render-chain.md` §29
- **设计裁定出处**：董事长 2026-11-12（需求 + 8 项决策点，计划档案
  `.agent_team/JJC-20261112-001-tls-passthrough-plan.md` §一）；S0 spike 五项验证全
  CONFIRMED（T-1/T-2/T-4/T-5 真实进程实跑报告 `.agent_team/spike/evidence/`；
  T-3 为 caddy-l4 源码走读 + 编译产物注册表断言，方法见计划档案 §三）。
  内部口端口可配为 2026-11-15 追加裁定（host 模式回环端口占用是真实故障路径；
  原始「固定 7443」的安全目标——绕过面收口在回环一处——由「默认绑 127.0.0.1」
  承担，不依赖端口值本身）。同批第二则裁定为**绑定地址可配**（家庭网络 / 上游
  封 443 时放弃 SNI 分流、外部直连终结口入站的逃生形态）：默认收口形态不变，
  因绑定可对外，该安全目标改由 `internalTerminateProxyAllow()` 派生的 allow 集合
  承担（spike T-5 断言 B：非 allow 源伪造 PROXY 头 → 握手 EOF），暴露必须显式
  选择并留告警。
- **关键设计点（也是相对上游的不可替代性）**：
  1. 443/TCP 由 Caddy Layer4（caddy-l4）接管，按 ClientHello 的 SNI 域名分流；
     多条透传规则聚合进同一 `matchers.tls.sni` 集合，同端口可共存。
  2. 透传域名做**字节流转发**：证书由上游自带并终结，本系统不申请、不续期、不监控。
  3. 无 SNI 命中的兜底路由注入 PROXY v2 转发到内部终结口（默认
     `127.0.0.1:<内部口>`，Caddy TLS 终结；指定 IP 绑定时拨号目标随之改为该 IP，
     见第 6/7 点）——本地终结域名的证书/ACME/WAF 链路**零迁移**。
  4. 全库无启用透传规则时渲染产物与改造前**逐字节一致**（R5 sha256 钉测）。
  5. 内部口换口整链一致：`internalTerminateAddr()` 是 HTTP listen 迁移地址、
     Layer4 兜底 dial、servers 挂载键的同源形态（**四元一致要点**：listen 地址 /
     dial 地址 / wrapper allow / servers 挂载键，详见 `docs/fork-notes/render-chain.md` §29），
     env 换口三处同步；**默认收口形态**下 `proxy_protocol` allow 只信 `127.0.0.1/32`。
  6. **listen / dial 分离**：绑定地址可配后，监听地址（`internalTerminateListenHost()`）
     与 Layer4 兜底拨号地址（`internalTerminateDialHost()`）是**两个独立取值**——
     `0.0.0.0` 只进 listen（对外收流），dial 恒 `127.0.0.1:<port>`；`::` 同理
     （`[::]:<port>` 监听 / `[::1]:<port>` 拨号）。合并成单一地址就会去拨
     `0.0.0.0` 这类不可连接的语义地址，本地终结链路整条断掉。
  7. **指定 IP 绑定时 allow 必须含该 IP**：dial 目标即该 IP，出站源不保证是回环；
     allow 若只有 `127.0.0.1/32`，Layer4 出站的 PROXY 头会被终结栈当 TLS 数据
     （握手 EOF，与 spike T-5 断言 B 同型），兜底链路坏。allow 由
     `internalTerminateProxyAllow()` 按形态派生：同族回环 + （指定 IP 时追加该 IP `/32`）。
- **防复发约束（下次追上游必须逐条核对）**：
  > ① **上游无同需求实现**——追平时不得以「上游有 TLS 转发能力」为由切换：
  > 本功能是**按 SNI 域名级分流 + 混合终结**（同端口透传/终结并存），上游
  > `reverse_proxy` 无法表达该语义。
  > ② `layer4` 是 Caddyfile **全局选项块** `{ layer4 { :443 {...} } }`，**不可顶层直写**。
  > ③ `servers <addr>` 的 addr 必须与站点 `bind` 监听地址**逐字一致**，否则
  > listener wrapper 静默失效（spike T-5 实证）。
  > ④ 内部终结口**默认必须收口 `127.0.0.1`**——全绑存在外部直连绕过面（spike T-5 C
  > 断言实测）；默认值不得改，对外只能经 `PASSTHROUGH_INTERNAL_BIND` **显式选择**
  > （家庭网络封 443 的取舍形态），且暴露必须留告警
  > （`warnInternalTerminateExposed()`）；该边界不随 `PASSTHROUGH_INTERNAL_PORT`
  > 换口变化。
  > 同理**不得**把 `internalTerminatePort()` 改回硬编码常量（机械取上游/旧形态
  > 会重新引入「host 模式回环 7443 被占用 → Caddy 绑不上整份拒绝」故障）。
  > ⑤ 追平新上游时核对 `Dockerfile` 的 `--with caddy-l4` 行与 Caddy
  > `modules/caddyhttp/proxyprotocol` 注册仍在（详见追平手册 §十 B.7）。
  > ⑥ **不得把 listen 与 dial 合并回单一地址**：`0.0.0.0` / `::` 只能出现在
  > listen，兜底 dial 恒为同族回环（合并即「拨 0.0.0.0」不可连接，本地终结
  > 链路全断）。两处取值分别由 `internalTerminateListenHost()` /
  > `internalTerminateDialHost()` 单源提供，不得在渲染处内联拼地址。
  > ⑦ **不得把 `proxy_protocol` 的 allow 写死 `127.0.0.1/32`**：指定 IP 绑定时
  > 出站源可能非回环，allow 缺该 IP 会把 PROXY 头当 TLS 数据（握手 EOF）；
  > allow 必须由 `internalTerminateProxyAllow()` 按绑定形态派生。
  >
  > 机械判据（可直接照抄执行，任一为红即视为回归；grep 通配按本文件维护规则 5 加引号）：
  > - `grep -rn 'func validatePassthroughRule' internal/handlers/` → 命中 `rule_features.go`
  > - `grep -c 'caddy-l4' Dockerfile` ≥ 1
  > - `grep -c 'passthrough_upstream' internal/db/db.go` ≥ 3（fresh DDL / 注册表 / 重建 DDL）
  > - `grep -n 'PASSTHROUGH_INTERNAL_PORT' internal/services/caddy.go` → 命中
  > - `grep -n 'PASSTHROUGH_INTERNAL_BIND' internal/services/caddy.go` → 命中
  > - `go test -run 'TestPassthroughRender_|TestInternalTerminatePort_' ./internal/services/` → PASS（R5 零回归钉测族 + 内部口端口钉测）
  > - `go test -run 'TestInternalTerminateBind_' ./internal/services/` → PASS（绑定地址四态）
  > - `go test -run 'TestPassthrough' ./internal/handlers/ ./internal/db/` → PASS
- **不适用面**：HTTP/3（QUIC）——透传域名自动降级 HTTP/2/1.1；透传规则的证书/ACME/
  WAF 面板能力全部不适用（证书归上游管理）。直连入站形态（`PASSTHROUGH_INTERNAL_BIND`
  选对外地址）下**SNI 分流本身不参与**——该入口是纯终结口，透传域名在此不可用，
  且缺少 Layer4 层 IP/GeoIP 拦截（代价清单见 `docs/deployment.zh-CN.md`
  「家庭网络 / 上游封 443（直连终结口入站）」）。

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
