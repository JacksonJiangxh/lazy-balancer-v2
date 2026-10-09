# 计划：新增「链式回退」（chain\_fallback）负载策略 —— 竞速 + 兜底截断

## 一、总结

在反代规则（HTTP）的上游负载策略中新增第五种策略 **链式回退（chain\_fallback）**，语义参考 `参考项目/cdn-edge-gateway` 的 failover/竞速设计：

* **优先级**：启用上游按 `weight` 降序组成回退链（权重越大优先级越高，同权重按列表顺序）。

* **竞速**：请求 1 发出后等待 `chain_race_interval_ms` 毫秒仍无有效响应，则向下一优先级上游并行发出请求 2，两路竞速；依次类推。先返回**有效响应**（status < 400）的一路胜出直达客户端，其余在途请求被取消截断。

* **兜底截断**：单一路径超过 `chain_request_timeout_ms` 毫秒未收到响应（响应头）即取消该路径，避免耗时浪费。

* **失败即切**：某一路返回错误或 4xx/5xx 时，不必等竞速间隔，立即发出下一路。

**实现方式（用户已确认）**：新建自定义 Caddy 模块 `caddychain`（`http.handlers.chain_proxy`），仿照现有 `caddygeoip` 模式（独立 Go 子模块 + Dockerfile xcaddy `--with` 挂载），实现真正的并行竞速。**仅 HTTP 规则可用**（TCP 校验拒绝，同 cookie 先例）。

## 二、现状分析

| 层        | 现状                                                                                                                                       | 位置                                                                                                                                                                                        |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 数据模型     | `LbRule.Strategy string` 单字段；现有值 `weighted_round_robin / least_conn / ip_hash / cookie / random / first`                                 | [models.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/models/models.go#L117-L131)                                                                                               |
| 上游       | `Upstream{Weight, HostHeader, Protocol...}`，DB 按 `(rule_id, enabled, id)` 排序                                                             | [models.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/models/models.go#L279-L292)                                                                                               |
| 校验       | `validateStrategyForProtocol` 白名单（http/tcp 两张 map）                                                                                       | [rule\_features.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/handlers/rule_features.go#L245-L273)                                                                              |
| Caddy 生成 | `Strategy` 透传为 `selection_policy.policy`；HTTP `try_duration=5s/try_interval=250ms` 硬编码；host 三级回退 `resolveUpstreamHostPlan`；X-LB-\* 头剥离清单 | [caddy.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/services/caddy.go#L3787-L3966)                                                                                             |
| DB       | `lb_rules` 纯列存储；新列走 `newColumns` ALTER 迁移                                                                                                | [db.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/db/db.go#L234-L292)                                                                                                           |
| 自定义模块先例  | `caddygeoip`（`http.handlers.geoip2region`），独立 go.mod 依赖 caddy v2.11.6，Dockerfile `--with lazy-balancer-v2/caddygeoip=./caddygeoip`       | [handler.go](file:///mnt/e/ide_project/lazy-balancer-v2/caddygeoip/handler.go)、[Dockerfile](file:///mnt/e/ide_project/lazy-balancer-v2/Dockerfile)                                        |
| 前端       | 策略 = 硬编码 strategy-card（非下拉），权重为百分比（和=100），策略白名单在提交校验中重复一份                                                                                | [Rules.vue](file:///mnt/e/ide_project/lazy-balancer-v2/web/src/views/Rules.vue#L592-L641)、[strategyLabels.ts](file:///mnt/e/ide_project/lazy-balancer-v2/web/src/utils/strategyLabels.ts) |

参考项目关键语义（提炼自 `src/balancer/failover.js`、`strategy.js`）：chain 按 order 升序取候选；竞速定时器到点未完成即并行发第二路（第二路按自己的上游独立构造请求）；错误响应不算成功，race 出 null 后需等两路落地复检；慢路 abort 不记故障；仅幂等/已物化 body 可竞速（body 上限 5MB）。

## 三、改动清单

### 3.1 新建 Caddy 模块 `caddychain/`（核心）

新目录 `/mnt/e/ide_project/lazy-balancer-v2/caddychain/`：

* `go.mod`：`module lazy-balancer-v2/caddychain`，`require github.com/caddyserver/caddy/v2 v2.11.6` + `go.uber.org/zap`（仿 caddygeoip/go.mod）。

* `chain.go`：模块注册 `ID: "http.handlers.chain_proxy"`（JSON 键 `"handler": "chain_proxy"`）。

**配置 JSON schema**（由 services/caddy.go 生成）：

```json
{
  "handler": "chain_proxy",
  "upstreams": [
    {"dial": "host:port", "scheme": "http|https", "host": "逐上游最终回源Host，空=用 dial 地址"}
  ],
  "race_interval_ms": 500,
  "request_timeout_ms": 10000,
  "dial_timeout_ms": 5,
  "body_replay_limit_bytes": 5242880,
  "strip_request_headers": ["X-LB-GeoIP-Country", "X-LB-Rule-ID", "...同现有剥离清单"]
}
```

**运行语义（模块内实现）**：

1. **车道编排**：按配置顺序（已按权重降序）启动车道 0；此后当 ① 距上一次发车道已过 `race_interval_ms` 仍无胜者，或 ② 某车道落定且结果为错误/`status>=400` 且还有未发车道 —— 发出下一车道。
2. **胜者判定**：最先返回 `status < 400` 响应头的车道胜出，其响应直接流式写客户端（透传 `http.Flusher`，支持 SSE）。胜者确定后 `context.Cancel` 其余在途车道。
3. **兜底截断**：每车道请求 context 挂 `request_timeout_ms` 超时（仅约束「收到响应头之前」；响应头到达后 body 流不再受此超时，避免误杀大文件/长连接）。超时车道被取消，视为失败车道。
4. **收尾**：全部车道落定为 bad → 写出**最先到达**的 bad 响应（status>=400 原样透传）；全部车道错误 → 502（全部为超时则 504）。
5. **请求体重放**：`len(upstreams)>1` 且方法含 body 时，物化请求体至上限 `body_replay_limit_bytes`（超出 → 退化为仅车道 0 直通，不竞速不重放）。
6. **WebSocket/Upgrade 请求**：不竞速；按链序逐个尝试 hijack 隧道（dial 失败换下一个）。
7. **每车道独立构造请求**：`URL` 按 dial/scheme 重建；`req.Host` = 该上游 `host`（空则 dial 地址）；追加 `X-Forwarded-For`、设置 `X-Forwarded-Proto/Host`；双向剥离 hop-by-hop 头；入口剥离 `strip_request_headers` 清单。
8. **TLS**：`scheme=https` → `InsecureSkipVerify: true`，SNI 取该上游 host 的主机名部分（剥端口），与现有 transport 生成口径一致。
9. **Provision**：构建共享 `http.Transport`（连接池/keepalive）；zap 记录每车道决策日志（车道序号、上游、结果、耗时，Debug 级）。
10. `weight<=0 → 1` 的不变量在生成侧（caddy.go）已保证，模块不重复处理；模块配置不发射 `weights` 键（避开 `caddy_weight_gate_test.go` 的发射权重扫描口径）。

* `chain_test.go`：模块单测（见 §3.6）。

### 3.2 Dockerfile

xcaddy build 行追加 `--with lazy-balancer-v2/caddychain=./caddychain`（[Dockerfile](file:///mnt/e/ide_project/lazy-balancer-v2/Dockerfile) xcaddy-builder 阶段）。版本断言脚本不受影响。

### 3.3 后端模型/校验/持久化

| 文件                                                                                                           | 改动                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [models.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/models/models.go)                            | `LbRule`、`CreateRuleRequest` 增加 `ChainRaceIntervalMS int` / `ChainRequestTimeoutMS int`（json: `chain_race_interval_ms` / `chain_request_timeout_ms`）；`UpdateRuleRequest` 用 `*int`（LB-02 指针化先例：省略=nil=保留原值）                                                                |
| [rule\_features.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/handlers/rule_features.go#L245-L273) | `httpStrategies` map 增加 `"chain_fallback": true`（**tcpStrategies 不加**），错误文案同步；`validateRuleFeatures` 增加参数范围校验：strategy=chain\_fallback 时 `0 <= race_interval <= 60000`、`0 <= request_timeout <= 600000`                                                                   |
| [rules.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/handlers/rules.go)                            | ① CreateRule 默认值（`:806` 附近）：strategy=chain\_fallback 且 race=0 → 500，timeout=0 → 10000；② TCP 兜底归一（`:1331` 附近，cookie→WRR 同款）：TCP 强制 chain\_fallback→weighted\_round\_robin；③ CreateRule/UpdateRule/复制 的 INSERT/UPDATE 列清单加两列（`:953`、`:1669`、`:2506` 附近）；④ UpdateRule nil 合并 |
| [db.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/db/db.go)                                        | `lb_rules` fresh DDL（`:234`）加 `chain_race_interval_ms INTEGER DEFAULT 0`、`chain_request_timeout_ms INTEGER DEFAULT 0`；`newColumns` 迁移清单（`:805` 起）加同两列                                                                                                                     |

**注意**：services 渲染层有自己的 `SingleRuleConfig`/`UpstreamConfig` 类型与 SELECT 列清单（caddy.go `:1348/:2738/:2932` 附近三处读取点）。执行时先 grep `SingleRuleConfig` 定义与 `FROM lb_rules` 的 SELECT，补两列 + 字段 + 默认值兜底（0 值在渲染时兜底为 500/10000，与写侧同口径）。

### 3.4 Caddy 配置生成

[caddy.go](file:///mnt/e/ide_project/lazy-balancer-v2/internal/services/caddy.go#L3728-L3967) `buildHTTPHandleChain` 内，当 `rule.Protocol=="http" && rule.Strategy=="chain_fallback"`：

1. 复制 `enabledUpstreams` 并**稳定排序：Weight 降序**（同权重保持 id/列表顺序；`weight<=0 → 1`）。
2. 逐上游解析最终回源 Host（复用 `resolveUpstreamHostPlan` 的三级回退口径：上游 HostHeader > 规则 HostHeader > 空=用 dial 地址）。
3. 组装 `chain_proxy` handler 配置（§3.1 schema）：`race_interval_ms`/`request_timeout_ms`（0 兜底 500/10000）、`dial_timeout_ms`（取 `resolveProxyTimeouts().dial`，秒）、`strip_request_headers` 用现有 X-LB-\* 剥离清单常量。
4. **跳过** `load_balancing`、`health_checks`、`transport`、`headers`、`lb_upstream_host`、`stream_timeout/flush_interval` 的 reverse\_proxy 专属发射（竞速即可用性机制，健康检查对链式规则不生效；前端健康检查区块保留现状不动，仅渲染忽略）。
5. 该分支仍走原 `handleChain` 组装点（`:3966`），替代 `proxyConfig` 位置；securityChain/静态响应短路/headers(deferred Server 删除) 等链上前置 handler 不变。

### 3.5 前端（web/src）

| 文件                                                                                              | 改动                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [types/rules.ts](file:///mnt/e/ide_project/lazy-balancer-v2/web/src/types/rules.ts)             | `Rule`、`CreateRuleRequest` 加 `chain_race_interval_ms: number`、`chain_request_timeout_ms: number`（UpdateRuleRequest 继承为可选）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| [strategyLabels.ts](file:///mnt/e/ide_project/lazy-balancer-v2/web/src/utils/strategyLabels.ts) | 加 `chain_fallback: '链式回退'`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| [Rules.vue](file:///mnt/e/ide_project/lazy-balancer-v2/web/src/views/Rules.vue)                 | ① 策略卡片区（`:592-628`）加第五张卡 `v-if="wizardForm.protocol === 'http'"`：标题「链式回退」，描述「按上游权重降序组成回退链，等待 X 毫秒无响应即并行发出下一路竞速，先回者胜」；② 选中 chain\_fallback 时在卡片下方显示两个 `el-input-number`：竞速间隔（10–60000ms，默认 500）、单请求兜底超时（100–600000ms，默认 10000），附说明「单个上游超过该时长仍未响应将被截断」；③ 权重列提示（chain 选中时）：「链式回退下权重=优先级，权重越大越先被请求，相同权重按列表顺序」（百分比 UI 与 sum=100 校验保持不变，仅语义提示）；④ 提交白名单（`:2719-2726`）http 数组加 `'chain_fallback'`；⑤ 协议切 TCP 的 watch（`:1985`）把 chain\_fallback 归一为 weighted\_round\_robin；⑥ `submitWizard` payload（`:2764-2839`）带上两字段；⑦ 编辑回填（`:2288` 附近）读取 `fullRule.chain_race_interval_ms/chain_request_timeout_ms`（0 → UI 显示默认值） |

wizardForm 初始值：`chain_race_interval_ms: 500, chain_request_timeout_ms: 10000`。

### 3.6 测试

* `internal/handlers`：chain\_fallback HTTP 创建成功且默认值落库（500/10000）；TCP 规则选 chain\_fallback → 400 或归一 WRR；参数越界 → 400。

* `internal/services`：chain 策略生成 `chain_proxy` handler，上游按权重降序且 `weight<=0→1`、逐上游 host 正确、跳过 reverse\_proxy 专属键；现有 WRR 生成不受影响（回归）。

* `caddychain`（模块内 `go test`）：① 车道 0 慢、车道 1 快 → 胜者 200 直达且车道 0 被 cancel；② 车道 0 返回 502 → 立即发车道 1，车道 1 200 胜出；③ 全部车道 4xx/5xx → 透传最先到达的 bad 响应；④ 全部超时 → 504；⑤ body 重放（POST + buffer 内）双路都收到相同 body；⑥ body 超上限 → 不竞速仅车道 0；⑦ 逐上游 Host/XFF/hop-by-hop 剥离；⑧ race\_interval 未到且车道 0 已返回 200 → 不发第二路。

### 3.7 备份/集群同步核查（只查不改为主）

grep 确认 `config_backup`、`cluster_sections`/`cluster_snapshot`、`config_import_v1` 中 lb\_rules 的列清单是否显式列出；凡显式列清单处补两列（恢复/同步/导入链保持同构）。`config_import_v1` 的未知策略归一逻辑确认 chain\_fallback 不受影响（它只归一 v1 的 `round_robin_custom`/未知值）。

## 四、假设与决策记录

1. **真竞速由自定义 Caddy 模块实现**（用户已确认）；Caddy 原生 `try_duration` 重试是串行语义，不采用。
2. **仅 HTTP 规则**（用户已确认）；TCP 白名单不含 chain\_fallback，双保险（校验 + 落库归一）。
3. **优先级 = 权重降序**，同权重按列表顺序；权重百分比 UI（和=100）保持不变，仅含义提示变化。
4. 「没收到回复」定义为**未收到响应头**；响应头后 body 流不受兜底超时约束（护住大文件/SSE/长连接）。
5. **可重试状态码 = status>=400**（对齐参考项目 `retryOn: 4xx5xx`）；网络错误/超时恒为失败。
6. 全部车道落定 bad 时返回**最先到达**的 bad 响应（最低客户端延迟）。
7. race\_interval=0 落库含义 = 用户未改默认 → 写侧兜底 500ms（UI 不提供 0=关闭；参考项目 speculativeMs=0 关闭的语义不引入，避免配置分叉）。
8. 单启用上游（含 DynamicDNS 规则）→ 链退化直通，合法但无竞速。
9. 链式规则不发射健康检查/transport/headers 配置（竞速即可用性机制），DB 健康检查字段保留但渲染忽略。

## 五、执行顺序与验证

1. `caddychain` 模块 + 单测 → `cd caddychain && go build ./... && go test ./...`（模块缓存已有 caddy v2.11.6，caddygeoip 同法可解）。
2. models/db/rules/rule\_features 改造 → `go build ./... && go test ./internal/...`。
3. services/caddy.go 生成分支 + 测试 → 同上。
4. Dockerfile `--with` 挂载（语法核查即可，完整构建走 Docker）。
5. 前端改动 → `cd web && npm run build`（含 vue-tsc 类型检查）。
6. 备份/集群列清单核查补齐 → 跑 `go test ./internal/...` 全量。
7. 手工验收路径（可选，需运行环境）：创建 chain 规则（两上游，上游1 指向不可达端口）→ curl 观察：上游1 立即失败 → 立即打上游2；上游1 为慢端点 → race\_interval 到点并行竞速。

