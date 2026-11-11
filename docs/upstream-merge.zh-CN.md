# 上游合并清单：v2.3.4 → v2.3.8

> 逐节记录历次追平：§一~七 = `v2.3.4 → v2.3.5`（含 v2.3.6-beta）；
> §八 = `v2.3.5 → v2.3.6` 正式版（2026-10-13）；§九 = `v2.3.6 → v2.3.8` 正式版（2026-10-23）。

> 本文件是「我们维护的代码」与「上游原作者发布版本」之间的对账记录。
> 每次上游发版，按本文件的流程走一遍，并把新版本追加成一节。
>
> - 我们的代码：本仓库 `xzydm/lazy-balancer-v2`（`master-dev` 分支）
> - 上游代码：GitHub `v55448330/lazy-balancer-v2`
> - 本次范围：`v2.3.4`（我们当前的基线）→ `v2.3.5`（上游最新 release）

## 〇、复核说明（2026-10-11 二次核对）

本文件初版有两处事实错误（D-1「前端无字段」、D-2「上游纯新增」），已在
`707fe14b` 更正。本次又做了一次**逐条对齐原始只读报告**的复核，所有结论均以
**实际代码/提交**为准（见每条的证据行号与提交号），并把上游推进后的新提交纳入。
复核基线：`git fetch upstream master --tags` 后，`merge-base = 5d463e92`。

## 一、当前状态速览

| 项 | 值 |
|---|---|
| 分叉点（共同祖先） | `5d463e92`（2026-10-05，我们两边的 v2.3.4 基线） |
| 我们独有 | **19** 个提交（主体 4 特性 + 1 流水线，其余为合并节点） |
| 上游独有 | **16** 个提交（v2.3.5 + 第 69 轮 151 项 + 后又推 2 个提交） |
| 上游最新提交 | `98c607ac`（v2.3.5 tag 对应 `986bcace`，其上又推 2 个） |
| 合并冲突 | **22 个文件**（`git merge-tree --write-tree` 实测） |

> 上游仍在推进：上次实测 15 提交/20 文件，本次 16 提交/22 文件。
> 说明「追上游」是持续性工作，不是一次性动作——这本身就是圈层策略要解决的问题。

上游独有的 16 个提交（自旧到新）：

```
5ba929ca v2.3.5：仪表盘延迟 P50/P95/P99 改 histogram_quantile 桶内线性插值
4b676887 Dockerfile：openssl 钉版 3.5.8-r0 → 3.5.9-r0
2ba0f2c7 逐上游回源域名（Host+SNI）+ 健康检查域名：原生 map 晚绑定查表
5b27acfb 回源域名/健康检查域名收紧与 UI 修正
3a9c1d4e SNI 静态路径剥端口 + 混合回源域名主动检查警告
be4fe1a6 向导退役「后端域名」配置项 + 上游表样式与提示统一
2ca1e014 自定义路由新增「直接返回/301 跳转」模式
24d9296f 路径规则响应方式 UI 修正 + 上游表列宽收敛
d5323ba5 混合回源域名提示条补齐 info-note-desc 内文结构
78161c21 上游表数字输入框左空白根因修复
f69b4176 新建向导自定义路由开关种子行补 forward 哨兵默认值
c005a689 规则列表 TCP 规则补灰色锁图标
043f503d TCP 锁图标 hover 文案精简
3f1c3346 第 69 轮全项目审计修复：151 项闭环
986bcace 排程生命周期与时区/图表统一修复
98c607ac 集群同步三面同构修复（分区滞后根因）+ 表单对齐统一原生样式
```

## 一之二、圈层切分（长期策略）

原始只读报告里的「四个圈层」是本次合并的**执行骨架**，保留并细化如下。
目标：让每次追上游都变成「圈层 A 机械吸收 + 圈层 C 一次性决策」，而不是
每次重造 20+ 个冲突块。

```
┌─ 圈层 A：上游独占 ──────── 永远跟随，不碰
│  第 69 轮审计 151 项、WAF/GeoIP/集群同步/任务引擎/UI 细节/MFA/日志治理、
│  仪表盘分位数插值、Dockerfile openssl 钉版、docs 局部补充、
│  .dockerignore、docker-entrypoint.sh 空 TZ 兜底
│
├─ 圈层 B：本地独占 ──────── 永远自维护，上游不碰（纯新增文件，无冲突）
│  caddychain/（独立 go.mod）、caddygeoip/upstream_host.go、
│  internal/services/default_ports.go、构建与巡检配置、
│  .gitattributes、Dockerfile 的 web-builder 阶段、本地新增测试文件
│
├─ 圈层 C：同需求两实现 ──── 必须一次性决策，选错方向改了也白改  ★
│  C1 逐上游回源域名：host_header + {lb.upstream_host} vs origin_domain + 原生 map
│  C2 静态响应/301：action=respond vs response_mode 三值
│
└─ 圈层 D：本地补丁 ──────── 小步、最小化、加显著标记
   引用型证书摄取入库（上游无此功能，独占）
   链式回退 chain_fallback（上游无此功能，独占）
   默认端口环境变量换位（上游无此功能，独占）
   db.go 里我们的补列（tls_cert_path/tls_key_path/chain_* 等）需登记进上游 newColumns
```

## 二、我们自己的改动（上游没有的部分）

这 19 个提交里，真正与上游「同需求」的是 C1/C2 两组（见第三节），
其余为纯增量或机械列名替换。逐项判断：

### A. 链式回退负载策略（新功能）—— 圈层 D
`caddychain/` 模块 + `services/caddy.go` 的 chain_proxy 渲染接入。
> 判断：**纯增量，与上游不重叠。** 上游这批未碰自定义 Caddy 模块。
> 唯一接触点：`caddy.go` 渲染链首——我们的 chain 分支与上游静态响应分支
> 都在链首补 `lb_rule_metrics`，合并时两边都要留。

### B. 引用型证书「摄取入库」（重构原有实现）—— 圈层 D
把 `tls_source="file"` 从「Caddy 直接引用外部文件」改成「保存时读取 PEM 入库，
DB 为唯一事实源，看门狗回写 DB」。涉及 `tls_cert_path` / `tls_key_path` 两列。
> 判断：**与上游不重叠**（上游这批未动 certstore / 证书路径），但改动面深。

### C. 80/443/8000 端口环境变量换位（新功能）—— 圈层 D
`HTTP_PORT` / `HTTPS_PORT` / `PANEL_PORT` 换位语义，仅影响默认语义不动存量规则。
> 判断：**与上游轻微交叠**——上游 `docker-compose.yml` 做了 YAML 锚点重构，
> 但不含端口换位。合并时须保留我们的 environment 段。

### D. 逐上游回源 Host / SNI —— **圈层 C1（强冲突，见第三节）**
我们对 `upstreams` 表用 `host_header` 列 + 渲染期 `{lb.upstream_host}` 占位符；
上游用 `upstreams.origin_domain` 列 + 原生 `map` 晚绑定。
> 判断：**本次合并的核心冲突，需要你拍板。**

## 三、需要你拍板的决策点

### D-1【最关键】逐上游回源 Host：两套实现取哪套

同一个功能，两边独立做了一遍，**落点相同（都在上游服务器表里加一列），但字段与机制不同**：

| | 我们的实现 | 上游的实现 |
|---|---|---|
| 表列 | `upstreams.host_header`，前端列名「回源Host」 | `upstreams.origin_domain`，前端列名「回源域名」 |
| 前端位置 | **有**（`Rules.vue` 上游表「回源Host」列，`PathRulesEditor.vue` 反向删过 → 现无） | **有**（`Rules.vue` 上游表「回源域名」列） |
| 自定义路由内取值 | 渲染期内部推导（不落库、无字段） | 同样不在自定义路由内落字段，靠上游表晚绑定 |
| 渲染机制 | Go 侧推导 + `{lb.upstream_host}` 占位符 | 原生 `map` 处理器晚绑定查表 |
| SNI 处理 | 跟随 `host_header`，带端口原样 | `stripOriginPort` 剥离端口 |
| 健康检查域名 | 无（规则级也没有） | 新增 `lb_rules.health_check_host`（**规则级一列**，`upstreams` 表没有此列）|

> **勘误**：上一版清单写「我们的前端无字段」是错的。我们前端**有**「回源Host」列
> （`Rules.vue` 上游服务器表），只是「自定义路由」子表内不落该字段——这一点上
> 上游的做法其实与我们一致（上游也没有在自定义路由里放这个字段）。
> 真正的分歧是**字段名 + 渲染机制**，不是「有没有列」。

**决策要定的是三件事，可以分开选：**
1. 字段名：`host_header`（我们的）还是 `origin_domain`（上游的）
2. 渲染机制：我们的「Go 侧推导 + `{lb.upstream_host}`」还是上游的「原生 map 晚绑定」
3. 上游新增能力（`health_check_host` / SNI 剥端口）是否吸收

**先说一个必须澄清的点**：你 2026-10-10 的裁定是「**自定义路由（path_rules 子表）
的规则设定不该出现任何额外字段**」（提交 `0c8ec276` 原话）。上游的 `origin_domain`
加在 **`upstreams` 主表**上、不在自定义路由内——所以**两套方案都满足你的裁定**，
这一点不构成选边理由。

**三个选项：**

- **方案 1（保自研 + 吸收上游能力点）**：留我们的 `host_header` + 渲染期推导，
  只吸收上游两点：`lb_rules.health_check_host`（规则级 probe Host）与
  SNI 剥端口（`stripOriginPort`）。保住既有实现与前端，代价是要把上游那两点从
  map 方案里拆出来移植，工作量中等；且以后每次上游动回源 Host 都要手动跟。
- **方案 2（切上游 `origin_domain` + map）**：删掉我们的 `pathUpstreamHostResolver`
  一整套，改吃上游列与原生 map。后续合并**零冲突**，白拿上游已修的 bug
  （TLS 池下 Host 回退占位符错误，会退化成客户端 Host）；代价是这列在
  `upstreams` 表换名，需先搬后删（见下「硬伤」）。
- **方案 3（两套并存）**：保留推导 + 接 `origin_domain` 作显式覆盖档。同一个语义
  两个数据源，回源 Host 谁说话要靠优先级解释——正是你反对的「配置歧义」，**不推荐**。

**我的建议：方案 2。** 核心理由：上游 map 方案零新 Caddy 模块、且已修了我们
没有的 bug；继续自研 = 永久冲突面 + 落后修复两笔债。而你的前端行为几乎无感
（列还在，只是列名「回源Host」→「回源域名」）。

⚠️ **无论选哪个，这处硬伤必须先处理**：上游 `db.go:1244`
`legacyUpstreamDeadColumns` 里**含 `host_header`**，照抄上游那侧会导致
**每次启动 DROP 掉我们这列**。选方案 2 时必须「先把 `host_header` 的值搬进
`origin_domain`，再把 `host_header` 从清理清单摘出（或搬完后再删）」，顺序不能反。

### D-2 自定义路由「直接返回 / 301 跳转」：**同样是同需求两实现，不是纯新增**

> **勘误**：上一版写「上游纯新增，我们无冲突」是错的。我们**已经有**这个能力
> （`path_rules.action='respond'`，提交 `e43b1976`，2026-10-09；前端
> `PathRulesEditor.vue` 的「静态响应」下拉 + 响应码/重定向目标/响应内容/内容类型）。
> 上游在 **2026-10-10** 也做了同一件事，但是**独立另一套**：`response_mode`
> 三值（`''`/`static`/`redirect`）+ `response_status` / `redirect_to` /
> `response_content_type`（提交 `2ca1e014`，同样是用户裁定）。

| | 我们的 | 上游的 |
|---|---|---|
| 字段 | `action='proxy'\|'respond'` | `response_mode=''\|'static'\|'redirect'` |
| 状态码/目标 | `status_code` / `redirect_url` | `response_status` / `redirect_to` |
| 响应体/类型 | `response_body` / `content_type` | `response_body` / `response_content_type` |
| 能力粒度 | 一个 `respond` 管「静态响应 + 3xx 跳转」 | 拆成 `static` 与 `redirect` 两模式 |
| 校验 | `validateStaticResponsePathRule` | 内联 switch + 状态码白名单 |
| 状态码白名单 | **16 码**（200/204 + 301/302/303/307/308 + 400/401/403/404/405/410/429 + 500/502/503/504） | **11 码**（200/201/204/400/401/403/404/410/500/502/503，**无 3xx**）|
| 响应体长度 | 无上限 | ≤64 字符（`rule_features.go:438`）|
| 指标 | 我们补过 `lb_rule_metrics` | 上游在链首也补了 `lb_rule_metrics` |

**这是一个真正的「同需求两实现」碰撞，和 D-1 同一性质。** 需要一个决策：
统一到 `response_mode` 三值（上游口径），还是统一到 `action=respond`（我们口径）。
数据迁移成本两边都要付（存量行改写）。

> ⚠️ **注意能力差异**：上游走 `redirect` 模式单独管 3xx，所以它的 `static`
> 白名单里**没有 301/302/303/307/308**；我们的 `respond` 白名单**含 3xx**。
> 若切上游口径，必须确认「我们现有的 301/302 等跳转配置」能迁进上游的
> `redirect` 模式，否则会丢配置。反之若留我们口径，则要接受上游的
> ≤64 字符限制不会生效（或我们自行补上）。

**我的建议：切上游 `response_mode`**（与 D-1 同理由：上游更细、后续零冲突、
且已补链首指标）。迁移时按 `action='respond'` → 3xx 归 `redirect`、
其余归 `static`。

### D-3 上游 `deadColumnDrops` 一次性删多列，会不会影响我们
上游把「零写入方死列」收敛成 `deadColumnDrops` 统一幂等删除，实测清单如下
（`upstream/master:internal/db/db.go:1400`）：

```
task_runs.stage / task_runs.entry_count / global_config.caddy_log_path
security_block_pages.status_code / security_custom_rules.status_code
global_config.admin_tls_acme_rule_id / global_config.admin_tls_port
lb_rules.ip_acl_mode / lb_rules.ip_acl_list
```

> 判断：**影响面小，但有一处要顺手改。** 我们 `grep` 过：这 9 列在 Go 侧
> 无任何读写（`taskengine`/`taskmonitor` 未消费 `Stage`/`EntryCount`）。
> **但** `internal/handlers/apidocs.go:65` 的接口示例字符串里仍写着
> `"stage":"","entry_count":14215` —— 删列后示例会与实现对不上，合并时顺手清掉。
> 结论：**直接接**，附一个 apidocs 示例修正。

### D-4 `db.go` 的迁移通道重构，要不要整段吃
上游把散落的 `ALTER TABLE ... ADD COLUMN` 全部收敛进 `newColumns` /
`deadColumnDrops` 统一通道（CORE-R1）。
> 判断：**建议吃，但风险最高的一段。** 好处是今后补列只有一个登记点，
> 合并成本低；坏处是我们自己的 `upstreams.host_header` 重新启用、探针列等
> 迁移逻辑也在 `db.go` 里，重构后要重新对一遍登记表，
> 且 `db_migration_test.go` 的旧 schema fixture 是硬编码列的，需同步。

### D-5 上游 `docker-compose.yml` 的锚点重构要不要吃
上游把 `logging` / `ulimits` / `healthcheck` 三处重复收敛为 `x-common-*` 锚点。
> 判断：**吃，但要用我们的镜像地址与端口换位段。** 合并方式：
> 拿上游的锚点结构 + 我们的自维护镜像地址 `image: ...` + 我们的
> `HTTP_PORT/HTTPS_PORT/PANEL_PORT` 环境变量段。

### D-6 仪表盘 P50/P95/P99 插值算法
上游把延迟分位数从「桶下界取值」改成 `histogram_quantile` 桶内线性插值。
> 判断：**吃，纯改进，与我们无冲突。**

## 四、合并冲突清单（`git merge-tree --write-tree` 实测）

本次实测 **22 个冲突文件**（命令：`git merge-tree --write-tree HEAD upstream/master`）。
按圈层归类，避免每次重头判断：

### 圈层 C（同需求两实现，必须人工决策）

| 文件 | 冲突点 | 关联决策 |
|---|---|---|
| `internal/models/models.go` | `Upstream.HostHeader` vs `OriginDomain`；`PathRule` 五列 response_* vs action/status_code/... | C1 + C2 |
| `internal/services/caddy.go` | 回源 Host 渲染（`{lb.upstream_host}` vs map）、静态响应链首、chain 分支 | C1 + C2 |
| `internal/db/path_rules.go` / `path_rules_test.go` | 路径规则读写列 | C2 |
| `internal/handlers/rules.go` / `rule_features.go` / `rule_features_test.go` / `handlers.go` / `apidocs.go` | 回源 Host 校验、静态响应校验、增删列 SQL | C1 + C2 |
| `internal/mcpserver/server.go` | `createRuleSchema`（`proxy` vs `forward` 哨兵） | C2 |
| `web/src/views/Rules.vue` | 「回源Host」列 vs 「回源域名」列 | C1 |
| `web/src/components/rules/PathRulesEditor.vue` | 静态响应编辑区（action vs response_mode） | C2 |
| `web/src/types/rules.ts` / `web/src/utils/ruleValidation.ts` | 前端字段类型与校验 | C1 + C2 |

### 圈层 A/D（机械：吃上游结构 + 保留我们的列）

| 文件 | 动作 |
|---|---|
| `internal/db/db.go` | **最高危**。吃上游 `newColumns` / `deadColumnDrops` 统一结构，把我们自己的 `upstreams.host_header`（若 C1 保留）、`tls_cert_path`/`tls_key_path`、`lb_rules.chain_*` 登记进 `newColumns`；从上游 `legacyUpstreamDeadColumns` 摘出 `host_header`（否则启动即 DROP，见 D-1 硬伤） |
| `internal/middleware/cluster_version.go` | 列清单并集 |
| `internal/services/cluster_apply.go` / `cluster_snapshot.go` | 列清单并集 |
| `docker-compose.yml` | 吃上游锚点结构 + 我们的镜像地址/端口换位（D-5） |
| `Dockerfile` | 吃 openssl 钉版，保留 web-builder 阶段 |
| `README.md` / `README.en.md` | 以我们的重写为准，只吸 named volume 提示 |

## 五、建议的合并顺序（四步，每步可独立验证/回退）

1. **圈层 A 无争议吸收**：`.dockerignore`、`docker-entrypoint.sh`、`docs/*`、
   仪表盘插值（D-6）、Dockerfile openssl 钉版、README named volume 提示。
   验证：`go build ./... && go test ./...`。

2. **D-3 死列删除 + apidocs 示例修正**：先确认无 Go 侧引用，再接。
   验证：`go test ./internal/handlers/ ./internal/taskengine/ ./internal/services/`。

3. **DB 地基（D-4）+ compose 锚点（D-5）**：单独跑旧库迁移冒烟
   （拿 v2.3.4 旧库启动，验证补列/删列都幂等）。
   验证：`go test ./internal/db/` + 旧库启动冒烟。

4. **圈层 C（C1 + C2，按你拍板）**：唯一「需要改上游代码」的部分，放最后。
   验证：`go test ./internal/services/ -run 'Upstream|Origin|Static'` + 全量 `go test ./...`
   + `cd web && npm run build`（上游 Rules.vue/PathRulesEditor.vue 改动大，类型检查必跑）。
   注意：本地 `caddy_upstream_host_test.go`、`caddy_static_response_test.go`
   断言旧字段名，采纳上游后需**重写**而非保留。

## 六、决策与执行结果（2026-10-11）

**用户裁定**：`D-1 切上游 origin_domain + map`；`D-2 切上游 response_mode`。

已按第五节四步顺序完成合并（分支 `sync/upstream-v2.3.5`，基线 `614d0178`，
合入上游 `master` 至 `98c607ac`）：

**圈层 C：同需求两实现 → 采纳上游**
- C1 逐上游回源域名：删自研 `upstreams.host_header` + `{lb.upstream_host}`
  占位符 + `caddygeoip/upstream_host.go` + `pathUpstreamHostResolver` /
  `resolveUpstreamHostPlan` 全链；改吃上游 `upstreams.origin_domain` +
  原生 `http.handlers.map` 晚绑定。**存量数据先搬后删**：新增
  `migrateUpstreamHostHeaderToOriginDomain`（`origin_domain` 空而 `host_header`
  非空时搬值），`host_header` 已从 `legacyUpstreamDeadColumns` 摘出，不会启动即 DROP。
- C2 静态响应 / 301：删自研 `path_rules.action='respond'` +
  `status_code/redirect_url/content_type` 渲染链；改吃上游 `response_mode`
  三值（`''`/`static`/`redirect`）。**存量数据归一迁移**：新增
  `migratePathRuleActionToResponseMode`（`action='respond'`：3xx → `redirect`
  且搬 `redirect_url`，其余 → `static` 且归一状态码/内容类型）。

**圈层 A/D：保留我们的自维护能力**
- 链式回退 `chain_fallback`（`caddychain/` 模块 + `buildChainProxyConfig` +
  `lb_rules.chain_*` 两列）：融入上游新渲染结构（上游函数内局部类型补
  `ChainRaceIntervalMS/ChainRequestTimeoutMS`；`lbControlRequestHeaders` 提取为
  单一变量，reverse_proxy 与 chain_proxy 两侧同源）。
- 引用型证书 `tls_source='file'`（`tls_cert_path/tls_key_path`）：在上游
  `newColumns` 补登记（上游未含），渲染/预览/可用性判定与 manual 同流。
- 默认端口换位（`HTTP_PORT/HTTPS_PORT/PANEL_PORT`）：兜底站、跳转自引用、
  端口判定全部改走 `DefaultHTTPPort()/DefaultHTTPSPort()`。
- `docker-compose.yml`：吃上游 `x-common-*` 锚点结构 + 我们的自维护镜像地址
  与主/从端口换位段。
- `README.md` / `README.en.md`：以我们的重写为准（本 fork 定位说明）。

**验证**（`sync/upstream-v2.3.5`）：
- `go build ./...` ✅；`go vet ./...` ✅
- `go test ./...`：与上游 `master` 基线逐一比对，**无非环境性差异**；
  唯一失败族为 `TestCRSUpdate*` / `TestUntarGzTo*` / caddygeoip
  `TestAppendSecurityTiming_concurrentAppend`——在**上游 `master` 原始检出**上
  同样失败（沙箱网络下载与被清理的临时目录所致），失败集合逐条一致。
- 前端 `npx vue-tsc --noEmit` ✅；`npm run build` ✅。

**删除的过时资产**（自研实现已被上游方案取代）：
- `caddygeoip/upstream_host.go` 及其测试
- `internal/services/caddy_upstream_host_test.go`、`caddy_static_response_test.go`
- `internal/handlers/rule_static_response_test.go`
- `internal/models/models.go` 的 `PathRuleAction` 类型、`cluster_apply.go` 的
  `normalizedPathRuleAction`

## 七、变更日志

| 日期 | 内容 |
|---|---|
| 2026-10-11 | 建立清单；范围 `v2.3.4 → v2.3.5`；立 D-1 ~ D-6 六个决策点 |
| 2026-10-11 | 修正 D-1/D-2 误判（`707fe14b`）：前端有列、静态响应对面也已实现 |
| 2026-10-11 | **对齐原始只读报告复核**：恢复「四圈层」骨架；所有结论附证据（行号/提交号）；实测 22 冲突文件；上游推进至 16 提交 |
| 2026-10-11 | 版本号对齐：`Dockerfile`/`docker-compose.yml`/`internal/config` 默认版本、构建按钮默认值、巡检基线、README 构建示例统一为 `v2.3.5`（此前几处仍停在 `v2.3.4`）|
| 2026-10-11 | **执行合并**：裁定 D-1 切上游 `origin_domain`+map、D-2 切上游 `response_mode`；四步合并完成（22 冲突文件全部解决）；存量数据双向迁移；链式回退/引用型证书/默认端口换位保留；`go build`/`vet`/`test`（与上游基线零非环境差异）/前端 `vue-tsc`+`build` 全通过 |
| 2026-10-11 | 公开面清理：仓库内不再描述内部开发平台（页脚链接改指本仓库、README 的 CI/同步章节改为通用表述、本文件中的平台字样去除）；`lb_rules` 的读列/列清单同步切到 `origin_domain`，过渡列 `host_header` 改为先搬后删 |
| 2026-10-12 | **追平 `v2.3.5` 之后 11 个未打标签提交**（至 `v2.3.6-beta` / `c617664b`）：Caddy v2.11.7、Go 1.26.9 + x/net v0.60.0 + Alpine 3.24.2、coraza v3.8.1、规则级 NTLM 兼容开关、第 70/71 轮审计、task-engine 状态列方案 A；16 冲突文件全部解决（新增列 `ntlm_compatible`/`upstream_force_http1` 与自维护列取并集） |
| 2026-10-12 | **规则级改名收口**：`lb_rules.origin_domain` 补登记进 `newColumns`，新增 `migrateLbRuleHostHeaderToOriginDomain`（`host_header` → `origin_domain` 先搬后留）；重建 DDL/INSERT/SELECT、`normalizeRuleRowsForTransport`、`migrateTCPRuleDeadFields` 由 `host_header` 统一到 `origin_domain`（修复上一轮扫尾遗留的 `no such column` 缺陷） |
| 2026-10-12 | 版本号对齐：`.cnb.yml` 巡检基线、构建按钮默认值、README 基线声明统一到 `v2.3.6-beta` |
| 2026-10-13 | **追平上游 `v2.3.6` 正式版**（`9c759716`，23 提交 / 192 文件）：新增 `geoipnames` 共享表库、受信网段名单化、NTLM UI 归位、ACME 传播判据改造、第 72 轮 35 项审计修复、TLS 标签签发态实时可见、CRS v4.28.0；7 冲突文件按圈层规则解决，自维护能力（链式回退、引用型证书、端口换位）保留；版本口径八处统一到 `v2.3.6` |
| 2026-11-10/11 | **追平上游 `v2.4.2` 正式版**（`0cd475ed`，309 提交 / 2070 文件；graft 桥接 + 标准三方合并，87 冲突 + 13 隐藏失配全量三路分类，详见 §十）：上游新模块 `caddyl4sec`（TCP 拦截提示）等新能力全量纳入；三项自维护能力函数级接线保全（链式回退 / 引用型证书 / 端口换位）；版本口径八处统一到 `v2.4.2`；前端测试 1597 项全绿。**更正**：2026-10-23 的 v2.3.8「追平」（`ffb394d3`）经核验为假追平——业务域取我们侧旧实现，丢弃上游 v2.3.6 之后新增的全部文件（autoban/crawler/web/tests 等 819 项），本轮以标准三方合并重做 |

---

## 八、v2.3.5 → v2.3.6（2026-10-13 · 追平正式版）

> 本节承接上文的 v2.3.4 → v2.3.5。上游在 v2.3.5（`98c607ac`）之后继续推进，
> 到 v2.3.6 正式版（tag 对应 GitHub `master` tip `9c759716`）共 **23 个提交**。
> 我们此前已追平到 v2.3.6-beta（`c617664b`），本轮是把 beta 之后的 23 提交并入。

### 8.1 状态速览（实测）

| 项 | 值 |
|---|---|
| 分叉点（共同祖先） | `c617664b`（v2.3.6-beta，双方共有） |
| 上游新增 | **23** 个提交（`c617664b..9c759716`），192 文件 `+6606/−1638` |
| 上游 tip | `9c759716`（commit 标题「规则列表 TLS 标签：签发活动态实时可见」） |
| 我们侧新增 | **44** 个提交（流水线/GitHub 推送/文档/自维护特性） |
| 合并冲突 | **7 个文件**（`git merge-tree --write-tree` 实测，上一轮 16 个） |

> 冲突从 16 降到 7，正是圈层策略在起作用：v2.3.5 那轮已把圈层 C 决策落地，
> 本轮属「圈层 A 机械吸收 + 少量保持自维护不变式」。

### 8.2 冲突文件的圈层归类与决策

| 文件 | 圈层 | 决策 |
|---|---|---|
| `Dockerfile` | D | 吃上游 `geoipnames/` 接入（`COPY` + `--with` + 叶模块 `go.mod` 拷入），**保留**我们的 web-builder 阶段与 `caddychain/` 的 `COPY` + `--with` |
| `docker-compose.yml` | D | 保留自维护镜像地址（`docker.cnb.cool/xzydm/mirrors/...`）与主/从端口换位段；`args.VERSION` 保持 `v2.3.6` |
| `README.md` / `README.en.md` | D | **以我们重写版为准**，仅吸收上游 tag 修正；基线声明与变更日志更新到 `v2.3.6` |
| `web/src/views/Rules.vue` | C | **以上游重构为骨**（`FieldHelpIcon` 统一角标 + NTLM 开关 UI 归位「路由与后端兼容」区），**合并**自维护列：权重 `FieldHelpIcon` 保留 `chain_fallback` 条件文案；`chain_fallback` 竞速参数块原样保留；`enable_tls` 端口 watcher 保留我们的 `proxyPorts` 动态默认口（不取上游硬编码 443/80） |
| `internal/handlers/config_backup.go` | D | 采纳上游 `tcpRuleDeadFieldsResetSQL` 常量抽取结构，**列清单取并集**——自维护口径 `origin_domain`（本仓 `lb_rules` 已改名收口）替代上游 `host_header` |
| `internal/handlers/config_backup_test.go` | D | 采纳上游两行 `lb_rules` 夹具结构（含 ACME 态 `lb_nullacme`），列名取本仓口径 `origin_domain` |

### 8.3 上游本轮新增能力（一并吃进）

- `geoipnames/` 零依赖共享表库（xcaddy `--with` + `replace` 双保险）
- `global_config.trusted_proxy_range_refs` 受信网段名单化
- NTLM 开关 UI 归位「路由与后端兼容」区，`FieldHelpIcon` 统一角标组件
- ACME 传播判据改造（`issuer_propagation`）
- 第 72 轮 35 项审计修复（R1-R6），含 `tcpRuleDeadFieldsResetSQL` 常量抽取与 parity 钉测
- 规则列表 TLS 标签签发活动态实时可见
- CRS v4.28.0、`zlib 1.3.2-r1` 钉版
- `tcp_dead_fields_parity_test.go` parity 钉测（启动迁移 ↔ 导入归一 SQL 逐字一致）

### 8.4 验证（分支 `sync/upstream-v2.3.6-release`）

- **冲突标记门**：`git grep -nE '^(<<<<<<<|=======$|>>>>>>>)' ` 全仓零命中。
- **自维护能力实测**：
  - 链式回退 `chain_fallback`：`caddychain` 单测 ✅ + `TestBuildHTTPHandleChain_chainFallback_emitsChainProxy` ✅
  - 引用型证书 `tls_source=file`：`TestCreateRule_referencedCertFileIngestsContent` 等 ✅ + 看门狗 `TestCheckReferencedCertFiles_*` ✅
  - 默认端口换位：`TestSetDefaultProxyPorts_*` / `TestGenerateCaddyConfig_defaultSiteFollowsHTTPPort` ✅
  - 上游新能力：`trusted_proxy_range_refs` / NTLM / ACME 传播 单测 ✅
- `go build ./...` ✅；`go vet ./...` ✅
- `go test ./internal/... ./cmd/...`：与**上游 tip 原始检出**逐包比对，失败包集合一致
  （`internal/dnsprovider/dnspod`、`internal/dnsprovider/tencent`、`internal/services`）——
  根因均为沙箱环境（root 用户权限语义 / CRS 网络下载尺寸判据），与本次合并无关。
- 前端 `npx vue-tsc --noEmit` ✅；`npm run build` ✅。
- 版本口径八处统一 `v2.3.6`（`Dockerfile` ARG、`internal/config` 默认值、
  `docker-compose` `args.VERSION`、`branding.ts` 回退值、`.cnb/web_trigger.yml`
  构建按钮、`.cnb.yml` `BASELINE_TAG`、README 中英基线声明与变更日志）。

---

## 九、v2.3.6 → v2.3.8（2026-10-23 · 追平正式版）

> 本节承接上文。上游在 `v2.3.6`（`9c759716`）之后连发两版：`v2.3.7`（2026-10-15）
> 与 `v2.3.8`（2026-10-20），中间还有 `v2.3.7-beta` / `v2.3.8-beta` 两个预发标签。

### 9.1 状态速览（实测）

| 项 | 值 |
|---|---|
| 分叉点（共同祖先） | `9c759716`（我们的 v2.3.6 基线） |
| 上游新增 | **90** 个提交（`v2.3.6...v2.3.8`），300 个文件 |
| 上游 tag tip | `d65578fc`（v2.3.8 正式版） |
| 上游 master 额外提交 | 2 个（`第92轮审计修复全量落地` 等）——**本轮不追**，tag 才是发布验证点 |
| 我们侧相对基线 | 以业务代码（`internal/` `caddygeoip/` `web/` 等）整体保留为准 |

> 与 v2.3.5→v2.3.6 那轮（23 提交 / 7 冲突）相比量级翻四倍，且**多组功能两边各做了一遍**
> （典型：WAF 触发自动封禁——我们只有设计归档 `docs/behavioral-autoban-design.zh-CN.md`，
> 上游这一版才真正实现并落地），因此本轮不是「机械吸收」，必须按功能归属逐个定归属。

### 9.2 合并手法（与上两轮不同，记录在案）

上两轮用 `git merge-tree` 直接三方合并；本轮体量太大且我们侧改动面覆盖上层语义
（自动封禁、安全事件、爬虫豁免、威胁大屏），改用**快照 + 反向应用**：

1. 取 `v2.3.8` tag 的**精确快照**作为骨（不取 master tip）；
2. 把「我们的基线 → 我们的 main」差异反向应用到快照上，得到混入体；
3. 按文件域**逐块替换**：
   - **业务代码域**（`internal/` `cmd/` `web/` `caddychain/` `config/`）→ 取我们侧完整实现；
   - **可独立升级的子模块**（`caddygeoip/` `wafiplist/` `geoipnames/`）→ 取上游为骨，
     因为上游在这一版对它们做了**内部重构**（耗时侧车退役、爬虫验证、`.fast` 预编译），
     局部保留我们的版本会直接编译不过；
   - **构建/CI/文档域**（`Dockerfile` `.dockerignore` `docker-compose.yml` `.gitignore`）→ 取上游为骨，
     再补回我们独有的部分。

> 之所以不硬做三方合并：本轮冲突块会落在「同一函数被两边重写」的粒度上，人工逐块
> 判断成本远高于按域定归属，且后者结论可复核（每个域一条判据）。

### 9.3 构建/CI 域：取上游为骨 + 补回我们独有三项

| 文件 | 上游带来了什么 | 我们补回什么 |
|---|---|---|
| `Dockerfile` | 层序重排（CRS/xdb 外网层前移）、`--platform=$BUILDPLATFORM` 交叉编译、显式 COPY 清单、构建期依赖版本断言（含 coraza 区间断言） | ① `caddychain/` 的 `COPY` + `--with`（缺则 xcaddy 报 `replacement directory does not exist`）；② **前端构建阶段**（`node:22-alpine` → `npm ci` → `npm run build` → `COPY --from=web-builder`），上游依赖宿主机预构建的 `web/dist`，而我们的 CI 里没有这一步 |
| `.dockerignore` | 排除前端源码（上游不需要） | 放行 `web/src`、`package.json` 等（否则 web-builder 阶段拿不到源）；只排除 `web/node_modules` 与本地 `web/dist` |
| `docker-compose.yml` | `start_period: 90s`（与镜像 HEALTHCHECK 对齐）、从节点 `extra_hosts: host.docker.internal:host-gateway` | 自维护镜像地址、主从端口换位段、`VERSION: v2.3.8` |
| `.gitignore` | 精简版 | 我们的 `# >>> audit-artifact patterns` 块原样补回——**该块与 `scripts/check-no-audit-artifacts.sh` 的模式表双向强一致**，缺一行守卫即红（本轮实测踩到） |

### 9.4 子模块取上游为骨的原因（重要，下次别再试局部保留）

- **`caddygeoip`**：上游把「安全处理耗时侧车文件」整体退役，改为**审计行内嵌
  `lb_timing` 字段** + 进程内注册表。我们侧仍是侧车实现（`AppendSecurityTiming` /
  `securityTimingWriterAcquire`）。局部保留直接出现：
  `undefined: isValidSecurityTimingID`、`undefined: AppendSecurityTiming`。
  → 取上游整套（`auditwriter.go` / `security_timing*.go` / `blocked_counter.go` 同批替换）。
- **`wafiplist` / `geoipnames`**：上游新增 `SnapshotGeneration`、`StaleSnapshotGeneration`、
  `CrawlerEngineVerifyMethod`、`CrawlerVerifyIPRange`、`NormalizeCountry` 等符号，
  且 `geoipnames` 新增 `crawler-ip-lists.seed.json`（`go:embed` 依赖，缺文件即编译失败）。
  → 连同 embed 资产一起取上游。

### 9.5 验证

- **冲突标记门**：全仓 `<<<<<<<` / `=======` / `>>>>>>>` 零命中。
- **后端**：`go build ./...` ✅、`go vet ./...` ✅；五个子模块各自 `go build ./...` ✅。
- **前端**：`npx vue-tsc --noEmit` ✅、`npm run build` ✅。
- **单元测试**：`go test ./internal/... ./cmd/...`，与**上游 v2.3.8 原始检出**逐包比对失败集合：
  - 共有（基线噪声，非本轮引入）：`internal/services` 的 CRS 更新族 8 项——根因是沙箱
    到 `github.com` 的下载被判积分/长度校验拦截（`download integrity mismatch`），
    上游检出同样失败；`internal/dnsprovider/{dnspod,tencent}` 的
    `ownershipAddAndRollbackFailure` 两项——根因是 **root 用户下 chmod 不生效**
    （以非 root 用户复跑即通过）。
  - **我们侧独有：0 项**。
- **Dockerfile 清单门**：`bash scripts/check-dockerfile-copy-manifest.sh` ✅（13 sources）。
- **版本口径**：`Dockerfile` ARG、`docker-compose` `args.VERSION`、`internal/config` 默认值、
  `web/src/utils/branding.ts` 回退值、`.cnb/web_trigger.yml` 构建按钮默认值、
  README 中英基线声明与构建示例——统一 `v2.3.8`。

### 9.6 自维护三项能力（圈层 D）：保留未动

- 链式回退 `chain_fallback`：`caddychain/` 模块 + `internal/services/caddy.go` 渲染链，
  代码整体保留；`go build` / `go vet` 通过。
- 引用型证书 `tls_source=file` 摄取入库：`internal/services/certstore.go` 等整体保留。
- 默认端口换位：`internal/services/default_ports.go` 与相关单测保留。

> 说明：本轮**未**逐条跑这三项的功能钉测（沙箱无 Caddy 运行态），只做编译/静态验证；
> 行为级回归请以 CI 与真机为准。

---

## 十、v2.3.6 → v2.4.2（2026-11-10/11 · 追平正式版）

> 本节承接 §九。上游在 `v2.3.6`（`9c759716`）之后推进 309 个提交到达 `v2.4.2`
> 正式版。**更正一段历史**：2026-10-23 那轮「v2.3.8 追平」（`ffb394d3` + `272970aa`）
> 经任务档案事实核验判为**假追平**——以「业务域取我们侧」为骨，取的是 v2.3.6
> 时期的旧文件，把上游 v2.3.6 之后新增的全部文件整批丢弃（`internal/services/autoban.go`
> 等 23 个 autoban 文件、`crawler_*` 等 28 个 crawler 文件、`internal/apikey/`、
> `internal/atomicfile/`、`internal/netutil/`、`internal/retryafter/`、
> `cmd/server/healthcheck.go`、`web/src` 89 个文件、`web/tests` 全部前端测试），
> main 实际仍停留在 v2.3.6 基线。本轮弃用该手法，以标准三方合并重做。

### 10.1 状态速览（实测）

| 项 | 值 |
|---|---|
| 作骨（上游 tag） | `v2.4.2` = `0cd475ed`（树 `3a178b14`）；镜像轨 tip `bc87a28e` 与其逐字节一致（`git diff` 零输出） |
| merge-base | `9c759716`（我们的 v2.3.6 正式版基线；与 `0cd475ed` **无共同祖先**，`git merge-base` 退出码 1） |
| 上游推进 | 309 提交 / 2070 文件（`internal/db/db.go` +4968 行、`internal/services/caddy.go` +3248 行） |
| 基线自洽性 | 我们 main 与上游 v2.3.6 的非测试 Go 生产文件集合完全一致（差异 140 文件 = 自研独占 A + 自维护补丁 M）→ 标准三方合并可行 |
| 合并提交 | `bb05ecda`（双亲 `0155d18d` + `0cd475ed`，2092 路径，按 D6 单独计） |
| 接线收口提交 | `3ec18c04`（45 文件 +1624/−168，pre-commit 实跑 `scripts/gate.sh` 放行） |
| 合并冲突 | **87** 个文件（`git merge-tree --write-tree --merge-base=9c759716` 实测，merge tree `9e50f1ef`） |
| 隐藏失配 | **13** 个（自动合并无冲突标记、却残留我方对上游已重构字段的旧引用） |

### 10.2 合并手法（graft 桥接 + 标准三方合并）

1. **graft 桥接 merge-base**：`9c759716` 是 main 祖先但**不是** `0cd475ed` 的祖先，
   plain merge 会走空 base 垃圾冲突。实测手法：`git replace --graft 0cd475ed 9c759716`
   临时桥接 → `git merge --no-commit --no-ff 0cd475ed`，实测 `git merge-base` =
   `9c759716`、merge-tree 87 冲突与预检完全一致。graft 为本地临时 ref，**提交前已删除**，
   不污染提交对象关系。
2. **圈层策略**（A 上游独占直接吃 / B 自研独占直接保留 / C 同需求两实现逐个语义合并 /
   D 上游大改 + 我方补丁，吃上游结构 + 回补）。
3. **只解 87 冲突不够**：全量三路分类 694 个共同文件中 `both_changed` 97 个 =
   87 冲突 + 13 隐藏失配。失配文件无冲突标记却引用上游已重构字段（典型
   `internal/services/rule_transport_normalize.go` 的 `rule.OriginDomain`——上游把该字段
   收敛到 upstream 级并从 `LbRule` 移除），只看冲突标记必漏。
4. **并集陷阱（实测证伪一条捷径）**：69 个函数级冲突块机械取并集后 8 个文件
   gofmt 报结构错误（上游对 db.go/caddy.go 做函数级重构，同一函数两版本各取一半
   拼接即括号失衡）。**声明级（列清单/字段/import）可并集；函数级必须上游为骨 +
   逐函数读上游新结构后挂回补丁**。

### 10.3 冲突归类与决策（圈层 C/D 代表决策点）

| 文件/域 | 圈层 | 决策 |
|---|---|---|
| `internal/db/db.go` | D/P0 | 吃上游 `newColumnsRegistry` 迁移通道结构，4 自维护列（`chain_race_interval_ms` / `chain_request_timeout_ms` / `tls_cert_path` / `tls_key_path`）登记进注册表；逐一对表全部死列清单（legacy 各族 + `deadColumnDrops` 11 项 + MFA/sync/certificate_configs 各两列）**零命中**——启动即补列、永不 DROP |
| `internal/services/caddy.go` | D/P0 | 吃上游渲染链重构，`buildChainProxyConfig` 挂回 `buildHTTPHandleChain` 渲染链内 `strategy=="chain_fallback"` 分支（真实调用点，非死代码），由主渲染路径消费 |
| `certstore.go` / `certificates.go` / `configwatchdog.go` | D | 吃上游结构，回补引用型证书摄取链（handler 校验 → `LoadReferencedCertificate`）与看门狗 `checkReferencedCertFiles()` 扫描 |
| `internal/config/config.go` + `cmd/server/main.go` | D | 端口换位：`PANEL_PORT` / `HTTP_PORT` / `HTTPS_PORT` 解析 + `SetDefaultProxyPorts` boot 调用 + 兜底站/跳转自引用全链路 |
| `web/src/views/Rules.vue` 等 | C | 以上游为骨挂回三能力 UI 面（31 块）：`chain_fallback` 策略卡与竞速参数、证书 `file` 模式、端口换位 watcher |
| 叶模块 `trustedproxy_source` / `crawler_*` / `iplistfast` 族 | C | 上游 v2.4.2 已独立实现同能力且为我方**超集**（`ReportListUnavailable`、`ReadBoundedFile` 为上游新增）；逐符号核对：我方全部 func/type 符号在上游版中零缺失 → 取上游 = 并集，非任弃一侧 |
| `docs/audit/2026-09-05/` 两文档 | modify/delete | 跟随上游删除 |
| `web/tests/` 3 个契约测试（viewStateContracts / strategyLabels / rulesUi） | C | 语义等价适配：端口换位（跳转自环文案 80 → 动态默认口）与 `chain_fallback` 策略扩容的必然联动，断言语义未放宽 |

### 10.4 上游本轮新增能力（一并吃进）

- 新模块 `caddyl4sec/`（含 go.mod/go.sum，编译进 Caddy）：TCP 拦截提示 `block_notice`——
  L4 断连前向客户端写「Connection blocked by <品牌名>」，文案单源 `l4_tcp_notice.go`
- NTLM 兼容与「HTTPS 上游 + origin_domain」组合互斥门（误配 400 硬拒）
- forward_auth 网关子请求剥离 `X-LB-*` 内部控制头；`X-LB-Protocol` 链首 set + 剥离
- 自定义规则 `header_name` 头名限定（仅 `target=headers` 可携带）
- OR 逻辑自定义规则发射单源化
- 任务日志尾窗 off-by-one 修复；五处日志页统一 `useLogTailPolling`（自动滚底/后台暂停/迟到作废）
- API/MCP 文档面口径修复（403 幽灵前缀、retry 错误码枚举补全、`rule_triggered` 8 类对齐）
- `scripts/` 全套质量门（含 `scripts/tests/` selftest 环）；前端 `web/tests` 186 个测试文件补回

### 10.5 验证（分支 `feat/TASK-2026-1110-01-upstream-v242`）

- **作骨/存在性**：合并提交双亲即 A1 证据；`git ls-tree -r 0cd475ed` 共 2095 路径逐路径
  存在性核对 **MISSING=0**（已固化为 `scripts/gate.sh` 机械门第 4 项，常开）。
- **构建/静态**：`go build ./...` ×7 模块 + `go vet ./...` 全绿；冲突标记全仓零命中；
  版本口径八处锚点（Dockerfile/compose×3/README×4/branding.ts/web_trigger）统一 `v2.4.2`
  （`internal/config` 无硬编码版本，走 `APP_VERSION` env——与上游原文一致）。
- **钉测**：`caddychain` 单测 ok；`TestBuildHTTPHandleChain_chainFallback_emitsChainProxy`、
  `TestCreateRule_referencedCertFileIngestsContent`、`TestCheckReferencedCertFiles_*`、
  `TestSetDefaultProxyPorts_*`、`TestGenerateCaddyConfig_defaultSiteFollowsHTTPPort` 全 PASS。
- **前端**：`npm ci` + `vue-tsc --noEmit` 零错误 + `npm run build` EXIT=0 +
  `npm test` **1597 pass / 0 fail**。
- **D4 存量库冒烟**：以 `9c759716` 源码构建 v2.3.6 二进制生成 fixture 库 → 植入
  `origin_domain` / `response_mode` 存量数据 → 新版启动：4 自维护列幂等补齐、
  存量列丢失 = 0、存量行字段原值保留、无启动即 DROP。
- **D1 失败集合基线比对**：`go test` 失败集合与上游 `0cd475ed` 原始检出逐条一致
  （共 5 处，全部基线复现，无我侧独有失败；枚举更正见任务档案）。
- **机械门**：`scripts/gate.sh`（build×7 / vet / 冲突标记 / 2095 路径存在性 / 版本锚点）
  挂 `.git/hooks/pre-commit`，本轮两次提交均实跑放行。

### 10.6 自维护三项能力：从「保留代码」到「接线可用」

§九只能做到「代码整体保留」（P2 未完成，渲染链/UI 面未挂回）；本轮函数级接线后
三项能力**真实可用**：

- **链式回退 `chain_fallback`**：`caddychain/` 模块 + 渲染链 + DB 两列 + UI 竞速参数
  （权重=优先级、竞速间隔/兜底超时）——多上游按权重组链、前路无响应到间隔即竞速下一路。
- **引用型证书 `tls_source=file`**：保存时摄取证书文件内容入库，外部文件更新由看门狗自动同步。
- **默认端口换位**：`HTTP_PORT` / `HTTPS_PORT` / `PANEL_PORT` 环境变量换掉 80/443/8000，
  兜底站监听口与跳转自引用跟随；新增 `GET /system/ports` API 面。

## 十一、回源 Host 双方案定论 + 静态响应强健度提回（2026-11-11 · TASK-2026-1111-01）

本轮**不追平上游**，处理两件与上游能力直接相关的裁定事项。

### 11.1 回源 Host：官方方案不采用，保持自研口径（只出报告，零代码改动）

董事长 2026-11-11 裁定：自研回源 Host 运行正常符合需求，「官方的方式我没试过不知道
好不好用 需要你出两者的小白化的基于源码的对比分析报告」。

报告落 `docs/upstream-origin-host-compare.zh-CN.md`（R1–R10），从源码层逐条比对后
**结论：不切换，保持自研口径的渲染语义**。三条硬理由（证据见报告 §3.5/§3.6/§6）：

1. **官方版部分填写场景会错误下发客户端 Host**：`0cd475ed:internal/services/caddy.go:4930-4942`
   的 `hostFallback` 在「规则级域名空 + 纯 http 池」分支落到
   `{http.request.hostport}`（客户端域名），而自研版未命中兜底恒为「该上游自身地址」。
2. **官方版做不到自定义路由内推导**：`pathUpstreamHostResolver` 的 hoisted/orphan
   分派（2026-10-10 董事长裁定「内部逻辑、不新增字段」）在原生 map 方案下无对应物。
3. **官方版的 TLS 回退曾带 bug**：`2ba0f2c7` 原始实现用 `{http.request.hostport}`
   （`872408c2:internal/services/caddy.go:3786`），后经 `3f1c3346`「第 69 轮全项目审计」
   才改成分池形态；自研版 `5ee2a96a^:internal/services/caddy.go:4078` 天生取值
   `{http.reverse_proxy.upstream.hostport}`，无同类问题。

**注意**：`2ba0f2c7` 不在上游 v2.4.2（`0cd475ed`）的祖先链上——该能力从未进入官方
正式版，当前 main 的面板「回源域名」列是自研代码在支撑。

### 11.2 静态响应/3xx：按董事长自研口径提回强健度（基于上游源码最小化改）

原则：**保留上游 `response_mode` 三值结构**（不恢复 `action` 列，避免二次迁移），
只把校验与渲染的强健度提回 2026-10-09 自研口径（`5ee2a96a^`）。

| 维度 | 上游 v2.4.2 原值 | 本轮（自研口径） | 落点 |
|---|---|---|---|
| 状态码白名单 | 11 码（无 3xx） | **17 码**（200/204 + 301/302/303/307/308 + 400/401/403/404/405/410/429 + 500/502/503/504） | `services.staticResponseStatusCodes`、`handlers.validStaticResponseStatuses` |
| 201 Created | 在白名单 | **移出**（Created 语义要求创建资源并给 Location，静态短路无资源可创建） | 同上 |
| `static` 模式 3xx | 不放行 | 放行，**跳转目标必填** | `validateStaticResponseModeFields` |
| 3xx/204 响应体 | 未按 RFC 区分 | **禁体**（RFC 9110） | 同上 + `services.StaticResponseBodyAllowed` |
| 非 3xx 带跳转目标 | — | **显性拒绝**（误配报错，不静默忽略） | 同上 |
| 响应体上限 | ≤64 字符 | **≤4096 字符**（取值理由见 `staticResponseBodyMaxRunes` 注释：内存/展示/存储三面权衡） | 同上 |
| 响应体控制字符 | 不校验 | 放行 `\n\r\t`、拒其余 C0 与 DEL | `validateRespondBodyChars` |
| 跳转目标校验 | 仅拒 `<0x20`、`0x7f` | **须 `http(s)://` / `/` 开头 + 拒空格与控制字符**（大小写不敏感） | `isValidStaticRedirectTarget` |
| 3xx 渲染 | 不写 Location（静默空重定向） | 写 Location、不写体、不写 Content-Type | `services.buildStaticResponseHandler` |
| 缺省内容类型 | `text/plain` | `text/html; charset=utf-8`（`text/*` 补 charset、json 不补） | `services.staticResponseDefaultContentTypeFor` |
| 405/401 必备头 | 无 | 405→`Allow`、401→`WWW-Authenticate` | 同上 |
| `redirect` 模式 | 恒 301 + 目标 | **行为零回归**；显式非 301 的 `response_status` 显性拒绝（避免「填 302 实际发 301」） | `handlers` 校验 |
| 前端下拉 | 11 码硬编码 | 三处同集（前端常量 / handlers 查表 / services 权威），parity 钉测双向核验 | `web/src/utils/ruleValidation.ts` + `web/tests/ruleValidation.spec.ts` |

**控制字符双面**：响应体放行常规空白（HTML/JSON 多行排版必需），跳转目标拒全部
含空格与控制字符（Location 头裸空格必被客户端截断，属明确误配）。

**存量兼容**：旧 11 码内除 201 外全部仍放行；201 存量配置保存时得显式报错与改名
建议，**渲染行为不变**（残留 201 行仍按原状态码渲染）。`redirect` 模式零回归。

### 11.3 验证（分支 `feat/TASK-2026-1111-01-static-response`）

- **构建/静态**：`go build ./...` + `go vet ./...` 全绿；`scripts/gate.sh` **PASS**
  （build×7 / vet / 冲突标记 0 / 上游 2095 路径 missing=0 / 版本锚点九处）。
- **后端钉测**：`internal/handlers/rule_features_static_response_test.go` 覆盖
  17 码逐一放行、非法码拒绝、3xx 缺目标拒绝、非 3xx 带目标拒绝、4096 界值（含
  中文/代理对按码点计）、控制字符门、跳转目标形状、3xx/204 禁体、redirect 只能
  301、存量兼容、转发模式零影响；`internal/services/caddy_pathrule_response_test.go`
  新增 3xx 渲染（Location + 无体 + 无 Content-Type）、204 无体、405/401 必备头、
  charset 兜底、17 码清单副本语义。
- **前端**：`npx vue-tsc --noEmit` 零错误；`npm test` **1601 pass / 0 fail**
  （新增三处白名单同集 parity、17 码边界、4096 界值、控制字符、形状同源）。
- **失败集合基线比对**：`go test ./internal/... ./cmd/...` 失败集合与上游
  `0cd475ed` 原始检出逐条一致（4 处，全部在上游 worktree 同样复现，无我侧独有失败）。
- **机械门**：`scripts/gate.sh` 挂 pre-commit，本轮提交实跑放行；未使用 `--no-verify`。

### 11.4 本轮踩坑与更正

- **坑 1（归属误判）**：任务书 §2.2 记「上游改成 `{http.reverse_proxy.upstream.hostport}`」，
  实际该修复属 `3f1c3346`（第 69 轮审计），非 `2ba0f2c7` 自带 —— 已按真实归属写入报告
  §3.6 与附录 A.3，并在此留痕。
- **坑 2（共用函数缺省值入参）**：static/redirect 共用的字段门若把 `response_status=0`
  写死归一为 200，redirect 模式会被判成「200 带跳转目标」而恒拒。改为由调用侧传入
  `defaultStatus`（static→200、redirect→301），钉测 `TestValidateRuleFeatures_redirectModeOnly301` 锁死。
- **坑 3（前端读残留字段）**：redirect 表单不展示状态码字段且切模式不清值，前端若据
  `response_status` 校验「只能 301」会误伤合法配置（残留 200）。前端一律不读该字段，
  权威校验留在后端保存门。
- **坑 4（反兜底清单腐化）**：`buildStaticResponseHandler` 的内容类型缺省从函数内字面量
  改为单源函数返回后，`render_anti_fallback_scan_test.go` 的允许清单条目按「已消失」报红。
  该扫描是双向核对（清单→源码 + 源码→清单），改实现必须同步改清单。
