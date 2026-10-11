# 上游合并清单：v2.3.4 → v2.3.5

> 本文件是「我们维护的代码」与「上游原作者发布版本」之间的对账记录。
> 每次上游发版，按本文件的流程走一遍，并把新版本追加成一节。
>
> - 我们的代码：CNB `xzydm/lazy-balancer-v2`（`main` 分支）
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
│  internal/services/default_ports.go、.cnb.yml/.cnb/web_trigger.yml、
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
> 拿上游的锚点结构 + 我们的 `image: docker.cnb.cool/...` + 我们的
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

## 六、本次尚未动业务代码的说明

本轮只做「对齐原始报告 + 事实复核 + 文档修正」，**未动任何业务代码**
（`git status` 干净，HEAD 仍为 `977a3b04`）。因为 C1/C2 选错方向改了也白改，
还会污染后续 diff。你回复决策后，我再按第五节顺序动手。

## 七、变更日志

| 日期 | 内容 |
|---|---|
| 2026-10-11 | 建立清单；范围 `v2.3.4 → v2.3.5`；立 D-1 ~ D-6 六个决策点 |
| 2026-10-11 | 修正 D-1/D-2 误判（`707fe14b`）：前端有列、静态响应对面也已实现 |
| 2026-10-11 | **对齐原始只读报告复核**：恢复「四圈层」骨架；所有结论附证据（行号/提交号）；实测 22 冲突文件；上游推进至 16 提交 |
