# 上游合并清单：v2.3.4 → v2.3.5

> 本文件是「我们维护的代码」与「上游原作者发布版本」之间的对账记录。
> 每次上游发版，按本文件的流程走一遍，并把新版本追加成一节。
>
> - 我们的代码：CNB `xzydm/lazy-balancer-v2`（`main` 分支）
> - 上游代码：GitHub `v55448330/lazy-balancer-v2`
> - 本次范围：`v2.3.4`（我们当前的基线）→ `v2.3.5`（上游最新 release）

## 一、当前状态速览

| 项 | 值 |
|---|---|
| 我们的基线版本 | `v2.3.4` |
| 上游最新版本 | `v2.3.5`（2026-10-11 发布，commit `986bcace`） |
| 差距规模 | 15 个提交，179 个文件，+6529 / −1740 行 |
| 分叉方式 | 我们基于上游 `v2.3.4`，之上叠加了 13 个自有提交 |

差距的提交构成（上游 `v2.3.4..v2.3.5`，自旧到新）：

```
5ba929ca v2.3.5：仪表盘延迟 P50/P95/P99 改 histogram_quantile 桶内线性插值
4b676887 Dockerfile：openssl 钉版 3.5.8-r0 → 3.5.9-r0（alpine 仓库下架旧版致构建失败）
2ba0f2c7 逐上游回源域名（Host+SNI）+ 健康检查域名：原生 map 晚绑定查表
5b27acfb 回源域名/健康检查域名收紧与 UI 修正
3a9c1d4e SNI 静态路径剥端口 + 混合回源域名主动检查警告
be4fe1a6 向导退役「后端域名」配置项 + 上游表样式与提示统一
2ca1e014 自定义路由新增「直接返回/301 跳转」模式
24d9296f 路径规则响应方式 UI 修正 + 上游表列宽收敛
d5323ba5 混合回源域名提示条补齐 info-note-desc 内文结构
78161c21 上游表数字输入框左空白根因修复
f69b4176 新建向导自定义路由开关种子行补 forward 哨兵默认值
c005a68 规则列表 TCP 规则补灰色锁图标
043f503 TCP 锁图标 hover 文案精简
3f1c334 第 69 轮全项目审计修复：151 项闭环
986bcac 排程生命周期与时区/图表统一修复
```

## 二、我们自己的改动（上游没有的部分）

这 13 个提交是本次合并的「冲突面」，也是必须逐项过一遍的原因。

### A. 链式回退负载策略（新功能）
`caddychain/` 模块 + 相关渲染与校验。
> 判断：**纯增量，与上游不重叠。** 上游这批改动没碰 Caddy 自定义模块。

### B. 引用型证书「摄取入库」（重构原有实现）
把 `tls_source="file"` 从「Caddy 直接引用外部文件」改成「保存时读取 PEM 入库，
DB 为唯一事实源，看门狗负责外部文件变化回写 DB」。
> 判断：**与上游不重叠**（上游这批没动 certstore / 证书路径），但改动面深。

### C. 80/443/8000 端口环境变量换位（新功能）
`HTTP_PORT` / `HTTPS_PORT` / `PANEL_PORT` 换位语义，仅影响默认语义不动存量规则。
> 判断：**与上游轻微交叠**——上游 `docker-compose.yml` 做了 YAML 锚点重构，
> 但不含端口换位。合并时须保留我们的 environment 段。

### D. 逐上游回源 Host / SNI（**强冲突，见第三节**）
我们对 `path_rules` 的回源 Host 做了「渲染期内部推导」，且**明确拒绝了**在
`upstreams_json` 里加字段的方案；上游选择了另一条路（新增 `upstreams.origin_domain` 列）。
> 判断：**这是本次合并的核心冲突，需要你拍板。**

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
| 健康检查域名 | 无（规则级 `lb_rules.health_check_host` 也无） | 新增 `lb_rules.health_check_host` + 上游级 `upstreams.health_check_host` |

> **勘误**：上一版清单写「我们的前端无字段」是错的。我们前端**有**「回源Host」列
> （`Rules.vue` 上游服务器表），只是「自定义路由」子表内不落该字段——这一点上
> 上游的做法其实与我们一致（上游也没有在自定义路由里放这个字段）。
> 真正的分歧是**字段名 + 渲染机制**，不是「有没有列」。

**决策要定的是三件事，可以分开选：**
1. 字段名：`host_header`（我们的）还是 `origin_domain`（上游的）
2. 渲染机制：我们的「Go 侧推导 + `{lb.upstream_host}`」还是上游的「原生 map 晚绑定」
3. 上游新增能力（`health_check_host` / SNI 剥端口）是否吸收

**推荐：字段名与渲染机制都切上游（`origin_domain` + map），同时吸收
`health_check_host` 与 SNI 剥端口。** 理由：
- 上游的 map 方案零新 Caddy 模块、代码量小，且**已修了我们大概率没修的 bug**
  （TLS 池下 Host 回退占位符错误，会退化成客户端 Host）；
- 我们已有的 `upstreams.host_header` **前端行为保持不变**（列还在，只是列名 →
  「回源域名」、列名背后字段换名），用户感知几乎为零；
- 继续留自研实现 = 永久冲突面 + 落后修复两笔债。
- 迁移：启动时 `host_header` 非空 → 搬入 `origin_domain`（并在
  `legacyUpstreamDeadColumns` 里保证先搬后删，避免我们这列被上游当死列 DROP 掉）。

**若选保守方案**：字段名切上游、渲染保留我们的推导，则需把上游的
`health_check_host` / SNI 剥端口两点从那套 map 里拆出来移植，工作量中等。

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
| 指标 | 我们补过 `lb_rule_metrics` | 上游在链首也补了 `lb_rule_metrics` |

**这是一个真正的「同需求两实现」碰撞，和 D-1 同一性质。** 需要一个决策：
统一到 `response_mode` 三值（上游口径），还是统一到 `action=respond`（我们口径）。
数据迁移成本两边都要付（存量行改写）。

### D-3 `task_runs` 表要删三列，会不会影响我们的任务监控
上游删了 `task_runs.stage` / `entry_count` 两个「零写入方」死列（`message` 留着），
存量库经 `deadColumnDrops` 幂等移除。
> 判断：**影响面小但要查。** 需确认我们代码里没有读写这两列
> （我们改过 `taskengine` 与 `taskmonitor`，必须 grep 一遍）。
> 确实无引用就直接接；有引用先改成不依赖这两列。

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

## 四、按文件的合并动作清单

按冲突概率从高到低。每一行都是「合并时必须看一眼」的文件。

| 文件 | 上游改动量 | 我们的改动 | 动作 |
|---|---|---|---|
| `internal/services/caddy.go` | +226 / −87 | 引用证书摄取、链式回退、自定义路由回源 Host | **重点**：见 D-1，逐 hunk 过 |
| `internal/db/db.go` | +82 / −109 | 探针列、`upstreams.host_header` 重启用 | **重点**：见 D-4 |
| `internal/handlers/rules.go` | +117 / −63 | 引用证书摄取、回源 Host 校验 | 见 D-1 / D-2，逐 hunk 过 |
| `internal/handlers/rule_features.go` | +160 / −22 | 引用证书、路径规则校验 | 见 D-1 / D-2 |
| `web/src/views/Rules.vue` | +161 / −41 | 端口换位提示、回源 Host 前端回退 | 别把上游的「回源域名」列合进来（取决于 D-1） |
| `web/src/components/rules/PathRulesEditor.vue` | +107 / −3 | 我们反向删过「回源 Host」列 | 同上 |
| `internal/taskengine/engine.go` | +115 / −33 | 我们改过任务引擎调度 | 见 D-3 |
| `internal/services/taskmonitor.go` | +16 / −7 | 我们改过 | 见 D-3 |
| `internal/services/schedule.go` | 有改动 | 我们改过 | 排程生命周期修复，需人工确认 |
| `internal/services/certstore.go` | 有改动 | 引用证书摄取核心 | **重点**：确认上游没动证书路径 |
| `docker-compose.yml` | 锚点重构 | 端口换位 + 镜像地址 | 见 D-5 |
| `Dockerfile` | openssl 钉版 3.5.9-r0 | 前端构建阶段下沉、VERSION | 两边都吃，注意 VERSION 取值 |
| `README.md` / `README.en.md` | 版本号、named volume 提示 | 已按我们的情况重写 | 以我们的为准，只吸收 named volume 提示 |
| `docs/*.zh-CN.md` | 局部补充 | 我们基本没动 | 直接吃 |
| `.dockerignore` | 加 `waf-slave/` | 我们没动 | 直接吃 |
| `docker-entrypoint.sh` | 空 TZ 兜底 | 我们没动 | 直接吃 |

## 五、建议的合并顺序

分四步走，每步都能独立验证、独立回退：

1. **无争议的一批**（先吃掉，减少后续 diff 噪音）
   `.dockerignore`、`docker-entrypoint.sh`、`docs/*`、仪表盘插值（D-6）、
   `Dockerfile` 的 openssl 钉版、README 的 named volume 提示。
   验证：`go build ./...` + `go test ./...`。

2. **纯新增能力**（D-2 直接返回/301，D-3 `task_runs` 删列）
   先 grep 确认我们没引用要删的列，再接。
   验证：`go test ./internal/handlers/ ./internal/taskengine/ ./internal/services/`。

3. **DB 迁移通道重构**（D-4）+ `docker-compose.yml` 锚点（D-5）
   这步动的是「地基」，要单独跑启动迁移：拿 v2.3.4 的旧库文件启动，
   验证补列与删列都幂等。
   验证：`go test ./internal/db/` + 旧库启动冒烟。

4. **D-1 逐上游回源 Host**（按你拍板的方案）
   放最后做，因为它是唯一一个「需要改上游代码而不只是接受上游代码」的部分。
   验证：`go test ./internal/services/ -run 'Upstream|Origin'` + 全量 `go test ./...`。

## 六、本次尚未动业务代码的说明

本轮只出了这份清单与配套的流水线/文档改动，**没有动任何业务代码**——
因为 D-1 一旦选错方向，改了也白改，还会污染后续 diff。
你回复决策后，我再按第五节顺序动手。

## 七、变更日志

| 日期 | 内容 |
|---|---|
| 2026-10-11 | 建立清单；范围 `v2.3.4 → v2.3.5`；立 D-1 ~ D-6 六个决策点 |
