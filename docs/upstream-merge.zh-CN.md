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

同一个功能，两边独立做了一遍，方向不同：

| | 我们的实现 | 上游的实现 |
|---|---|---|
| 数据落在哪 | `upstreams.host_header`（复用已有列） | 新增 `upstreams.origin_domain` 列 |
| 自定义路由怎么取值 | 渲染期内部推导（不落库、前端无字段） | 前端有「回源域名」列，随 `upstreams_json` 落库 |
| 渲染机制 | Go 侧推导 + `{lb.upstream_host}` 占位符 | 原生 `map` 处理器晚绑定查表 |
| 是否新增 Caddy 模块 | 否 | 否（上游也做到了零新模块） |
| SNI 处理 | 跟随 `host_header`，带端口原样 | `stripOriginPort` 剥离端口 |
| 健康检查域名 | 无 | 新增 `upstreams.health_check_host`（probe Host 头） |

**三个选项：**

- **方案 1（推荐）：以我们的实现为基线，选择性吸收上游的能力点。**
  保留我们的三级回退 + 渲染期推导（这是你 2026-10-10 亲自裁定的口径：
  「自定义路由的规则设定不该出现任何额外字段」），但吸收上游这两点：
  - 新增 `upstreams.health_check_host` 列与 probe Host 头支持（我们目前是缺的）；
  - SNI 剥端口（`stripOriginPort`，上游理由是 RFC 6066 SNI 无端口语义）。
  代价：需要把上游这两个点从它那套 map 方案里「拆」出来、移植到我们的推导方案上，
  工作量中等，但代码口径保持统一，前端一行不动。

- **方案 2：完全切到上游实现。**
  删掉我们的 `pathUpstreamHostResolver` / `hostPlanValueFor` 一整套，改吃
  `origin_domain`。好处是后续合并零冲突；坏处是**推翻你之前对前端的裁定**
  ——你的原话是自定义路由不应出现「回源 Host」列，而上游方案前端是有这个字段的。

- **方案 3：两套并存。**
  保留我们的推导，同时接上游的 `origin_domain` 作为「显式覆盖」优先档。
  好处是兼容两边；坏处是**同一个语义有两个数据源**，回源 Host 到底谁说话
  要靠一套优先级规则解释——这正是你此前反对的「配置歧义」形态，我不推荐。

> 我的建议：**方案 1**。理由是它保住了你已经拍过板的用户可见行为（自定义路由
> 无额外字段），同时把上游真正缺的那块能力（健康检查域名、SNI 剥端口）补上。

### D-2 自定义路由「直接返回 / 301 跳转」要不要接
上游新增 `path_rules` 五列（`response_mode` / `response_status` / `response_body` /
`response_content_type` / `redirect_to`），支持路径规则直接返回静态响应或 301。
> 判断：**纯新增能力，与我们无冲突，建议直接接。** 唯一要补的是预检渲染路径的
> 字段回填（上游在 `toPathRuleConfigs` 里补了，我们改过该函数的上下文，
> 合进去时要人工确认没丢字段）。

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
