# Fork 改动最小化分析报告（O2）

> **本报告只做分析与方案，r1 不执行任何生产代码改动。** 改造需董事长批准后另开一轮。
> 任务：`TASK-2026-1111-03` · 作者：开发总监 · 日期：2026-11-11
> 度量工具：`scripts/fork-diff.sh`（配套清单 `docs/fork-diff/latest.{md,json}`）
> 参照系：`0cd475ed`（上游 v2.4.2）→ `d31665db`（本 fork main）

---

## 〇 结论先行（给董事长）

| # | 结论 | 一句话理由 |
|---|---|---|
| **1** | **总改动量无法显著压缩**（14879 行里 ~77% 是测试/文档/台账/依赖，不产生冲突面） | 真正暴露在冲突面的「生产代码」只有 3471 行，其中注释占 910 行 |
| **2** | **但「冲突面」可以实质压缩：建议做注释外置（H1）** | 910 行注释里 **523 行分布在 ≥3 行的连续注释块**中；这些块与上游改同一行的概率最高，且删掉不损失任何功能 |
| **3** | **建议做 H2（挂点收敛），但要限定范围**：只针对 `db.go` / `rule_features.go` 的「登记式」补丁 | 这两处是「每次上游加列/加字段都要跟着改」的结构性成本，收敛成登记表能一次止血；`caddy.go` 的 28 个 hunk 里有 20 个是**语义必需**，压不动 |
| **4** | **H3（常量外置）收益有限，暂不推荐** | 可外置的常量只有 ~30 行，却要多 1–2 个文件 + 1 处上游同文件修改点，属于「换汤不换药」 |
| **5** | **不建议追求「文件数下降」** | 92 个文件里 36 个是测试、11 个是文档台账、13 个是基建。**文件数是结果不是目标**，硬压只会牺牲可验证性 |

**如果只做一件事：做 H1（注释外置）。** 预期把生产代码的注释占比从 26% 降到约 5%，
同行冲突面积减少约 **15%**，且**零功能风险**（注释不参与编译）。
**如果做两件事：H1 + H2（限定 db.go / rule_features.go）。** 预期冲突面再降约 10%。

---

## 一、量化基线（全部实测，可复现）

### 1.1 总量

| 指标 | 值 | 来源 |
|---|---|---|
| 差异文件 | **92**（新增 41 / 修改 51） | `bash scripts/fork-diff.sh 0cd475ed d31665db` |
| 新增 / 删除行 | **+14879 / −564** | 同上 |
| 变更块（hunk） | **253** | 同上 |
| 独立 Go 模块 | `caddychain/`（1534 行，含 go.sum 581） | 同上 |

> 注：任务书 §2.1 记 `+14880`，实测 `+14879`（`git diff --shortstat` 同值）。
> 差 1 行来自 `.npc-teams/tasks/TASK-2026-1111-03.md` 本轮自身新增，属台账口径漂移，
> 不影响任何结论。

### 1.2 按「是否产生冲突面」切分（**这是本报告的核心分解**）

差异的 14879 行里，**只有落在「上游也存在的文件」上的改动才会在追平时冲突**。
按此切分（实测，`docs/fork-diff/latest.json` 可复核）：

| 类别 | 文件数 | 新增行 | 占总量 | 追平冲突面 |
|---|---:|---:|---:|---|
| **测试**（`*_test.go` + `web/tests/`） | 36 | 4879 | 32.8% | **零**（上游无同名测试文件时纯新增；有名时冲突但可整体重写） |
| **文档 / 台账 / 规范**（`docs/` `.npc-teams/` `AGENTS.md`） | 11 | 4595 | 30.9% | **零**（上游无此路径） |
| **基建 / CI / 依赖**（`.cnb*` `.github/` `scripts/` `go.mod/sum` `Dockerfile`） | 13 | 1669 | 11.2% | 低（`Dockerfile` 3 行、`go.mod` 2 行） |
| **自研独立模块**（`caddychain/` `caddygeoip/upstream_host.go`） | 5 | 1480 | 9.9% | **零**（上游无此路径） |
| **产品代码**（`internal/` `cmd/` `web/src/` 非测试） | 27 | 2256 | 15.2% | **★ 全部冲突在这里** |

> 精确数字：产品代码 27 个文件 = 19 backend + 7 frontend + 1 specs 之外的其他；
> 去掉测试后产品代码新增 **2256 行**（含注释）。

### 1.3 注释占增量（**O2 的靶心，实测**）

统计口径：`git diff -U0 0cd475ed d31665db` 中新增行以 `//` `#` `--` `/*` `*` 开头者。

| 文件 | 新增行 | 注释行 | 占比 | ≥3 行连续块 | 块内行数 |
|---|---:|---:|---:|---:|---:|
| `internal/services/caddy.go` | 734 | 252 | **34%** | 27 | 208 |
| `internal/handlers/rule_features.go` | 271 | 108 | **40%** | 8 | 75 |
| `internal/db/db.go` | 164 | 49 | 30% | 9 | 44 |
| `internal/handlers/rules.go` | 143 | 41 | 29% | 8 | 28 |
| `internal/models/models.go` | 41 | 20 | **49%** | 3 | 14 |
| `internal/services/certstore.go` | 174 | 26 | 15% | 3 | 17 |
| `internal/services/configwatchdog.go` | 122 | 20 | 16% | 3 | 13 |
| `caddygeoip/upstream_host.go` | 102 | 36 | 35% | 2 | 22 |
| `internal/services/default_ports.go` | 48 | 16 | 33% | 1 | 12 |
| `internal/config/config.go` | 63 | 11 | 17% | 1 | 5 |
| `web/src/views/Rules.vue` | 137 | 28 | 20% | 4 | 13 |
| **小计（上表 11 文件）** | **1999** | **607** | **30%** | **69** | **451** |

全量口径（所有非测试的 `.go/.ts/.vue/.sh`）：
**新增 3471 行，注释 910 行，占 26.2%**。
其中「≥3 行连续注释块」共 **523 行**（含上表 451 行 + 脚本类 72 行）。

### 1.4 三类成本源（任务书 §2.2 框架做实）

| 源 | 判定 | 文件 | 行数 | 可压缩性 |
|---|---|---|---:|---|
| **(a) 自研功能代码** | 能力本体，压掉就没功能 | `caddychain/`(5) `caddygeoip/upstream_host.go` `default_ports.go` | 1480 + 150 | **不可压缩**（除注释部分，约 121 行） |
| **(b) 与上游同行改动的重叠** | 上游文件里的补丁 | `caddy.go` `db.go` `certstore.go` `models.go` `rule_features.go` `rules.go` `config.go` `configwatchdog.go` + 前端 4 文件 | **2256** | **部分可压缩**（见 §三 H2） |
| **(c) 解释性注释** | 不产生功能，只产生冲突面 | 分散在上述所有文件 | **910** | **可压缩**（见 §三 H1） |

> **(b) 内部再分解**（决定 H2 能压多少）：
> - `caddy.go` 的 734 行里，**约 480 行是两个自研能力的真实实现**（`upstreamHostPlan`
>   四态 + 解析器 ~300 行、`buildChainProxyConfig` ~55 行、静态响应强健度 ~130 行），
>   **压不动**——这些是功能本体；
> - `db.go` 164 行 = 列登记（~12 行）+ 重建 DDL 两处（~12 行）+ **3 个迁移函数 100 行**
>   （含 44 行注释）——**迁移函数可收敛**；
> - `rule_features.go` 271 行 = 静态响应校验 ~190 行（功能本体）+ 端口换位替换 ~20 行
>   + 链式回退参数 ~20 行 + 注释 108 行。

---

## 二、理论可降至多少（推导过程，每项有依据）

### 2.1 不做的部分（压不动，也不能压）

| 项 | 行数 | 依据 |
|---|---:|---|
| 测试 | 4879 | 删测试 = 失去「追平后功能对不对」的判据。**追平流程要靠它**（手册 §五 验证门） |
| 文档 / 台账 | 4595 | 本次三件交付物本身就在里面；台账是协作事实源 |
| 自研模块功能实现 | 1480 | 删 = 能力消失 |
| 产品代码功能实现（去注释后） | 2256 − 910 ≈ **1346** | 四项核心自研的落地实现 |

### 2.2 可动的部分

| 项 | 当前 | 可降至 | 依据 |
|---|---:|---:|---|
| (c) 注释 → 外置到 `docs/fork-notes/` | 910 | **~120** | 保留「一句话锚点」`// 详见 docs/fork-notes/caddy.md §3.2`，估计每块 1 行 × 约 90 块 ≈ 90–120 行 |
| `db.go` 三个迁移函数 → 表驱动 | 100（含 44 注释） | **~40** | 三个函数结构同构（查列存在 → UPDATE 搬值 → 记日志），可抽象成 `[]columnMigration{from,to,table,where}` 表 + 一个执行器 |
| `rule_features.go` 端口换位字面量替换 | 20 | **~14** | 已是 `services.DefaultHTTPPort()` 单源，只剩调用点，压不动多少 |
| 前端同款注释 | 28+30+12 | **~15** | 同 H1 |

### 2.3 结论数字

| 指标 | 当前 | 做完 H1 | 做完 H1 + H2（限定） |
|---|---:|---:|---:|
| **生产代码新增行** | 2256 | **≈1466**（−35%） | **≈1406**（−38%） |
| **生产代码注释占比** | 26.2% | **≈6%** | **≈6%** |
| **产品代码文件的 hunk 数** | 163 | **≈95**（估算） | **≈78**（估算） |
| **差异文件数** | 92 | 92（**不变**） | 92（**不变**） |
| **总行数** | 14879 | ≈14089 | ≈14029 |

> **必须说清楚的两件事**：
> 1. **文件数不会降**。想降到 60 文件只能靠删测试或删文档，那是拿可验证性换数字，
>    **不建议**。董事长要的「减少修改量」应理解为「减少**冲突概率**」，不是「减少文件数」。
> 2. **总行数只降 ~6%**，因为 77% 的体量（测试/文档/基建）本来就不产生冲突。
>    真正的收益在 **hunk 数**（冲突的直接度量）和 **同行重叠概率**。

### 2.4 为什么「hunk 数下降」才是真收益（数据支撑）

上一轮真实追平（v2.3.6 → v2.4.2）的实测成本：

| 轮次 | 上游跨度 | 冲突文件 | hunk 级冲突块 | 投入 |
|---|---|---:|---:|---|
| v2.3.4→v2.3.5 | 16 提交 | 22 | 未计 | 4 步 |
| v2.3.5→v2.3.6 | 23 提交 | 7 | 未计 | 4 步 |
| v2.3.6→v2.4.2 | 309 提交 | **87** | **69 个函数级冲突块**（其中 8 个文件机械取并集后语法崩） | r1–r3 |

> 关键教训（`卡-20261110-02`）：**69 个函数级冲突块取并集 → 8 个文件括号失衡**。
> 冲突块数量直接决定人工判断成本。**注释块每减少一个 hunk，就少一次人工决策。**

---

## 三、三个优化假设逐条评估

### H1 注释外置 —— **建议执行**

| 项 | 内容 |
|---|---|
| **做法** | 把 ≥3 行的连续解释性注释迁到 `docs/fork-notes/<模块>.md`，代码内留一行锚点：`// 详见 docs/fork-notes/caddy.md §3.2 回源 Host 四态` |
| **预期收益** | 生产代码注释 910 → ~120 行；注释占比 26% → 6%；**同行冲突概率降约 15%**（注释块与上游改动同行的概率与注释行数成正比） |
| **风险** | ① 知识可发现性下降（缓解：锚点必须精确到 `§N`，且 `docs/fork-notes/` 建索引）；② 有人会觉得代码少了上下文（缓解：锚点行写「一句话结论」，不是「详见某文档」） |
| **依据** | 实测 523 行注释在 ≥3 行连续块里，删掉不参与编译；且 `caddy.go` 的 27 个注释块中，**11 个位于 `buildHTTPHandleChain` 内**——而该函数正是上游重构最频繁的位置（v2.4.2 对 `caddy.go` 改了 +3248 行） |
| **是否建议** | ✅ **建议执行**（董事长 §4.2 已裁定「注释外置：接受」） |
| **额外约束**（董事长要求） | 锚点必须真实存在可跳转：改造后须跑机械校验 —— 对每个 `// 详见 docs/x.md §N`，检查 `docs/x.md` 里有对应 `## §N` 或 `### N` 标题。此校验建议写成 `scripts/check-doc-anchors.sh`（r2 落地） |

**示例（以 `caddy.go` `resolveUpstreamHostPlan` 为例）**：

```go
// 改造前（38 行注释 + 45 行代码）：
// upstreamHostPlan 逐上游回源 Host 三级回退计划（董事长自研第 4 项核心能力，
// 2026-10-09 立项；自定义路由链 2026-10-10 同源复用……）
// 四态互斥（有启用上游时恒居其一）：
//   - staticHost：全统一静态值……（下略 30 行）
type upstreamHostPlan struct { ... }

// 改造后（3 行注释 + 45 行代码，代码零改动）：
// upstreamHostPlan 逐上游回源 Host 三级回退计划，四态互斥。
// 要点：任何回退态都不用 {http.request.hostport}（那是客户端 Host）。
// 详见 docs/fork-notes/origin-host.md §2（四态语义）与 §3（为何不用客户端 Host）
type upstreamHostPlan struct { ... }
```

> **等价性证明方式（r2 执行时）**：注释外置是**纯注释删除**——可用
> `git diff --ignore-all-space` + Go 编译器层面的等价性：
> 改造前后 `go build` 产物用 `go tool objdump` 比对，或更简单：
> 用 `gofmt -r` 无法做，改用 **AST 比对**——`go run golang.org/x/tools/cmd/... ` 太重。
> **实操建议**：改造前后各跑一次 `go vet` + 全量钉测 + 一次性 `go test ./internal/services/ -run 'UpstreamHost|ChainFallback|StaticResponse'`
> + O2-5 要求的渲染产物逐字节比对（`scripts/verify-generated-config-decodes.sh` 已具备该能力）。
> 更硬的证明：**`go build -gcflags=-S` 汇编对比**——注释不进汇编，若前后一致即为铁证。

---

### H2 挂点收敛 —— **建议执行，但限定范围**

| 项 | 内容 |
|---|---|
| **做法** | 把「上游每加一个列/字段，我们就要跟着登记一次」的补丁，收敛成**表驱动 + 单一注册入口** |
| **预期收益** | `db.go` 三个迁移函数（100 行含 44 注释）→ 表 + 执行器（~40 行）；**未来上游加列时我们只改表里一行**，而不是改 3 个函数 |
| **风险** | ① 抽象成表后调试栈变深（缓解：执行器逐条记日志，与现状同级）；② 若上游重构 `runMigrations` 结构，注册点仍要改（但只改 1 处，不是 3 处） |
| **依据** | `db.go` 的 hunk 分布实测：**11 个 hunk 分布在 5 个函数 + 2 个 DDL 常量里**，其中 `migrateLbRulesPrimaryKey` 占 5 个 hunk——每次上游动 DDL 都要在这里冲突 5 次 |
| **是否建议** | ⚠️ **建议执行，但只做 `db.go` 的迁移函数收敛**；`caddy.go` 不做 |

**为什么 `caddy.go` 不做 H2（重要，防走弯路）**：

`caddy.go` 的 28 个 hunk 分布（实测）：

| 函数 | hunk 数 | 性质 | 能否收敛 |
|---|---:|---|---|
| `generateCaddyConfigWithCertSource` | 11 | 5 处列读取 + 3 处能力接线 + 2 处端口换位 + 1 处类型提升 | ❌ 每处都要读不同的列/调不同的函数 |
| `buildHTTPHandleChain` | 6 | 回源 Host 计划 + chain 分支 + SNI + Host 头 | ❌ 这 6 处是**能力的核心实现**，收敛成 1 个函数调用会把 300 行逻辑搬到另一个函数里，**hunk 数不降反升** |
| 其余 11 处 | 11 | 结构体字段、常量、单点替换 | ⚠️ 已经很散 |

> **结论**：H2 在 `caddy.go` 上**不成立**。任务书 §3.3 设想「上游函数只留一行调用」，
> 实测不可行——因为我们的逻辑要读上游函数的**局部变量**（`enabledUpstreams`、`rule`），
> 抽成外部函数就得把这些都传进去，形参爆炸，且上游改函数签名时冲突更严重。

**H2 落地示例（`db.go`）**：

```go
// 改造前：3 个结构几乎相同的迁移函数（100 行）
func migratePathRuleActionToResponseMode() error { /* 查列 ×2 → UPDATE ×2 → log */ }
func migrateUpstreamHostHeaderToOriginDomain() error { /* 查列 ×2 → UPDATE ×1 → log */ }
func migrateLbRuleOriginDomainToHostHeader() error { /* 查列 ×2 → UPDATE ×1 → log */ }

// 改造后：一张表 + 一个执行器
var columnMigrations = []struct {
    name           string
    table          string
    fromCol, toCol string
    where          string
}{
    {"path_rules.action→response_mode(3xx)", "path_rules", "action", "response_mode",
        "action='respond' AND status_code>=300 AND status_code<400"},
    {"upstreams.host_header→origin_domain", "upstreams", "host_header", "origin_domain",
        "COALESCE(origin_domain,'')=''"},
    {"lb_rules.origin_domain→host_header", "lb_rules", "origin_domain", "host_header",
        "COALESCE(host_header,'')=''"},
}

func runColumnMigrations() error {
    for _, m := range columnMigrations {
        if err := migrateColumn(m); err != nil { return fmt.Errorf("%s: %w", m.name, err) }
    }
    return nil
}
```

> **等价性证明方式**：`internal/db/db_migration_test.go` + `merge_migration_test.go` 已有
> 三函数的覆盖测试（实测存在，76 + 4 行）。改造后这些测试**必须逐条仍绿**，
> 且额外加「表驱动的每条恰好执行一次、顺序稳定」的钉测。**这是可机械验证的等价性**。

---

### H3 常量/配置外置 —— **不建议执行**

| 项 | 内容 |
|---|---|
| **做法** | `caddy.go` 里的自研常量（`chainProxyDefaultRaceIntervalMS` 3000、`chainProxyDefaultRequestTimeoutMS` 30000、`chainProxyBodyReplayLimitBytes` 5MiB、`staticResponseBodyMaxRunes` 4096、`staticResponseDefaultContentType`）挪进独立文件/包 |
| **预期收益** | 减少 `caddy.go` 约 **6 行**（常量定义本身），多 1 个新文件 |
| **风险** | 新建文件若上游也无 → 零冲突 ✅；但**引用点仍在 `caddy.go` 里**（`buildChainProxyConfig` 里用），所以 `caddy.go` 的冲突面**一点没减** |
| **依据** | 实测可外置的自研常量共 5 个、合计 6 行。`caddy.go` 的 28 个 hunk 里，常量定义只占 **0 个**（常量都在新增行内，不与上游同行） |
| **是否建议** | ❌ **不建议**（收益 6 行 vs 多 1 文件 + 多一层间接；属于「为了做而做」） |

> **诚实结论**：H3 在本仓**不成立**。任务书把它列为假设是对的，但实测收益可忽略。

---

## 四、具体改造方案（若董事长批准）

### 4.1 H1 注释外置（优先级 P0，建议先做）

**改哪些文件**

| 文件 | 注释行 | 外置目标文档 |
|---|---:|---|
| `internal/services/caddy.go` | 252 | `docs/fork-notes/render-chain.md`（渲染链与回源 Host）+ `docs/fork-notes/static-response.md` |
| `internal/handlers/rule_features.go` | 108 | `docs/fork-notes/static-response-validation.md` |
| `internal/db/db.go` | 49 | `docs/fork-notes/db-migrations.md` |
| `internal/handlers/rules.go` | 41 | `docs/fork-notes/tls-file-source.md` |
| `internal/models/models.go` | 20 | `docs/fork-notes/model-fields.md` |
| `internal/services/certstore.go` | 26 | `docs/fork-notes/tls-file-source.md` |
| 其余 5 文件 | 111 | 对应模块文档 |
| 前端 3 文件 | 70 | `docs/fork-notes/frontend.md` |

**怎么改（严格顺序，可回滚）**

1. 每个模块先建文档，把现有注释**逐字搬过去**（不改写），按 `## §N` 编号；
2. 代码内替换为 1–3 行锚点（含一句话结论 + `详见 docs/... §N`）；
3. 跑 `scripts/check-doc-anchors.sh`（r2 新建）验证每个锚点可跳转；
4. 跑全量测试 + 渲染产物逐字节比对（见 §4.4）。

**预期效果**

| 指标 | 前 | 后 |
|---|---:|---:|
| 生产代码注释行 | 910 | ~120 |
| 注释占比 | 26.2% | ~6% |
| 新增文件 | 0 | 8 个 `docs/fork-notes/*.md` + 1 个检查脚本 |
| `caddy.go` 新增行 | 734 | ~490 |

### 4.2 H2 迁移函数收敛（优先级 P1，H1 完成后做）

**改哪些文件**：仅 `internal/db/db.go`（+ 其测试）

**怎么改**：见 §三 H2 示例。三个函数合并为「表 + 执行器」。

**预期效果**：`db.go` 164 → ~110 行；hunk 11 → ~7；**未来上游加列时，我们的改动点从 3 处降到 1 处**。

### 4.3 不建议做的（列出以免反复讨论）

| 项 | 原因 |
|---|---|
| 删测试或合并测试文件 | 追平验证门依赖它们；文件数不是目标 |
| 把 `caddy.go` 的自研逻辑抽成独立包 | 需要读上游函数局部变量，形参爆炸；且上游改签名时冲突更重 |
| 改为 patch 队列 / quilt 架构 | 超出董事长诉求（任务书 §2.5 已划出边界） |
| 把 `caddychain/` 合并回主模块 | 独立模块是「上游不动即零冲突」的结构优势，合并反而扩大冲突面 |

### 4.4 行为等价的证明方式（O2-5 要求的「逐字节」）

三条证据链，缺一不可：

| # | 证据 | 命令 | 判据 |
|---|---|---|---|
| ① | **构建产物等价**（H1 专用，注释不进汇编） | `go build -gcflags='-S' ./internal/services/ > /tmp/before.asm`（改造前后各一次） | `diff` 为空 |
| ② | **渲染产物逐字节等价** | `bash scripts/verify-generated-config-decodes.sh`（已有的生产渲染链 → Caddy 解码链） | `VERIFY: PASS` + 前后产物 `sha256` 相同 |
| ③ | **行为钉测全绿** | `go test -run 'UpstreamHost|ChainFallback|StaticResponse|ReferencedCert|DefaultPort' ./internal/services/ ./internal/handlers/ ./internal/db/` | PASS 集合与改造前**完全相同** |

> ①对 H2 不适用（H2 会改编译产物），故 H2 用 ②③ + 迁移冒烟：
> 拿一个 v2.3.6 的旧库 fixture 启动新版，比对「列补齐结果 / 迁移行数 / 日志」三项与改造前一致。

### 4.5 改造后的验收（对齐任务书 O2-4/O2-5/O2-6）

- `go build ./...` × 7 模块 + `go vet ./...`；
- `go test`：失败集合**与改造前逐条一致**（本仓已知基线失败：`internal/services` CRS 网络族、
  `internal/dnsprovider/*` 权限族，见 `docs/upstream-merge.zh-CN.md` §10.5）；
- 前端 `npx vue-tsc --noEmit` + `npm test`（当前基线 1601 pass / 0 fail）；
- `bash scripts/gate.sh` → `GATE: PASS`；
- 重跑 `bash scripts/fork-diff.sh 0cd475ed main` → 与本文档 §2.3 的预测数字比对。

---

## 五、与 O1 / O3 的一致性（任务书 V1）

| 一致性要求 | 落实 |
|---|---|
| O1 清单的差异项 ↔ 本报告分类 | O1 的 `self_dev_feature` 与本报告 §1.4 三类成本源一一对应：`self_dev:N` → (a) 自研本体；`none` → (b) 上游文件上的补丁；注释 (c) 是跨 (a)(b) 的横向切面（O1 里体现为行数占比，见 §1.3） |
| O2 压缩结论 ↔ O3 冲突分类 | H1 直接对应 O3 的「**函数冲突**」与「**结构冲突**」（注释块少了，同行冲突块就少）；H2 对应「**结构冲突**」（上游重构 `runMigrations` 时的重新挂点） |
| O3 手册引用本报告 | 手册附录 B「四项自研速查」引用本报告 §1.4 的成本分解 |

---

## 六、给董事长的决策清单

请在三项中选一：

| 选项 | 内容 | 代价 | 收益 |
|---|---|---|---|
| **A（推荐）** | 只做 H1 注释外置 | 1 轮（约 12 文件改动 + 8 新文档 + 1 检查脚本）；零功能风险 | 注释占比 26%→6%，冲突概率降 ~15% |
| **B（更彻底）** | H1 + H2（db.go 收敛） | 2 轮；H2 有中等风险（迁移逻辑重构，需旧库冒烟） | 在 A 基础上再降 ~10% 冲突面，并永久降低「上游加列」的维护成本 |
| **C（不改造）** | 维持现状 | 0 | 每次追平继续承受当前冲突面 |

> **我的建议是 A**：收益明确、风险为零、一轮可完成；H2 可以留到下次真追平时
> （那时能顺手验证迁移逻辑，省一次专门的冒烟轮）。

---

## 附：本报告的全部数字如何复核

```bash
# 1) 总量与逐文件归属
bash scripts/fork-diff.sh 0cd475ed d31665db
python3 -c "import json;d=json.load(open('docs/fork-diff/latest.json'));print(d['summary'])"

# 2) 注释占比（逐文件）
git diff -U0 0cd475ed d31665db -- internal/services/caddy.go \
  | grep -cE '^\+\s*(//|#|--|/\*|\*)'

# 3) 生产代码（去掉测试）总新增与注释
git diff --numstat 0cd475ed d31665db \
  | awk '$1>0{print $3}' | tr -d '"' \
  | grep -E '\.(go|ts|vue|sh)$' | grep -vE '_test\.(go|ts)$' | wc -l

# 4) hunk 分布到函数
git diff 0cd475ed d31665db -- internal/services/caddy.go \
  | grep -E '^@@' | sed 's/@@[^@]*@@ *//' | sort | uniq -c | sort -rn
```
