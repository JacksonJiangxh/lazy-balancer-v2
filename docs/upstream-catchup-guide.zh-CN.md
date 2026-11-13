# 上游追平作业手册

> **何时用**：上游发新版，要把它吃进来且四项核心自研不被切掉。**怎么用**：从上到下照做。
> **面向两类读者**：第一部分（§一~§八）给决策者——步骤/判据/命令可直接复制；
> 第二部分（§九~§十二）给 AI 代理——精确到 `文件:行` / 函数名 / grep 判据，可当任务书直接派发。
> 配套：`docs/fork-diff/latest.md`（差异清单）· `docs/self-developed-features.zh-CN.md`（自研登记）
> · `docs/upstream-merge.zh-CN.md`（历次对账）· `docs/fork-minimization-analysis.zh-CN.md`（能否再压缩）
> · `docs/fork-notes/`（注释外置库：代码里 `详见 docs/fork-notes/*.md §N` 的落点）
> 最近演练：2026-11-11 模拟上游 v2.5.0 跑通全流程（`docs/fork-diff/drill-log.md`）

---

## 一、30 秒速览

```
① 确认版本        → ② 生成差异清单 → ③ 冲突预判 → ④ 按决策树处置 → ⑤ 过验证门 → ⑥ 归档
   上游 tag 是哪个     一条命令出账本      哪些文件会撞      六类冲突各有一条规则    九项硬判据      更新清单与对账
```

**六条铁律**（违反任何一条 = 这轮白做）：

1. **绝不「按目录取一侧」** —— 这招静默丢过上游 819 个新增文件（假追平）。
2. **没跑差异清单不许开工** —— 靠回忆判断「我们改了什么」必然漏。
3. **函数级冲突绝不机械取并集** —— 69 个冲突块取并集，8 个文件语法直接崩。
4. **自研归属只认 `self-developed-features.zh-CN.md`** —— 上游有同需求实现 ≠ 可以切过去。
5. **验证门没过不许合并** —— 「测试绿」≠「功能对」，要钉测 + 存量库冒烟 + **镜像真能构建**。
6. **`Dockerfile`/CI 脚本不跟上游照抄** —— 上游靠外部 CI 预构建前端，本仓是一条 `docker build`；
   照抄会让镜像构建挂掉，而所有 Go 测试照旧全绿（§十 B.6、§十一 C.5）。

---

## 二、第一步 · 确认版本（5 分钟）

**做什么**：定下「起点」（上次追平的版本）与「终点」（这次要追的 tag）两个 commit。

```bash
git fetch upstream --tags                        # 拉上游 tag
git tag -l 'v2.*' | sort -V | tail -5            # 看最近 5 个版本
git rev-parse <新tag>                            # 终点（40 位）
git rev-parse main                               # 起点是我们的 main tip
```

**成功判据**：拿到两个 40 位 commit（脚本只认真实存在的 commit，写错直接报错退出）。

**失败处置**：`fatal: bad revision` → 重跑 `git fetch upstream --tags`；
tag 与镜像版本号不一致 → **停下来问**，以 tag 为准；
`git merge-base <起点> <终点>` 退出码 1 → 上游重写过历史（本仓实测过），别硬 merge，走 §九 A.1。

---

## 三、第二步 · 生成差异清单（2 分钟）

**做什么**：一条命令出「账本」——改了上游哪些文件、每个归哪个自研项。

```bash
bash scripts/fork-diff.sh <起点> <终点>                  # 生成 docs/fork-diff/latest.{md,json}
bash scripts/fork-diff.sh <起点> <终点> --check          # 校验已入库的清单有没有漂移
```

**成功判据**：终端打印 `→ N 个差异路径`；清单 §三 每行都有归属（`self_dev:N` / `infra` / `docs` / `none`）；
`N` 与 `git diff --numstat <起点> <终点> | wc -l` 相等。

**失败处置**：`无法解析 base ref` → 第一步 commit 打错，重取；文件数与 `git diff` 不一致 → 脚本报错退出，把原文交给 AI 代理；
`--check` 报漂移 → 有人改了代码没重跑清单，**先重跑生成**再核对归属变化；归属大面积 `none` → 自研登记「关键符号」被改坏，见 §九 A.3。

---

## 四、第三步 · 冲突预判（10 分钟）

**做什么**：开工前分清「哪些文件一定会撞」。**这一步最省时间。**

```bash
bash scripts/fork-diff.sh <起点> <终点> --upstream-next <新tag>   # 标出上游侧也改过的文件
grep '⚠ 是' docs/fork-diff/latest.md                              # 只看会撞的
```

**成功判据**：能填出下表每一行：

| 归属 | 上游也改了？ | 处置 |
|---|---|---|
| `self_dev:N`（自研本体） | 否 | **直接保我方**，不动 |
| `self_dev:N`（自研本体） | 是 | **人工判**：走第四步决策树 |
| `none`（我们的补丁在上游文件里） | 是 | **人工判**：走第四步决策树 |
| `none` | 否 | 随便吃上游 |
| `infra` / `docs` / 测试 | 是 | 吃上游结构，补回我们的部分 |

**失败处置**：若 `⚠ 是` 超过 50 个文件，说明这版改动极大 → **分批**：基建 → 数据库 → 渲染链 → 前端，
每批单独合并并单独过验证门（第五步）。

---

## 五、第四步 · 处置冲突（主体工作）

**做什么**：每个冲突文件先**归类**，再按该类的唯一规则处理。**不许「看着办」**（机械判据与决策树见 §十 B）。

| 类型 | 一句话识别 | 唯一处置规则 | 本仓真实样本 |
|---|---|---|---|
| **功能冲突** | 上游也做了同一个功能 | 查自研登记：**登记过的保我方**（并把上游优点摘进来）；**没登记的取上游** | 回源 Host：上游 `origin_domain`+map vs 我方 `resolveUpstreamHostPlan` |
| **函数冲突** | 同一函数两边都改了 | **以新结构为骨**，逐函数把补丁挂回。**禁机械并集** | `buildHTTPHandleChain`（我方 6 个 hunk）、`generateCaddyConfigWithCertSource`（11 个） |
| **名称冲突** | 同一标识符两边语义不同 | **建对照表**再改，**禁静默改名** | `upstreams.origin_domain`（我方=三级回退第一档，上游=map 输入） |
| **结构冲突** | 上游把我们的挂点重构了 | 在新结构里找等价挂点重挂；找不到就报上来 | `db.go` 迁移通道收敛成 `newColumnsRegistry` |
| **文件冲突** | add/add、modify/delete | add/add：我方文件在自研登记里→保我方并吸收上游；否则取上游。modify/delete：跟随性改动→跟随删除；功能依赖它→保我方 | `docs/audit/2026-09-05/` 上游删除 |

### 每批做完就验一次（别攒到最后）

```bash
(cd <模块> && go build ./...)   # 该模块能编译
bash scripts/gate.sh            # 机械门（构建×7 / vet / 冲突标记 / 上游路径存在性 / 版本锚点）
```

**失败处置**：`go vet` 报 `undefined: xxx` = **补丁没挂回去**（不是语法问题），按符号名查 §十 B；
`gofmt` 报括号失衡 = 机械并集了，回滚该文件重做；冲突标记残留用 `git grep -nE '^(<<<<<<<|=======$|>>>>>>>)'` 清掉。

---

## 六、第五步 · 过验证门（30 分钟，**不许跳**）

**做什么**：跑九项硬判据，**九项全绿才算追平成功**。（完整命令、基线失败集合见 §十一 C）

| # | 验什么 | 命令 | 期望 |
|---|---|---|---|
| ① | 构建 + 静态 + 机械门 | `bash scripts/gate.sh` | `GATE: PASS` |
| ② | 冲突标记零残留 | `git grep -nE '^(<<<<<<<|=======$|>>>>>>>)'` | 无输出 |
| ③ | 上游文件一个不丢 | 已含在 `gate.sh` 第 4 项 | `MISSING=0` |
| ④ | 四项核心自研钉测 | 见 §十一 C.2（四条 `go test -run`） | 全部 PASS |
| ⑤ | 自研防复发判据 | `grep -rn "originDomains\|originDialOrder" internal/services/caddy.go`；`bash scripts/verify-generated-config-decodes.sh` | 无命中；`VERIFY: PASS` |
| ⑥ | 全量测试失败集合 | `go test ./internal/... ./cmd/...` | 失败数 = 基线数（§十一 C.3） |
| ⑦ | 前端 | `cd web && npx vue-tsc --noEmit && npm test -- --run` | 类型零错误 + 全 pass |
| ⑧ | 存量库冒烟 | 上一版二进制建 fixture 库 → 新版启动 | 补列幂等、无 DROP、存量值保留 |
| ⑨ | **干净 checkout 一条 `docker build` 出镜像** | 见 §十一 C.5 | 构建成功、镜像内含 `/app/ui/index.html` |

**成功判据**：九项期望值全部命中，命令 + 输出摘要记入任务档案。

**失败处置**：③ MISSING>0 = **假追平**（上游新增文件被丢），立即回滚重做；④ 钉测红 = 自研能力被切/挂丢了，
按符号名回第四步重挂；⑤ 有命中 = 上游缺陷形态混回来，按「防复发约束」逐条改回；⑥ 失败数>基线 = 分辨环境还是真失败；
⑧ 冒烟异常 = **立即回滚**（最高危）；
⑨ 构建失败 = **缺前置（最常见是前端产物）**，按 §十 B.6 判断是补我方阶段还是管道里加步骤——**不要靠本地手工跑一次 build 后把 dist 塞进上下文蒙混**（那只能骗过本地，CI 干净 checkout 照样失败）。

---

## 七、第六步 · 归档（10 分钟）

**做什么**：把账做平。`bash scripts/fork-diff.sh <新tag> main` 重跑清单（新起点=刚追平的 tag），
再 `--check` 确认可复现（退出码 0）。然后三件事：① `docs/upstream-merge.zh-CN.md` 追加一节
（版本跨度/冲突文件数/决策/验证结果）；② 需长期保留的新能力登记进 `docs/self-developed-features.zh-CN.md`
（**必须写「关键符号」**，否则下次判不出归属）；③ 踩了坑写六字段经验卡（`AGENTS.md` §10.3）进
`.npc-teams/tasks/casebook/engineering.md`。

---

## 八、出问题了怎么退（回滚点）

每步都有明确落点，可单独回退：

| 做到哪一步 | 回退方式 |
|---|---|
| 刚建分支、还没提交 | `git checkout main && git branch -D <分支>` |
| 已提交但没过验证门 | 不合并即可；分支留着做证据 |
| 已合并但冒烟失败 | `git revert <merge-commit>`（**不要** `reset --hard` 推过的主分支） |

> **绝不做**：`git push --force` 到 main、删别人分支、`git commit --no-verify` 跳机械门——`AGENTS.md` §10.1 红线。

---

# 第二部分 · 机械判据（给 AI 代理）

> **任务书级判据，每条可照抄执行**；路径相对仓库根。

## 九、环境与准备（附录 A）

### A.1 上游重写过历史（`git merge-base` 退出码 1）
**判据**：`git merge-base <起点> <终点>` 退出码 **1**。**处置**（graft 桥接，实测有效）：
```bash
git replace --graft <终点> <真实共同祖先>   # 例：git replace --graft 0cd475ed 9c759716
git merge-base <起点> <终点>                # 应输出 <真实共同祖先>
git merge --no-commit --no-ff <终点>
git replace -d <终点>                       # **提交前必须删除**，否则污染提交对象关系
```
**判据**：合并提交双亲含 `<终点>`，且 `git replace -l` 为空（graft 已清）。

### A.2 脚本可移植性与 zsh 陷阱
`bash scripts/fork-diff.sh --help`（用法）· `--check`（退出码 0 = 未漂移）。**判据**：只依赖 `git bash awk sort sed grep cut paste join mktemp diff`，
无 `jq` 也能跑；干净 `git clone` 里同样通过。zsh 下 `grep --include='*.go'` 必须带引号（不加引号报 no matches found 且**退出码 0**＝假通过）。

### A.3 自研登记文件维护（决定归属判定能否成立）
归属判定读 `docs/self-developed-features.zh-CN.md` 两处：① 一览表「关键符号」列；② 每项「**代码位置**」的缩进子条目。改完必跑：
`bash scripts/fork-diff.sh 0cd475ed main` 后查 JSON 的 `summary.by_feature`。**判据**：每个 `feature_N` ≥ 1；
为 0 或 `none` 激增 → 符号写错或条目被删。符号须本能力独有、长度 ≥ 8、含大写或下划线；`manual`/`file` 这类通用词不可用。

### A.4 注释外置锚点可跳转（2026-11-11 新增）
`bash scripts/check-doc-anchors.sh` → `ANCHORS: PASS`。**判据**：代码里每条 `详见 docs/... §N`
在目标文档都有对应标题；`docs/fork-notes/` 下每份文档都在其 `README.md` 索引里。
**处置**：锚点 MISSING → 补标题或改锚点（**不许删锚点了事**，那等于丢知识）；NOT INDEXED → 补索引行。

## 十、六类冲突 · 机械判据与决策树（附录 B）

### B.0 先判定「这个文件属于哪一类」
```bash
bash scripts/fork-diff.sh <起点> <终点> --upstream-next <新tag>    # 归属 + 上游是否同改
grep '⚠ 是' docs/fork-diff/latest.md
git merge-tree --write-tree --merge-base=<真实共同祖先> <起点> <终点> | head -30   # 冲突预演
```
**判据**：冲突文件 = `git merge-tree` 输出里 `CONFLICT` 行涉及的文件；逐个按 B.1–B.5 分类。

### B.1 功能冲突（上游也实现了同一功能）
**机械判据**（三条任一命中即命中）：① `git diff --name-only <起点> <新tag> | grep -F -f <(git diff --name-only <起点> <终点)`
（落点同改）；② `grep 'self_dev:' docs/fork-diff/latest.md | cut -d'|' -f2`（在登记里）；
③ `git grep -n 'origin_domain\|response_mode' <新tag> -- internal/services/caddy.go`（同语义符号）。

**决策树**：`在 self-developed-features.zh-CN.md 有登记？`
`├ 有 → 保我方`：逐条核对「防复发约束」并把上游优点移植进来（例：`health_check_host` / SNI 剥端口）；
判据＝登记文件里所列 grep 判据全过。`└ 无 → 取上游`：判据＝`go build` + `go vet` 无 `undefined`，旧测试按上游语义重写。

**真实反例**：2026-10-11 曾把回源 Host 切成上游 `origin_domain`+map（理由「上游零新模块」），2026-11-11 董事长裁定恢复自研并登记为第 4 项。
教训：**上游有同需求实现不构成切换理由**（缺陷实证见 `upstream-origin-host-compare.zh-CN.md` §2.4）。

### B.2 函数冲突（同一函数两边都改）
**机械判据**：对 `<file>` 分别跑 `git diff <起点> <终点> -- <file> | grep -E '^@@' | sed 's/@@[^@]*@@ *//' | sort -u`
与同一命令换 `<新tag>`，两输出出现同名函数即命中。

**处置（唯一手法）**：① 用上游版本**整函数替换**（`git checkout <新tag> -- <file>` 后重做我方改动）；
② 按符号定位**逐条挂回**（不整段贴回）；③ 验证 `gofmt -l <file>`（无输出）+ `go build` + `go vet`（无 `undefined`）。

**禁令**：`--union` 或保留双方文本块 —— 实测 69 个函数级块取并集后 8 个文件 `gofmt` 报 `expected '('`。
**声明级（import / 结构体字段 / 列清单）可并集，函数体不行。** 真实样本：`caddy.go:4922 buildHTTPHandleChain`（我方 6 hunk）、
`:2125 generateCaddyConfigWithCertSource`（11 hunk）。

### B.3 名称冲突（同标识符语义分叉）
**机械判据**：`git grep -n '<标识符>' <新tag> -- internal/models internal/db internal/services` 与对 `<终点>` 的结果对照，
同名不同义即命中（例：`origin_domain` 我方=三级回退第一档 / 上游=map 输入值）。
**处置**：先建对照表（写进对账文档）再改代码。**禁令**：不得静默改名（会致存量库列丢失 / 前端字段错位）。
本仓对照表（已固化，直接复用）：

| 标识符 | 我方语义 | 上游语义 | 本轮处置 |
|---|---|---|---|
| `upstreams.origin_domain` | 自研三级回退**第一档**（上游级回源 Host） | 原生 map 的输入值 | **列名不改**（零迁移），语义按我方 |
| `lb_rules.host_header` | 规则级回源 Host（第二档） | 同名字段（上游也在用） | 保持上游名 |
| `path_rules.response_mode` | 上游三值 `''/static/redirect`（我方已采纳） | 同 | 一致，无冲突 |
| `path_rules.action` | 历史自研列 `proxy/respond` | 上游无此列 | 仅迁移读，不写 |

**判据**：迁移后按 C.4 检查列存在性；`grep -rn 'host_header' internal/` 无「列不存在」隐患。

### B.4 结构冲突（上游重构了我们的挂点）
**机械判据**：`git grep -n 'func buildHTTPHandleChain\|func runMigrations' <新tag>`（挂点函数还在否）+
`git grep -n 'newColumnsRegistry\|deadColumnDrops' <新tag> -- internal/db`（是否收敛成注册表）。

**处置**：找等价挂点重挂；**找不到就上报，不自行发明挂点**。本仓三个已确认挂点：

| 我方补丁 | 上游新结构（`0cd475ed`） | 挂点 |
|---|---|---|
| 4 个自维护列（`chain_race_interval_ms` / `chain_request_timeout_ms` / `tls_cert_path` / `tls_key_path`） | `internal/db/db.go:1167 newColumnsRegistry` | 注册表里加 4 行 |
| 渲染链 chain 分支 | `internal/services/caddy.go:4922 buildHTTPHandleChain` | 函数内 `strategy=="chain_fallback"` 分支 |
| 静态响应/3xx 强健度 | `internal/services/caddy.go` `buildStaticResponseHandler` | 函数内按状态码分派 |

**判据（挂点真生效）**：`go test -run 'TestBuildHTTPHandleChain_chainFallback_emitsChainProxy' ./internal/services/` PASS
且 `grep -c 'chain_race_interval_ms' internal/db/db.go` ≥ 3（fresh DDL / 注册表 / 重建 DDL 三处）。

### B.5 文件冲突（add/add、modify/delete）
**机械判据**：`git merge-tree --write-tree --merge-base=<base> <起点> <终点 | grep -E 'CONFLICT \((add/add|modify/delete)\)'`。
**决策树**：`add/add` → 路径在自研登记「代码位置」里？是=保我方并吸收上游新增，否=取上游；
`modify/delete` → 我方改动属跟随性（被迫随上游重构）？是=跟随上游，否=保我方并记录理由。
**真实样本**：`docs/audit/2026-09-05/` 两文档 modify/delete → 跟随删除（我方无功能依赖）。

### B.6 构建模型冲突（`Dockerfile` / CI 脚本 / `.dockerignore`）★ 2026-11-11 新增

**为什么单列一类**：`Dockerfile` 在差异清单里只是一行 `M Dockerfile`，看不出「构建模型」变了。
但它承载的是**谁负责产出什么**的契约——上游和本仓的契约可能不同，吃了没标记，直到 CI 跑挂才暴露。

**机械判据**（两条任一命中即命中）：
```bash
# ① 上游 Dockerfile 是否少了我们有的构建阶段
git show <新tag>:Dockerfile | grep -c '^FROM .* AS '   # 上游阶段数
grep -c '^FROM .* AS ' Dockerfile                       # 我方阶段数
# ② 上游是否 COPY 了「需要前置构建」的目录（本仓的典型是 web/dist）
git show <新tag>:Dockerfile | grep -nE '^COPY (web/dist|dist|build)/'
```

**本仓已知的构建模型契约（务必对齐，别吃上游形态）**：

| 维度 | 上游 v2.4.2 的模型 | **本仓必须保持的模型** | 为什么 |
|---|---|---|---|
| 前端产物 `web/dist` | 由 **GitHub Actions 先 `npm build`**，Dockerfile 只 `COPY web/dist` | **Dockerfile 内自带 `web-builder` 阶段**（`node:22-alpine` → `npm ci` → 构建） | 本仓 CI（`.cnb.yml`）是「点按钮 → 一条 `docker build`」，**没有前置 npm 步骤** |
| 取产物方式 | `COPY web/dist /app/ui` | `COPY --from=web-builder /app/web/dist /app/ui` | 上下文中没有 dist，只能从阶段里取 |
| `.dockerignore` 对前端源码 | 排除 `web/src`、`web/package.json` 等（只留 dist） | **必须放行**（`web-builder` 要 `COPY web ./web` 才能构建）；只排 `web/node_modules/`、`web/tests/` | 排掉了阶段就无源可建 |

**处置决策树**（机械可判）：
1. 上游 Dockerfile 的 `COPY` 目标是否由**阶段内**产出？
   - 是 → 取上游形态（自洽）
   - 否（依赖外部预构建）→ **保留我方阶段**，不要为了「跟上游一致」而删
2. 保留/新增当前阶段后，**同步核 `.dockerignore`**：该阶段的每条 `COPY <dir>` 的 `<dir>` 是否都在放行侧？
3. 阶段命名冲突（双方都有 `AS builder`）→ 改名我方阶段（如 `web-builder`），`COPY --from` 同步

**验证**：`§十一 C.5`（干净 checkout 的 docker build）。**沙箱无 docker 时**：至少在镜像外实跑该阶段的命令链
（如 `cd web && npm run typecheck:src && npm run build:vite`）并断言产物存在——这能证明命令链有效，但**不能替代 C.5**，
须在回报里标注「C.5 待 CI 端到端」。

**真实样本（2026-11-11 · TASK-2026-1111-04）**：
追平 v2.4.2 时 P4 吃了上游 Dockerfile 形态（删了我方 `web-builder` 阶段、改 `COPY web/dist`），
同时 `.dockerignore` 也随上游排除了前端源码。本地 `go build`/`gate.sh`/前端 `npm test` **全绿**，
但 CNB 点按钮构建在 `COPY web/dist /app/ui` 处报 `failed to calculate checksum ... "/web/dist": not found`。
修复：恢复阶段 + 恢复 `.dockerignore` 放行（一条 revert 可回）。
**教训**：`gate.sh` 的 7 模块 build 只覆盖 Go，**不覆盖镜像构建链**——所以 A 组验收全绿也拦不住它。

### B.7 TLS 透传追平注意事项（`protocol='passthrough'` · Layer4 SNI 分流）★ 2026-11-13 新增

**编译产物要素（渲染依赖，追平新上游时核对仍在）**：① `Dockerfile` 的
`--with github.com/mholt/caddy-l4@<ver>` 行（Layer4 + `matchers.tls.sni`）；
② Caddy 原生 `modules/caddyhttp/proxyprotocol`（listener wrapper 还原 PROXY v2 源 IP）。

**语法语义变动即重验**：上游 Caddy 升级若改动 `layer4` 全局选项块语法或
`matchers.tls.sni` 字段语义 → 重验 spike（`.agent_team/spike/` 五项可复用）。

**机械判据**（防复发约束全文见自研登记第 5 项）：
```bash
grep -c 'caddy-l4' Dockerfile                                # ≥ 1
grep -rn 'func validatePassthroughRule' internal/handlers/   # 命中 rule_features.go
```

## 十一、验证门命令清单（附录 C）

### C.1 机械门
`bash scripts/gate.sh` → 末行 `GATE: PASS`。含 build×7 模块 / vet / 冲突标记 / 上游 2095 路径存在性 / 版本口径九处。

### C.2 四项核心自研钉测（逐项）
```bash
go test -run 'TestUpstreamHost_|TestPathRuleUpstreamHost_' ./internal/services/                        # 第4项 回源Host
go test -run 'TestBuildHTTPHandleChain_chainFallback|TestBuildHTTPHandleChain_healthCheckHost' ./internal/services/  # 第1项 链式回退
(cd caddychain && go test ./...)                                                                      # 第1项 模块侧
go test -run 'ReferencedCert' ./internal/services/ && go test -run 'referencedCert' ./internal/handlers/   # 第2项（handlers 侧首字母小写）
go test -run 'TestSetDefaultProxyPorts|TestGenerateCaddyConfig_defaultSiteFollowsHTTPPort' ./internal/services/      # 第3项 端口换位
```
**判据**：每条输出 `ok`，无 `FAIL`。

### C.3 全量测试失败集合比对
`go test ./internal/... ./cmd/... 2>&1 | tee /tmp/t.log` → 提取 `^--- FAIL` 行排序 → 与上游 tag 原始检出的
baseline 文件 `diff`，**期望无输出**。已知基线失败：`internal/services` CRS 更新族（沙箱下载被拦）、
`internal/dnsprovider/{dnspod,tencent}` 的 `ownershipAddAndRollbackFailure`（root 下 chmod 不生效）。

### C.4 存量库冒烟（跨版本迁移必跑）
上一版源码建 fixture 库 → 新版指向该库启动（独立 `data_dir`，勿碰生产目录）→ 三条判据：
① `pragma_table_info('lb_rules')` 含 `chain_race_interval_ms` / `chain_request_timeout_ms` / `tls_cert_path` / `tls_key_path` / `host_header` 共 5 列；
② `SELECT COUNT(*) FROM upstreams WHERE COALESCE(origin_domain,'')='' AND COALESCE(host_header,'')<>''` = **0**（搬值无遗漏）；
③ 启动日志 `DROP` 出现次数 = **0**（无 DROP 自维护列）。

> ⚠️ **fixture 来源陷阱（2026-11-11 实测）**：**不要**拿上游 v2.3.6（`9c759716`）二进制建库来跑这三条迁移——
> 它的 `db.go` 根本没有自维护列，迁移全部静默 no-op，冒烟是「空跑通过」。能触发这三条迁移的是
> **本 fork 自己的历史版本库**（见 `docs/fork-notes/db-migrations.md` §4）。拿不到真实存量库时，
> 要么推迟到下次真实追平，要么自造形态并在回报里**明确标注「自造，非真实升级路径」**。

### C.5 镜像构建端到端（★ 主干第 ⑨ 项 · 2026-11-11 新增）

**为什么必须单独验**：`gate.sh` 只跑 Go 的 7 模块 build，**完全不碰 `Dockerfile`**。
而镜像构建链断掉的典型表现是「所有测试绿 + 构建挂」——TASK-2026-1111-04 就是这样漏网的。

**命令（有 docker 的环境）**：
```bash
# 在干净 checkout 上（不要在你有 web/dist 的工作区跑——脏上下文会掩盖问题）
git clone -b <分支> <repo> /tmp/lb-ci && cd /tmp/lb-ci
docker build -t lb-catchup-check . 2>&1 | tail -20
docker run --rm --entrypoint sh lb-catchup-check -c 'ls -l /app/ui/index.html /usr/local/bin/caddy /usr/local/bin/lazy-balancer'
```
**判据（三条全过）**：① `docker build` 退出码 0 ② `/app/ui/index.html` 存在（前端产物真进了镜像）
③ `caddy` 与 `lazy-balancer` 两个二进制都在。

**无 docker 时的降级证据（必须标注局限）**：
```bash
# 逐段证明「Dockerfile 里每条需要产物的指令，其生产者都在」
grep -nE '^FROM .* AS |^COPY (web/dist|--from=)' Dockerfile   # 阶段定义与取产物必须配对
# 实跑该阶段的命令链，断言产物
cd web && npm run typecheck:src && npm run build:vite && ls -l dist/index.html
# .dockerignore 是否排掉了阶段要 COPY 的源
grep -nE '^web/' .dockerignore      # 只允许 node_modules/ 与 tests/
```
降级证据能证明「命令链有效 + 阶段配对 + 上下文放行」，**不能证明 docker 真的能构建成功**——
回报里必须写「C.5 待 CI 端到端验证」，并由人点一次 CI 构建收口（TASK-2026-1111-04 即此路径）。

**本仓红线（勿改）**：`.cnb.yml` 的按钮构建是**一条 `docker build`**，没有前置 npm 步骤。
因此 `Dockerfile` 必须自带 `web-builder` 阶段；**禁止**改成「CI 先 build → Dockerfile 只 COPY dist」的上游形态。
若要改成上游形态，必须同时在 `.cnb.yml` 加 npm 构建步骤——那是另一件事，不能顺手改。

## 十二、演练记录与误判库（附录 D + 主干九）

### D.1 演练记录
见 `docs/fork-diff/drill-log.md`：以当前 `main` 为「上游」造 v2.5.0 模拟版本，按本手册走完六步（含每步实际输出）。

### D.2 常见误判（历史教训 · 原主干 §九）

| 误判 | 真实后果 | 怎么避免 |
|---|---|---|
| 「上游新功能包含我们的能力了，切上游省事」 | 丢自研独有语义（回源 Host 退化成透传客户端 Host） | 先读自研登记「防复发约束」逐条核对 |
| 「按目录整体取我方」 | 静默丢上游 819 个新增文件 | 只用 `scripts/fork-diff.sh` 的逐文件清单 |
| 「测试绿了就是追平了」 | 测试没覆盖的能力静默丢失 | 必须跑钉测 + 存量库冒烟 |
| 「函数冲突取并集最快」 | 8 个文件语法崩 | 函数级一律「上游为骨 + 逐函数挂回」 |
| 「冲突标记清了就完事」 | 13 个隐藏失配（引用已删字段但无标记） | 跑 `go vet`，`undefined` 就是未接线补丁 |
| 「拿上游旧版二进制建库就能做迁移冒烟」 | 迁移静默 no-op，冒烟空跑却显示通过 | 见 §十一 C.4 的 fixture 来源陷阱 |
| **「Dockerfile 跟上游一致更省事」** | 上游靠外部 CI 预构建前端，本仓 CI 是一条 `docker build` → **镜像构建直接挂**（`COPY web/dist` 找不到），而 `gate.sh`/全部测试照旧全绿 | 见 §十 B.6 构建模型契约 + §十一 C.5；`.dockerignore` 要同步核 |

---

## 十三、给 AI 代理的交办方式

交四样：**本手册**（第一部分定方向 + 第二部分给判据）+ 冲突文件清单
（`grep '⚠ 是' docs/fork-diff/latest.md` 的结果）+ 对应的 `docs/fork-notes/*.md`（被外置的注释原文）
+ **构建链契约提醒**（`Dockerfile`/`.dockerignore`/CI 脚本属 §十 B.6 类，交付后必须跑 §十一 C.5，
无 docker 环境须在回报里标注「C.5 待 CI 端到端」，不许当已验证）。
派活时必须写明：改哪些文件（白名单）、验证门命令、以及「自研归属只认登记文件」这条不可协商的约束。
