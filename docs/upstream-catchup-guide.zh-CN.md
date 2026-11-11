# 上游追平作业手册（主干 · 给决策者）

> **何时用**：上游发新版，要把它吃进来且四项核心自研不被切掉。**怎么用**：从上到下照做。
> **要动手改代码**：本手册 + 附录（`docs/upstream-catchup-guide-appendix.zh-CN.md`，精确到 `文件:行`）一起交 AI 代理。
> 配套：`docs/fork-diff/latest.md`（差异清单）· `docs/self-developed-features.zh-CN.md`（自研登记）
> · `docs/upstream-merge.zh-CN.md`（历次对账）· `docs/fork-minimization-analysis.zh-CN.md`（能否再压缩）
> 最近演练：2026-11-11 模拟上游 v2.5.0 跑通全流程（`docs/fork-diff/drill-log.md`）

---

## 一、30 秒速览

```
① 确认版本        → ② 生成差异清单 → ③ 冲突预判 → ④ 按决策树处置 → ⑤ 过验证门 → ⑥ 归档
   上游 tag 是哪个     一条命令出账本      哪些文件会撞          五类冲突各有一条规则    八项硬判据      更新清单与对账
```

**五条铁律**（违反任何一条 = 这轮白做）：

1. **绝不「按目录取一侧」** —— 这招静默丢过上游 819 个新增文件（假追平）。
2. **没跑差异清单不许开工** —— 靠回忆判断「我们改了什么」必然漏。
3. **函数级冲突绝不机械取并集** —— 69 个冲突块取并集，8 个文件语法直接崩。
4. **自研归属只认 `self-developed-features.zh-CN.md`** —— 上游有同需求实现 ≠ 可以切过去。
5. **验证门没过不许合并** —— 「测试绿」≠「功能对」，要钉测 + 存量库冒烟。

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
`git merge-base <起点> <终点>` 退出码 1 → 上游重写过历史（本仓实测过），别硬 merge，走附录 A.1。

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
`--check` 报漂移 → 有人改了代码没重跑清单，**先重跑生成**再核对归属变化；归属大面积 `none` → 自研登记「关键符号」被改坏，见附录 A.4。

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

**做什么**：每个冲突文件先**归类**，再按该类的唯一规则处理。**不许「看着办」**（机械判据与决策树在附录 B）。

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

**失败处置**：`go vet` 报 `undefined: xxx` = **补丁没挂回去**（不是语法问题），按符号名查附录 B；
`gofmt` 报括号失衡 = 机械并集了，回滚该文件重做；冲突标记残留用 `git grep -nE '^(<<<<<<<|=======$|>>>>>>>)'` 清掉。

---

## 六、第五步 · 过验证门（30 分钟，**不许跳**）

**做什么**：跑八项硬判据，**八项全绿才算追平成功**。（完整命令、基线失败集合见附录 C）

| # | 验什么 | 命令 | 期望 |
|---|---|---|---|
| ① | 构建 + 静态 + 机械门 | `bash scripts/gate.sh` | `GATE: PASS` |
| ② | 冲突标记零残留 | `git grep -nE '^(<<<<<<<|=======$|>>>>>>>)'` | 无输出 |
| ③ | 上游文件一个不丢 | 已含在 `gate.sh` 第 4 项 | `MISSING=0` |
| ④ | 四项核心自研钉测 | 见附录 C.2（四条 `go test -run`） | 全部 PASS |
| ⑤ | 自研防复发判据 | `grep -rn "originDomains\|originDialOrder" internal/services/caddy.go`；`bash scripts/verify-generated-config-decodes.sh` | 无命中；`VERIFY: PASS` |
| ⑥ | 全量测试失败集合 | `go test ./internal/... ./cmd/...` | 失败数 = 基线数（附录 C.3） |
| ⑦ | 前端 | `cd web && npx vue-tsc --noEmit && npm test -- --run` | 类型零错误 + 全 pass |
| ⑧ | 存量库冒烟 | 上一版二进制建 fixture 库 → 新版启动 | 补列幂等、无 DROP、存量值保留 |

**成功判据**：八项期望值全部命中，命令 + 输出摘要记入任务档案。

**失败处置**：③ MISSING>0 = **假追平**（上游新增文件被丢），立即回滚重做；④ 钉测红 = 自研能力被切/挂丢了，
按符号名回第四步重挂；⑤ 有命中 = 上游缺陷形态混回来，按「防复发约束」逐条改回；⑥ 失败数>基线 = 分辨环境还是真失败；
⑧ 冒烟异常 = **立即回滚**（最高危）。

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

## 九、常见误判（历史教训）

| 误判 | 真实后果 | 怎么避免 |
|---|---|---|
| 「上游新功能包含我们的能力了，切上游省事」 | 丢自研独有语义（回源 Host 退化成透传客户端 Host） | 先读自研登记「防复发约束」逐条核对 |
| 「按目录整体取我方」 | 静默丢上游 819 个新增文件 | 只用 `scripts/fork-diff.sh` 的逐文件清单 |
| 「测试绿了就是追平了」 | 测试没覆盖的能力静默丢失 | 必须跑钉测 + 存量库冒烟 |
| 「函数冲突取并集最快」 | 8 个文件语法崩 | 函数级一律「上游为骨 + 逐函数挂回」 |
| 「冲突标记清了就完事」 | 13 个隐藏失配（引用已删字段但无标记） | 跑 `go vet`，`undefined` 就是未接线补丁 |

---

## 十、给 AI 代理的交办方式

交三样：**本手册** + **附录**（`docs/upstream-catchup-guide-appendix.zh-CN.md`）+ 冲突文件清单
（`grep '⚠ 是' docs/fork-diff/latest.md` 的结果）。附录含：A 环境准备 · B 五类冲突机械判据与决策树
（精确到 grep 命令 / `文件:行` / 函数名）· C 验证门命令与基线失败集合 · D 演练记录。
