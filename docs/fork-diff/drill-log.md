# 演练记录 · 上游追平手册实操验证（O3-6）

> **目的**：证明 `docs/upstream-catchup-guide.zh-CN.md` 的六步流程**真的能跑**，且每步判据有效。
> **日期**：2026-11-11 · **执行**：开发总监 · **任务**：`TASK-2026-1111-03` O3-6
> **方式**：以当前 `main`（= 上游 v2.4.2 + 四项自研）为「已追平的 fork」，在 `0cd475ed`（v2.4.2）
> 之上造一个**只含上游侧改动**的模拟版本 `v2.5.0`，然后按手册把它追平进来。
> 下文命令中的 `/tmp/...` 一律只是临时中转目录（任何系统都可替换成自己的临时目录），不构成环境依赖。
> **演练另暴露一个脚本缺陷**（已修）：`usage()` 内 `$0` 在本环境会解析成函数名 `usage`，
> 导致 `--help` 报 `awk: cannot open "usage"`。改为文件顶部存 `SELF=${BASH_SOURCE[0]:-$0}` 后修复；
> 修复后 `--help` 正常输出、其余模式回归通过（可复现性/干净 clone 均已复测）。

---

## 〇 演练设计（为什么这样造）

模拟上游 v2.5.0 = `0cd475ed` + **3 处纯上游改动**（不碰我方任何自研功能，也不改我方文件）：

| # | 改动 | 模拟的真实形态 | 想验证什么 |
|---|---|---|---|
| 1 | 新增 `internal/services/upstream_v250_probe.go`（14 行） | 上游新增能力/新文件 | ①「按目录取一侧」会不会丢它 ②`gate.sh` 路径存在性门能不能发现 |
| 2 | `caddy.go` 内部头清单 `lbInternalControlHeaders` 加一个 `X-Lb-Upstream-Probe` | 上游改了我们**也有大量补丁**的文件 | 功能冲突预判（`upstream_also_touched`）能否命中 |
| 3 | `certstore.go` 新增 `UpstreamV250CertDirAudit()` | 上游改了我们**自研能力落点**的文件（第 2 项引用型证书） | 冲突预判 + 双方实现共存验证 |

上传改动 commit：`e42c7a1d`（`git diff --stat 0cd475ed e42c7a1d` = 3 files, +20）

---

## 一 · Step1 版本确认

```bash
$ git rev-parse e42c7a1d
e42c7a1da4ce15eb4f94b8b655a956d67deca07d      # 终点
$ git rev-parse main
818467dbce26f6c233348f6263cfe83fc36b24f4      # 我方当前
$ git merge-base 0cd475ed e42c7a1d >/dev/null; echo $?
0                                             # 有共同祖先，无需 graft 桥接
```

**判据通过**：两个 40 位 commit 齐备；共同祖先存在（退出码 0，不需要走附录 A.1 的 graft 路径）。

---

## 二 · Step2 生成差异清单

```bash
$ bash scripts/fork-diff.sh 0cd475ed main --out-dir /tmp/drill
fork-diff: 0cd475ed..818467db → 92 个差异路径
```

**判据通过**：92 个差异路径，与 `git diff --numstat 0cd475ed main | wc -l` = 92 一致；
清单 §三 每行都有归属，无「未分类」。

---

## 三 · Step3 冲突预判（**本步最关键，验证 `upstream_also_touched` 有效**）

```bash
$ bash scripts/fork-diff.sh 0cd475ed main --upstream-next e42c7a1d --out-dir /tmp/drill
$ grep '⚠ 是' /tmp/drill/latest.md
| `internal/services/caddy.go` | M | backend | self_dev:1,4 | 28 | 734 | 170 | ⚠ 是 |
| `internal/services/certstore.go` | M | backend | self_dev:2 | 5 | 174 | 5 | ⚠ 是 |
```

**判据通过**：预判命中 **2 个文件**，与手工核对的结果**完全一致**：

```bash
$ comm -12 <(git diff --name-only 0cd475ed e42c7a1d | sort) \
           <(git diff --name-only 0cd475ed main | sort)
internal/services/caddy.go
internal/services/certstore.go
```

> 第 1 处改动（新增 `upstream_v250_probe.go`）**不出现在预判里**——因为它是纯上游新增，
> 我方没有这个文件，不会冲突。这正是 `upstream_also_touched` 字段该有的行为：
> **只标「双方都动过」的，不把纯上游新增误报成冲突**。

按手册 §四 的判据表分类：
- `caddy.go`：`self_dev:1,4` + 上游同改 → **人工判**（走功能/函数冲突决策树）
- `certstore.go`：`self_dev:2` + 上游同改 → **人工判**
- `upstream_v250_probe.go`：上游纯新增，我方无 → **直接吃**

---

## 四 · Step4 处置冲突

```bash
$ git checkout -b drill/catchup-v2.5.0 main
$ git merge --no-commit --no-ff e42c7a1d
Auto-merging internal/services/caddy.go
Auto-merging internal/services/certstore.go
Automatic merge went well; stopped before committing as requested
```

**结果：零冲突标记**（两处改动在文件内不同位置，git 自动合并成功）。这在真实场景里
很常见——**「上游同改」≠「一定冲突」**，预判的作用是让人提前知道该重点看哪几处，而不是
断定必然冲突。逐项人工核对（手册 B.1/B.2 判据）：

| 文件 | 上游改动位置 | 我方改动位置 | 是否语义冲突 | 处置 |
|---|---|---|---|---|
| `caddy.go` | `lbInternalControlHeaders` 数组末尾（:4855） | 分散在 28 个 hunk（渲染链/回源Host/chain/静态响应） | **否**（数组追加 vs 别处逻辑） | 双方共存，自动合并 |
| `certstore.go` | 文件头部新增审计函数（:25） | `ResolveReferencedCertPath`(:52) 等函数体 | **否**（新增函数 vs 既有函数体） | 双方共存，自动合并 |
| `upstream_v250_probe.go` | 新增文件 | 无 | 无 | 直接吸收 |

**共存验证（手册要求的「挂点真生效」判据）**：

```bash
$ ls internal/services/upstream_v250_probe.go          # 上游新文件在
-rw-r--r-- 1 root root 593 ... upstream_v250_probe.go

$ grep -n 'X-Lb-Upstream-Probe\|X-Lb-Security-Timing-Start-Ns' internal/services/caddy.go
4853:	"X-Lb-Security-Timing-Start-Ns",
4855:	"X-Lb-Upstream-Probe",                            # 上游新增在

$ grep -c 'resolveUpstreamHostPlan\|buildChainProxyConfig\|lb_upstream_host' internal/services/caddy.go
13                                                    # 我方自研符号全在

$ grep -n 'func UpstreamV250CertDirAudit\|func ResolveReferencedCertPath' internal/services/certstore.go
25:func UpstreamV250CertDirAudit() string { return certDir }    # 上游新增在
52:func ResolveReferencedCertPath(rawPath string) (string, error) {   # 我方自研在
```

**判据通过**：上游 3 处改动全部落地，我方四项自研符号零丢失。

---

## 五 · Step5 验证门（八项）

| # | 项 | 命令 | 结果 | 判定 |
|---|---|---|---|---|
| ① | 机械门 | `bash scripts/gate.sh` | `modules build OK=7/7` / `vet OK` / `conflict markers: 0` / `upstream paths total=2095 missing=0` / 版本锚点 9 处 ok / **`GATE: PASS`** | ✅ |
| ② | 冲突标记 | 含在 gate 第 3 项 | `conflict markers: 0` | ✅ |
| ③ | 上游文件一个不丢 | gate 第 4 项 | `2095 missing=0` | ✅ |
| ④ | 四项自研钉测 | 见下 | 全 `ok` | ✅ |
| ⑤ | 自研防复发判据 | `grep -rn "originDomains\|originDialOrder" internal/services/caddy.go` + `verify-generated-config-decodes.sh` | 命中 **0**；`VERIFY: PASS` | ✅ |
| ⑥ | 全量测试失败集合 | 6 个核心包 | 4 项失败，**与 main 基线逐条一致** | ✅ |
| ⑦ | 前端 | `npx vue-tsc --noEmit` + `npm test -- --run` | 类型 EXIT=0；**1601 pass / 0 fail** | ✅ |
| ⑧ | 存量库冒烟 | — | **本轮未实跑**（见下「盲区如实标注」） | ⚠️ 盲区 |

### ④ 四项自研钉测明细

```
$ go test -run 'TestUpstreamHost_|TestPathRuleUpstreamHost_' ./internal/services/
ok  	lazy-balancer-v2/internal/services	2.174s        # 第4项 回源 Host
$ go test -run 'TestBuildHTTPHandleChain_chainFallback|TestBuildHTTPHandleChain_healthCheckHost' ./internal/services/
ok  	lazy-balancer-v2/internal/services	0.249s        # 第1项 链式回退
$ (cd caddychain && go test ./...)
ok  	lazy-balancer-v2/caddychain	(cached)              # 第1项 模块侧
$ go test -run 'referencedCert' ./internal/handlers/ && go test -run 'ReferencedCert' ./internal/services/
ok  	lazy-balancer-v2/internal/handlers	1.217s        # 第2项 引用型证书
ok  	lazy-balancer-v2/internal/services	1.417s
$ go test -run 'TestSetDefaultProxyPorts|TestGenerateCaddyConfig_defaultSiteFollowsHTTPPort' ./internal/services/
ok  	lazy-balancer-v2/internal/services	0.440s        # 第3项 端口换位
```

> **手册勘误（本演练发现）**：附录 C.2 第 2 项原写 `go test -run 'ReferencedCert' ... ./internal/handlers/`，
> 实际 handlers 侧测试名是 `TestCreateRule_referencedCertFileIngestsContent` 等（小写 r 开头），
> 大写的 `ReferencedCert` 在 handlers 包**匹配不到任何测试**（输出 `no tests to run`）。
> **已在附录里改为 `referencedCert`（区分大小写）**——这正是演练的价值：不跑一遍发现不了。

### ⑥ 失败集合基线比对（4 项，全部是既有失败）

```
追平分支：                     main 基线（git worktree 独立检出复跑）：
--- FAIL: TestApplySnapshot_ruleLogCleanupFailureDoesNotFailSync      --- FAIL: 同名（同样失败）
--- FAIL: TestTaskLogsHousekeeping_countsMetadataFailures             --- FAIL: 同名（同样失败）
--- FAIL: TestCaddyProcessControlAllowedOutsideImportWindow           --- FAIL: 同名（同样失败）
--- FAIL: TestGetClusterWafFiles_409DuringImportWindow                --- FAIL: 同名（同样失败）
```

**判据通过**：失败集合在追平分支与基线**逐条一致**，无我侧独有失败。
（这 4 项与 `docs/upstream-merge.zh-CN.md` §12.7 登记的既有失败同族。）

### ⑧ 盲区如实标注

存量库冒烟未实跑，理由：本次模拟上游**没有任何 DB schema 改动**（3 处改动全在 Go 逻辑层，
无新增/改名/删除列）。冒烟要验的「补列幂等 / 搬值完整 / 无 DROP」三项在本次无被测对象。
**真实追平若含 DB 改动，此项必跑**（判据见附录 C.4 三条）。不把它标成「已通过」是刻意的。

---

## 六 · Step6 归档

```bash
$ bash scripts/fork-diff.sh e42c7a1d drill/catchup-v2.5.0 --out-dir /tmp/drill2
fork-diff: e42c7a1d..7d86e6aa → 92 个差异路径
$ bash scripts/fork-diff.sh e42c7a1d drill/catchup-v2.5.0 --out-dir /tmp/drill2 --check
fork-diff: CHECK PASS —— 清单未漂移（92 个文件）   # 退出码 0
```

**判据通过**：新起点（`e42c7a1d`）下差异仍是 92 个文件（我方 fork 的固有改动量），
`--check` 退出码 0 证明清单可复现。

**反假追平交叉验证**：追平后我方相对新上游的差异 = 92 文件 / +14880 行，
与追平前（对 v2.4.2 的 92 文件 / +14879 行）**几乎相同**（多 1 行 = `upstream_v250_probe.go`
被上游带进基线、我方不再计入差异）。这说明**上游 3 处改动已全部进入基线，我方没有多吃/少吃**。

---

## 七 · 演练结论

| 项 | 结论 |
|---|---|
| 六步流程 | **可执行**，每步都有明确的机械判据，无需人工解释 |
| 冲突预判（`upstream_also_touched`） | **准确**：命中 2 个真同改文件，纯上游新增的 1 个文件未误报 |
| 五类冲突决策树 | **可判**：本次命中「文件冲突（纯新增）」+「同改但语义不冲突」，两条判据均给出正确处置 |
| 验证门 | **八项中七项已实跑通过**；第 8 项（存量库冒烟）在无 DB 改动的场景下无被测对象，已如实标注盲区 |
| 手册可用性 | **可用**，并发现 1 处勘误（附录 C.2 测试名大小写），已修 |
| 未覆盖的形态 | 真正的**冲突标记**（本次自动合并成功）、**函数级并集陷阱**、**modify/delete**、**上游重写历史（graft）**——这四种在本仓历史轮次里发生过（见 `docs/upstream-merge.zh-CN.md` §十），手册里以真实样本形式记录，但本轮未再复现 |

---

## 八 · 演练产物清理

| 产物 | 处理 |
|---|---|
| 分支 `drill/upstream-v2.5.0-sim`（模拟上游，commit `e42c7a1d`） | **已删除** |
| 分支 `drill/catchup-v2.5.0`（演练追平结果，commit `7d86e6aa`） | **已删除** |
| worktree `/tmp/baseline-wt`（基线复跑用） | **已移除** |
| `internal/services/upstream_v250_probe.go` 等 3 处模拟改动 | 只在演练分支上，主线**零残留**（`git status` 可核） |

> 清理命令与核验见任务档案 §7 的自测证据；主线 `main` 上不存在任何演练文件。
