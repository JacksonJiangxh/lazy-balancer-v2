# 附录 · 上游追平机械判据（给 AI 代理）

> 配合主干 `docs/upstream-catchup-guide.zh-CN.md` 使用。**任务书级判据，每条可照抄执行**；路径相对仓库根。

## A 环境与准备

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
## B 五类冲突 · 机械判据与决策树

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

## C 验证门命令清单

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

## D 演练记录
见 `docs/fork-diff/drill-log.md`：以当前 `main` 为「上游」造 v2.5.0 模拟版本，按本手册走完六步（含每步实际输出）。
