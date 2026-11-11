# fork-notes · 自维护列与结构体字段（`internal/models/models.go`）

> 来源：`internal/models/models.go` 内我方新增的解释性注释，2026-11-11 TASK-2026-1111-03
> 注释外置时**逐字搬迁**至此（只去注释符号、加章节号，内容未改写）。
> 涉及核心自研第 1 项（静态响应）、第 2 项（文件型证书）、第 3 项（链式回退）、第 4 项（回源 Host）。

**自维护列总原则**：这些列是**我们自己加的**、上游没有。上游同名/近名重构时
必须查 `docs/self-developed-features.zh-CN.md` 决定归属，禁静默改名（会破库）。
列登记与 DDL 的位置见 `internal/db/db.go`（该文件不在本任务白名单内，仅作指引）。

---

## §1 链式回退竞速参数（`strategy=chain_fallback`，仅 HTTP）

链式回退（`strategy=chain_fallback`，仅 HTTP）竞速参数（2026-10-09）：
`ChainRaceIntervalMS` 竞速间隔——等待该时长无有效响应即并行发出下一路；
`ChainRequestTimeoutMS` 单请求兜底截断——超过该时长未收到响应头即取消
该路。0 值在写侧（`CreateRule`/`UpdateRule`）与渲染侧兜底 3000/30000
（预算公式：(N−1)×race+timeout ≤ 60s，按 N=6 封顶设计，见 `caddy.go`）。

---

## §2 `TLSCertPath` / `TLSKeyPath` 摄取源路径（运行时信任源是 DB）

`TLSCertPath` / `TLSKeyPath` 引用型证书（`tls_source="file"`）：`/app/certs` 内成品
证书文件的摄取源路径——保存时读取并校验，PEM 内容入库（`tls_cert`/`tls_key`，
与 manual 同列）；数据库是运行时唯一信任源，路径仅供看门狗检测外部更新。
