# fork-notes · 自研字段搬迁与列登记（`internal/db/db.go`）

> 来源：`internal/db/db.go` 内我方新增的解释性注释，2026-11-11 TASK-2026-1111-03
> 注释外置时**逐字搬迁**至此（只去注释符号、加章节号，内容未改写）。
>
> **注意**：本文件只记录**背景与语义**，不是改造方案。`db.go` 的注释**本轮不外置**
> （该文件不在 r2 白名单内；且 H2「迁移收敛」已由总经理裁决推迟，理由见
> `docs/fork-minimization-analysis.zh-CN.md` §七）。本文件存在的目的是：让追平的人
> **不必读代码就能知道这三条迁移在防什么**，从而在冲突时不做错决策。

**为什么这三条迁移最容易在追平时出事**：

1. 它们搬迁的列**上游也在动**（`origin_domain` / `host_header` / `action` 都是上游 v2.4.2
   引入或沿用的），所以迁移方向可能是**双向**的；
2. 它们的语义是「幂等 + 旧列缺失则静默返回」，**改错不报错**——静默 no-op 会让存量
   用户数据看起来"迁移成功"其实没动（`卡-20261111-10` 就是这个坑）；
3. 调用顺序有依赖：`host_header` 的搬迁**必须早于** `legacyUpstreamDeadColumns` 的 DROP。

---

## §1 `migratePathRuleActionToResponseMode`：自研 `action` → 上游 `response_mode`

`migratePathRuleActionToResponseMode` 把自研路径规则静态响应（`action='respond'`
+ `status_code`/`redirect_url`/`response_body`/`content_type`）搬迁到上游口径
`response_mode`（`''`/`static`/`redirect`）+ `response_status`/`redirect_to`/
`response_body`/`response_content_type`（上游合并 C2 决策：切上游）。

- 3xx -> `response_mode='redirect'`，`redirect_to=redirect_url`
- 其余 -> `response_mode='static'`，`response_status`/`response_content_type`
- 仅处理仍是自研遗留形态的行（`response_mode=''` 且 `action='respond'`），幂等。

旧列缺失（fresh 库 / 上游原版库）时静默返回。

---

## §2 `migrateUpstreamHostHeaderToOriginDomain`：自研 `host_header` → 上游 `origin_domain`

`migrateUpstreamHostHeaderToOriginDomain` 把自研早期逐上游回源 Host（`host_header`）
搬迁到上游口径的 `origin_domain`（上游合并 C1 决策：切上游 `origin_domain` +
原生 map）。幂等：`origin_domain` 已有值时不动（显式配置优先于遗留列）。

两列任一不存在（fresh 库 / 极端残库 / 已删列）时静默返回——
搬迁与删列都幂等，任意顺序重入都收敛到同一形态。

**调用点必须先于 `legacyUpstreamDeadColumns` 清理**（上游把 `host_header` 列入
死列即 DROP 且无搬迁，后置会丢存量值）。

---

## §3 `migrateLbRuleOriginDomainToHostHeader`：本 fork 改名列 → 上游 `host_header`

`migrateLbRuleOriginDomainToHostHeader` 把规则级回源域名从本 fork 改名列
`lb_rules.origin_domain` 搬回上游口径 `lb_rules.host_header`（2026-10-11 合并曾
改名收口，上游 v2.4.2 仍用 `host_header`——渲染/写侧全链按上游字段名消费）。

幂等：`host_header` 已有值时不动（显式配置优先）。`host_header` 列由
`newColumnsRegistry` 登记兜底保证存在；`origin_domain` 列不存在（上游原版库）
时静默返回。**先搬后留**：`origin_domain` 列本轮不删，保留人工核对窗口。

---

## §4 追平时对这三条迁移的处置规则（比注释更要紧的结论）

| 情形 | 处置 |
|---|---|
| 上游把 `origin_domain` / `host_header` 任一列改名或删除 | **停**，先把两侧列名对照表写进 `docs/self-developed-features.zh-CN.md`，再改本文件 §2/§3 的搬迁方向；**禁**按字段名猜 |
| 上游新增自己的迁移函数 | 按「结构冲突」处理（见手册附录 B.4），以新结构为骨重挂我们的三条，**保顺序依赖**（§2 的 DROP 前置） |
| 要在本机验证迁移是否真生效 | **不要**用上游旧版建库（它的库根本没这些列，见 `卡-20261111-10`）；要么拿真实存量库，要么按「补列 + 回填旧列位」自造并**在回报里标注是自造形态** |

> 最后一行是 r2 阻塞的根因记录：上游 v2.3.6（`9c759716`）的 `db.go` 不含任何自维护列，
> 其库不可能触发这三条迁移 → 强行拿它做冒烟只是"空跑通过"。详见
> `docs/fork-minimization-analysis.zh-CN.md` §七。
