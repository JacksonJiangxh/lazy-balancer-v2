# fork-notes · handlers 零星挂点（`helpers.go` / `system.go` / `rule_write_columns.go`）

> 来源：`internal/handlers/helpers.go`、`internal/handlers/system.go`、`internal/services/rule_write_columns.go`
> 内我方新增的解释性注释，2026-11-11 TASK-2026-1111-03 注释外置时**逐字搬迁**至此
> （只去注释符号、加章节号，内容未改写）。

---

## §1 `validateReferencedCertificateFiles` 校验内容并交回 PEM

`validateReferencedCertificateFiles` 校验引用型证书（`tls_source="file"`）的文件
路径与内容：路径须位于程序可读写证书目录内、文件存在可读、且证书与私钥配对
合法。返回归一后的路径、已读取的 PEM 内容（保存时摄取入库——文件只是采集
来源，运行时唯一信任源是数据库）与质量警告（不阻断，与 manual 同口径）。

---

## §2 `GetProxyPorts` 面板与前端共享部署侧端口

`GetProxyPorts` 返回部署侧代理默认口与面板口（`HTTP_PORT`/`HTTPS_PORT`/`PANEL_PORT`，
ISSUE #7）。前端新建规则向导的默认 `listen_port`、TLS 联动与保留端口校验
读此值，避免「compose 改了变量、面板新建规则还默认 80」的割裂。全部认证用户
可见（只读配置，无敏感信息）。

---

## §3 规则写路径列清单：唯一事实源 `lbRuleColumnSpecs`

规则写路径列清单与值投影唯一事实源。
此前 `CreateRule`/`DuplicateRule`/集群 apply（`insertSnapshotRules`）/快照导出
（`snapshotRules` SELECT）四处各自手写列清单，已出现形态差异（Duplicate 显式
写审计四列、Create 依赖默认）；新增列必须同时改多处，漏一处即「保存成功
但与快照/副本不同形」。

`lbRuleColumnSpecs` 是唯一手写处（规范序 = 集群镜像序，id 先行）；写侧 INSERT
列清单/语句/值投影与快照 SELECT 投影全部由此机械派生。parity 钉测
（`rule_write_columns_test.go`）把 specs 与 lb_rules schema 逐列锁死——
schema 加列而 specs 未更新即测试失败。

`lbRuleColumnSpec` 逐列定义：name 为写侧列名；`snapshotExpr` 为快照导出读侧
投影（NULL 收敛口径，与既有 `snapshotRules` 逐列一致——快照哈希主从对齐
依赖该口径，不得随意改默认值）。

`lbRuleColumnSpecs` 规范序唯一事实源。列集合必须与 lb_rules schema 完全一致
（parity 钉测强制）。
