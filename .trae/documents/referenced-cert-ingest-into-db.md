# 引用型证书「摄取入库」改造：DB 恢复为唯一信任源

## Context

上游审计指出 `tls_source="file"`（引用型证书）违反项目设计原则「数据库为唯一事实源」：当前实现里 DB 只存路径，证书内容的真相在文件里，Caddy 直接引用外部路径，看门狗只做「指纹比对 → 强制重载」，内容从未入库。

用户裁定的新语义：**引用文件只是采集来源，程序运行时唯一读取 DB**。
- 保存规则时：按路径读取并校验证书/私钥文件 → 把 PEM 内容写入 `lb_rules.tls_cert/tls_key`（与 manual 模式同列，schema 无需迁移）；
- 渲染/物化/集群/备份：file 模式与 manual 模式完全同流（DB 内容 → 物化 `/app/certs/{rule}.crt/.key` → 引用物化路径）；
- 看门狗：检测文件指纹变化 → 读取+校验新内容 → 回写 DB（审计留痕）→ 走 cert-aware 强制应用（普通 apply 会因渲染 JSON 同字节被 errSameConfig 短路，先例：caddy.go `ApplyConfigFromTxCertAwareForce` R72 W1-1 注释）。

`tls_cert_path/tls_key_path` 列保留，语义改为「摄取源路径记录」（看门狗与展示仍需要），前端继续只传路径。

## 改动清单（按实施顺序）

### 1. 保存路径摄取（handlers）
- [internal/handlers/rules.go](file:///workspace/internal/handlers/rules.go) `CreateRule` ~L850-862：现置 `req.TLSCert/TLSKey=""`，改为把 `validateReferencedCertificateFiles`（[helpers.go:75-84](file:///workspace/internal/handlers/helpers.go#L75-L84)，已返回 `CertPEM/KeyPEM`）的结果写入 `req.TLSCert/TLSKey`。INSERT 语句已含两列，无需改 SQL。
- `UpdateRule` ~L1616-1639 同上回填；核对 ~L1776-1783 条件式 SQL（`req.TLSCert != ""` 才写列）在「仅改路径」场景的行为；L1674-1676 非 file 清 path 保留。
- [rule_features.go:1130-1134](file:///workspace/internal/handlers/rule_features.go#L1130-L1134) `EnableRule` 前置校验：file 分支从「路径齐备」改为「内容齐备」（`tls_cert/tls_key` 非空），与 manual 分支（L1126-1129）同款。

### 2. 渲染统一（caddy.go，删除 file 特例，file 行走 manual 同路）
- L1522-1527：file 分支不再只登记空 `CertMaterial`，删除分支让 file 行与 manual 一样进入 `materials` → `MaterializeCertPairs`（L1537）自动物化。
- L1968-2005：删除 file 分支 L1999-2000（直用外部路径 + 跨规则去重合并 tags），统一走 `CertFilePaths(ruleID)` 物化路径（L2003-2004 manual 基准）。共用文件去重语义随之消失（每规则各物化一份，与 manual 一致）。
- `GenerateRuleServerContext` L2637-2738：L2664 `tlsSource=="file" && path!=""` 判 hasCert、L2690 端口策略、L2719-2724 外部路径 `load_files` —— 全部并入 manual 口径（`certPresent/keyPresent` 即 `tls_cert/tls_key` 非空；恒用 `CertFilePaths`），删除 `certFilePath/keyFilePath` 变量。
- L2848-2849 单规则预览条件、L2902-2929 预览分支：删 file 半句/分支。

### 3. 启动物化（certstore.go）
- [MaterializeAllCertsFromDB](file:///workspace/internal/services/certstore.go#L491) L499 查询：`tls_source='manual'` 扩为 `tls_source IN ('manual','file')`，否则 file 行物化文件重启丢失。调用点：main.go:169、certificates.go:880（6h 对账）——核对两处行为。
- `ResolveReferencedCertPath` / `LoadReferencedCertificate` / `ReferencedCertFileDigest` 保留，作为摄取与看门狗工具。

### 4. 看门狗改为摄取回写（configwatchdog.go）
重写 `checkReferencedCertFiles`（L78-137）：
1. 查询 file 模式规则路径（保留现查询），逐条算 `ReferencedCertFileDigest`，与首轮基线比对（首扫仅建基线语义不变，`ResetReferencedCertWatch` 保留）。
2. 检出变化且 digest 为 `missing:`（文件缺失）→ 跳过回写，warn 留痕，保留 DB 旧内容（last-good）。
3. 内容变化 → 对变化规则的 path 对执行 `LoadReferencedCertificate`：校验失败（配对不匹配，外部工具更新到一半）→ 跳过本轮、warn，下轮重试；成功 → `UPDATE lb_rules SET tls_cert=?, tls_key=? WHERE caddy_id IN (…)`（同文件多规则一并回写），写序对齐 UpdateRule（持 caddy 操作锁 + 事务），并 `RecordAuditLog("system", "证书摄取", "负载规则", FormatAuditDetail(AuditRulePart(id), "来源：<path>"), "")`。
4. 回写成功后触发 cert-aware 强制应用（注入点沿用 `SetReferencedCertReload`，main.go:121-123/185 传入的函数改为 cert-aware force 变体；沿用 `TaskLogf("config-watchdog","cert-file",…)`）。
- 集群无需改：[cluster_version.go:35](file:///workspace/internal/middleware/cluster_version.go#L35) 触发器列含 `tls_cert,tls_key`，回写自动 bump 版本传播；快照/apply 全列同步（cluster_snapshot.go:755-786、cluster_apply.go:1128-1129）内容天然下发。**验证项**：从节点应用侧是否也有同 JSON 短路问题（对齐 R72 W1-1 从节点先例）。

### 5. 备份/导入兜底（轻量）
- 旧备份/旧快照的 file 行只有路径没有内容：还原时若文件在本机可读则尝试 `LoadReferencedCertificate` 摄取回填，不可读则保留行 + warn（[config_backup.go](file:///workspace/internal/handlers/config_backup.go) ~L1020 validateV2BackupRules 附近、db.go `restoreTable` L2584-2643 v2 导入同理）。
- [db.go:1674-1676](file:///workspace/internal/db/db.go#L1674-L1676) `legacyHTTPSHasCertPredicate`：file 分支「有证」判定改为检查 `tls_cert/tls_key` 内容。

### 6. 文案与文档
- [apidocs.go:80/83](file:///workspace/internal/handlers/apidocs.go#L80)：POST/PUT /rules 的 file 说明改为「保存时读取入库；外部更新文件后看门狗自动同步入库并重载」，删「不落 PEM / 形态互斥」表述（互斥实测：file 行现也持有 tls_cert/tls_key）。
- [mcpserver/server.go:253/255](file:///workspace/internal/mcpserver/server.go#L253) schema 文案同步。
- 前端：[Rules.vue:427](file:///workspace/web/src/views/Rules.vue#L427) 提示「外部更新文件后会自动重载」→「自动同步入库并重载」；types/rules.ts:105/164 注释更新。提交逻辑 L2833-2837 不改（前端继续只传路径，入库由后端完成）。

### 7. 测试
- 重写 [rule_tls_file_source_test.go:74](file:///workspace/internal/handlers/rule_tls_file_source_test.go#L74) `...PersistsPaths`：断言 PEM 内容入库（路径仍落库）；其余三个校验用例（白名单外/缺失/不配对拒绝）保留。
- 重写 [certstore_referenced_test.go:152](file:///workspace/internal/services/certstore_referenced_test.go#L152) `TestCheckReferencedCertFiles_triggersReloadOnChange`：变化 → 读文件 → 写 DB → 触发 force 应用；补「文件缺失跳过回写」「配对无效跳过（last-good）」两用例。
- 新增渲染测试（样板：certstore_test.go `matchingCertificatePair` + DB 种子模式）：file 行渲染与 manual 行同构（物化路径 load_files、内容物化落盘）。
- `MaterializeAllCertsFromDB` 补 file 行启动恢复用例。
- db_migration_test.go 旧 schema fixture 硬编码列——列保留，应原样通过，跑一遍确认。

## 验证

1. `go build ./...`
2. 定向测试：`go test ./internal/services/ -run 'Referenced|MaterializeAll|CertFiles'`、`go test ./internal/handlers/ -run 'Referenced|TlsFile|Rule'`、`go test ./internal/db/`
3. 全量回归：`go test ./...`（项目审计文化重，跑全量防连带破坏）
4. 手工冒烟（如环境可行）：保存 file 模式规则 → 查 DB `tls_cert/tls_key` 非空 → 外部改文件 → 等 60s 看门狗 → DB 内容更新 + Caddy 重载 + 审计留痕。
