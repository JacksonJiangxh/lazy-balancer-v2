# Fork 差异清单（自动生成 · 勿手工编辑）

> 由 `scripts/fork-diff.sh` 生成。**同一 ref 对重复生成逐字节一致**（无时间戳、全排序）。
> 重新生成：`bash scripts/fork-diff.sh 0cd475ed d31665db`
> 漂移检测：`bash scripts/fork-diff.sh 0cd475ed d31665db --check`
> 用法与分类规则：`bash scripts/fork-diff.sh --help`

## 一、范围与总量

| 项 | 值 |
|---|---|
| 基线（上游） | `0cd475ed` = `0cd475ed8b2e8bd130ef5a4c5ef2392db9962076` |
| 目标（我们） | `d31665db` = `d31665db995602f60fcc43b0abbbd1784395dea7` |
| 上游下一版（可选） | 未提供（`upstream_also_touched` 全为 null） |
| **差异文件数** | **92** |
| 新增 / 删除行 | **+14879 / −564** |
| 变更块（hunk）总数 | **253** |
| 自研项编号（登记文件解析） | 1,2,3,4 |

## 二、按变更类型

| 类型 | 文件数 |
|---|---|
| A | 41 |
| M | 51 |

## 三、按自研归属（`self_dev_feature`）

| 归属 | 文件数 | 含义 |
|---|---|---|
| docs | 11 | 文档 / 台账 |
| infra | 13 | 基建 / CI / 工具链 / 依赖 |
| none | 54 | 非自研：上游文件上的自维护补丁或追平适配 |
| self_dev:1 | 8 | 自研能力本体或其挂点（命中登记符号/路径） |
| self_dev:2 | 3 | 自研能力本体或其挂点（命中登记符号/路径） |
| self_dev:3 | 1 | 自研能力本体或其挂点（命中登记符号/路径） |
| self_dev:4 | 3 | 自研能力本体或其挂点（命中登记符号/路径） |

## 四、按路径域

| 域 | 文件数 | 新增 | 删除 | hunk |
|---|---|---:|---:|---:|
| backend | 19 | 1850 | 292 | 120 |
| deps | 3 | 732 | 0 | 3 |
| docs | 10 | 4247 | 0 | 9 |
| frontend | 7 | 280 | 50 | 43 |
| infra | 12 | 1637 | 2 | 14 |
| module | 4 | 906 | 0 | 4 |
| specs | 1 | 348 | 0 | 1 |
| test | 36 | 4879 | 220 | 59 |

## 五、逐文件清单

| 路径 | 类型 | 域 | 归属 | hunk | + | − | 上游同改 |
|---|---|---|---|---:|---:|---:|---|
| `.cnb.yml` | A | infra | infra | 1 | 442 | 0 | — |
| `.cnb/settings.yml` | A | infra | infra | 1 | 549 | 0 | — |
| `.cnb/web_trigger.yml` | A | infra | infra | 1 | 61 | 0 | — |
| `.codebuddy/plans/lazy-balancer-v2_CNB_\346\265\201\346\260\264\347\272\277_0e8d5861.md` | A | infra | infra | 0 | 126 | 0 | — |
| `.gitattributes` | A | infra | infra | 1 | 3 | 0 | — |
| `.github/workflows/sync-upstream-master.yml` | A | infra | infra | 1 | 171 | 0 | — |
| `.npc-teams/tasks/TASK-2026-1110-01.md` | A | docs | docs | 1 | 641 | 0 | — |
| `.npc-teams/tasks/TASK-2026-1111-01.md` | A | docs | docs | 1 | 766 | 0 | — |
| `.npc-teams/tasks/TASK-2026-1111-02.md` | A | docs | docs | 1 | 897 | 0 | — |
| `.npc-teams/tasks/casebook.md` | A | docs | docs | 1 | 26 | 0 | — |
| `.npc-teams/tasks/casebook/engineering.md` | A | docs | docs | 1 | 36 | 0 | — |
| `.npc-teams/tasks/ledger.md` | A | docs | docs | 1 | 18 | 0 | — |
| `AGENTS.md` | A | specs | docs | 1 | 348 | 0 | — |
| `Dockerfile` | M | infra | infra | 3 | 3 | 0 | — |
| `caddychain/chain.go` | A | module | self_dev:1 | 1 | 274 | 0 | — |
| `caddychain/chain_test.go` | A | test | self_dev:1 | 1 | 507 | 0 | — |
| `caddychain/go.mod` | A | deps | self_dev:1 | 1 | 149 | 0 | — |
| `caddychain/go.sum` | A | deps | self_dev:1 | 1 | 581 | 0 | — |
| `caddychain/lane.go` | A | module | self_dev:1 | 1 | 384 | 0 | — |
| `caddychain/tunnel.go` | A | module | self_dev:1 | 1 | 146 | 0 | — |
| `caddygeoip/caddy_decode_generated_config_test.go` | A | test | none | 1 | 308 | 0 | — |
| `caddygeoip/upstream_host.go` | A | module | self_dev:4 | 1 | 102 | 0 | — |
| `caddygeoip/upstream_host_test.go` | A | test | none | 1 | 216 | 0 | — |
| `cmd/server/main.go` | M | backend | none | 1 | 8 | 0 | — |
| `docs/self-developed-features.zh-CN.md` | A | docs | docs | 1 | 163 | 0 | — |
| `docs/sysconf-gov-20261013-01-\346\202\254\347\251\272\345\274\225\347\224\250\345\244\204\347\275\256\350\241\250.md` | A | docs | docs | 0 | 285 | 0 | — |
| `docs/upstream-merge.zh-CN.md` | A | docs | docs | 1 | 766 | 0 | — |
| `docs/upstream-origin-host-compare.zh-CN.md` | A | docs | docs | 1 | 649 | 0 | — |
| `go.mod` | M | deps | infra | 1 | 2 | 0 | — |
| `internal/config/config.go` | M | backend | none | 6 | 63 | 1 | — |
| `internal/config/config_test.go` | M | test | none | 1 | 10 | 0 | — |
| `internal/config/ports_test.go` | A | test | none | 1 | 58 | 0 | — |
| `internal/db/db.go` | M | backend | none | 11 | 164 | 5 | — |
| `internal/db/db_migration_test.go` | M | test | none | 1 | 4 | 0 | — |
| `internal/db/merge_migration_test.go` | A | test | none | 1 | 76 | 0 | — |
| `internal/handlers/apidocs.go` | M | backend | none | 2 | 4 | 3 | — |
| `internal/handlers/apidocs_static_response_parity_test.go` | A | test | none | 1 | 165 | 0 | — |
| `internal/handlers/b_core_regression_01_test.go` | M | test | none | 1 | 4 | 0 | — |
| `internal/handlers/general_regression_09_test.go` | M | test | none | 1 | 1 | 1 | — |
| `internal/handlers/handlers.go` | M | backend | none | 1 | 4 | 4 | — |
| `internal/handlers/helpers.go` | M | backend | self_dev:2 | 2 | 21 | 3 | — |
| `internal/handlers/rule_chain_fallback_test.go` | A | test | none | 1 | 164 | 0 | — |
| `internal/handlers/rule_features.go` | M | backend | none | 17 | 271 | 52 | — |
| `internal/handlers/rule_features_static_response_test.go` | A | test | none | 1 | 342 | 0 | — |
| `internal/handlers/rule_features_test.go` | M | test | none | 1 | 4 | 0 | — |
| `internal/handlers/rule_pathrule_response_test.go` | M | test | none | 2 | 16 | 6 | — |
| `internal/handlers/rule_tls_file_source_test.go` | A | test | none | 1 | 206 | 0 | — |
| `internal/handlers/rules.go` | M | backend | none | 27 | 143 | 35 | — |
| `internal/handlers/system.go` | M | backend | none | 1 | 30 | 0 | — |
| `internal/handlers/system_test.go` | M | test | none | 2 | 94 | 0 | — |
| `internal/handlers/tcp_dead_fields_parity_test.go` | M | test | none | 1 | 2 | 0 | — |
| `internal/mcpserver/mcp_routes_parity_test.go` | M | test | none | 1 | 1 | 0 | — |
| `internal/mcpserver/schema_static_response_parity_test.go` | A | test | none | 1 | 171 | 0 | — |
| `internal/mcpserver/server.go` | M | backend | none | 1 | 2 | 2 | — |
| `internal/middleware/cluster_version.go` | M | backend | none | 2 | 4 | 0 | — |
| `internal/middleware/middleware.go` | M | backend | none | 1 | 1 | 0 | — |
| `internal/models/models.go` | M | backend | none | 7 | 41 | 12 | — |
| `internal/models/update_rule_clear_semantics_test.go` | M | test | none | 1 | 2 | 0 | — |
| `internal/services/audit_action_mapping_test.go` | M | test | none | 1 | 3 | 2 | — |
| `internal/services/caddy.go` | M | backend | self_dev:1,4 | 28 | 734 | 170 | — |
| `internal/services/caddy_chain_fallback_test.go` | A | test | none | 1 | 170 | 0 | — |
| `internal/services/caddy_emit_config_validate_test.go` | A | test | none | 1 | 194 | 0 | — |
| `internal/services/caddy_path_upstream_host_test.go` | A | test | none | 1 | 570 | 0 | — |
| `internal/services/caddy_pathrule_response_test.go` | M | test | none | 3 | 176 | 4 | — |
| `internal/services/caddy_upstream_origin_test.go` | M | test | self_dev:4 | 8 | 626 | 159 | — |
| `internal/services/certstore.go` | M | backend | self_dev:2 | 5 | 174 | 5 | — |
| `internal/services/certstore_referenced_test.go` | A | test | none | 1 | 399 | 0 | — |
| `internal/services/cluster_snapshot.go` | M | backend | none | 1 | 2 | 0 | — |
| `internal/services/configwatchdog.go` | M | backend | none | 2 | 122 | 0 | — |
| `internal/services/default_ports.go` | A | backend | self_dev:3 | 1 | 48 | 0 | — |
| `internal/services/default_ports_test.go` | A | test | none | 1 | 158 | 0 | — |
| `internal/services/enginerole_regression_01_test.go` | M | test | none | 1 | 1 | 1 | — |
| `internal/services/render_anti_fallback_scan_test.go` | M | test | none | 6 | 65 | 8 | — |
| `internal/services/rule_write_columns.go` | M | backend | none | 4 | 14 | 0 | — |
| `internal/services/rule_write_columns_test.go` | M | test | none | 3 | 13 | 2 | — |
| `scripts/check-no-audit-artifacts.sh` | M | infra | infra | 1 | 15 | 1 | — |
| `scripts/gate.sh` | A | infra | infra | 1 | 120 | 0 | — |
| `scripts/test-all.sh` | M | infra | infra | 1 | 1 | 0 | — |
| `scripts/tests/guard-selftest.sh` | M | infra | infra | 2 | 86 | 1 | — |
| `scripts/verify-generated-config-decodes.sh` | A | infra | infra | 1 | 60 | 0 | — |
| `web/src/components/rules/PathRulesEditor.vue` | M | frontend | none | 2 | 9 | 2 | — |
| `web/src/types/rules.ts` | M | frontend | none | 6 | 19 | 0 | — |
| `web/src/utils/auditActionTone.ts` | M | frontend | none | 1 | 4 | 0 | — |
| `web/src/utils/pathRulesEditor.ts` | M | frontend | none | 2 | 37 | 5 | — |
| `web/src/utils/ruleValidation.ts` | M | frontend | self_dev:2 | 2 | 67 | 12 | — |
| `web/src/utils/strategyLabels.ts` | M | frontend | none | 3 | 7 | 2 | — |
| `web/src/views/Rules.vue` | M | frontend | self_dev:1 | 27 | 137 | 29 | — |
| `web/tests/pathRulesEditor.spec.ts` | M | test | none | 2 | 4 | 4 | — |
| `web/tests/ruleValidation.spec.ts` | M | test | none | 5 | 135 | 27 | — |
| `web/tests/rulesUi.spec.ts` | M | test | none | 1 | 3 | 1 | — |
| `web/tests/strategyLabels.spec.ts` | M | test | none | 1 | 8 | 4 | — |
| `web/tests/viewStateContracts.spec.ts` | M | test | none | 1 | 3 | 1 | — |

## 六、冲突风险排序（hunk ≥ 4 或上游同改的文件）

| 路径 | 归属 | hunk | 上游同改 | 命中符号 |
|---|---|---|---:|---|---|
| `internal/config/config.go` | none | 6 | — | — |
| `internal/db/db.go` | none | 11 | — | — |
| `internal/handlers/rule_features.go` | none | 17 | — | — |
| `internal/handlers/rules.go` | none | 27 | — | — |
| `internal/models/models.go` | none | 7 | — | — |
| `internal/services/caddy.go` | self_dev:1,4 | 28 | — | path:internal/services/caddy.go |
| `internal/services/caddy_upstream_origin_test.go` | self_dev:4 | 8 | — | path:internal/services/caddy_upstream_origin_test.go |
| `internal/services/certstore.go` | self_dev:2 | 5 | — | path:internal/services/certstore.go |
| `internal/services/render_anti_fallback_scan_test.go` | none | 6 | — | — |
| `internal/services/rule_write_columns.go` | none | 4 | — | — |
| `web/src/types/rules.ts` | none | 6 | — | — |
| `web/src/views/Rules.vue` | self_dev:1 | 27 | — | path:web/src/views/Rules.vue |
| `web/tests/ruleValidation.spec.ts` | none | 5 | — | — |

