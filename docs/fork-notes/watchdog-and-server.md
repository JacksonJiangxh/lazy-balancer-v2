# fork-notes · 证书看门狗与启动链（`configwatchdog.go` + `cmd/server/main.go`）

> 来源：`internal/services/configwatchdog.go` 与 `cmd/server/main.go` 内我方新增的解释性注释，
> 2026-11-11 TASK-2026-1111-03 注释外置时**逐字搬迁**至此（只去注释符号、加章节号，内容未改写）。
> 涉及核心自研第 2 项（文件型证书自动重载）、第 1/3 项的端口单源注入。

---

## §1 引用型证书外部更新自动摄取（主节点 60s 节拍）

引用型证书（`tls_source="file"`）外部更新自动摄取（摄取入库语义）：引用文件只是
采集来源——保存时已把 PEM 内容入库，运行时唯一信任源是数据库。看门狗（主节点，
60s 节拍）检测 `/app/certs` 内源文件的内容指纹变化，变化后读取并校验新内容回写
DB（`tls_cert`/`tls_key`，审计留痕），再触发强制重载：物化路径不变导致渲染 JSON
同字节，普通 apply 会被 `errSameConfig` 短路（`caddy changeConfig`），必须 force
变体让 Caddy 重新 provision TLS 证书。文件缺失/配对无效时跳过本轮摄取并留痕，
DB 保留上次有效内容（last-good），下轮重试。

---

## §2 `checkReferencedCertFiles` 扫描与首扫基线

`checkReferencedCertFiles` 扫描引用型证书规则，逐条比对证书/私钥源文件的内容
指纹；检出变化即摄取新内容回写 DB（校验失败/文件缺失跳过并留痕），任一回写
成功后触发强制重载。首扫仅建基线不摄取——避免启动/升主即产生一次多余重载。

---

## §3 与一致性检查同节拍、同主节点门（不重复查 is_master）

引用型证书文件变化检测（外部更新 `/app/certs` 内成品证书后自动摄取入库并重载）：
与一致性检查同节拍、同主节点门（从节点 Caddy 无需本地证书热更），复用
上方同一次角色查询——不另发 `is_master` 查询。

---

## §4 启动期注入代理默认口（只影响默认语义）

代理默认监听口注入渲染层（`HTTP_PORT`/`HTTPS_PORT`，ISSUE #7）：兜底站监听口、
HTTP→HTTPS 跳转 Location 判定、规则侧保留端口判定同源。只影响默认语义，
不动存量规则的 `listen_port`（那是持久化数据，保存时以面板值为准）。

---

## §5 启动期接线：证书看门狗复用同一强制重载执行体

引用型证书（`tls_source="file"`）外部更新自动摄取：看门狗检出 `/app/certs` 内
源文件变化后读取校验并回写 DB（运行时唯一信任源是数据库），再复用同一强制
重载执行体（物化路径不变导致渲染 JSON 同字节，必须 force）。

---

## §6 文件变更实时生效：退避重试与放弃告警（路径引用架构，2026-11-25）

路径引用架构（重构 JJC-20261125-001）下库只存路径、渲染层 load_files 直接读
文件，文件变更在配置 JSON 上是零字节差异——生效的唯一通道是 force 重载
（`ReloadFromDB` → `ApplyConfigForce`，`POST /load` + `must-revalidate`，
`cmd/server/main.go` 的 `certReloader` 注入 `SetReferencedCertReload`）。
`checkReferencedCertFiles` 在该链路上补齐失败韧性（基准线不得先于生效推进）：

- **基线推进出口**：扫描检出的变化只有在「强制重载成功」或「重试达上限放弃」
  后才推进基线（`referencedCertWatchState`）；校验失败/重载失败时基线回滚到
  变化前——否则一次瞬时失败会让该次变更永久消失（与 errSameConfig 短路同效
  的静默失效）。
- **退避重试**：逐规则失败账面（`referencedCertRetry`，key=caddy_id），指数
  退避 60s·2ⁿ 封顶 30min；文件再次变化（digest 变）即清零额度重开。
- **放弃与告警**：连续 5 次失败（`referencedCertRetryLimit`）→ 运行日志
  error + 任务日志（`config-watchdog`/`cert-file`）告警一次、基线钉住磁盘
  当前内容、停止重试（fail-safe 保持旧配置）；文件下次变化以新 digest 重新
  走完整链路。
- **文件缺失**：不计入失败账面（渲染层 fail-closed 已让规则下线，重试刷屏
  无意义），基线直接推进到 missing；文件恢复时 digest 不同仍会触发重载。
