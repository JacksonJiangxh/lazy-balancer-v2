# fork-notes · 文件型（引用型）证书摄取（`certstore.go` + `rules.go`）

> 来源：`internal/services/certstore.go` 与 `internal/handlers/rules.go` 内我方新增的解释性注释，
> 2026-11-11 TASK-2026-1111-03 注释外置时**逐字搬迁**至此（只去注释符号、加章节号，内容未改写）。
> 涉及核心自研第 2 项（文件型证书 / 自动重载）。

**核心不变量**：引用型证书的**运行时唯一信任源是数据库**；文件路径列只是「摄取源记录」。
渲染与 TLS 就绪判定一律看库里的 `tls_cert` / `tls_key` 内容，不看文件是否存在。

---

## §1 `ResolveReferencedCertPath` 路径校验与归一

`ResolveReferencedCertPath` 校验并归一引用型证书文件路径（2026-10-09）：

- 绝对路径、位于 `certDir` 内（前缀 + 分隔符边界，防 `/app/certs-evil` 绕过）；
- 拒绝空串、目录、含 NUL 的路径；
- 文件须存在且为常规文件；
- 解析符号链接后再次校验边界（防目录内软链指向容器任意文件）。

返回归一路径用于展示与落库（保持用户输入语义），安全性由真实路径校验保证。

---

## §2 `ReferencedCertFileDigest` 变更检测指纹

`ReferencedCertFileDigest` 返回引用型证书文件对的内容指纹（含文件不存在标记）。
供「外部更新证书文件 → 自动重载」的变更检测使用：与上次快照比对，不同即视为
证书已更新。

---

## §3 `IngestMissingReferencedCerts` 启动期回填（幂等）

`IngestMissingReferencedCerts` 启动期回填：引用型证书（`tls_source="file"`）的
运行时唯一信任源是数据库——旧版本升级、旧备份还原或 v2 导入产生的「只有
摄取源路径、内容为空」的行，在本机源文件可读时摄取回填内容；不可读则保留
空内容并留痕（渲染按无证、`EnableRule` 门拒绝启用，用户重新保存即修复）。

- 返回成功回填的规则数（0 = 无可回填行或全部失败，调用方按需留警告）。

幂等：内容已非空的行不命中。

---

## §4 保存链：读文件 → 摄取内容入库 → 路径列留作摄取源

引用型证书：文件只是采集来源——校验路径边界与文件有效性后，把读取到的
PEM 内容摄取入库（`tls_cert`/`tls_key`，与 manual 同列）；路径列保留作摄取源
记录（看门狗据此检测外部更新并同步回写 DB）。

同模式可沿用存量路径（前端编辑回填已带），跨模式必须显式提供
（空路径由校验层响亮拒绝）；通过后归一落库，并把读取到的 PEM 内容摄取入库
（文件只是采集来源，运行时唯一信任源是数据库）。

---

## §5 `validateRuleListenPort` 包级端口校验（导入/还原链）

`validateRuleListenPort` 是包级规则端口校验（导入/备份还原链走此路径，无
`Handlers` 实例）。管理口口径为「出厂默认 8000/2019」——真实管理口校验由
`validateRuleListenPortForSave` 叠加（保留端口判定口径）。HTTP/HTTPS 保留端口取部署侧
默认口（`HTTP_PORT`/`HTTPS_PORT`，出厂 80/443）：改口后 TCP 规则不得再抢
服务端默认 HTTP/HTTPS 口（那是代理面本身的落点）。

---

## §6 `queryRedirectShadowConflict` 跳转遮蔽冲突（双向同判）

`queryRedirectShadowConflict` 检查 HTTP 默认口（`HTTP_PORT`，出厂 80）的跳转遮蔽：
启用中的 TLS+HTTP 跳转规则会在该口服务器头部生成 terminal 跳转路由
（`caddy.go` `redirectRoutes`），同域名直接监听该口的规则会被遮蔽为死规则。两个
方向同判：保存该口规则时查跳转规则占用；保存/启用 TLS+跳转规则时查该口规则
占用。返回冲突规则描述与冲突域名。

---

## §7 HTTP 规则端口兜底（端口 0 = 未指定）

HTTP 规则的端口兜底（端口为 0 = 未指定）：TLS 开 → HTTPS 默认口（出厂 443），
否则 → HTTP 默认口（出厂 80）。部署侧改 `HTTP_PORT`/`HTTPS_PORT` 后向导与 API
的缺省落点随动（ISSUE #7）；显式传了端口则原样使用，不做任何改写。

---

## §8 链式回退参数 0 值兜底（不引入「0 = 关闭」语义）

链式回退（2026-10-09）：0 值兜底默认参数（UI 不提供 0 = 关闭语义，避免
配置分叉；参考项目 `speculativeMs=0` 关闭语义不引入）。默认按 N=6 封顶 +
浏览器 60s 等待约束设计：5×3000+30000=45s < 60s（预算公式见 `caddy.go`，
本库 [`render-chain.md`](render-chain.md) §21）。
