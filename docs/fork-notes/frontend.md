# fork-notes · 前端校验与规则编辑器（`web/src/`）

> 来源：`web/src/utils/ruleValidation.ts`、`web/src/utils/pathRulesEditor.ts`、
> `web/src/utils/auditActionTone.ts`、`web/src/views/Rules.vue` 内我方新增的解释性注释，
> 2026-11-11 TASK-2026-1111-03 注释外置时**逐字搬迁**至此（只去注释符号、加章节号，内容未改写）。
> 涉及核心自研第 1 项（静态响应）、第 2 项（文件型证书）、第 3 项（链式回退）。

**前端总原则**：前端校验必须与后端**逐条同口径、同顺序**，否则会出现
「前端放行、保存 400」的晚失败（用户点了保存才知道错，且不定位到行）。
后端判据单源见 [`static-response-validation.md`](static-response-validation.md)。

---

## §1 `ruleValidation.ts` 状态码白名单扩至 19 码

2026-11-11 TASK-2026-1111-01：按董事长自研口径从 11 码扩至 **19 码**——补入
3xx 五码 + 405/429/504，并保留 201（存量兼容：201 规则在旧白名单内，
移出会让存量数据连改名都保存不了；后端保存时仅打 warn 日志提醒
「Created 应创建资源并给 Location，静态短路不创建资源，建议改用 200」）。

---

## §2 `isStaticResponseBodyAllowed`：204/304 与全部 3xx 不允许带体

响应体是否被允许（204/304 与全部 3xx 不允许，RFC 9110）——与后端
`services.StaticResponseBodyAllowed` 同口径。

---

## §3 跳转目标形状判定与后端同口径

跳转目标形状判定——与后端 `isValidStaticRedirectTarget` 同口径：`http(s)://`
绝对地址（大小写不敏感）或 `/` 开头站内路径，且不含空格与控制字符。

---

## §4 `validateStaticResponseModeFields` 前端同序复刻（行内红框 = 保存被拒）

与后端 `validateStaticResponseModeFields` 逐条同口径（顺序也一致：
状态码 → 禁体码 → 长度 → 控制字符 → 格式 → 跳转目标），保证行内红框
与保存被拒是同一句话，不出现「前端放行、保存 400」的晚失败。

---

## §5 redirect 模式不读 `rule.response_status`（残留值会误伤）

redirect 恒 301（渲染侧恒写 301）。**不读 `rule.response_status`**：该字段在
redirect 表单里不展示（`applyResponseMode` 切模式时不清它），读到的常是
切换前的残留值（如 static 的 200），据此报错会误伤合法配置。后端保存门
对显式非 301 值有权威拒绝（API/MCP 直写面），UI 面无需重复。

---

## §6 `pathRulesEditor.ts` 行内校验补齐（原为 late failure）

行内校验（与后端 `validateRuleFeatures` / `ruleValidation.ts` 同口径）。

2026-11-11 TASK-2026-1111-01：static 模式此前**没有任何行内诊断**——选 3xx
不填跳转地址、非 3xx 填了跳转地址、超长/控制字符内容都只在点保存时被整组
拒绝且不定位到行（late failure）。现按后端同序补齐。

注意：redirect 模式**不读 `rule.response_status`**——该值在 redirect 表单里
不展示（`applyResponseMode` 切换模式时不清它），读到的常是切换前的残留值
（如 static 的 200）。渲染侧恒写 301，故此处只校验跳转目标本身；状态码
口径由「直接返回」模式的 static 分支与后端保存门负责。
形状判定查原串（仅空判用 `trim`）：后端按原串判定——`" http://x"`

---

## §7 `auditActionTone.ts` 证书摄取成功/失败的语气

证书摄取（引用型证书看门狗）：源文件外部更新后新内容成功入库——
与「自动检测」同族的例行自愈成功动作，success 呈现；摄取失败由
「失败」关键词派生 danger。

---

## §8 `Rules.vue` 部署侧代理默认口（`/system/ports` 覆盖）

部署侧代理默认口与面板口（`HTTP_PORT`/`HTTPS_PORT`/`PANEL_PORT`，ISSUE #7）。
出厂默认与后端一致；`onMounted` 拉取 `/system/ports` 后覆盖——保证「compose 改了
变量、面板向导默认值随动」不割裂。只影响默认语义，不迁移存量规则的 `listen_port`。

`userExplicitPort`，关闭方向的自动回 HTTP 口仍受其约束（既有语义）。
自维护合并（圈层规则）：上游此处硬编码 443/80，本仓口径须走 `proxyPorts`
动态默认口（默认端口换位能力，见 `internal/services/default_ports.go`）。

管理口 / HTTP(S) 保留口随部署配置（`/system/ports`）：管理口含面板实际口与固定
的 Caddy admin 2019；保留口取 `HTTP_PORT`/`HTTPS_PORT`（出厂 80/443）。computed
以随 `/system/ports` 异步返回更新——向导校验实时用最新值。

`stalePortHint`：编辑存量规则时，若其已存端口既非 HTTP 默认口也非 HTTPS 默认口
（说明部署侧换过口号或该规则建于换口前），提示保存语义——避免用户误以为改
compose 变量后老规则会自动跟着变（ISSUE #7：不自动迁移，手动改后保存即覆盖）。
