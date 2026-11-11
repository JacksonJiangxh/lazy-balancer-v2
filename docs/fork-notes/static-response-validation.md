# fork-notes · 静态响应与链式回退校验（`internal/handlers/rule_features.go`）

> 来源：`internal/handlers/rule_features.go` 内我方新增的解释性注释，2026-11-11 TASK-2026-1111-03
> 注释外置时**逐字搬迁**至此（只去注释符号、加章节号，内容未改写）。
> 涉及核心自研第 1 项（静态响应 / 直接返回）、第 3 项（链式回退）。
> 渲染侧的对应语义见 [`render-chain.md`](render-chain.md) §23–§27。

---

## §1 `validStaticResponseStatuses` 白名单与单源纪律

`validStaticResponseStatuses` 直接返回的状态码白名单
（2026-10-10 用户裁定初版 11 码；2026-11-11 TASK-2026-1111-01 按董事长自研口径
扩至 19 码）。

**单源纪律**：本表内容必须与 `services.staticResponseStatusCodes` 逐值同集，
由 parity 钉测（`rule_features_static_response_test.go`）机械核验。校验与渲染
之所以各自持表而不直接互调：handlers → services 的依赖方向不能反转成
services → handlers，而校验需要 O(1) 查表。渲染侧另有
`services.StaticResponseIsSupportedStatus` 供其它调用方复用。

与上游 v2.4.2 的 11 码差异：补入 3xx 五码 + 405/429/504，并保留 201。
3xx 进白名单的前提是渲染侧真实写 Location 并按 RFC 9110 不带响应体
（见 `services.buildStaticResponseHandler`）。

**201 口径（r2 按总经理裁决修订）**：201 曾于 r1 被移出白名单，风控官 P1-2
指出该改法会让「存量 201 规则连改名都存不了」——因本表在 `validateRuleFeatures`
内对整条规则的每条 path_rule 执行，任何一次编辑都会整体被拒。现改回**放行**：
201 属「带体、无 Location」的普通成功响应（`StaticResponseBodyAllowed(201)` 为
true，天然成立），渲染侧 v2.4.2 从未拦截。仅在新写入时给 warn 级提示提醒语义
偏差（见 `warnStaticResponse201Semantics`），**提醒而非拦截**。

---

## §2 `staticResponseDeprecatedSemantics`：白名单子集，不是第二道门

`staticResponseDeprecatedSemantics` 登记「可保存但语义可疑」的状态码及提示文案。

与白名单的关系：本表是白名单的**子集**，不是第二道门——命中不拦截、只打
warn 日志（`services.Logf("warn", ...)`）。设计动机：201 在 RFC 9110 §15.3.2
里是「服务端已按请求创建资源并应返回其位置」，而静态短路响应不创建任何资源，
用它表达「成功」属语义误用；但存量数据里可能已有 201 规则（v2.4.2 的 11 码
白名单本就含 201），硬拒会让用户「连改名都存不了」。故取「放行 + 提醒」。

提示文案（代码内 `staticResponseDeprecatedSemantics` 的值，与注释同源）：
`201 语义为已创建资源（应带 Location 指向新资源），静态短路不创建资源，建议改用 200`。

---

## §3 `warnStaticResponse201Semantics` 纯提示、不参与拒绝判定

`warnStaticResponse201Semantics` 对命中 `staticResponseDeprecatedSemantics` 的
静态响应状态码打 warn 级日志。**纯提示，不参与任何拒绝判定**——保存流程在
校验通过后调用，日志失败绝不影响保存结果。

定位信息只有行号 + 匹配方式 + 路径：`ruleFeatureInput` 不带规则名（校验入口是
纯特性门，不持有规则标识），日志里用「路径规则」定位足够用户找到那一行。

---

## §4 `staticResponseBodyMaxRunes` 为何取 4096

`staticResponseBodyMaxRunes` 响应体长度上限（按 Unicode 码点计，与前端
`[...body].length` 同口径）。

取值理由（TASK-2026-1111-01 派活要求说明依据）：上游原值 64 字符过紧——
一段带样式的维护页 HTML 或一条结构化 JSON 错误体轻松超 100 字符，用户被迫
写「请稍后再试」这类无信息量的占位串。上限放到 4096 字符（4 KiB 量级）
的依据三条：

1. 内存面：响应体在渲染期作为 Caddy 配置字段常驻，单条规则一条路径一个
   字符串——4096 字符 × 每条规则路径数十条 = 百 KB 级，相对 Caddy 配置
   与进程常驻内存可忽略；反观放到 1 MiB 会让「配置」变成「静态资源托管」，
   那是 vhost/文件服务的职责，不是路径规则短路的职责。
2. 展示面：面板「内容」输入框单行展示、编辑器卡片高度有限；4 KiB 的正文
   在输入框内仍需折叠/滚动，再放宽只会恶化编辑体验。
3. 存储面：path_rules 属集群同步矩阵内的表，行级触发器逐行同步整行内容；
   4 KiB 单行对 SQLite 页与同步载荷都安全（同族 block_pages 内容列上限
   64 KiB，是整页 HTML 的独立特性，不可类比）。

仍「无硬上限」的诉求由「走上游 + 静态文件」满足；本特性定位是短路响应。

---

## §5 `validateStaticResponseModeFields` 两模式共用字段门

`validateStaticResponseModeFields` 是 static 与 redirect 两个模式共用的字段门
（2026-11-11 TASK-2026-1111-01 从自研 `validateStaticResponsePathRule` 提回）：
状态码白名单 → 响应体不进禁用码 → 响应体长度 → 响应体控制字符 → 响应格式
→ 跳转目标（3xx 必填且形状合法 / 非 3xx 禁携带）。

两个模式共用一份判定的理由：redirect 就是「恒 301 的 static」，若各写一份，
3xx 的 RFC 约束（禁体、Location 必填）必然在其中一处漂移。文案带行号前缀由
本函数直接给出（`index+1`），调用侧不再包一层。

`defaultStatus` 为 `response_status=0` 时的缺省归一值：static 模式给 200、
redirect 模式给 301。**必须由调用侧传入**——共用函数若写死 200，redirect 模式
会被按「200 + 跳转目标」判成误配（redirect 恒 301 是渲染侧事实）。

---

## §6 `isValidStaticRedirectTarget` 比上游多拒空格

`isValidStaticRedirectTarget` 校验跳转目标（2026-11-11 提回自研强健口径）：
站内绝对路径（`/` 开头）或绝对 URL（http/https，大小写不敏感），且不含空格
与任何控制字符。比上游原判据（仅拒 `<0x20` 与 `0x7f`）多拒**空格**——URL 中的
裸空格在 Location 头里必然被客户端截断或转义，属明确的误配形态。

---

## §7 直接返回/301 跳转的模式校验挂点（`validateRuleFeatures` 内）

直接返回/301 跳转（2026-10-10 用户裁定；2026-11-11 TASK-2026-1111-01 强健度
提回自研口径）：模式枚举 + 按模式字段门 + 与转发配置互斥。
static = 19 码白名单（含 3xx 与 201）+ 响应体上限 + 控制字符门 + 格式白名单，
选 3xx 时跳转目标必填；redirect = 恒 301、目标必填且形状合法。
判据单源在 `validateStaticResponsePathRule`（与渲染侧 services 同口径），
校验失败文案带行号由本函数补——两个模式共用同一份判定，避免双写分叉。

---

## §8 C-F2：HTTP 默认口 + TLS 跳转自环必须拒

C-F2: HTTP 默认口 + TLS 跳转自环：跳转目标 `https://host:HTTP_PORT` 与来源
同为该口，请求会被跳回自身监听器形成循环，必须在保存前拒绝（`HTTP_PORT` 在
部署侧可变，目标口随之判定）。
