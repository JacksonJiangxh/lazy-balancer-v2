# fork-notes · 渲染链与回源 Host（`internal/services/caddy.go`）

> 来源：`internal/services/caddy.go` 内我方新增的解释性注释，2026-11-11 TASK-2026-1111-03 注释外置
> 时**逐字搬迁**至此（只去注释符号、加章节号，内容未改写）。
> 涉及核心自研第 1 项（静态响应 / 直接返回）、第 3 项（链式回退）、第 4 项（逐上游回源 Host 三级回退）。

---

## §1 回源 Host 计划类型 `upstreamHostPlan`（四态语义）

`upstreamHostPlan` 逐上游回源 Host 三级回退计划（董事长自研第 4 项核心能力，
2026-10-09 立项；自定义路由链 2026-10-10 同源复用：自定义路由的上游行各自
携带推导出的回源 Host）。登记见 docs/self-developed-features.zh-CN.md。

四态互斥（有启用上游时恒居其一）：

- `staticHost`：全统一静态值（含仅规则级 host_header 生效的场景）——直接
  下发，不发射 handler、不需要占位符；
- `usePlaceholder`：全回退——`Host={http.reverse_proxy.upstream.hostport}`
  （等价每上游用自身 dial 地址），**恒不用 `{http.request.hostport}`**；
- `overrideMap`：混合——dial→回源 Host 映射（未收录上游由处理器未命中兜底
  回上游自身地址）；`Host={lb.upstream_host}`，由 lb_upstream_host 处理器
  在请求期惰性下发；
- `sniTarget`：TLS server_name 目标（静态值剥端口 / `{lb.upstream_sni}` /
  `""`=维持规则级 HostHeader 现状语义——全回退时规则级亦空，等价 Caddy 以
  dial host 兜底）。

三级回退优先级：上游级 > 规则级 > 上游自身 dial 地址。**绝不透传客户端
Host**——这是本自研实现相对上游 map 方案的关键区分（上游纯 http 池 + 规则
级为空时回退 `{http.request.hostport}` = 客户端 Host，属缺陷，见
`docs/upstream-origin-host-compare.zh-CN.md` §2.4）。

---

## §2 `resolveUpstreamHostPlan` 计算规则

`resolveUpstreamHostPlan` 计算启用上游集合的回源 Host 计划。DynamicDNS 规则经
`buildHTTPHandleChain` 前置校验强制单启用上游（`ErrDynamicDNSUpstreamCount`），
且动态解析 IP 逐请求变化、dial 不可预知——单上游恒落入全回退/全统一两态，
混合映射天然不出现，无需特判。

入参 `upstreams` 为「已解析逐上游回源 Host」的上游集合：主链来自 upstreams 表
（origin_domain 列，语义为自研版的逐上游回源 Host，列名保持不改以零迁移），
自定义路由链（2026-10-10）来自 `path_rules.upstreams_json` 的推导结果——两条
链共用本函数与同一三级回退口径，避免第二套解析分叉。

---

## §3 混合态收录口径（只命中规则级第二档的上游也要收录）

混合态：收录全部「有效值非空」的上游——含**只命中规则级第二档**的上游。
这一点必须与全统一态口径一致：若只收录第一档，那台「上游留空、规则级非空」
的上游会被处理器未命中兜底到自身 dial 地址，规则级回退在那台机上静默失效
（正是三级回退第二档的语义丢失）。dial 与 Caddy 的
`{http.reverse_proxy.upstream.hostport}` 同格式：`net.JoinHostPort`，见
`joinUpstreamAddress`。仅「三级全空」的上游不收录，由处理器未命中兜底回
自身地址——**绝不透传客户端 Host**。

---

## §4 `fallbackHostPlan` 三级回退第三档的唯一构造出口

`fallbackHostPlan` 三级回退第三档的唯一构造出口（全回退态）。

语义：上游级与规则级都没配回源 Host → 每上游以**自身 dial 地址**作为回源
Host（`{http.reverse_proxy.upstream.hostport}`）。这不是「用默认值替换无效库
值」，而是把合法配置状态映射到第三档；显式拒绝两类错误产物：空 Host，以及
客户端 Host（`{http.request.hostport}`）——后者正是上游 map 方案的缺陷。
收为单出口是刻意的：回退语义只有一处可改，避免两处分支各自漂移。

---

## §5 `hostPlanValueFor` 取值与兜底

`hostPlanValueFor` 从回源 Host 计划里取指定上游的有效值（含最终回退档的解析）：
静态档统一取值；混合档查 `overrideMap`（未收录项 = 该上游回退自身地址）；全回退
档返回空串表示「用自身地址」，调用侧按 `joinUpstreamAddress` 兜底。
自定义路由上游（`path_rules.upstreams_json`）的逐行值由此函数派生。

---

## §6 `lbRule` / `upstream` / `ruleWithUpstreams` 提升为包级类型的原因

`lbRule` / `upstream` / `ruleWithUpstreams` 生成期内存形态（lb_rules / upstreams
行的渲染视图）。**原为 `generateCaddyConfigFromStore` 的函数内局部类型**，因
自定义路由回源 Host 解析器 `buildPathUpstreamHostResolver`（董事长自研第 4 项
P 组）需在包级函数里读取「规则 + 其上游集合」，故提升为包级类型——定义体
逐字未变，语义与填充路径完全一致（同一函数内 `SELECT` → `append` → 渲染）。

---

## §7 `upstream` 结构体的 `OriginDomain` 字段

`upstream` 启用上游行（upstreams 表视图）。`OriginDomain` 即
`upstreams.origin_domain` 列，语义为自研版三级回退的第一档，见
`UpstreamConfig.OriginDomain` 注释。

---

## §8 `pathUpstreamHostResolver` 两类解析器（hoisted / orphan）

`pathUpstreamHostResolver` 自定义路由上游（`path_rules.upstreams_json` 里的
`address:port`）的回源 Host 解析入口。自定义路由前端不携带该字段（董事长
2026-10-10 裁定 `0c8ec276` 原话：「自定义路由的规则设定不该出现任何额外
字段，回源 Host 全程是内部逻辑」），渲染期按「该地址是否出现在统一上游集合
里」分派给两类解析器：

- `hoisted`：地址在上游表里——用该上游所属规则的上游集合整体计划（与规则
  主链同一函数、同一三级回退），即逐上游 Host 优先、规则级兜底；
- `orphan`：地址不在上游表里（外部/第三方地址）——Host 只有规则级（规则
  基础设置里的后端域名）一档，仍空才用自身地址。

两类都只回退到「规则级」与「自身地址」，**绝不透传客户端 Host**。
归属：董事长核心自研第 4 项（P 组），登记见
`docs/self-developed-features.zh-CN.md`。

---

## §9 `buildPathUpstreamHostResolver` 组装与歧义处理

`buildPathUpstreamHostResolver` 组装自定义路由上游的回源 Host 解析上下文。
数据源为统一上游集合（upstreams 表 + 其规则级 host_header），键为「主机:端口」：

- `hoisted`：地址命中集合 → 取「该地址所属规则」的上游集合整体计划里的对应值；
- `orphan`：地址不在集合 → 只有规则级一档；规则级也为空 → 自身地址。

同一 `host:port` 命中多行/多规则时取首个命中（确定性：按规则集合顺序），此时
取值来源可能与实际转发的那条不同——属配置歧义，由用户侧消歧（同一地址配成
两台上游本身即属可疑配置），不阻断渲染。

---

## §10 `decodePathUpstreamsWithResolver` 忽略存储行 `host_header` 的理由

`decodePathUpstreamsWithResolver` 解析 `path_rules.upstreams_json` 并当场定下行内
回源 Host。自定义路由的该字段全部由渲染期内部推导（董事长 2026-10-10 裁定：
规则设定不新增额外字段，只有内部逻辑）：

- 存储行里的 `host_header` 被**有意忽略**——外部负载（备份导入、API/MCP 直写）
  无法保证与统一上游集合一致，而回源 Host 属上游属性，配置真相只在 upstreams
  表；忽略它还让本特性的渲染与「前端回拨的旧值」解耦（同一份规则集合恒等价）；
- 解析结果由 resolver 分派：地址在统一上游集合里走集合整体计划（逐上游优先、
  规则级兜底），不在集合里只走规则级、再空用自身地址（`joinUpstreamAddress`）。

resolver 为 nil（无规则上下文的调用方）时行内留空，落到规则级/自身地址，
与「地址不在统一上游集合里」同口径。

---

## §11 自定义路由上游的回源 Host 解析上下文（渲染主链内）

自定义路由上游的回源 Host 解析上下文（董事长自研，2026-10-10 裁定）：
地址在统一上游集合里 → 用「该地址所属规则」的上游集合整体计划（逐上游
优先、规则级兜底）；不在集合里 → 只有规则级一档，空则用自身地址。数据源
与主链同一张表，避免第二套配置真相；自定义路由子表不新增任何字段。

---

## §12 逐上游回源 Host 的三级回退接线（渲染主链内）

逐上游回源 Host（董事长自研第 4 项，DB 列名保持 `upstreams.origin_domain`
以零迁移，语义为「自研版的三级回退第一档」）：非空时压过规则级
`HostHeader`，驱动该上游回源 Host 头与 HTTPS SNI；空 = 回退规则级/自身 dial
地址。混合态经 lb_upstream_host 处理器（`{lb.upstream_host}` /
`{lb.upstream_sni}`）在请求期下发，**绝不透传客户端 Host**。
自定义路由链（`path_rules.upstreams_json`）的该字段由
`pathUpstreamHostResolver` 在渲染期内部推导，不落库、不给前端加字段。

---

## §13 `httpDefaultPort` / `httpDefaultServer` 兜底站落点

`httpDefaultPort` / `httpDefaultServer` 是兜底站与 HTTP→HTTPS 跳转的落点：
出厂 80（`HTTP_PORT` 未改时行为与旧硬编码一致）；改 `HTTP_PORT` 后兜底站与
全部跳转路由跟随——规则本身仍是用户显式指定的端口。

---

## §14 渲染主链内的三级回退接线块

逐上游回源 Host 三级回退（董事长自研第 4 项，2026-10-09）

优先级：上游自定义 `origin_domain` > 规则级 `host_header` > 上游自身 `host:port`。
Caddy 单个 `reverse_proxy` 的请求头操作为 handler 级——同一负载池共享一个
Host 值：全统一态用静态值；全回退态用
`{http.reverse_proxy.upstream.hostport}`（等价每上游用自身地址）；混合态
（上游间取值不一致）由 lb_upstream_host 处理器（caddygeoip 模块
`http.handlers.lb_upstream_host`）在请求期按选中上游惰性下发——负载均衡/
健康检查/重试语义不变。TLS `server_name` 同源取值（混合态走
`{lb.upstream_sni}`，处理器侧剥端口）。

与上游 map 方案的关键区分：**任何回退态都不使用
`{http.request.hostport}`**（那等于透传客户端 Host，属上游缺陷）。见
`docs/upstream-origin-host-compare.zh-CN.md` §2.4 与
`docs/self-developed-features.zh-CN.md` 第 4 项。

---

## §15 回源 Host 下发（三级回退计划，恒显式设置 Host）

回源 Host 下发（三级回退计划；有启用上游时四态必居其一——恒显式设置 Host，
全回退态从「透传客户端 Host」改为「每上游用自身 `host:port`」，与程序定位
一致：默认即以回源目标身份访问）。

---

## §16 混合态 handler 顺序（lb_upstream_host 先于 reverse_proxy）

混合态：lb_upstream_host（caddygeoip 模块）须先于 `reverse_proxy` 执行——
请求期向 replacer 注册惰性占位符提供者 `{lb.upstream_host}` / `{lb.upstream_sni}`，
`reverse_proxy` 选中上游后求值（每次 attempt 先 Set 上游占位符再展开
headers/transport，重试换上游逐次重展开）。未收录上游由处理器未命中兜底
回自身地址，**绝不透传客户端 Host**。

---

## §17 SNI 取值口径与主动健康检查的已知限制

SNI 取自回源 Host 计划的 `sniTarget`（四态同源）：静态统一态 = 该值剥端口
（SNI 无端口语义，RFC 6066；Host 头侧保留端口原样）；混合态 =
`{lb.upstream_sni}`（`server_name` 占位符逐连接展开实证，
`httptransport.go:427-446`，处理器侧剥端口）；全回退态 = `""`（维持规则级
`HostHeader` 现状语义，等价 Caddy 以 dial host 兜底）。

已知限制：主动健康检查 probe 用全新 replacer（`healthchecks.go:442`），
占位符不展开 → probe 不发 SNI；项目恒 `insecure_skip_verify`，TLS 层不断
（严格 SNI 多租户上游为边角）。

---

## §18 `GenerateRuleServerContext` 按 v2.3.6 语义移植回的说明

`GenerateRuleServerContext` builds a Caddy-config-shaped map containing only
the server context hosting a single rule: the deterministic server identity
for its listen port, the same-port TLS connection policies (mirroring
`generateCaddyConfigFromStore`'s available-cert semantics), and the rule's own
certificate files.

上游 v2.4.2 在渲染重构中移除本函数（`GetRuleCaddyConfig`
改走运行配置归集），此处按 v2.3.6 语义移植回自维护面：引用型证书
（`tls_source=file`）与 `manual` 同口径判有证（内容在库即有证，路径列只是
摄取源记录），TLS 判定复用 certstore 的 ACME 就绪查询。

---

## §19 TLS 策略已就绪判定的同口径要求（Round 34 F-2）

与全量渲染 `availableCerts` 同口径（`caddy.go` 全量路径
要求 `EnableTLS`），未开 TLS 的规则不加载证书。
引用型证书与手动证书同口径：内容（`tls_cert`/`tls_key`）在库即有证，
路径列只是摄取源记录，不参与运行配置判定。

与全量渲染 `httpServersByPort` 同口径——仅 `enable_tls=1` 且
存在启用上游的规则进入 TLS 策略（无上游/关 TLS 规则在真实配置中不存在）。
证书仅有无的判断在 SQL 侧完成，不再把整列 PEM 拉进进程。

---

## §20 链式回退的车道渲染（`strategy=chain_fallback`）

链式回退（2026-10-09）：`strategy=chain_fallback` 渲染为自定义 chain_proxy
处理器（caddychain 模块）——上游按权重降序组成回退链，竞速 + 兜底截断 +
失败即切。`reverse_proxy` 专属的负载均衡/健康检查/transport/headers/回源
Host 占位符全部不发射（竞速即可用性机制；逐上游回源域名在生成侧解析后
随车道下发）。安全链/静态响应短路等链上前置 handler 不变。

---

## §21 `chainProxyDefaults` 的预算公式

`chainProxyDefaults` 与 caddychain 模块 `Default*` 常量同口径（模块侧 Provision
亦有兜底，此处显式落 JSON 便于配置可读与测试断言）。预算公式（全挂兜底最坏
情形）：总耗时 ≈ (N−1)×RaceInterval + RequestTimeout，按 N=6 封顶 + 浏览器
60s 等待约束设计：5×3000+30000=45s < 60s（15s 余量）。

---

## §22 `buildChainProxyConfig` 组装口径（权重与三级回退）

`buildChainProxyConfig` 组装 chain_proxy 处理器配置（`strategy=chain_fallback` 分支 +
JJC-20261118-002 混布池分支，mode 由 `chainProxyModeFor` 单源推导）。
上游按权重降序稳定排序（同权重保持列表顺序；`weight<=0`→1 经 `normalizedWRRWeight`
单源，满足「发射权重恒 > 0」不变量——race 模式不发射 `weights`/`weight` 键
（优先级=数组序），**wrr 模式发射逐上游 `weight` 键与顶层 `mode:"wrr"`**）；
逐上游回源域名按「上游 `origin_domain` > 规则级 `host_header` > 空 = 用 dial 地址」
三级回退解析（与 `reverse_proxy` 侧 map 方案同语义，chain 车道直接下发静态值）。

**mode 分权（2026-11-18 JJC-20261118-002 裁决 1）**：
- `strategy=chain_fallback` → `race`（竞速回退，现状语义零变化，mode 键缺省）；
- 混布池（`httpUpstreamPoolMixed`，启用池 http/https 并存）∧ 其余策略 →
  `mode="wrr"`（确定性平滑加权轮询，nginx interleave smooth WRR 同构，跨请求
  持久状态）；**渲染触发器不分策略**——混布+不允许策略的存量脏行也整池切 chain
  承载，绝不落 reverse_proxy（池级 TLS 化会使 http 上游静默 502 的历史必坏路径）；
- **404 分叉**：race 全挂/单车道直通上游 404 → 干净 404（对象存储防护，不透传
  后端报文）；wrr（含 `serveWRRDirect` 直通路径）404 **透传**（与原生对齐）——
  两模式各自钉测，禁互相复用 404 分支；
- **健康检查（2026-11-19 JJC-20261119-001 更新）**：chain 模块已落地主动健康检查
  子系统（`caddychain/health.go` `healthMonitor`）。**发射条件**：`EnableActiveHealthCheck`
  且走 chain 分支（`buildChainProxyConfig`）时发射 `health_check` 键——race/wrr 同发射
  （值域一致：interval/timeout 秒→毫秒、path 透传、lag 直传；expect_status/body 无
  规则级字段不发射）；**0/空值不发射**（存量脏行模块按缺省 30s/5s/2,3/"/" 兜底）；
  uniform 走 reverse_proxy 的路径零改动（原生 `health_checks` 组装不触碰）。原
  `mixedPoolHealthCheckError` 伴随门（混布+HC=400）**整体移除**（保存链/存量启用门/
  复制链/v2 导入链四处调用同步移除；warn 三口径退两口径）；uniform+chain_fallback+HC
  的既有「静默忽略」死配置分叉就此**收口为真探测**。**初始态**：全 healthy（先放行
  后探测收敛，重载即新实例不持久化）；**全灭不专判**：全部车道 unhealthy 时真实请求
  照常放行到全部车道（防探测器误判全站 502），502/504 收尾语义不变；**差异口径**：
  仅主动探测，被动 5xx 摘除不做（uniform 原生 HC 有被动——差异如实钉死，另立项）。
- **HTTP/1.1 恒定**：`caddychain` transport 恒 `ForceAttemptHTTP2=false`——
  `upstream_force_http1` 在链式/混布车道下无附加效果（语义已满足），不加门；
- **dns_server 不消费**：chain 模式车道走系统解析器（混布池×DynamicDNS 结构互斥，
  单上游锁）；文档钉死不静默宣称；
- **隧道 Hijack 约束**（卡-20261118-02）：升级请求经 `serveTunnel`，取客户端连接
  必须 `http.NewResponseController(w).Hijack()`——真实引擎 writer 为
  `*caddyhttp.IdleTimeoutWriter` 包装（不实现 `http.Hijacker`），类型断言必失败。

---

## §23 `StaticResponseStatusCodes` 集合口径（19 码，唯一权威）

`StaticResponseStatusCodes` 直接返回模式支持的状态码清单（前端下拉与 API 文档
同源获取，后端为唯一权威）。

归属：2026-10-09 自研 `respondStatusCodes`（16 码，`5ee2a96a^:internal/services/
caddy.go:2961-2966`）；上游 v2.4.2 为 11 码（无 3xx）；2026-11-11
TASK-2026-1111-01 按董事长裁定提回自研口径并把 3xx 五码补齐。

集合口径（**19 码**，本注释为唯一权威口径，其余位置一律引用本数）：
200/201/204 成功 + 301/302/303/307/308 重定向（必须带 Location，按 RFC 9110
不带消息体）+ 400/401/403/404/405/410/429 客户端错误 + 500/502/503/504 服务端
错误。

**201 的保留理由（r2 修订）**：上游 v2.4.2 的 11 码本含 201，本任务 r1 曾把它
移出白名单，风控官 P1-2 指出后果是「存量 201 规则连改名都保存不了」（白名单
校验对整条规则的每条 path_rule 执行）。现改回保留：201 属「带体、无 Location」
的普通成功响应（`StaticResponseBodyAllowed(201)` 为 true，天然成立），渲染侧
行为与上游一致；保存侧仅打 warn 级日志提醒语义（Created 应创建资源并给
Location，静态短路不创建资源，建议改用 200），**提醒而非拦截**。

---

## §24 `staticResponseDefaultContentType` 兜底值取自研口径的理由

`staticResponseDefaultContentType` 静态响应带体且未指定内容类型时的兜底值。
自研口径为 `text/html; charset=utf-8`（自研 `defaultRespondContentType`）；
上游为 `text/plain`。取自研值：短路响应最常见用途是维护公告/错误页，
带 charset 的 HTML 是浏览器可直接渲染的形态；显式选了纯文本的用户
仍会写入 `text/plain`，不受兜底影响。

---

## §25 `staticResponseDefaultContentTypeFor` 按用户选择给渲染值

`staticResponseDefaultContentTypeFor` 按用户选择的内容类型给出渲染值：
空 = 兜底 HTML（带 charset）；`text/plain` 与 `application/json` 补 charset/
不加参数（json 无 charset 语义，RFC 8259 规定 UTF-8 无需标注）。

---

## §26 `buildStaticResponseHandler` 语义（redirect / static 两模式）

`buildStaticResponseHandler` 渲染路径规则的直接返回/301 跳转 handler（全原生
`http.handlers.static_response`）。

语义（2026-11-11 TASK-2026-1111-01 按董事长自研口径改造）：

- `redirect` 模式 = 恒 301 + Location + 无体（行为与改造前完全一致，不回归）；
- `static` 模式 = 按 status 分派必备响应头（3xx→Location、401→WWW-Authenticate、
  405→Allow、带体→Content-Type），3xx 与 204 不带体（RFC 9110）；
- 响应体操 placeholder 转义后原样输出（`{` 转义为 `\{`，否则用户 JSON/
  模板里的花括号会被 Caddy 占位符替换静默吞掉）。

改造前上游实现的缺陷（本轮修复）：static 模式恒写 Content-Type + body，不看
状态码——选 3xx 时不发 Location（3xx 变成空重定向）、204 仍带体。校验侧虽
未放行 3xx，但 204 是白名单内且原实现给 204 发了 Content-Type 空体。

`static_response` 的 headers 值与 body 在
运行时经 Caddy replacer 展开已知占位符（v2.11.6 `staticresp.go:193-208` 实证，
`ReplaceKnown`）——`redirect_to` / `body` 中的 `{http.request.uri}` 等会被改写为请求
值（与 `httpsRedirectLocation` 的占位符用法同引擎机制）。校验侧有意不拒 `{`
（保路径跳转的合法占位符用法），审计不重报。

---

## §27 `escapeCaddyPlaceholders` 为什么必须转义 `{`

`escapeCaddyPlaceholders` 转义响应体中的 `{`——Caddy `static_response` 的 body
会做占位符替换，且未识别的占位符按 `replacer.ReplaceAll` 的
`treatUnknownAsEmpty` 语义展开为空串，用户内容里的 JSON/模板花括号会被静默
吞掉。转义为 `\{` 后引擎按字面输出（`replacer.go` 的 phEscape 分支），
保证所见即所得。

---

## §28 `stripPortForSNI` 与自研版的等价说明

（含裸 IPv6 字面量）原样返回。回源 Host 计划（静态态 TLS `server_name`）与
自研求值路径共用；与自研版 `stripPortForSNI` 语义等价（本任务吸收上游已修
的「SNI 静态路径剥端口」能力，见 TASK-2026-1111-02 §3.1）。

## §29 TLS 透传 Layer4 SNI 分流渲染（JJC-20261112-01 S1-b）

`protocol=passthrough` 规则的渲染接线。S1-a 只交付数据面（`passthrough_upstream`
列 + 保存门 + 恒禁用态落库），本节交付渲染面并解除恒禁用态门。

**按端口启用（R5 红线）**：透传规则按 `listen_port` 分组进
`passthroughRulesByPort`（与 `httpServersByPort`/`tcpServersByPort` 并列的第三
族）。端口集合为空（全库无启用透传规则）时，所有新代码路径零迭代，渲染产物与
改造前（main@c45efb06）**逐字节一致**——由
`TestPassthroughRender_noPassthroughRulesByteIdenticalToBaseline` 钉住（基线
sha256 内嵌常量，fixture 证书固定 PEM + certDir 归一化，见该测试注释）。

**存在透传规则的端口 P**，四处改动：

1. Layer4 app 新增 server `tls_<P>`（`buildPassthroughLayer4Server`）：listen
   `:P`；每条启用透传规则一条 SNI 路由（`@id`=caddy_id，match
   `tls.sni=[归一 SNI]` → `buildPassthroughProxyHandler`），之后恒一条兜底
   路由（无 match）→ `proxy 127.0.0.1:7443 { proxy_protocol: v2 }`。**路由
   顺序是语义**：SNI 未命中的流量（含 ACME TLS-ALPN-01 挑战与本地终结域名）
   全部落兜底进 7443 的 Caddy TLS 栈——证书/ACME 链路因此零改动（spike T-1
   真实签发实证）。多条规则**不合并**成单 route：上游 dial /
   proxy_protocol / 健康检查都是规则级参数。
2. HTTP app 该端口 server：listen 从 `[":P"]` 迁移为
   `["tcp/127.0.0.1:7443", "udp/:P"]`（TCP 退内部回环口，UDP 留公网给
   HTTP/3——Layer4 不碰 UDP；此为默认收口形态，`PASSTHROUGH_INTERNAL_BIND`
   对外时 tcp/ 侧主机部分由 `internalTerminateListenHost()` 派生，见下方语义表）。
3. 该 server 挂 `listener_wrappers: [proxy_protocol{allow:[<派生 allow>],
   fallback_policy: reject}, tls]`——顺序不可颠倒（wrapper 必须在 TLS 握手前
   剥头）；allow 由 `internalTerminateProxyAllow()` 按绑定形态派生（**默认形态**
   即 `127.0.0.1/32`：内部口仅绑回环、唯一合法来源是 Layer4 出站，外部伪造头被
   fallback_policy reject 在解析阶段关闭，spike T-5 断言 B/D；bind 可配后的
   派生规则见本节下方语义表）。
4. 证书/ACME 零改动：TLS 连接策略、certmagic、load_files 全部照旧。

**四元一致要点（spike T-5 踩坑实证，2026-11-15 由三元升为四元）**：Caddy 的
`servers` 挂载键必须与 server.Listen 逐字一致，否则 listener wrapper
**静默不生效**。需要同源的取值共**四处**：**listen 地址 / Layer4 兜底 dial
地址 / `proxy_protocol` wrapper 的 allow 集合 / `servers` 挂载键**。渲染侧的
唯一定义点：`internalTerminateListenHost()`（listen 主机部分）、
`internalTerminateDialHost()`（dial 主机部分）、`internalTerminateProxyAllow()`
（allow 集合）、`internalTerminateAddr()`（servers 挂载键与同类 `host:port`
形态），端口由 `internalTerminatePort()`（默认 7443）单源提供。任一处内联拼
地址即视为回归。

**内部口端口与绑定地址均可配（2026-11-15 追加裁定，两则）**：

1. `PASSTHROUGH_INTERNAL_PORT` 换内部终结口——host 网络下 7443 与宿主其他
   回环监听冲突的逃生门（面板口/代理口同款故障路径）。
2. `PASSTHROUGH_INTERNAL_BIND` 换绑定地址——家庭网络 / ISP 封禁入站 443 时
   **放弃 Layer4 SNI 分流**，把终结口绑到对外地址由外部直连入站；默认值
   不变（收口回环），对外是显式选择。

绑定地址语义表（`internalTerminateBind()` 求值；`internalTerminateExposed()`
判是否对外，对外时 `warnInternalTerminateExposed()` 告警，每进程一次）：

| 取值 | listen | Layer4 兜底 dial | wrapper allow | 对外 |
|---|---|---|---|---|
| 未设 / `localhost` / `127.0.0.1` / `::1` | 该回环 | 同址 | 同族回环 `/32` 或 `/128` | 否 |
| `0.0.0.0` | `0.0.0.0:<port>` | `127.0.0.1:<port>` | `127.0.0.1/32` | 是 |
| `::` | `[::]:<port>` | `[::1]:<port>` | `::1/128` | 是 |
| 其他 IP | 该 IP | 该 IP | 回环 + 该 IP `/32` | 是 |
| 非法 | 回落 `127.0.0.1` + 告警 | 同左 | 同左 | 否 |

语义边界：

- 端口未设/非法（非数字/0/负/>65535）→ 告警回落默认 7443（与 `envPort`
  同口径）；绑定地址非法 → 告警回落 `127.0.0.1`（不静默生效）；
- **listen 与 dial 必须分离**：`0.0.0.0` / `::` 只进 listen（对外收流），兜底
  dial 恒为同族回环——合并成单一地址就会去拨 `0.0.0.0` 这类不可连接的语义
  地址，本地终结链路全断；两处取值分别由 `internalTerminateListenHost()` /
  `internalTerminateDialHost()` 单源提供；
- **指定 IP 绑定时 allow 必须含该 IP**：dial 目标即该 IP，出站源不保证是回环，
  allow 若只有 `127.0.0.1/32` 会把 PROXY 头当 TLS 数据（握手 EOF），兜底链路坏；
- 换口三处同步（HTTP listen 迁移地址 / Layer4 兜底 dial / 挂载键），由
  `internalTerminateAddr()` 单源保证；钉测
  `TestInternalTerminatePort_followsEnv` 断言整链跟随；
- 规则监听口与内部口同口 → 渲染显性 generationFailure（指向换口手段），
  由 `TestInternalTerminatePort_conflictsWithRulePort` 钉住；
- 绑定四态由 `TestInternalTerminateBind_` 四条钉住：`_defaultsLoopback`（默认
  收口回环）/ `_wildcardExposed`（listen 通配 + dial 回环 + allow 不变）/
  `_specificIPAddsAllow`（指定 IP 且 allow 追加该 IP）/ `_invalidFallsBack`
  （非法回落）。

**直连入站形态成立（spike T-5 断言 B/C 实证）**：绑全网卡后，外部源**不带**
PROXY 头直连 `<对外地址>:<内部口>` 可正常完成 TLS 握手（断言 C）——即「放弃
SNI 分流、外部直连终结口入站」在协议层成立；而非 allow 源**伪造** PROXY 头
→ 握手 EOF（断言 B），说明 wrapper 的 allow 是唯一入站信任边界，伪造头打不开
通路；仅绑回环时外部连接被 refused（断言 D）。三者共同结论：**对外能力只依赖
`PASSTHROUGH_INTERNAL_BIND` 显式开启，安全边界由派生 allow 承担，不靠「是否
对外」这一隐式前提**——故 ④ 类约束从「恒绑回环」改述为「默认必须收口回环 +
暴露须显式且告警」。代价（入站无 SNI 分流、无 L4 层 IP/GeoIP 拦截、无 HTTP/3、
外部 ACME TLS-ALPN-01 不可达、须防火墙限源）见
`docs/deployment.zh-CN.md`「家庭网络 / 上游封 443（直连终结口入站）」。

**与 TCP 分支的关键差异**：透传**允许多规则同端口**（SNI 分流天然语义，每条
规则一个 route），TCP 的「同端口唯一规则」互斥约束不适用；透传上游存
`passthrough_upstream` 单值列（upstreams 表零行），故不过「零启用上游即跳过」
的发布谓词，改由「passthrough_upstream 非空」判空（带外脏行 fail-closed 跳过，
不拖垮整份配置）。`tcp_proxy_protocol`→上游侧 PROXY v2、`tcp_try_*`→重试
窗口、健康检查族→`health_checks.active` TCP 探测——复用 TCP 字段语义
（`healthCheckCore` 单源）。dial 归一走 `passthroughDialAddress`
（SplitHostPort/JoinHostPort 往返，IPv6 bracket 形态，与 `joinUpstreamAddress`
同口径——裸 IPv6 末段 `::1:10443` 歧义形态显性报错）。

**透传规则不进 HTTP 语义面**：同端口共存时（HTTP 规则 + 透传规则都在
`httpServersByPort[P]`），透传规则跳过 HTTP 路由生成、错误归因路由与 TLS
连接策略三处循环（各自显式 `protocol == "passthrough" → continue` 门）——其
流量在 Layer4 按 SNI 分走，永不进本 server。透传也不进 `publishedHTTPRules`
（logger_names/logs 零发射）。同端口 tcp_*/tls_* Layer4 server 归属冲突
（带外脏数据）显性 generationFailure。

**解除恒禁用态门**：CreateRule/UpdateRule 的 S1-a 400（「暂不支持启用」）
移除；渲染数据完整性由 `validatePassthroughRule`（passthrough_upstream 必填
host:port）单源把守，导入链（v2 备份 `validateRuleFeatures` 输入补
Domain/PassthroughUpstream）走同一门。v1（nginx）源无透传语义，转换器恒不
产出 passthrough，手造携带按「v1 导出格式不支持 TLS 透传」显性跳过。

