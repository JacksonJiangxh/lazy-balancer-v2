# fork-notes · 回源 Host 处理器（`caddygeoip/upstream_host.go`）

> 来源：`caddygeoip/upstream_host.go` 内我方新增的解释性注释，2026-11-11 TASK-2026-1111-03
> 注释外置时**逐字搬迁**至此（只去注释符号、加章节号，内容未改写）。
> 这是**核心自研第 4 项**的处理器本体；渲染侧四态与接线见
> [`render-chain.md`](render-chain.md) §1–§17。

**注**：本文件属**独立 Go 模块**（上游无此路径）→ 上游发版时天然零冲突，
注释外置在这里的主要收益是「代码可读性 + 一致性」，不是冲突面。

---

## §1 占位符键：双侧必须同步改名

占位符键（请求期由本处理器惰性注册；生成侧 `internal/services/caddy.go`
同步引用，改名须双侧同步）。

- `upstreamHostPlaceholder` 回源 Host：命中映射返回配置值，未命中回退上游
  自身 dial 地址（`host:port`）——用于 `reverse_proxy` headers 的 Host 头。
- `upstreamSNIPlaceholder` 回源 SNI：命中映射返回配置值（剥离端口），未命中
  回退上游纯主机名——用于 TLS transport 的 `server_name`（SNI 不得含端口）。

---

## §2 `UpstreamHostOverride` 为什么必须存在（Caddy 内建方案的表达能力缺口）

`UpstreamHostOverride` 逐上游回源 Host 覆盖处理器（`http.handlers.lb_upstream_host`）。

背景：Caddy 单个 `reverse_proxy` 的请求头操作是 handler 级配置——同一负载池的
所有上游共享一个 Host 值（静态串或 `{http.reverse_proxy.upstream.hostport}`
占位符），无法表达「同一规则内不同上游使用不同静态回源 Host」。本处理器在
请求期向 replacer 注册惰性占位符，求值时机恰为 `reverse_proxy` 选中上游之后
（`reverseproxy.go` v2.11.x：先 `repl.Set("http.reverse_proxy.upstream.hostport")`
再应用 headers/transport 占位符），此时按选中的 hostport 查表下发对应回源
Host——使「上游自定义 > 规则级 > 上游自身」三级回退在单一负载池内成立，
负载均衡/健康检查/重试语义不变。

稳定设计：零 Provision/零失败模式；未配置映射或 replacer 上下文缺失时纯
透传；未命中映射回退上游自身地址（绝不产出空 Host、绝不透传客户端 Host）；
next 原样透传。

归属：**董事长核心自研第 4 项**（回源 Host 逐上游自定义），登记见
`docs/self-developed-features.zh-CN.md`。禁止以「上游同需求两实现」为由切回
Caddy 内建 `http.handlers.map` 方案（上游实现存在三处缺陷，见
`docs/upstream-origin-host-compare.zh-CN.md` §2.4）。

---

## §3 `Hosts` 映射只收录「非自身地址」的条目

`Hosts` 上游 dial（`host:port`，与 `{http.reverse_proxy.upstream.hostport}`
输出同格式）→ 回源 Host 的映射；仅收录「有效回源 Host 非上游自身」的
条目，未收录的上游由未命中兜底走自身地址（回退语义第三级）。

---

## §4 `ServeHTTP` 不做事、只注册

`ServeHTTP` 注册惰性占位符提供者后原样透传下游（`reverse_proxy` 之前执行）。
