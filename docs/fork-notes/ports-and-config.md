# fork-notes · 端口单源与配置（`default_ports.go` + `config.go`）

> 来源：`internal/services/default_ports.go` 与 `internal/config/config.go` 内我方新增的解释性注释，
> 2026-11-11 TASK-2026-1111-03 注释外置时**逐字搬迁**至此（只去注释符号、加章节号，内容未改写）。
> 涉及核心自研第 1 项（静态响应兜底站）、第 3 项（链式回退）；对应 ISSUE #7「改端口」诉求。

---

## §1 代理默认监听口的语义边界（只决定「默认语义」）

代理默认监听口（`HTTP_PORT` / `HTTPS_PORT` env，见 `internal/config`）。

语义边界（2026-10-10 用户裁定，ISSUE #7）：这两个值只决定「默认语义」——

- 渲染兜底站的监听口（原硬编码 `:80`）
- HTTP→HTTPS 跳转 Location 的自引用端口判定（原硬编码 443）
- 规则侧 80/443 保留端口判定与跳转遮蔽比对（handlers 侧读同一来源）

**不决定存量规则**：`lb_rules.listen_port` 是持久化数据，渲染时原样使用。
想要「全项目换口」的用户需在面板逐条改规则后保存——保存即落新端口。

与 `SetDefaultLandingBody` 同模式：boot 时注入一次，渲染期只读；测试不注入
时取出厂默认 80/443（等价旧硬编码行为）。

---

## §2 `Config.HTTPPort/HTTPSPort`：host 网络下就是实际绑定口

Proxy 默认监听口（`HTTP_PORT` / `HTTPS_PORT` env，默认 80/443）。
host 网络下这俩就是 Caddy 实际绑定的端口，"换端口" = 换监听口，不是端口转发。

语义范围（2026-10-10 用户裁定）：仅影响「默认值/兜底语义」——新建规则向导
默认值、TLS 联动、80/443 保留端口判定、空域名兜底站、HTTP→HTTPS 跳转的
Location 自引用判定；存量规则的 `listen_port` 是持久化数据，不随之迁移。
