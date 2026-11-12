# JJC-20261112-001 · TLS 透传实施计划（TLS Passthrough · 443 统一入口 · SNI 分流）

> 体系：三省六部（本文件按当前 agent 架构台账约定落 `.agent_team/`；历史任务档案见 `.npc-teams/tasks/`，保留为历史档案，不再新增）
> 判级：XL · 状态：**方案定稿，待 spike 闸门（S0）**
> 需求来源：董事长 2026-11-12「参考 traefik 的透传：特定域名不在自身 TLS 终结，直接给另外一个处理」
> 前置基线：`aef45d9a`（v2.4.2 + 四项核心自研 + 追平标准化资产）
> 编成：中书省（方案）→ 门下省（审议）→ 尚书省派兵部（施工）+ 刑部（评审）；预计 8–10 天两轮施工

---

## 一、需求与决策记录（董事长已拍板，8 项）

| # | 决策点 | 裁定 |
|---|---|---|
| 1 | 入口形态 | **必须 443 统一入口**（TCP 层由 Layer4 接管） |
| 2 | 透传上游 | 上游自带反代与证书；本系统不终结、不管理、不监控其证书 |
| 3 | 混合模式 | **需要**：同一 443 端口，部分域名透传、部分域名本地终结 |
| 4 | ACME | **保留 TLS-ALPN-01** |
| 5 | 客户端真实 IP | **透传与本地终结两条路径都不得丢失**（见 §五 PROXY 链路） |
| 6 | 健康检查 | TCP 连接探测 |
| 7 | L4 安全边界 | 接受：透传域名仅有 IP/GeoIP 级拦截，无 HTTP 语义 WAF |
| 8 | 规则类型 | `protocol` 增加第三值 **`passthrough`**（与 http/tcp 并列） |
| 9 | 部署与端口 | host 网络；公网 80/443 依 `HTTP_PORT`/`HTTPS_PORT` env；**内部端口固定 7443**（仅 127.0.0.1，不随 env）；透传上游为用户配置任意 `host:port`（10443 仅为示例） |

---

## 二、架构方案

```
                     公网（host 网络）
  ┌────────────────────────────────────────────────────────┐
  │  80/TCP   = HTTP_PORT env → Caddy http app 直连          │
  │  443/TCP  = HTTPS_PORT env → Layer4 接管 ↓               │
  │  443/udp  = HTTP/3，Caddy 直连（Layer4 不碰 UDP）        │
  └────────────────────────┬───────────────────────────────┘
                           ▼
        ┌──────────────────────────────────────┐
        │ Layer4 server :443                   │
        │ peek ClientHello → 取 SNI（不终结）   │
        └───────┬──────────────────┬───────────┘
     SNI ∈ 透传集合        其余 SNI（含 ACME 挑战）
                │                    │
                ▼                    ▼
   ┌────────────────────┐  ┌──────────────────────────────┐
   │ (可选)lb_ipfile /   │  │ layer4.handlers.proxy_protocol│
   │ lb_geoip / lb_l4_sec│  │ （注入 PROXY v2：真实源 IP）   │
   │ (IP/GeoIP 级拦截)   │  │            ▼                  │
   │         ▼           │  │ proxy → 127.0.0.1:7443       │
   │ proxy → 上游:port    │  └──────────────┬───────────────┘
   │ + proxy_protocol v2 │                 ▼
   │ + TCP 健康检查       │  ┌──────────────────────────────┐
   └────────────────────┘  │ Caddy http app :7443          │
   （不终结 TLS，           │ TLS 终结 + listener wrapper    │
     上游终结证书）          │ 还原真实源 IP；证书/ACME/WAF/  │
                          │ 静态响应/链式回退零迁移          │
                          └──────────────────────────────┘
```

**三条核心设计原则**：

1. **按端口启用**：只有存在 `passthrough` 规则的端口才插入 Layer4 前置；无透传规则的端口渲染产物**逐字节不变**（验收 R5 分端口断言）。
2. **纯字节流转发**：Layer4 全程只 peek ClientHello，不终结任何 TLS——本地终结域名的证书/ACME/WAF 能力原样保留。
3. **第一期限制**：透传规则监听端口必须等于 `HTTPS_PORT`（其他端口 SNI 分流留二期，控风险）。

---

## 三、Spike 前置闸门（S0 · 五项全绿才动生产代码）

| # | 验证项 | 方法 | 失败后果 |
|---|---|---|---|
| **T-1** | ACME TLS-ALPN-01 经兜底到 7443 仍可签发 | 本地 Caddy 监听 7443 + Layer4 前置；客户端 ALPN=`acme-tls/1` 握手，断言返回含 `acmeIdentifier` 扩展的挑战证书；辅以 certmagic 源码走读（GetCertificate 与端口无关性） | 上报重设计（备选：Layer4 侧 ALPN 识别直通专用处理） |
| **T-2** | SNI 嗅探不破坏握手 | peek ClientHello 后转发，断言 TLS 版本/SNI/ALPN 与直连一致 | 上报 |
| **T-3** | `layer4.matchers.tls`（caddy-l4 v0.1.2）能力 | 读模块源码 + 编译产物注册表断言；确认按 `sni` 匹配 | 自研 `lb_l4_sni` matcher（+2 天，上报工作量） |
| **T-4** | 混合并发 | 同 443 端口透传/终结域名并发请求互不影响 | 阻塞施工 |
| **T-5** | 源 IP 链路端到端 | Layer4 兜底注入 PROXY v2 → 7443 listener wrapper 还原 → Caddy 日志/GeoIP 看到的 IP 与真实一致；wrapper 仅信 `127.0.0.1` 来源（防伪造） | 上报（备选：验证 caddy-l4 是否自带 listener wrapper 形态） |

---

## 四、数据模型与校验

**`lb_rules` 新增列**（走现有 `newColumnsRegistry` 迁移通道；列登记需同步 `docs/self-developed-features.zh-CN.md` 防死列）：

| 列 | 类型 | 说明 |
|---|---|---|
| `passthrough_upstream` | TEXT | 透传上游 `host:port`（仅 passthrough 规则消费） |

**复用既有列**：`domain`（= SNI 匹配域名）、`listen_port`（默认 443）、`tcp_health_check_port`/`tcp_try_*`（健康检查/重试）、`tcp_proxy_protocol`（上游 PROXY v2）、安全策略绑定。

**校验规则（全部显性拒绝，不静默）**：

1. 同端口同 SNI 重复；通配符与精确匹配重叠歧义
2. **同一域名既透传又本地终结** → 拒绝（最危险配置歧义；前端行内红框 + 后端保存门双拦）
3. passthrough 规则携带 `enable_tls`/证书字段 → 拒绝并提示「透传域名证书由上游管理」
4. 透传规则监听端口 ≠ `HTTPS_PORT` → 拒绝（第一期）
5. 上游地址格式（`host:port`）与保留端口校验复用现有链

---

## 五、渲染设计

| 组件 | 形态 |
|---|---|
| Layer4 server | `tls_<port>`：`listen :443`（跟随 `DefaultHTTPSPort()`） |
| 透传 route | match `layer4.matchers.tls(sni=[...])` →（可选安全链）→ `proxy`（upstream dial + `proxy_protocol: v2` + `health_checks.active` TCP 探测 + 现有负载均衡/重试） |
| 兜底 route | 无 match → `layer4.handlers.proxy_protocol` 注入 PROXY v2 → `proxy 127.0.0.1:7443` |
| HTTP app | 该端口 server `listen = ["tcp/:7443", "udp/:443"]`（UDP 保留公网端口给 HTTP/3） |
| 新模块 | **listener wrapper**（`caddy.ListenerWrapper` + `go-proxyproto`，7443 剥头还原真实源 IP，仅信 127.0.0.1）挂进 xcaddy build |
| 零回归断言 | 无透传规则的端口：渲染产物与改造前逐字节一致（验收 R5） |

---

## 六、前端设计

| 项 | 说明 |
|---|---|
| 类型选择 | 规则类型新增「TLS 透传」（与 HTTP/TCP 并列，独立图标/文案） |
| 表单 | 监听端口（默认 443，只读跟随 HTTPS_PORT）、SNI 域名、上游地址、权重、TCP 健康检查、PROXY v2 开关、IP/GeoIP 策略绑定 |
| 证书提示 | 显式提示「本域名证书由上游服务器管理，本系统不申请、不续期、不监控有效期」；证书字段整组隐藏 |
| 冲突提示 | 与本地终结规则同域名 → 行内红框（与后端同口径，避免晚失败） |
| 限制提示 | 「透传域名不支持 HTTP/3（QUIC），自动降级 HTTP/2」 |

---

## 七、实施阶段与时间线（~8–10 天）

| 阶段 | 内容 | 工期 | 闸门 |
|---|---|---|---|
| **S0 spike** | T-1~T-5（兵部，门下省审结论） | 1–1.5 天 | **五项全绿才进 S1** |
| **S1 数据+校验** | §四 D 组 + 渲染分端口零回归断言 | 2 天 | |
| **S2 渲染** | §五 R 组（Layer4 分流 + 内部端口迁移 + wrapper 模块） | 2 天 | R5 零回归断言红即停 |
| **S3 前端** | §六 F 组 | 2 天 | |
| **S4 验证收口** | 端到端 + 存量库冒烟 + 镜像构建（追平手册 C.5）+ 文档（自研登记第 5 项 / 追平手册 B.6 补充 / fork-notes） | 2 天 | 合并前置五条 |

---

## 八、验收清单摘要

- **T 组**（5 项 spike）· **D 组**（数据/校验，含渲染零变化双证）· **R 组**（渲染，含分端口逐字节断言）· **F 组**（前端）· **V 组**（build/vet/gate/四自研钉测集合/端到端/镜像 C.5/存量库冒烟）
- **红线**：无透传端口渲染零变化；PROXY 头仅信 127.0.0.1；透传域名不进证书监控面

---

## 九、风险与回滚

| 风险 | 等级 | 缓解 |
|---|---|---|
| T-1 失败（TLS-ALPN-01 不可签发） | 高 | spike 前置；备选方案已备（ALPN 识别直通），失败即上报不硬做 |
| 源 IP 还原被绕过（伪造 PROXY 头） | 中 | wrapper 仅信 127.0.0.1 来源（Layer4 兜底是唯一合法路径） |
| 内部端口迁移破坏存量 HTTPS | 中 | 按端口启用 + R5 逐字节断言 + 存量库冒烟 |
| 上游 `remote_ip_list` 有三处缺陷（容器实证 P0） | 低 | spike 前置；备选方案已备 |
| 回滚 | — | 功能完全由「是否存在 passthrough 规则」驱动：删除透传规则 → 渲染回到改造前形态；代码回滚 = 一次 revert，新列仅追加无迁移风险 |

---

## 十、与现有体系的关系

- **追平手册**（`docs/upstream-catchup-guide.zh-CN.md`）：S4 时按 §十 B.6 补「构建模型冲突」条目（passthrough listener wrapper 属自研模块，须入 xcaddy build 清单——Dockerfile 白名单联动）
- **自研登记**（`docs/self-developed-features.zh-CN.md`）：交付时登记第 5 项「TLS 透传 SNI 分流」（符号：`passthrough_upstream` · `lb_l4_sni`? · listener wrapper ID）
- **台账体系**：本文件为 `.agent_team/` 首份档案；历史档案（TASK-2026-1110-01 ~ 1111-04）在 `.npc-teams/tasks/` 保留不动
