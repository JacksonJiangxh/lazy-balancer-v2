# MCP 服务文档

## 概述

Lazy Balancer V2 内置 **Model Context Protocol (MCP)** 服务，AI 代理可操作全部主要功能。工具清单以运行时 `tools/list` 输出为准（`GET /api/v1/mcp/tools` 提供同一注册表），本文不复制固定数字——增删工具不会让本文失真。少数能力仅经 REST API 提供，见文末「仅 REST 可用的能力」。

## 接入

| 配置项 | 值 |
|---|---|
| 端点 | `http://<host>:8000/api/v1/mcp` |
| 协议 | Streamable HTTP (POST) |
| 认证 | `X-API-Key: lb_sk_...` 或 `Authorization: Bearer lb_sk_...` |
| Content-Type | `application/json` |

## 快速验证

```bash
curl -s http://localhost:8000/api/v1/mcp \
  -H "X-API-Key: lb_sk_your_key" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

## 工具权限

| Key 类型 | 可用工具 |
|---|---|
| 管理员 Key（读写） | 全部工具（以 `tools/list` 为准） |
| 只读 Key（read_only） | GET 查询工具（export_config 与 get_caddy_config 除外——前者导出含用户/密钥哈希、后者原始 Caddy 配置可能含内联私钥，二者对只读 Key 一律 403，列表亦不展示）+ 3 个读探测 POST 工具（parse_certificate / validate_import / preview_config；证书配置测试含真实 DNS 写入、CA 提供商测试在 ZeroSSL 缺 EAB 时会写入 CA 凭据，均已移出只读豁免） |
| 非管理员用户 Key | 仅查询类工具与上述读探测 POST；负载规则/证书配置/证书签发/集群与系统管理等写工具对该 Key 一律 403，`tools/list` 不会列出这些工具 |
| IP 白名单 Key | 请求来源 IP 必须命中白名单（MCP 内部转发不受影响） |

请求体必须是**单条 JSON-RPC 对象**：服务器不接受 JSON-RPC 批处理数组（返回 HTTP 400 + `PARSE_ERROR`）。客户端请逐条发送请求；`tools/list` 的按 Key 过滤也按单条请求生效。

## 工具分组（节选）

| 分组 | 工具 |
|---|---|
| 负载规则 | list_rules、get_rule、create_rule、update_rule、delete_rule、enable_rule、disable_rule |
| 证书 | list_cert_jobs、retry_cert_job、issue_certificate、list_certificates |
| 安全策略 | list_security_policies、create_security_policy、update_security_policy |
| 自定义规则 | list_custom_rules、create_custom_rule |
| IP 名单 | list_ip_lists、create_ip_list、update_ip_list |
| 监控 | get_metrics_overview、get_metrics_dashboard、get_realtime_traffic、get_upstream_health |
| 集群 | get_cluster_status、create_register_token |
| 配置 | get_config、update_config、reload_caddy |

完整工具列表通过 `tools/list` 方法获取。

## 操作手册

连接后可通过 `resources/read` 读取内置操作手册：

```
lazy-balancer://docs/ops-playbook
```

手册包含：接入指南、权限范围、常用工作流、排障手册、纪律约束、性能建议。

## 常用工作流示例

### 创建负载均衡规则

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_rule","arguments":{"name":"my-rule","protocol":"http","domain":"example.com","listen_port":80,"strategy":"weighted_round_robin","upstreams":[{"host":"10.0.0.1","port":8080,"weight":1}]}}}
```

### 查看安全事件

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_security_events","arguments":{"page":1,"page_size":20,"action":"blocked"}}}
```

### 触发证书签发

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"issue_certificate","arguments":{"caddy_id":"lb_xxx"}}}
```

## 错误码

| 错误 | 含义 |
|---|---|
| 400 | 请求体不可读 |
| 413 | 请求体超过 1 MiB |
| 401 | API Key 无效 |
| 403 | MCP 未启用 / IP 不在白名单 / 只读 Key 调写工具 ；非 admin 属主的写工具 403；从节点非集群写工具 403 |

## 仅 REST 可用的能力

以下能力暂无对应 MCP 工具，需要时经 REST API（`http://<host>:8000/api/v1`，同一 API Key 认证）访问。
**没有 MCP 工具 ≠ 只读**：表中既有机读聚合端点，也有配置写入/批量运维端点。

| 域 | 仅 REST 的端点示例 | 说明 |
|---|---|---|
| 监控指标 | `GET /caddy/metrics`、`GET /caddy/host-metrics`、`GET /logs/stats` | Caddy 进程级/按域名聚合指标与日志保留统计 |
| 规则查询 | `POST /rules/cert-info` | 按域名批量查询规则关联证书信息 |
| 证书队列 | `POST /certificates/jobs/current` | 查询当前进行中的证书签发任务 |
| 审计 | `GET /audit-logs/options` | 审计日志筛选下拉选项 |
| WAF 规则库 | `GET /security/crs/setup` | CRS 全局配置（crs-setup 摘要） |
| 自动封禁 | `GET /security/autoban`、`PUT /security/autoban` | 自动封禁阈值/窗口/时长/作用域/演练模式配置 |
| 威胁情报库 | `PUT /security/threat-lib/auto-update`、`PUT /security/threat-lib/schedule`、各源开关 | 库开关与排程 |
| 爬虫地址库 | `PUT /security/crawler-lib/auto-update`、`PUT /security/crawler-lib/schedule` | 库开关与排程 |
| CRS / IP 库开关与排程 | `PUT /security/crs/auto-update`、`PUT /security/crs/schedule`、`PUT /security/ip2region/auto-update`、`PUT /security/ip2region/schedule` | 库开关与排程 |
| 安全策略与规则 | `POST /security/policies/batch-bind`、`POST /rules/batch-block-pages` | 策略批量绑定、规则批量指定拦截页 |
| 系统任务 | `POST /system/tasks/:id/{toggle,control}` | 任务调度启停（引擎元数据驱动） |

完整豁免清单以 MCP 工具与 REST 路由的一致性测试（parity）和 `GET /api/v1/openapi.yaml` 为准——两份清单任一变更都会被机械对账拦下。
