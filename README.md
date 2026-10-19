# Lazy Balancer V2

[English](README.en.md) | 简体中文

基于 **Caddy v2.11** 的可视化负载均衡管理平台，内置 WAF 安全防护，单容器交付。

## 功能一览

| 功能 | 说明 |
|---|---|
| 负载均衡 | HTTP/HTTPS/TCP 四层代理，多种策略，健康检查，路径路由 |
| WAF 防护 | OWASP CRS + 自定义规则 + IP 控制 + 地域拦截 + 限流 |
| 爬虫豁免 | UA+反向 DNS/官方 IP 段验证真实搜索引擎与 AI 爬虫，豁免地域拦截；官方爬虫地址库定时更新 |
| 免费证书 | ACME 自动签发（DNS-01），自动续签 |
| 主从集群 | 增量同步，防篡改签名，从节点只读，一键提升 |
| 监控告警 | 流量/延迟 P50-99，上游健康，安全事件总览 |
| MCP 服务 | AI 代理可通过 136 个工具操作全部主要功能 |
| 自动备份 | 按日/周/月定时备份配置到服务器 backup 目录，支持一键还原 |

## 快速开始

**Linux（推荐，host 网络）**：

```bash
docker run -d --name lazy-balancer --network host \
  --restart unless-stopped \
  --ulimit nofile=1048576:1048576 \
  -v $(pwd)/data:/app/data -v $(pwd)/certs:/app/certs \
  -v $(pwd)/logs:/app/logs -v $(pwd)/waf:/app/waf \
  -v $(pwd)/backup:/app/backup \
  v55448330/lazy-balancer-v2:latest
```

**Docker Desktop（macOS/Windows，bridge 网络 + 端口映射）**：

```bash
docker run -d --name lazy-balancer \
  --restart unless-stopped \
  --ulimit nofile=1048576:1048576 \
  -p 8000:8000 -p 80:80 -p 443:443 -p 443:443/udp \
  -v lb-data:/app/data -v $(pwd)/certs:/app/certs \
  -v $(pwd)/logs:/app/logs -v $(pwd)/waf:/app/waf \
  -v $(pwd)/backup:/app/backup \
  v55448330/lazy-balancer-v2:latest
```

挂载说明:`/app/data` 数据库与配置(必选)、`/app/certs` 证书与私钥(必选)、`/app/backup` 自动备份落盘目录(必选——不挂载则容器重建后备份文件丢失)、`/app/logs` 日志(推荐)、`/app/waf` 规则库与 GeoIP(推荐)。

> host 网络模式仅推荐在 Linux 宿主使用。Docker Desktop 的 host 网络支持依版本/设置而异，请用上面的 `-p` 命令，并将 `/app/data` 放在 named volume(`lb-data`)；bind mount 经 FUSE 共享层有 SQLite WAL 丢页风险(Linux 宿主 bind mount 无此问题)。仓库 `docker-compose.yml` 的主节点固定 host 网络，仅适用于 Linux 开发/部署场景。

打开 `http://localhost:8000` 进入管理面板。首次访问进入初始化向导，无默认凭据。

<details>
<summary>Docker Compose / 构建源码</summary>

```bash
# Docker Compose（Linux；主节点为 host 网络）
docker compose up -d

# 从源码构建
cd web && npm install && npm run build && cd ..
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v2.3.8 \
  --provenance=false --sbom=false \
  -t v55448330/lazy-balancer-v2:v2.3.8-beta --push .
```
</details>

## 文档

| 文档 | 内容 |
|---|---|
| [部署指南](docs/deployment.zh-CN.md) | 挂载目录、环境变量、端口、生产参数 |
| [安全配置](docs/security.zh-CN.md) | WAF 策略、IP 控制、事件采集、规则更新 |
| [集群管理](docs/cluster.zh-CN.md) | 主从架构、MFA、安全模型、升级须知 |
| [OIDC 登录](docs/oidc.zh-CN.md) | 企业认证对接、Entra 示例、用户管理 |
| [生产调优](docs/production-tuning.zh-CN.md) | 内核/容器/LB/WAF/HTTP3 五层调优 |
| [API 文档](docs/api.zh-CN.md) | REST 端点概览、认证、错误码 |
| [MCP 文档](docs/mcp.zh-CN.md) | AI 代理接入、工具权限、工作流示例 |

## 交流群

<div align="center">

**LazyBalancer 交流群** · 群号：**303410331**

<img src="docs/qq-group-qr.webp" alt="QQ 交流群" width="240">

</div>

## 技术栈

Go 1.26 · Gin · SQLite · Caddy v2.11 · Coraza v3 · OWASP CRS v4 · Vue 3 · Element Plus

## License

[Apache License 2.0](LICENSE)
