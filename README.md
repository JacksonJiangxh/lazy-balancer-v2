# Lazy Balancer V2 · 自维护分支

[English](README.en.md) | 简体中文

> **这不是上游官方仓库。** 这里是 [v55448330/lazy-balancer-v2](https://github.com/v55448330/lazy-balancer-v2)
> 的一个 **fork 自维护版本**：在上游基础上叠加我们自己的修复与增强，
> 并按自己的节奏同步上游版本。

基于 **Caddy v2.11** 的可视化负载均衡管理平台，内置 WAF 安全防护，单容器交付。

## 这个仓库是什么

一句话：**上游的容器级能力 + 我们踩过的坑的修复。**

我们实际在生产里用这套东西，遇到问题就改，改完留在这个仓库。因此它和上游的
关系是「同源、有分叉、定期回流」：

| | 上游 | 本仓库 |
|---|---|---|
| 定位 | 官方发布 | 生产自用 + 定制 |
| 版本节奏 | 官方 tag | 跟官方 tag，我们自己的改动随时发 |
| 分支 | `master` | `master-dev`（开发主线）、`master`（上游镜像轨） |
| 镜像 | Docker Hub `v55448330/...` | `docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest` |
| 反馈 | 上游 issue | 本仓库 issue |

### 分支说明

| 分支 | 位置 | 作用 |
|---|---|---|
| `master-dev` | 本仓库默认分支 | **开发主线。** 上游基线 + 我们的全部改动，日常都提交到这里 |
| `master` | 本仓库 | **上游镜像轨。** 由 GitHub Actions 自动同步上游 release，逐字节等于上游某个 tag，**不含任何我们的改动，请勿在此分支开发** |

> 为什么 `master` 要单独留一条干净的轨：这样「比上游差了什么」永远只有一个
> 参照物，不会被我们自己的改动污染。巡检任务也是靠它来判断版本差距的。

## 快速开始

```bash
docker run -d --name lazy-balancer --network host \
  --ulimit nofile=1048576:1048576 \
  -v $(pwd)/data:/app/data -v $(pwd)/certs:/app/certs \
  -v $(pwd)/logs:/app/logs -v $(pwd)/waf:/app/waf \
  -v $(pwd)/backup:/app/backup \
  docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest
```

挂载说明：`/app/data` 数据库与配置（必选）、`/app/certs` 证书与私钥（必选）、
`/app/backup` 自动备份落盘目录（必选——不挂载则容器重建后备份文件丢失）、
`/app/logs` 日志（推荐）、`/app/waf` 规则库与 GeoIP（推荐）。

打开 `http://localhost:8000` 进入管理面板。首次访问进入初始化向导，无默认凭据。

> Docker Desktop（macOS/Windows）用户：`/app/data` 推荐 named volume
> （`-v lb-data:/app/data`）；bind mount 经 FUSE 共享层有 SQLite WAL 丢页风险
> （Linux 宿主 bind mount 无此问题）。

> 宿主机 80/443/8000 被占用时，用 `HTTP_PORT` / `HTTPS_PORT` / `PANEL_PORT` 换位
> （host 网络下即换监听口）。详见[部署指南](docs/deployment.zh-CN.md)。
> 存量规则端口不会被自动改写，需手动逐条修改后保存。

<details>
<summary>Docker Compose / 从源码构建</summary>

```bash
# Docker Compose —— compose 文件里的 image 已指向我们自维护的镜像
docker compose up -d

# 从源码构建
# 前端由 Dockerfile 内的 node 构建阶段产出，无需先本地 npm build
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg VERSION=v2.3.5 \
  --provenance=false --sbom=false \
  -t docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest --push .
```

镜像由内部流水线构建发布（`docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2`）：双架构
原生构建 → 真容器探活 → 打 `latest` 与版本号两个 manifest。

> 官方 Docker Hub 的 `v55448330/lazy-balancer-v2` 是**上游**的镜像，
> 不含我们的改动，请勿在本仓库的部署流程里引用它。
</details>

## 我们相对上游改了什么

**当前上游基线：`v2.3.5`（`98c607ac`）。** 上游在这个版本里的迭代
（回源域名原生 `map` 晚绑定、静态响应 `response_mode` 三值、健康检查域名、
SNI 剥端口、仪表盘分位数插值、第 69 轮 151 项审计修复等）已全部吃进，
逐条对账见[上游合并清单](docs/upstream-merge.zh-CN.md)。

下表只列「人话版」的**我们独有**能力（上游没有的部分）：

| 改动 | 说明 |
|---|---|
| 链式回退负载策略 | 一路后端全挂/全 404 时按配置回退到下一组，且不透传后端错误报文 |
| 引用型证书摄取入库 | `tls_source=file` 改为保存时读取 PEM 入库，DB 成为唯一信任源；外部文件变更由看门狗回写并热重载 |
| 端口换位 | `HTTP_PORT` / `HTTPS_PORT` / `PANEL_PORT` 三个环境变量正式换位，只影响默认语义，不动存量规则 |
| 引用证书更新放行 | 修掉更新规则时引用证书文件来源被误拦的问题 |
| 上游版本巡检 | 定时检查上游新 release，发现即开 Issue 提醒 |

## 同步上游的方式

三道闸，各管一段：

1. **GitHub Actions**（`sync-upstream-master.yml`）
   每 6 小时查一次上游 tag（只认 `v<major>.<minor>.<patch>` 形态的版本级 tag），
   有新 tag 就把它的提交同步到本仓库的 `master`。
   需要仓库 Secret `UPSTREAM_SYNC_TOKEN`（PAT，含 repo 权限）。

2. **版本巡检**
   定时任务比对上游最新版本与维护基线，出现新版本即开 Issue 通知。
   同一版本只开一条，不会刷屏。

3. **人工合并**
   收到 Issue 后按[上游合并清单](docs/upstream-merge.zh-CN.md)走一遍：
   出清单 → 拍板 → 改代码 → 更新基线 → 关 Issue。

## 文档

| 文档 | 内容 |
|---|---|
| [上游合并清单](docs/upstream-merge.zh-CN.md) | 与上游的差异对账、待决策项、合并顺序 |
| [部署指南](docs/deployment.zh-CN.md) | 挂载目录、环境变量、端口、生产参数 |
| [安全配置](docs/security.zh-CN.md) | WAF 策略、IP 控制、事件采集、规则更新 |
| [集群管理](docs/cluster.zh-CN.md) | 主从架构、MFA、安全模型、升级须知 |
| [OIDC 登录](docs/oidc.zh-CN.md) | 企业认证对接、Entra 示例、用户管理 |
| [生产调优](docs/production-tuning.zh-CN.md) | 内核/容器/LB/WAF/HTTP3 五层调优 |
| [API 文档](docs/api.zh-CN.md) | REST 端点概览、认证、错误码 |
| [MCP 文档](docs/mcp.zh-CN.md) | AI 代理接入、工具权限、工作流示例 |

## 功能一览

| 功能 | 说明 |
|---|---|
| 负载均衡 | HTTP/HTTPS/TCP 四层代理，多种策略，健康检查，路径路由 |
| WAF 防护 | OWASP CRS + 自定义规则 + IP 控制 + 地域拦截 + 限流 |
| 免费证书 | ACME 自动签发（DNS-01），自动续签 |
| 主从集群 | 增量同步，防篡改签名，从节点只读，一键提升 |
| 监控告警 | 流量/延迟 P50-99，上游健康，安全事件总览 |
| MCP 服务 | AI 代理可通过工具操作全部功能 |
| 自动备份 | 按日/周/月定时备份配置，支持一键还原 |

## 变更日志

我们自己的迭代按时间倒序记在这里。上游的版本变更请直接看上游 release。

| 日期 | 内容 |
|---|---|
| 2026-10-11 | **合入上游 v2.3.5**（`98c607ac`）：逐上游回源域名改吃上游 `origin_domain` + 原生 `map`，静态响应改吃上游 `response_mode` 三值——自研 `host_header` / `action=respond` 两套实现退役，存量数据自动双向迁移；保留链式回退、引用型证书摄取入库、端口换位三项自维护能力 |
| 2026-10-11 | 清理仓库内与内部开发平台相关的描述（页脚链接、CI 章节、迁移说明），公开面统一指向本仓库 |
| 2026-10-11 | 端口换位补齐默认口漏网点；引用证书摄取入库；链式回退策略；新增 GitHub Actions 上游同步与版本巡检；重写 README；`docker-compose` 引用改为自维护镜像 |

## 技术栈

Go 1.26 · Gin · SQLite · Caddy v2.11 · Coraza v3 · OWASP CRS v4 · Vue 3 · Element Plus

## License

上游采用 [Apache License 2.0](LICENSE)。本仓库同样遵循该协议。

按 Apache-2.0 的约定，我们对上游代码的修改已在本仓库的提交历史与
[上游合并清单](docs/upstream-merge.zh-CN.md)中逐项标注来源与改动内容。
本仓库**移除了上游 README 中的交流群二维码与群号**（那是上游的社区入口，
不是本仓库的），并保留上游的 LICENSE 与版权声明不变。
