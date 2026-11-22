# 部署指南

## 镜像与上游 compose 改造（先读这节）

本仓库是上游 [lazy-balancer](https://github.com/v55448330/lazy-balancer)（Lazy Balancer V2）的 fork——**追平上游 + 叠加自研能力**（端口换位、TLS 透传 SNI 分流、链式回退等，登记见 `docs/self-developed-features.zh-CN.md`）。由此有一个关键结论：

> **上游官方仓库的 docker-compose.yml 不能直接用来部署本版本**——上游 compose 的 `image:` 指向官方镜像，拉起来跑的是上游程序，不含本 fork 的任何自研能力（端口换位 env、`PANEL_PORT` 探针跟随、透传内口可配等全部不生效）。

本 fork 的镜像发布地址：

```text
docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest
```

部署本版本只有两条路，**共同点是镜像必须用上面这个地址**：

1. **用本仓库自带的 `docker-compose.yml`**（已指向本 fork 镜像 + 已内置全部自研参数的注释行，改一行注释即生效）——见下文「完整 compose（本 fork 版）」；
2. **改造上游官方 compose**：把两处 `image:` 换成本 fork 镜像地址，再按需取消自研参数注释——逐项对照见下表。

### 上游 compose → 本 fork 版逐项对照

| 改动点 | 上游官方 compose | 本 fork 版 | 不改的后果 |
|---|---|---|---|
| **镜像（两处）** | `v55448330/lazy-balancer-v2:<tag>` | `docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest` | **跑的是上游程序，自研能力全部不存在** |
| build 段 | `build: context: . + args` | 上游形态照抄会拿上游源码构建 | 本地构建出上游版本 |
| 自研端口参数 | environment 仅 `NODE_NAME`/`LOG_FILE` | 预置 `HTTP_PORT`/`HTTPS_PORT`/`PANEL_PORT`/`PASSTHROUGH_INTERNAL_PORT` 注释行，取消注释即生效 | 80/443/8000/7443 被占用时没有换口手段 |

### 完整 compose（本 fork 版，可直接复制）

以下即本仓库 `docker-compose.yml` 的当前形态（主节点），镜像与参数已就位，注释行按需取消：

```yaml
services:
  lazy-balancer:
    image: docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest
    container_name: lazy-balancer
    network_mode: host          # Linux 专用；macOS/Windows 见 README「Docker Desktop」
    restart: unless-stopped
    stop_grace_period: 30s      # 优雅关停链最长 25s，默认 10s 会被 SIGKILL
    ulimits:
      nofile: { soft: 1048576, hard: 1048576 }   # 每连接一个 fd，默认 1024 必炸
      nproc:  { soft: 4096, hard: 4096 }
    pids_limit: 4096
    healthcheck:
      test: ["CMD", "/usr/local/bin/lazy-balancer", "--healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 90s          # 冷启动含 CRS 种子/证书物化，30s 必误报
    logging:
      driver: json-file
      options: { max-size: "50m", max-file: "5" }
    volumes:
      - lb-data:/app/data        # named volume：SQLite WAL 不经宿主共享层
      - ./logs:/app/logs
      - ./certs:/app/certs
      - ./waf:/app/waf
      - ./backup:/app/backup
    environment:
      - NODE_NAME=master
      - LOG_FILE=/app/logs/lazy-balancer.log
      # ↓↓ 本 fork 自研参数（上游无），按需取消注释：
      # - HTTP_PORT=8080                  # 代理默认口（默认语义，存量规则不迁移）
      # - HTTPS_PORT=8443
      # - PANEL_PORT=9000                 # 面板口换口（默认 8000），健康探针自动跟随
      # - PASSTHROUGH_INTERNAL_PORT=17443 # 透传内部终结口（默认 7443，仅绑 127.0.0.1）

volumes:
  lb-data:
```

主从部署、`build` 段与版本号锚点说明见本仓库 `docker-compose.yml` 全文；从节点（bridge 网络）形态与注册说明同文件「lazy-balancer-slave」段。

## 挂载目录

| 容器路径 | 内容 | 必需 |
|---|---|---|
| `/app/data` | 业务/审计/指标数据库、ACME 账户密钥 | **是** |
| `/app/certs` | 证书与私钥 | **是** |
| `/app/logs` | 应用日志、Caddy 日志、按规则访问日志 | 推荐 |
| `/app/waf` | CRS 规则树（IP2Region xdb 实际位于 `/app/data/ip2region.xdb`，随数据卷持久化；旧版 Coraza 审计日志在 `/app/logs/waf-audit`，B 形态下仅作兜底） | 推荐 |
| `/app/backup` | 自动备份落盘目录（不挂载则容器重建后备份文件丢失） | **是** |
| `/app/config` | 启动期最小 Caddyfile（admin 监听等）；运行配置恒由数据库渲染覆盖，手改不持久 | 可选 |

> 不挂载 `/app/waf` 时，容器重建会将 CRS 回退到镜像捆绑版本；系统自动将更新后的规则树快照持久化到数据卷并在启动时对账恢复。数据库是配置的唯一真实来源。

> Docker Desktop（macOS/Windows）用户：`/app/data` 推荐 named volume（`lb-data:/app/data` 形态）；bind mount 经 FUSE 共享层有 SQLite WAL 丢页风险（Linux 宿主 bind mount 无此问题）。同时请用「端口」一节的 `-p` 端口映射启动（host 网络仅推荐 Linux）；仓库 docker-compose.yml 的主节点固定 host 网络，仅适用于 Linux 场景。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `JWT_SECRET` | 自动生成 | JWT 签名密钥；生产建议显式设置。显式设置时必须 **≥32 字节且至少含 8 个不同字节**（高熵随机串，例如 `openssl rand -hex 32`）——不满足时启动日志以「强度不足」告警但**不阻断启动**（运维显式输入不自动替换，避免已签发令牌静默全失效）；弱密钥可被离线爆破，JWT 与 OIDC state 均可被伪造。不设置时自动生成并持久化到数据目录 |
| `LOG_FILE` | `/app/logs/lazy-balancer.log` | 运行日志文件路径（恒启用，LOG_FILE 仅覆盖路径） |
| `NODE_NAME` | `node-1` | 集群注册的默认节点名 |
| `BACKUP_DIR` | `data_dir` 同级 `backup`（容器 `/app/backup`） | 自动备份落盘目录 |
| `APP_VERSION` | 构建时注入 | 显示版本号（正式版本号，不含 `-beta` 等通道后缀；镜像 tag 可带后缀，二者刻意不同） |
| `TZ` | 数据库 `timezone` | 进程时区。数据库已初始化后，容器启动时 entrypoint 会以数据库时区覆盖该变量（`-e TZ=...` 传入不生效）；时区请经面板「基础设置」修改 |
| `LB_CERT_DEK_B64` | 空 | 证书库（甲路线）DEK 的 base64 值（32 字节 AES-256），**仅开发/CI 用**；生产用 KMS。设置它或 `LB_CERT_KMS_ENDPOINT` 任一即启用甲路线 |
| `LB_CERT_KMS_ENDPOINT` | 空 | KMS 解封端点（HTTPS）；生产环境启用甲路线的推荐方式 |
| `LB_CERT_KMS_TOKEN_ENV` | 空 | KMS 请求 Bearer token 所在的**环境变量名**（不是 token 本身） |
| `LB_CERT_KMS_CLIENT_CERT` / `LB_CERT_KMS_CLIENT_KEY` | 空 | KMS mTLS 客户端证书/私钥路径（只读路径，凭据由部署注入、不入仓） |
| `LB_CERT_WRAPPED_DEK` | 空 | 启动回填时用于初次封装的 wrapped DEK（env 模式通常留空） |
| `LB_CLUSTER_CLIENT_CERT` / `LB_CLUSTER_CLIENT_KEY` | 空 | 从节点访问集群同步端点的 mTLS 客户端证书/私钥路径 |
| `LB_CLUSTER_CLIENT_CA` | 空 | 主节点校验集群客户端证书的 CA bundle 路径；配置后集群机器端点强制 mTLS |
| `LB_CERT_FILE_SCAN_INTERVAL` | `60` | 主节点证书文件扫描周期（正整数秒）。每轮扫描 `/app/certs` 下 `<规则ID>.crt` / `.key` 配对并按需入库；甲路线关闭或 DEK 未配置时完全 no-op。非法/非正值回落 60 秒 |

## 证书库单源（甲路线）与滚动升级

甲路线把证书私钥从「面板进程内存 + SQLite 密文列 + Caddy 定制 `CertificateLoader`」直读，配置 JSON 与快照不再出现明文 PEM/`load_files`。启用判据只有一个：`LB_CERT_DEK_B64` 或 `LB_CERT_KMS_ENDPOINT` 任一非空；未配置时行为与基线逐字一致（旧 `load_files` / JJC-001 引用型证书随快照同步零回归）。

**滚动升级论证（必须满足的前提，勿留隐含假设）：**

1. 甲路线**默认关闭**。滚动升级期间全群都不设 DEK/KMS，所有节点处于明文兼容模式，快照继续携带 `Certs`/`ReferencedCerts`、`load_files` 路径照常工作——此阶段行为与基线 ed04bd38 完全相同，新旧版本可任意混跑。
2. 只有当**全群节点都已升级到本版本**、且统一注入同一份 DEK/KMS 配置后，才允许在全部节点同时开启甲路线。因为密文快照新增了 `vault_certs` 字段：所有节点都必须认识该字段（旧版本节点不认识，会忽略它并退回明文 `Certs`——若此时只有部分节点开了甲路线，未升级节点仍走明文，不属于本方案的安全边界，但也不破坏功能）。
3. 切换后快照的证书载荷改走 `vault_certs` 密文列（逐字复制主节点密文，从节点用本地 DEK/KMS 独立解密），`Certs`/`ReferencedCerts` 不再下发明文。回滚用 `git revert`，不 amend、不强推。

**内存保护基线（P1-3）：** 私钥明文只在解密瞬间驻留进程内存并即刻 zero（`clearBytes`）。三层防护：entrypoint `ulimit -c 0` 禁 core dump；Go 侧 Linux `PR_SET_DUMPABLE=0` 禁 ptrace/core（启用甲路线时失败即拒绝启动）；**宿主机必须 swapoff 或使用加密 swap**——这是部署方责任，容器内无法强制。不要依赖 mlock：Go 的 GC 与栈复制使逐分配 mlock 不可靠，且默认 `RLIMIT_MEMLOCK` 极小。

**集群 mTLS（P1-2）：** 配置 `LB_CLUSTER_CLIENT_CA` 后，主节点 TLS 层验证客户端证书（`VerifyClientCertIfGiven`，浏览器 UI 不受影响），集群机器端点（`/cluster/sync/*`、`/cluster/registration/confirm`、`/cluster/nodes/report`、`/cluster/register/:id/status`）由 `clusterClientCertGuard` 强制要求验证链。未配置 CA 时 no-op，既有「TLS + 指纹钉扎 + X-Cluster-Token」posture 不变。mTLS 是**叠加**不是替换令牌鉴权。

## 证书文件扫描 → 密文同步 → 从节点自动热重载（用户裁定流程）

甲路线启用后证书生命周期按以下流程闭环，**从节点全程不需要重启容器**：

1. **主节点定期扫描文件入库**：主节点的 cluster-sync daemon 在主分支每 `LB_CERT_FILE_SCAN_INTERVAL`（默认 60 秒）扫描一次 `/app/certs`，配对读取 `<规则ID>.crt` / `<规则ID>.key`，用 `tls.X509KeyPair` 校验合法性后计算指纹；只有指纹变化（新证书或内容更新）才以密文 `Upsert` 进 `cert_secrets` 并推进 `cert_version`。指纹一致时**绝不重复写入**——否则触发器每轮 +1，从端会永久强制重载。单个文件损坏只告警跳过，不中断整批。本轮只要有任一证书真实入库，主节点**立即自身 force reload 一次**（`CaddyOpLock` 内现场渲染最新 DB → `POST /load` 带 `must-revalidate`），所以主节点也是「放文件即生效」；指纹全同的周期轮零重载。
2. **密文随快照同步**：快照证书轴走 `vault_certs` 密文列（只下发密文 + wrapped DEK，无明文 PEM）。证书库水位 `cert_version` 已进入快照缓存键：即使 `cluster_version` 没变，证书变化也会让主节点重建快照、从节点收到全量下发而非 304。口径说明：用户已裁定「过通道明文可接受」，但现行实现保留密文轴（更安全），不倒退回明文轴；JJC-001 引用型证书随快照同步的行为在甲路线关闭时逐字保留。
3. **从节点自动热重载**：从节点导入密文行后比较本地导入前后的 `cert_version`，只要 `before < after` 就走 `ReloadFromDB` → `ApplyConfigForce` 强制 `POST /load`（带 `Cache-Control: must-revalidate`）。证书路径确定性使渲染 JSON 字节在证书变化前后完全相同，强制重载确保 Caddy 的 `lb_db` loader 重新 provision、新证书立即生效；证书未变时不做额外重载。

**运维要点：** 证书由主节点扫描 `/app/certs` 入库，从节点**不依赖**自身 `/app/certs` 落盘（甲路线下 Caddy 从本地密文库解密装载）。主节点扫到变化即自身 force reload，从节点同步后 force reload，**两端都无需重启容器**；两处 reload 共用 `CaddyOpLock` 串行，且都在锁内重新渲染当前 DB，不会互相用陈旧配置覆盖。甲路线关闭或 DEK 未配置时扫描器完全 no-op，行为与基线一致；DEK 来源见 `LB_CERT_DEK_B64` / `LB_CERT_KMS_ENDPOINT` 说明。

## 端口

| 端口 | 用途 |
|---|---|
| `8000` | 管理面板与 REST API |
| `80 / 443` | HTTP/HTTPS 代理流量 |
| `2019` | Caddy Admin API（仅回环） |
| 自定义 | TCP 规则监听端口 |

> Linux 推荐 `--network host`。macOS/Windows 用 `-p 8000:8000 -p 80:80 -p 443:443 -p 443:443/udp`（UDP 为 HTTP/3 必需）。
>
> **容器配置用环境变量**（上表）。`docker run <镜像> -config <路径>` 之类的显式参数会被入口脚本透传给面板进程（早期镜像会静默丢弃参数），但容器内侧面板端口固定 8000——用 `-config` 改 `port` 会让内置健康检查打错端口，容器形态请勿改面板端口。

## 修改默认端口（含 compose 具体改法）

80/443 被宿主其他服务占用时的换口方式。**先分清两个端口**：

| 端口 | 能否改 | 方式 |
|---|---|---|
| 代理默认口 80/443 | **可改** | 环境变量 `HTTP_PORT` / `HTTPS_PORT` |
| 面板口 8000 | **容器形态不可改** | 内置健康检查恒打 8000，改了必被判 unhealthy；`PANEL_PORT` 仅裸机自定义启动可用 |

### docker run

```bash
docker run -d --name lazy-balancer --network host \
  -e HTTP_PORT=8080 -e HTTPS_PORT=8443 \
  <其余参数同 README 快速开始> \
  docker.cnb.cool/xzydm/mirrors/lazy-balancer-v2:latest
```

### docker-compose.yml

host 网络下这两个值就是 Caddy 在宿主实际绑定的端口。仓库自带的 `docker-compose.yml` 主节点 environment 段已预置注释行，取消注释即可：

```yaml
  lazy-balancer:
    # ...
    environment:
      - NODE_NAME=master
      - LOG_FILE=/app/logs/lazy-balancer.log
      - HTTP_PORT=8080      # 取消注释并改成目标端口
      - HTTPS_PORT=8443
```

Docker Desktop（bridge 网络）场景换口的是 `-p` 映射侧（如 `-p 8080:80`），`HTTP_PORT`/`HTTPS_PORT` 一般保持默认——它决定的是 Caddy 在容器内绑定的端口，与映射无关。

### 语义边界（重要）

`HTTP_PORT`/`HTTPS_PORT` 是本 fork 自研能力（上游无），只决定**默认语义**：

- 新建规则向导的默认端口、空域名兜底站监听口、HTTP→HTTPS 跳转 Location 的自引用判定、80/443 保留端口判定；
- **已保存规则的监听端口是持久化数据，不会自动迁移**——全项目换口需在面板逐条修改规则后保存。

非法值（0/负数/>65535）启动时回退出厂默认 80/443 并写运行日志告警；`HTTP_PORT`/`HTTPS_PORT` 与面板口同值时同样告警（面板抢占后 Caddy 无法绑定）。实现见 `internal/config/config.go` 与 `internal/services/default_ports.go`，语义说明见 `docs/fork-notes/ports-and-config.md`。

### 面板口 8000 被占用（host 模式专属问题）

host 网络下面板直接绑定宿主 8000——若被宿主其他服务占用，面板启动即绑定失败、容器退出并随 `unless-stopped` 进入重启循环（`docker logs` 可见 bind error）。

处理方式按优先级：

1. **首选**：停掉或迁移占用 8000 的宿主服务（`ss -ltnp | grep :8000` 定位）；
2. **换口**：设 `PANEL_PORT` 环境变量（如 compose 里 `- PANEL_PORT=9000`），面板真实监听新口，**内置健康探针自动跟随该口**（探针按 `PANEL_PORT` 求值，非法值告警回落 8000）——无需覆盖 healthcheck。本 fork 自研能力（上游探针硬编码端口），实现见 `cmd/server/healthcheck.go` 的 `healthcheckPanelPort` / `healthcheckURLs`；
3. **禁止**：`PANEL_PORT` 与代理口（`HTTP_PORT`/`HTTPS_PORT`）或 80/443 同值——面板抢占后 Caddy 无法绑定，启动日志有互斥告警。

> 探针跟随只认 `PANEL_PORT` env。用 `docker run <镜像> -config` 经配置文件换面板口的部署不受支持（见「端口」一节注），探针也不会跟随。

### 透传内部终结口 7443 被占用

启用 TLS 透传规则后，系统会在 `127.0.0.1:7443`（仅回环）挂内部 TLS 终结口。它不对外，但 host 网络下仍可能与宿主其他进程的**回环监听**冲突——冲突时 Caddy 绑定失败、配置应用报错。

换口：设 `PASSTHROUGH_INTERNAL_PORT` 环境变量（如 compose 里 `- PASSTHROUGH_INTERNAL_PORT=17443`）。语义边界：

- **默认**绑 `127.0.0.1`（绑定地址另可配，见下节）；换口不改变绑定地址，
  `proxy_protocol` 的 allow 由绑定形态派生，默认仍只信回环来源；
- 换口后 Layer4 兜底路由、HTTP 监听迁移地址三处自动同步，无需其他配置；
- 与规则的监听端口同值时配置生成显性报错（不会静默生成绑不上的配置）；
- 非法值（非数字/0/负/>65535）告警回落 7443。

实现见 `internal/services/caddy.go` 的 `internalTerminatePort`，自研登记第 5 项。

### 家庭网络 / 上游封 443（直连终结口入站）

家宽或 ISP 封禁入站 443 时，TLS 透传的 Layer4 SNI 分流本身收不到流量（443 上
没有连接可分流）。逃生形态：把内部终结口绑到对外地址，让外部**直接连终结口
入站**——代价是这一入口上放弃 SNI 分流（透传域名不可用），本地终结域名照常。
compose 两行：

```yaml
environment:
  - PASSTHROUGH_INTERNAL_PORT=17443
  - PASSTHROUGH_INTERNAL_BIND=0.0.0.0
```

`PASSTHROUGH_INTERNAL_BIND` 取值：未设 / `127.0.0.1` / `localhost` / `::1` = 收口
回环（默认，不对外）；`0.0.0.0` = 全部 IPv4 网卡（dial 仍走 `127.0.0.1`）；`::` =
全部 IPv6 网卡（`[::]:<port>`，dial 走 `[::1]`）；其他 IP = 只绑该 IP（allow 自动
追加该 IP）。非法值告警回落 `127.0.0.1`（不静默生效）。

**五条代价，逐条确认再上**：

1. **入站放弃 SNI 分流**：所有域名（含透传域名）都进同一终结口，透传域名在该
   入口**不可用**（其证书在上游，本系统不持有、不终结）。
2. **L4 层 IP/GeoIP 拦截不生效**：直连终结口的连接不经 Layer4 的 IP/GeoIP 门
   （HTTP 层 WAF、规则级 IP 黑名单仍生效）；需要按来源封禁时，前移到防火墙或
   路由器。
3. **该口无 HTTP/3**：QUIC（UDP）仍留在原 HTTPS 端口，443 被封后 HTTP/3 不可达，
   客户端降级 HTTP/2 / HTTP/1.1。
4. **外部 ACME TLS-ALPN-01 不可达**：该挑战走 443 入站，封 443 即失败；证书须用
   **DNS-01** 签发（本系统支持）。
5. **必须用防火墙/路由器限制来源**：该口一旦对公网开放，`proxy_protocol` 的
   allow 只挡伪造头，不能替代来源控制。

其余边界：`PASSTHROUGH_INTERNAL_PORT` 须与规则监听端口不同（同值渲染显性报错）；
listen / dial / allow / servers 挂载键四元同源，换绑定无需其他配置。实现见
`internal/services/caddy.go` 的 `internalTerminateBind` / `internalTerminateExposed` /
`internalTerminateProxyAllow`，自研登记第 5 项。

## 生产参数

**文件描述符**是必需项（已内置在 compose 中）：

```bash
--ulimit nofile=1048576:1048576
```

**进程/线程配额**建议同时设置两层（compose 已内置）：

```bash
--ulimit nproc=4096:4096   # 容器内 RLIMIT_NPROC（ulimit -u）
--pids-limit=4096          # cgroup pids.max（按线程计数）
```

两层作用域不同：`nproc` 是进程级 rlimit，`pids_limit` 是容器 cgroup 硬上限；实际可创建的任务数取较低者。**两者只作用于容器，宿主系统 ulimit 不需要修改**。

**停止宽限期**（优雅关停）：面板关停链的最坏路径预算为 25 秒（HTTP 在途请求 → Caddy 排水 → 威胁大屏停止 → 任务引擎排空 → metrics/时区/日志轮转收尾 → ACME 收尾）。Docker 默认停止宽限只有 10 秒，第 10 秒即 SIGKILL：在途代理连接被硬断（`docker events` 里 `die` 的 `exitCode=137`）、`task_runs` 可能滞留在 `running`、日志尾部丢失。因此裸 `docker run` 必须带 `--stop-timeout 30`（compose 文件已内置 `stop_grace_period: 30s`）；systemd/Kubernetes 等自管编排请配置等效的 ≥25 秒停止宽限。

内核级调优（sysctl）均为可选——默认值已生产就绪，完整指南见 [生产调优](production-tuning.zh-CN.md)。

## 安全事件采集（IPC + 兜底补采）

当前镜像的安全事件采集使用 **IPC 主路径 + fallback spool**：

```text
Caddy 审计写侧 → Unix socket → 面板入库（DB commit 后 ack）
                      └─ 失败/超时/未确认 → /app/data/security-events-spool
                                                  ↓
                                          现有采集任务补采 → 删除已提交文件
```

- IPC socket：`/app/data/security-events.sock`（仅本机；权限 0600）
- 兜底目录：`/app/data/security-events-spool`（正常应为空）
- 正常事件只写 `lazy-balancer-metrics.db` 的 `security_events`，不再保留全量 WAF 审计文件；
- IPC/DB 失败的事件进入 spool，采集任务补采，**DB commit 成功后才删除**；
- 补采完成后 spool 为空；事件日志页的“缓存 N 条”即为待补采条目数；
- 成功事件以 metrics DB 为权威，请配置数据库备份；spool 建议一并纳入备份；
- 自定义 `data_dir` 部署需保证 Caddy 与面板共享同一数据卷，并用
  `LB_SECURITY_EVENTS_IPC_SOCKET` / `LB_SECURITY_EVENTS_SPOOL_DIR` /
  `LB_SECURITY_EVENTS_L4_SPOOL_DIR` 显式覆盖时保持一致（第三项为 L4 兜底事件
  spool，缺失时写侧落默认路径、面板永不扫描）；
- 旧版 `audit.log` 会在升级后继续消费存量，消费完成后不再新增；该文件由安全事件摄取链路管理，日志清理任务不再轮转/截断它。

详见 `docs/security.zh-CN.md`。

## 品牌定制

`data/branding.json`（启动时检查:缺失建模板、缺字段补空值、齐全零写入;载入内存后修改即时生效——mtime 检测自动重载(热重载记操作日志「重载/品牌配置」,逐字段旧→新;半截写保旧值不闪默认、不镜像到从节点,文件恢复即收敛);单字段类型错仅该字段回退默认。集群模式:主节点修改随恒同步的「系统数据」节自动分发到从节点,从节点本地手改会被同步覆盖）:

```json
{ "app_name": "Lazy Balancer", "footer_text": "Copyright © 2026 XiaoBao.", "landing_text": "", "version": "" }
```

| 字段 | 说明 | 空值行为 |
|---|---|---|
| `app_name` | 产品名（侧栏/登录页/拦截页） | 回退 `Lazy Balancer` |
| `footer_text` | 页脚文案 | 回退默认页脚（含 GitHub 链接） |
| `landing_text` | 空域名命中网关时的提示页文案 | 回退 `Lazy Balancer V2 is running!` |
| `version` | 覆盖构建版本号显示 | 回退构建版本 |

## 配置备份

- **导出**：系统信息 → 配置备份（.lbbak 备份包，tar.gz，含配置/凭证与证书；勾选安全防护分类含规则库文件）。可按四个分类选择性导出：**系统数据**（用户/密钥/证书配置，含全局配置）、**负载规则**（规则/上游/路径/证书任务）、**安全防护**（策略/自定义规则/拦截页/名单/规则库版本）、**节点拓扑**（从节点列表与站点坐标，含节点令牌哈希——灾备后旧令牌仍可认证，备份文件需同等加密保管）
- **导入**：校验失败零写入；v2 备份需 ≥ v2.1.2 导出。可按分类导入，未选分类保持现状；勾选「节点拓扑」会整体替换从节点列表——备份中不再存在的节点，其证书指纹钉与分区上报缓存一并清除，备份中无令牌的节点恢复为待审批（需在节点页重新注册/审批）。导入失败（含事务提交前被 Caddy 拒绝）时整体回滚：数据库与规则库文件（CRS 规则树、IP2Region 库、威胁名单）一并回到导入前状态，界面会明确提示是否已回退；回退失败会显性告警并写入审计，请按提示重新导入或触发规则库更新收敛
- **v1 迁移**：选择 nginx 版备份自动转换

## 四道合法性关卡

每次配置写入经过：前端校验 → 后端字段校验 → caddy CLI 校验 → 事务内应用。非法值 400 拒绝、零落库。

## 受信代理（CDN 真实 IP 还原）

代理规则前置 CDN / 反向代理时，TCP 源地址是回源节点地址。若不还原，IP 黑白名单/信任名单、地域判定、限流与安全事件的来源 IP 都会按回源节点判定——同一节点的全部访客共享限流桶、名单形同虚设、事件来源失真。

在「基础设置 → 安全防护 → 受信代理」开启并配置（仅作用于代理规则的数据面；管理面板 API 恒按 TCP 直连源地址判定，见下一节）：

- **受信网段**：填写该 CDN 官方公布的回源网段（CIDR；IPv4 最宽 /8、IPv6 最宽 /29；内联条目上限 64 条，内联与引用合计上限 2000 条——AWS CloudFront 等长清单请改用下方「引用地址列表」维护）。仅这些网段发来的代理头会被采信；网段为空时不采信任何头（退回 TCP 源地址，fail-closed）。
- **引用地址列表**：可引用「规则集 → IP 地址列表」中自定义列表的条目，与内联网段合并去重；内置系统名单（威胁情报/爬虫/自动封禁）不可引用。
- **请求头**：按优先级排列可信头（上限 8 条），留空等价于仅 `X-Forwarded-For`；面板提供 Cloudflare / Akamai / Fastly / AWS CloudFront / 阿里云 CDN/ESA / 腾讯云 CDN/EdgeOne 等预设，仅一键填充头名，网段仍需按官方列表维护。
- **严格模式**：默认开启，取「最右可信」值；关闭后取最左值，可被客户端伪造，仅用于特殊代理链。

保存后约 1 秒内热生效，无需手动重载；网段/引用名单变更通过投影文件热收敛（零 `/load`），因此不会产生「重载」审计。只有启用态、请求头或严格模式变化才触发 Caddy 热应用与重载记录。受信代理与「面板直连」是两套语义：前者还原**代理流量**的真实客户端 IP，后者约束**管理面板**的访问路径。

## 面板访问与安全语义（多节点/反代须知）

**限流与锁定是面板实例本地状态**：登录/IP 限流桶（内存）与账户级登录锁定计数均存于单节点，集群多节点间不共享（仅活跃锁 `locked_until` 随用户快照单向同步至从节点，失败计数不传播）。多节点同时可达面板时，同一来源的爆破预算按节点数放大、锁定按节点独立判定——请将面板管理入口收敛到主节点或统一入口。

**面板应直连访问，不要在前置反向代理/CDN 之后暴露**：面板启动时执行 `SetTrustedProxies(nil)`（不信任任何代理头），`ClientIP` 恒取 TCP 直连源地址。若置于反代之后，所有请求的源 IP 都会是代理地址——限流桶被全体访问者共享（一人触发限流全体遭殃）、IP 白名单只会匹配到代理地址（形同虚设）、审计与安全事件的来源 IP 全部失真。需要 HTTPS 终结时，请在面板所在主机本机回环侧做代理并确信直连源语义可接受。

## 重启语义与容器策略

面板的“重启服务”、启用面板 HTTPS、集群 `restart_app` 都会让面板进程退出，作为 PID 1 的 tini 随后退出，容器因此停止。裸 `docker run` 必须带 `--restart unless-stopped`（compose 已内置 `restart: unless-stopped`），否则容器不会自动拉起，面板与代理流量会同时停摆。裸机 systemd 部署需配置等效的自动重启策略。

**PID 1 与子进程回收**：当前镜像以 tini 作为 PID 1，健康检查也由二进制子命令完成（不派生 shell/客户端进程），被遗弃的子进程会被自动回收，部署时无需额外加 `--init`。若固定使用更早镜像，容器内 PID 1 是面板进程且不回收孤儿，请务必追加 `--init`。启动示例默认设置 `--pids-limit=4096`（cgroup PID 配额按线程计数），可按部署规模调整。诊断命令：`cat /sys/fs/cgroup/pids.current`、`/sys/fs/cgroup/pids.max`、`/sys/fs/cgroup/pids.events`（`max` 计数即历史撞线次数）。

## Caddy 2.11.6+ 行为变化（当前镜像 2.11.9，升级前须知）

以下为底层 Caddy 升级到 v2.11.6 后的默认行为变化与后续版本增量（当前镜像已包含 2.11.6→2.11.9 全部增量）。仓库自身渲染面不受影响（已核验零引用），但**用户自建数据面**需要注意：

- **（v2.11.8 安全加固）异常 Host 值的请求直接拒绝**：Host 值含点段（如 `example.com..`）或斜杠的请求现在会被服务端拒绝（此前这类请求可能绕过路径类防护）——正常域名解析场景不受影响。
- **（v2.11.8 修复）HTTP/2 慢上传不再 502**：经反向代理的大体量 HTTP/2 上传（如 WebDAV、文件上传）此前偶发 502，已修复。
- **（v2.11.8 修复）压缩 ETag 匹配**：启用压缩的规则对带 ETag 请求的匹配行为修正。

以下为底层 Caddy 升级到 v2.11.6 后的默认行为变化。仓库自身渲染面不受影响（已核验零引用），但**用户自建数据面**需要注意：

- **下划线/点号请求头移除**：Caddy 收紧了非标准头名（含下划线/点号，如 `user_agent` 变体）的处理，此类头不再进入匹配面。若你的自创 WAF 规则或 `access_log_format` 引用了下划线头名，升级后会**静默停止匹配/记录**——请改用连字符头名（如 `user-agent`）。
- **请求头总大小默认上限 16KiB，超出返回 431**：大 Cookie 的边缘部署（如携带大量凭证头的内网系统）会命中新上限；如需旧行为可显式设置更大的头上限（Caddy `max_header_size` 选项）。
- **未显式配置超时时的新默认：1 分钟空闲读/写超时**：慢客户端长连接（大文件上传挂起、半开连接）超过空闲窗口会被服务端主动关闭，不再无限等待。
- **499 客户端取消语义**：客户端在响应完成前主动断开时，访问日志按 499 分桶记录（此前计入 4xx）——基于状态码 4xx 的告警口径不受影响，但日志分析需知晓该新桶。
