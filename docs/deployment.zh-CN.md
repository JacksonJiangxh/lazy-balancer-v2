# 部署指南

## 挂载目录

| 容器路径 | 内容 | 必需 |
|---|---|---|
| `/app/data` | 业务/审计/指标数据库、ACME 账户密钥 | **是** |
| `/app/certs` | 证书与私钥 | **是** |
| `/app/logs` | 应用日志、Caddy 日志、按规则访问日志 | 推荐 |
| `/app/waf` | CRS 规则、IP2Region xdb（Coraza 审计日志在 `/app/logs/waf-audit`） | 推荐 |
| `/app/backup` | 自动备份落盘目录（不挂载则容器重建后备份文件丢失） | **是** |
| `/app/config` | Caddyfile（仅高级定制） | 可选 |

> 不挂载 `/app/waf` 时，容器重建会将 CRS 回退到镜像捆绑版本；系统自动将更新后的规则树快照持久化到数据卷并在启动时对账恢复。数据库是配置的唯一真实来源。

> Docker Desktop（macOS/Windows）用户：`/app/data` 推荐 named volume（`lb-data:/app/data` 形态，见仓库 docker-compose.yml）；bind mount 经 FUSE 共享层有 SQLite WAL 丢页风险（Linux 宿主 bind mount 无此问题）。

## 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `JWT_SECRET` | 自动生成 | JWT 签名密钥；生产建议显式设置 |
| `LOG_FILE` | `/app/logs/lazy-balancer.log` | 运行日志文件路径（恒启用，LOG_FILE 仅覆盖路径） |
| `NODE_NAME` | `node-1` | 集群注册的默认节点名 |
| `APP_VERSION` | 构建时注入 | 显示版本号 |
| `TZ` | 数据库 `timezone` | 进程时区 |
| `HTTP_PORT` | `80` | HTTP 代理默认监听口（见下方「端口换位」） |
| `HTTPS_PORT` | `443` | HTTPS 代理默认监听口 |
| `PANEL_PORT` | `8000` | 管理面板与 REST API 监听口 |

## 端口

| 端口 | 用途 |
|---|---|
| `8000`（可改 `PANEL_PORT`） | 管理面板与 REST API |
| `80 / 443`（可改 `HTTP_PORT` / `HTTPS_PORT`） | HTTP/HTTPS 代理流量 |
| `2019` | Caddy Admin API（仅回环，不可改） |
| 自定义 | TCP 规则监听端口 |

> Linux 推荐 `--network host`。macOS/Windows 用 `-p 8000:8000 -p 80:80 -p 443:443 -p 443:443/udp`（UDP 为 HTTP/3 必需），改口号后同步替换映射。

### 端口换位（80/443/8000 被占用时）

宿主机 80/443 已被其他服务占用时，用三个环境变量等位替换：

```yaml
environment:
  - HTTP_PORT=8080     # 原 80
  - HTTPS_PORT=8443    # 原 443
  - PANEL_PORT=9000    # 原 8000
```

**是换监听口，不是端口转发**：host 网络下 Caddy 直接绑这些端口，改 `HTTP_PORT=8080` 后 80 不再被本容器监听。

影响范围（只影响「默认语义」）：

- 新建规则向导的默认监听端口，以及 TLS 开关时的 80↔443 联动；
- 空域名兜底站与 HTTP→HTTPS 跳转的落点端口；
- 80/443 保留端口判定（TCP 规则不得抢这两个口）与管理口拦截。

**不影响存量规则**：`lb_rules.listen_port` 是持久化数据，渲染时原样使用。存量规则需要你手动逐条改成新端口并保存——保存即落库生效，不会被自动迁移或覆盖。

> 提示：面板口与代理口不要设成同一个值；非法值（0 / 超范围 / 非数字）会回退出厂默认并在日志留痕。

## 生产参数

**文件描述符**是唯一必需项（已内置在 compose 中）：

```bash
--ulimit nofile=1048576:1048576
```

内核级调优（sysctl）均为可选——默认值已生产就绪，完整指南见 [生产调优](production-tuning.zh-CN.md)。

## 品牌定制

`data/branding.json`（启动时检查:缺失建模板、缺字段补空值、齐全零写入;载入内存后修改即时生效——mtime 检测自动重载(热重载记操作日志「重载/品牌配置」,逐字段旧→新;半截写保旧值不闪默认、不镜像到从节点,文件恢复即收敛);单字段类型错仅该字段回退默认。集群模式:主节点修改经「全局配置」同步开关自动分发到从节点,从节点本地手改会被同步覆盖）:

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

- **导出**：系统信息 → 配置备份（.lbbak 备份包，tar.gz，含配置/凭证与证书；勾选安全防护分类含规则库文件）
- **导入**：校验失败零写入；v2 备份需 ≥ v2.1.2 导出
- **v1 迁移**：选择 nginx 版备份自动转换

## 四道合法性关卡

每次配置写入经过：前端校验 → 后端字段校验 → caddy CLI 校验 → 事务内应用。非法值 400 拒绝、零落库。

## 面板访问与安全语义（多节点/反代须知）

**限流与锁定是面板实例本地状态**：登录/IP 限流桶（内存）与账户级登录锁定计数均存于单节点，集群多节点间不共享（仅活跃锁 `locked_until` 随用户快照单向同步至从节点，失败计数不传播）。多节点同时可达面板时，同一来源的爆破预算按节点数放大、锁定按节点独立判定——请将面板管理入口收敛到主节点或统一入口。

**面板应直连访问，不要在前置反向代理/CDN 之后暴露**：面板启动时执行 `SetTrustedProxies(nil)`（不信任任何代理头），`ClientIP` 恒取 TCP 直连源地址。若置于反代之后，所有请求的源 IP 都会是代理地址——限流桶被全体访问者共享（一人触发限流全体遭殃）、IP 白名单只会匹配到代理地址（形同虚设）、审计与安全事件的来源 IP 全部失真。需要 HTTPS 终结时，请在面板所在主机本机回环侧做代理并确信直连源语义可接受。

## Caddy v2.11.6 行为变化（升级前须知）

以下为底层 Caddy 升级到 v2.11.6 后的默认行为变化。仓库自身渲染面不受影响（已核验零引用），但**用户自建数据面**需要注意：

- **下划线/点号请求头移除**：Caddy 收紧了非标准头名（含下划线/点号，如 `user_agent` 变体）的处理，此类头不再进入匹配面。若你的自创 WAF 规则或 `access_log_format` 引用了下划线头名，升级后会**静默停止匹配/记录**——请改用连字符头名（如 `user-agent`）。
- **请求头总大小默认上限 16KiB，超出返回 431**：大 Cookie 的边缘部署（如携带大量凭证头的内网系统）会命中新上限；如需旧行为可显式设置更大的头上限（Caddy `max_header_size` 选项）。
- **未显式配置超时时的新默认：1 分钟空闲读/写超时**：慢客户端长连接（大文件上传挂起、半开连接）超过空闲窗口会被服务端主动关闭，不再无限等待。
- **499 客户端取消语义**：客户端在响应完成前主动断开时，访问日志按 499 分桶记录（此前计入 4xx）——基于状态码 4xx 的告警口径不受影响，但日志分析需知晓该新桶。

## 流水线密钥：键名直接使用，不要中转改名

### 先用对，再说坑

`imports` 会把密钥文件的每个键**逐 key 原样注入为环境变量**，变量名就是文件里的键名。
所以脚本里**直接引用同名变量**即可：

```yaml
# 密钥仓库 xzydm/xzsecret 的 github.yml
GIT_163_ALL_TOKEN: "ghp_163..."

# .cnb.yml
imports:
  - https://cnb.cool/xzydm/xzsecret/-/blob/main/github.yml
stages:
  - script: |
      TOKEN="${GIT_163_ALL_TOKEN:-}"
```

**不要中转改名。** 像这样是错的方向：

```yaml
env:
  GIT_ALL_TOKEN: ${163_GIT_ALL_TOKEN}   # ❌ 中转：审计对象与真实取值分离
```

两个理由：

1. **审计链路会断**。密钥仓库的审计记录的是"哪个流水线引用过这个文件"，被审计的是**密钥文件里的那个键名**。一旦把值转进你自己起名的变量，真正参与拼接的字符串就不再对应审计条目——排查"这个 token 被谁用过"时，链路上多出一段查不到的黑箱。你担心的泄露面，正是从这里长出来的，不是被消掉的。
2. **中转没有任何好处。** 它唯一的作用是绕开"名字不合法"，而绕开的方式本就该是改键名（见下）。多一层变量 = 多一处可能被误打印、误导出、误落日志的地方。

### 真正会踩的坑：键名以数字开头

本仓此前"构建镜像成功、推送 GitHub 拿不到 token"，根因就是键名 `163_GIT_ALL_TOKEN` 以数字开头。
官方文档对变量名有硬约束（[环境变量 · 限制说明](https://docs.cnb.cool/zh/build/env.md)）：

> 变量名格式：仅支持字母、数字和下划线，**不能以数字开头**。

并且明确：**不符合规则的变量会被忽略。**

实测（Debian 13，`/bin/sh` → `dash`）：

```console
$ env -i 163_GIT_ALL_TOKEN=SECRET123 dash -c 'printenv 163_GIT_ALL_TOKEN'
                                    # 无输出：变量不存在
$ env -i 163_GIT_ALL_TOKEN=SECRET123 bash -c 'printenv 163_GIT_ALL_TOKEN'
SECRET123                           # bash 能拿到
$ env -i 163_GIT_ALL_TOKEN=SECRET123 dash -c 'python3 -c "import os;print(os.environ.get("163_GIT_ALL_TOKEN"))"'
None                                # dash 里连子进程都拿不到
$ env -i 163_GIT_ALL_TOKEN=SECRET123 python3 -c 'import os;print(os.environ.get("163_GIT_ALL_TOKEN"))'
SECRET123                           # 不经 shell 就能拿到
```

结论：**token 确实被 `imports` 注入到了进程环境，是默认 shell（`dash`）在启动时把这条非法名目删掉了**
（`/proc/self/environ` 里的对应槽位也没了）。所以任何 shell 层的事后补救——`printenv`、`env`、
`bash -c`、外包一个脚本——都没用，变量在脚本开始前就不存在了。

### 修法：保留账号标识，只挪位置

163 是多账号场景的账号标识，必须留。它只是不能出现在**开头**，放在中间或结尾一样能区分账号：

```yaml
# 密钥仓库 xzydm/xzsecret 的 github.yml
GIT_163_ALL_TOKEN: "ghp_163..."   # ✅ 推荐：账号号夹在中间
GIT_ALL_TOKEN_163: "ghp_163..."   # ✅ 等价：账号号放结尾
163_GIT_ALL_TOKEN: "ghp_163..."   # ❌ 数字开头：sh 脚本里永远读不到

# 多账号并列，各自独立、互不串号：
# GIT_163_ALL_TOKEN: "ghp_163..."    # 163 账号
# GIT_ABC_ALL_TOKEN: "ghp_abc..."    # 另一个账号
```

改完键名，流水线侧**直接用**，不需要配套改动：

```yaml
stages:
  - script: |
      TOKEN="${GIT_163_ALL_TOKEN:-}"
      [ -n "$TOKEN" ] || { echo "缺少令牌"; exit 1; }
```

### 诊断口诀

**`imports` 授权错了 → 整个文件加载失败（流水线直接报错）；键名非法 → 文件正常加载但变量读不到（表现为空值）。**

两种现象完全不同，后者跟密钥仓库的 `allow_*` 无关——先分清现象属于哪一类，再去查 `allow_*`，否则会白折腾一轮。
