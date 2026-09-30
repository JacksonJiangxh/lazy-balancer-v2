# 统一任务引擎标准（lazy-task-engine SPEC v1.1）

**裁定日**: 2026-09-29 · **适用**: v2.3.4+ 全部任务族

## 1. 原则

1. **单一事实源**：任务的身份/调度/状态/历史/日志/控制只有引擎一个定义点。面板、API、MCP、审计全部消费引擎产出，禁止平行任务实现。
2. **引擎管生命周期，任务体管业务**：调度、单飞、取消、启停、历史、日志、审计框架归引擎；业务编舞（哈希/重试/回滚/竞态守卫）归任务体，原样保留。
3. **手动 ≡ 自动**（2026-09-29 用户裁定）：同一任务体、同一审计、同一日志、同一历史；触发源仅是记录维度，不得产生行为分叉。
4. **标准、通用、可拔插**：任务注册即接入全部能力（UI/API/MCP/审计/历史/日志）；摘除注册即干净退出，不残留。
5. **业务解耦**：任务体经 `Descriptor` 声明接入，禁止任务代码反向依赖面板/handler；引擎不 import 业务包（业务经 wire 层组装闭包注入）。

## 2. 职责边界

| 面 | 引擎 | 任务体（业务） | 面板/Handler |
|---|---|---|---|
| 身份/类型/分类 | Descriptor 定义 | — | 只读展示 |
| 调度 | tick 驱动、间隔/探测轮 | 排程槽 due 判定（探测体内） | 开关透传 |
| 执行 | 单飞/主节点门/角色门 | Run 编舞 | — |
| 取消 | ctx 管道+CancelHook | 检查点响应 | 确认弹框 |
| 历史 | task_runs（策略见 §6） | — | 只读 |
| 日志 | tasks/{id}.log 生命周期行 | TeeTaskLog 分阶段流水 | 暗色终端弹框 |
| 审计 | — | **体内自记**（手动≡自动） | 人机操作（启停/暂停）才补记 |
| 状态 | 循环态/最近终态 | StatusFn 镜像 | — |

## 3. 类型（Kind = 驱动节拍；AsKind = 展示性质）

| Kind | 驱动 | 用途 |
|---|---|---|
| Continuous | IntervalFn 动态间隔 | 常驻循环/探测轮 |
| Scheduled | 经 Continuous 探测轮实现 | 排程槽族（AsKind=Scheduled） |
| Queue | 无（镜像） | 队列状态镜像 |
| Oneshot | 无 | 单次触发（启动/手动） |
| Info | 无 | 引擎外信息行 |

## 4. 状态机

`running / idle / queued / failed / cancelled / stopped / disabled / passive / no_runs / interrupted`
- 定时族：StatusFn 镜像 > 最近 task_runs 终态；循环态不外露
- 常驻族：循环态（running/stopped）；工作感知族（CA 等待轮询）叠加有活判定
- 下次执行：排程槽族以槽为权威（禁探测兜底）；间隔族 last+interval；未启用/常驻/队列/单发 → `—`

## 5. 调度策略

- 排程槽（周/时刻）：NextSlotFn 声明式读取族配置；调度正确性由探测轮体内 due 逻辑保证
- 固定间隔：IntervalFn（动态；tick 每秒重读即热生效——Reschedule 已随死构件清理移除，v1.1）
- 探测轮：1min，SilentProbes（不落历史）
- 角色门：RunsOn（master-only/slave-only/any）+ demote 竞态守卫留在任务体

## 6. 记录策略（统一）

| 记录面 | 策略 |
|---|---|
| task_runs 历史 | 真实运行全记；探测轮静默；高频成功轮 RecordFailuresOnly；**manual 恒记**；保留 90 天 |
| 任务日志 tasks/{id}.log | 生命周期行 + 业务 tee；与历史同策略（静默成功轮零行）；>cert_job_log_size_mb（默认 10MB） rotate 保 .1；保留期同审计月数 |
| 审计 | 任务体自记（更新/载入/备份等业务事件）；清理/循环轮不进审计（task_runs 即记录）；人机操作（启停/暂停/触发确认）由 handler 记 |
| 时区 | 全部写入/展示按基础设置 timezone（engineLoc 注入） |

## 7. 可拔插契约

注册 = `Register(Descriptor)` + 可选 `SetAsKind/SetManualRun`；摘除 = `Unregister`。任务清单、监控页、MCP、apidocs 自动收敛。动态行（cert-job:*）经收集器并入视图，同一 TaskInfo 形状。

**调度列语义（2026-09-29 用户裁定）**：调度开关仅属于定时族（ToggleFn 声明者可操作；无排程槽的固定间隔族显示「固定间隔」标识）；常驻族显示**循环启停**（绑 loop_on）；Info/Queue 显示「—」。cert-job 动态行计数=终态映射（issued→成功+1/failed→失败+1）。

## 8. 合规核对矩阵（16 族 + 队列卡 + 动态行）

| 族 | Kind/AsKind | 状态口径 | 下次时间 | 历史 | 日志 | 审计 | 手动≡自动 | 结论 |
|---|---|---|---|---|---|---|---|---|
| threat/crs/ip2region | Continuous/Scheduled | 镜像>终态 | 槽✓ | ✓ | tee✓ | 体自记✓ | ✓ | 合规 |
| auto-backup | Continuous/Scheduled | 终态 | 槽✓ | ✓(executor 记) | tee?→补 | 体自记✓ | ✓ | 日志 tee 缺 |
| watchdog/ingestion | Continuous/Continuous | 循环态 | —✓ | 失败留痕 | 生命周期行 | 不进✓ | n/a | 合规 |
| log-cleanup/audit/events-retention | Continuous/Scheduled | 终态 | last+24h✓ | ✓ | 生命周期行 | 不进✓ | ✓ | 合规 |
| cert-renewal/reconcile | Continuous/Scheduled | 终态 | last+6h✓ | ✓ | 生命周期行 | 不进✓ | ✓ | 合规 |
| cert-manual | Continuous/Scheduled | 工作感知 | last+10min✓ | 失败留痕 | 生命周期+摘要行 | 不进✓ | ✓ | 合规 |
| waiting-ca | Continuous/**Continuous（可控）** | 工作感知（门控） | CA 可用时间✓ | 失败留痕 | 生命周期+有活摘要行 | 不进✓ | ✓ | 合规（v1.1：真正可控——控制面元数据化后 Controllable 派生要求 AsKind=Continuous，描述符「可经调度开关停用」已兑现） |
| config-load | Oneshot/Oneshot | 终态 | —✓ | ✓ | 生命周期行✓ | 体自记✓ | ✓(共享体) | 合规 |
| cluster-sync | Info/Scheduled | 角色镜像 | last+间隔✓ | 边界(快照) | 边界 | 边界 | n/a | 声明边界 |
| caddy 轮转 | 未注册（非任务） | — | — | — | — | — | n/a | 合规裁定 |
| cert-job:* 动态行 | Queue | 作业状态 | —✓ | cert_jobs | 作业日志端点 | 队列域 | n/a | 合规 |

**缺口清单**：~~auto-backup 任务日志 tee 缺失~~（已闭合——Round 62 修复：backupTee 全阶段留痕）。

### 6.4 任务日志统一口径（2026-09-29 用户裁定）

- **同一目录**：全部任务日志唯一存在于 tasks/{id}.log——每个任务的日志没有第二种文件，所有依赖方（任务监控弹框/规则集更新日志弹框/日志统计栏）读同一文件
- **统一 rotate**：5MB→保 .1 一份；过期按「审计保留月数」配置清理；由「运行日志轮转副本清理」任务族每轮执行（taskLogsHousekeeping）
- **统计栏**：/logs/stats 提供任务日志聚合行（key=tasks）与三库更新行（同文件测量）——全部日志弹框显示 LogStorageBar

## 6.5 业务摘要行（v1.1 新增，2026-09-29 用户裁定）

每个**真实执行轮**在 tasks/{id}.log 留 1-3 行业务结果（用户可读结论，非仅生命周期行）：
- 低频族（证书扫描/对账/清理三族/载入/备份）：每轮一行结论（「无临期证书/清理 N 条/物化 N 个/应用成功 N 规则」）
- 高频静默族：watchdog 每轮一行结论入日志文件（task_runs 仍失败留痕）；ingestion **有事件才写**（零事件轮零行）；waiting-ca **有活才写**
- 更新族：既有分阶段流水 tee（write*UpdateLog 挂点）即业务摘要
- cluster-sync（v1.1 突破 Info 边界，用户裁定）：同步轮成败各一行
- 写入统一经 services.TaskLogf（时间戳与 tee 流水同形态）
