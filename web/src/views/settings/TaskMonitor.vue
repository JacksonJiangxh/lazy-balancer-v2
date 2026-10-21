<template>
  <div class="tm-root">
    <!-- 历史修复：轮询失败横幅（照 CertJobs 形态；行内件样式复用 main.css
         .polling-error-*/.error-banner，FE-R2 家族收敛第 4 点） -->
    <el-alert v-if="pollingError.errorMessage.value" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>任务监控加载失败：{{ pollingError.errorMessage.value }}</span>
          <el-button link type="danger" :loading="refreshing" @click="retryPolling">立即重试</el-button>
        </div>
      </template>
      <div class="polling-error-meta">{{ pollingErrorDescription }}</div>
    </el-alert>
    <!-- KPI 概览（四卡） -->
    <el-row :gutter="20" class="tm-kpis">
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num">{{ tasks.length }}</div>
          <div class="tm-kpi-label">任务族</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num tm-kpi-run">{{ runningCount }}</div>
          <div class="tm-kpi-label">运行中</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num">{{ total24h }}</div>
          <div class="tm-kpi-label">24h 执行</div>
        </el-card>
      </el-col>
      <el-col :xs="12" :md="6">
        <el-card class="tm-kpi">
          <div class="tm-kpi-num" :class="{ 'tm-kpi-bad': fail24h > 0 }">{{ fail24h }}</div>
          <div class="tm-kpi-label">24h 失败 <el-icon v-if="readOnly" class="tm-kpi-lock"><Lock /></el-icon></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 图表行：状态分布 + 24h 执行 -->
    <el-row :gutter="20">
      <el-col :xs="24" :md="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <div class="card-title"><el-icon class="title-icon"><PieChartIcon /></el-icon><span>任务状态分布</span></div>
            </div>
          </template>
          <v-chart v-if="loaded" :option="statusPieOption" autoresize class="tm-chart" />
          <div v-else class="tm-chart tm-skeleton"></div>
        </el-card>
      </el-col>
      <el-col :xs="24" :md="16">
        <el-card>
          <template #header>
            <div class="card-header">
              <div class="card-title"><el-icon class="title-icon"><DataLine /></el-icon><span>近 24 小时执行（成功 / 失败）</span></div>
              <el-button :icon="Refresh" circle size="small" :loading="refreshing" @click="refreshNow" title="立即刷新" />
            </div>
          </template>
          <!-- 数据就位后再挂载（vue-echarts 8 增量规划对「空 option 挂载→数据后到达」
               的 series/legend 合并不稳——实证轴渲染而序列/图例缺失；挂载即完整
               option 与独立 echarts 实证一致） -->
          <v-chart v-if="loaded && series24h.length" :option="statsBarOption" :update-options="{ notMerge: true }" autoresize class="tm-chart" />
          <div v-else class="tm-chart tm-skeleton"></div>
        </el-card>
      </el-col>
    </el-row>

    <!-- 证书队列横幅（实时——非任务） -->
    <el-card class="tm-cq-banner">
      <div class="tm-cq-banner-inner">
        <div class="tm-cq-banner-title"><el-icon class="title-icon"><Lock /></el-icon><span>ACME 证书任务队列</span></div>
        <div v-if="certQueueError" class="tm-cq-banner-stats">
          <span class="tm-cq-chip">排队 <b>—</b></span>
          <span class="tm-cq-chip">进行中 <b>—</b></span>
          <span class="tm-cq-chip">等 CA <b>—</b></span>
        </div>
        <div v-else class="tm-cq-banner-stats">
          <span class="tm-cq-chip">排队 <b>{{ certQueue.truncated ? '≥' : '' }}{{ certQueue.queued }}</b></span>
          <span class="tm-cq-chip">进行中 <b class="tm-c-run">{{ certQueue.truncated ? '≥' : '' }}{{ certQueue.running }}</b></span>
          <span class="tm-cq-chip">等 CA <b class="tm-c-wait">{{ certQueue.truncated ? '≥' : '' }}{{ certQueue.waiting }}</b></span>
        </div>
        <div class="tm-cq-banner-live">
          <span v-if="certQueueError" class="tm-cq-idle">证书队列状态加载失败（下一轮轮询自动重试）</span>
          <!-- 历史修复：正文空态改按聚合存活计数判定（原只看首页存活行——
               首页均为终态而聚合计数非空时会谎报「空闲」）。 -->
          <template v-else-if="certQueueHasLive(certQueue)">
            <span v-for="j in certQueue.jobs.slice(0, CERT_QUEUE_VISIBLE_JOBS)" :key="j.id" class="tm-cq-domain-chip">
              {{ j.domain }}<i :class="'tm-cq-dot tm-cq-dot--' + j.status" />
            </span>
            <span v-if="certQueueMoreCount(certQueue) > 0" class="tm-cq-more">+{{ certQueueMoreCount(certQueue) }}</span>
          </template>
          <span v-else class="tm-cq-idle">空闲——临期证书由「证书续期扫描」自动入队</span>
        </div>
        <!-- 历史修复：标签判据与聚合计数同口径——排队/等 CA 亦为「非空闲」。 -->
        <el-tag :type="certQueueError ? 'danger' : certQueueIsBusy(certQueue) ? 'primary' : 'success'" size="small" effect="plain">
          {{ certQueueError ? '加载失败' : certQueueIsBusy(certQueue) ? '队列非空' : '空闲' }}
        </el-tag>
      </div>
    </el-card>

    <!-- 任务列表 -->
    <div v-if="certJobsTruncated" class="info-note-bar"><span class="info-note-desc">证书任务行仅显示最近 100 条（更老的签发记录请在证书任务页按规则查看）</span></div>

    <el-card>
      <template #header>
        <div class="card-header">
          <div class="card-title"><el-icon class="title-icon"><List /></el-icon><span>全部任务</span>
            <span class="tm-count">{{ filteredTasks.length }}</span>
          </div>
          <el-select v-model="categoryFilter" size="small" clearable placeholder="全部分类" class="tm-category-filter" @change="page = 1">
            <el-option label="全部分类" value="all" />
            <el-option v-for="c in categoryOptions" :key="c" :label="c" :value="c" />
          </el-select>
          <el-radio-group v-model="kindFilter" size="small">
            <el-radio-button value="all">全部</el-radio-button>
            <el-radio-button value="scheduled">定时</el-radio-button>
            <el-radio-button value="daemon">常驻</el-radio-button>
            <el-radio-button value="periodic">循环</el-radio-button>
            <el-radio-button value="oneshot">触发</el-radio-button>
                      </el-radio-group>
        </div>
      </template>
      <el-table :data="pagedTasks" v-loading="!loaded" size="default" row-key="id" class="tm-nowrap-table">
        <el-table-column label="任务" min-width="128" show-overflow-tooltip>
          <template #default="{ row }">
            <el-tooltip :disabled="!row.description" placement="top" :offset="8" :show-after="150" :show-arrow="false" popper-class="tm-name-tip">
              <template #content>
                <div class="tm-tip-title">{{ row.name }}</div>
                <div v-if="row.cadence" class="tm-tip-cadence">节奏：{{ row.cadence }}</div>
                <div class="tm-tip-desc">{{ row.description }}</div>
              </template>
              <div class="tm-task-name">{{ row.name }}</div>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="分类" width="92">
          <template #default="{ row }">
            <el-tag size="small" effect="plain" :type="categoryTagType(row.category)">{{ row.category }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="类型" width="72">
          <template #default="{ row }">
            <el-tag size="small" :type="kindTag(row.kind)" effect="plain" :class="kindTagClass(row.kind)">{{ kindLabel(row.kind) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="96">
          <template #default="{ row }">
            <!-- 状态列词表=引擎执行语义三态（空闲/运行中/失败，2026-10-22 用户
                 裁定）：证书业务生命周期态（已签发/限流中…）不进状态列，
                 由任务名称下的业务文本承载。 -->
            <span class="tm-status" :data-status="row.status"><span class="tm-dot"></span>{{ statusLabel(row.status) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="调度" width="92">
          <template #default="{ row }">
            <!-- v2.0 调度开关统一：定时/循环=停止/恢复调度、
                 常驻=启停自管理循环——绑定 loop_on 走 /toggle（后端按 Kind 路由）。
                 方案 A（2026-10-12）：并判 enabled（业务开关联动，如自动更新关闭/
                 备份未启用）——业务关时开关显示「已停止」，状态列不再用 disabled 表达 -->
            <!-- 历史修复（历史）：cert-waiting-ca 默认调度关闭、续期扫描入队
                 唤醒——开关上加 tooltip 说明自动唤醒语义（页内既有 tooltip 范式） -->
            <el-tooltip v-if="row.id === 'cert-waiting-ca'" content="有证书任务入队时自动唤醒" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <el-switch :model-value="!!row.loop_on" :disabled="!canOperate" @change="(v: string | number | boolean) => onToggle(row, !!v)" />
            </el-tooltip>
            <el-tooltip v-else-if="row.kind !== 'oneshot'" :content="isBusinessDrivenTask(row) ? '由对应业务页自动更新控制' : '停止/恢复调度'" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <el-switch :model-value="!!row.loop_on" :disabled="!canOperate || isBusinessDrivenTask(row)" @change="(v: string | number | boolean) => onToggle(row, !!v)" />
            </el-tooltip>
            <!-- 触发类（含 cert-job 动态行）：统一显示禁用开关保持页面一致性——
                 仅手动/代码触发执行（2026-10-01 用户裁定；cert-job 特例已消除） -->
            <el-tooltip v-else content="触发类任务不可调度——仅手动/代码触发执行" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <el-switch :model-value="false" disabled />
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="执行时间" width="180">
          <template #default="{ row }">
            <el-tooltip :disabled="!row.last_run" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <template #content>
                <div class="tm-tip-title">最近执行</div>
                <div>{{ fmtTime(row.last_run?.started_at) || '—' }}<template v-if="row.last_run?.duration_ms > 0">（耗时 {{ fmtDuration(row.last_run.duration_ms) }}）</template></div>
                <div class="tm-tip-sep"></div>
                <div class="tm-tip-title">完成时间</div>
                <div>{{ row.status === 'running' ? '进行中' : fmtTime(row.last_run?.finished_at) || '—' }}</div>
              </template>
              <!-- 执行时间列=最近执行时刻（全类型统一，含常驻——其执行记录=boot 行）；
                   不再显示「常驻 · 启动于」文案（2026-10-03 用户裁定） -->
              <span v-if="row.last_run?.started_at">{{ fmtTime(row.last_run.started_at) }}</span>
              <span v-else class="tm-dim">—</span>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column label="下次执行" width="180">
          <template #default="{ row }">
            <span v-if="row.next_run_at && row.loop_on && row.kind !== 'daemon'">{{ row.next_run_at }}</span>
            <span v-else class="tm-dim">—</span>
          </template>
        </el-table-column>
        <el-table-column width="104">
          <template #header>
            <el-tooltip content="近 24 小时成功 / 失败次数（完整统计见详情）" placement="top" :show-arrow="false">
              <span>成功/失败 ⓘ</span>
            </el-tooltip>
          </template>
          <template #default="{ row }">
            <span class="tm-ok">{{ row.success_24h }}</span> / <span :class="{ 'tm-bad': row.fail_24h > 0 }">{{ row.fail_24h }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="225" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="row.triggerable"
              link type="primary" size="small" :disabled="!canOperate || row.status === 'running'"
              @click="onTrigger(row)"
            >运行</el-button>
            <el-button
              v-if="row.cancellable && row.status === 'running'"
              link type="danger" size="small" :disabled="!canOperate"
              @click="onCancel(row)"
            >取消</el-button>
            <!-- 常驻行启停已由调度列开关承担（loop_on 同源，历史问题-6e）——操作列改「重启」 -->
            <el-button
              v-if="row.controllable"
              link type="warning" size="small"
              :disabled="!canOperate || taskActionPendingId !== null"
              @click="onRestart(row)"
            >重启</el-button>
            <el-button link type="info" size="small" @click="openLogs(row)">日志</el-button>
            <el-button link type="info" size="small" @click="openDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="tm-pagination">
        <el-pagination
          v-model:current-page="page"
          :page-size="pageSize"
          :page-sizes="[10, 20, 50]"
          :total="filteredTasks.length"
          layout="total, sizes, prev, pager, next"
          @size-change="(s: number) => { pageSize = s; page = 1 }"
        />
      </div>
    </el-card>

    <!-- 任务详情 -->
    <!-- 历史修复：同类弹框均 min(…,92vw)——固定 720px 在窄屏横向溢出。 -->
    <el-dialog v-model="detailVisible" width="min(720px, 92vw)" top="8vh">
      <template #header>
        <DialogHeader
          :icon="detailIcon" :title="detailTask?.name || ''"
          :subtitle="detailTask ? `${detailTask.category} · ${kindLabel(detailTask.kind)} · ${statusLabel(detailTask.status)}` : ''"
          :tone="detailTone"
        />
      </template>
      <div v-if="detailTask" class="tm-detail">
        <div v-if="detailTask.description" class="tm-detail-desc">{{ detailTask.description }}</div>
        <el-descriptions :column="2" border size="small" class="tm-detail-descs">
          <el-descriptions-item label="运行节奏">{{ detailTask.cadence || '—' }}</el-descriptions-item>
          <el-descriptions-item label="调度开关">
            <el-tooltip content="引擎调度投递开关（列表「调度」列同源）" placement="top" :offset="8" :show-after="150" :show-arrow="false">
              <el-tag v-if="detailTask.kind !== 'oneshot'" size="small" :type="detailTask.loop_on ? 'success' : 'warning'" effect="plain">{{ detailTask.loop_on ? '开启' : '关闭' }}</el-tag>
              <el-tag v-else size="small" type="info" effect="plain">不可调度</el-tag>
            </el-tooltip>
          </el-descriptions-item>
          <el-descriptions-item label="下次执行">{{ detailTask.next_run_at || '—' }}</el-descriptions-item>
          <el-descriptions-item label="24h 成功 / 失败">
            <span class="tm-ok">{{ detailTask.success_24h }}</span> / <span :class="{ 'tm-bad': detailTask.fail_24h > 0 }">{{ detailTask.fail_24h }}</span>
          </el-descriptions-item>
          <el-descriptions-item v-if="detailTask.kind === 'daemon'" label="启动时间">{{ fmtTime(detailTask.started_at) || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="开始时间">{{ fmtTime(detailTask.last_run.started_at) || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="完成时间">{{ detailTask.status === 'running' ? '进行中' : fmtTime(detailTask.last_run.finished_at) || '—' }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="耗时">{{ fmtDuration(detailTask.last_run.duration_ms) }}</el-descriptions-item>
          <el-descriptions-item v-if="detailTask.last_run" label="触发 / 结果"><span class="tm-inline-flex">{{ triggerLabel(detailTask.last_run.trigger) }} · {{ detailTask.last_run.operator || '系统' }} · <el-tag size="small" :type="resultTagType(detailTask.last_run.result)">{{ statusResultLabel(detailTask.last_run.result) }}</el-tag></span></el-descriptions-item>
        </el-descriptions>
        <div v-if="detailTask.last_run?.message" class="tm-detail-msg">{{ detailTask.last_run.message }}</div>
        <!-- 历史修复：历史加载失败显性化（原静默呈现为空表，与「无记录」不可区分） -->
        <el-alert v-if="detailHistoryError" type="error" :closable="false" show-icon title="运行历史加载失败，请关闭后重新打开" style="margin-bottom: 12px" />
        <template v-if="history.length">
          <div class="tm-detail-section">{{ historyTitle }}</div>
          <el-table :data="history" size="small" max-height="240" class="tm-nowrap-table">
            <el-table-column prop="started_at" label="开始" width="152">
              <template #default="{ row }">{{ fmtTime(row.started_at) }}</template>
            </el-table-column>
            <el-table-column prop="duration_ms" label="耗时" width="78">
              <template #default="{ row }">{{ fmtDuration(row.duration_ms) }}</template>
            </el-table-column>
            <el-table-column prop="trigger" label="触发" width="72">
              <template #default="{ row }">{{ triggerLabel(row.trigger) }}</template>
            </el-table-column>
            <el-table-column label="操作者" width="120" show-overflow-tooltip>
              <!-- operator 为空=自动/排程/启动等系统触发（后端 auto/startup/legacy 恒空） -->
              <template #default="{ row }">{{ row.operator || '系统' }}</template>
            </el-table-column>
            <el-table-column prop="status" label="结果" width="88">
              <template #default="{ row }">
                <el-tag size="small" :type="resultTagType(row.status)">{{ statusResultLabel(row.status) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="message" label="信息" min-width="120" show-overflow-tooltip />
          </el-table>
        </template>
      </div>
    </el-dialog>

    <!-- 任务日志弹框（与证书日志同款：暗色终端流） -->
    <el-dialog v-model="logsVisible" width="min(1100px, 94vw)" top="5vh" destroy-on-close @closed="closeLogs">
      <template #header>
        <DialogHeader :icon="Timer" :title="`任务日志 · ${logsTask?.name || ''}`" subtitle="统一任务引擎文本日志（实时刷新）" />
      </template>
      <!-- 日志存储统计栏：task:<id> 逐任务真实文件（含 cert-job 动态行）；后端未含该键时组件自隐 -->
      <div class="tm-log-stats">
        <LogStorageBar :log-key="logsTaskStorageKey" style="margin-right: auto" />
      </div>
          <div ref="logContainerRef" class="tm-log-container">
        <pre v-if="logsText" class="tm-log-content">{{ logsText }}</pre>
        <el-empty v-else description="暂无日志" :image-size="60" />
      </div>
      <template #footer>
        <div style="display: flex; align-items: center;">
          <span v-if="logsLoadError" style="font-size: 12px; color: var(--el-color-danger); margin-right: 12px;">日志加载失败，自动重试中</span>
          <span style="font-size: 12px; color: #9aa0b5; margin-right: auto;">每 5 秒自动刷新</span>
          <el-button @click="logsVisible = false">关闭</el-button>
        </div>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import '@/utils/echarts' // 统一注册（含 LineChart——直刷本页不再依赖先到 Dashboard）
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'
import axios from 'axios'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, PieChart as PieChartIcon, DataLine, List, Monitor, Lock, Box, Timer } from '@element-plus/icons-vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { usePollingTask } from '@/composables/usePollingTask'
import { useLogTailPolling } from '@/composables/useLogTailPolling'
import { formatDate } from '@/utils/date'
import { usePollingErrorState } from '@/composables/usePollingErrorState'
import { useClampedPagination } from '@/composables/useClampedPagination'
import { statusColor } from '@/utils/chartTheme'
import { certJobStatusLabel, type CertJobStatus } from '@/utils/certJobStatus'
import { CERT_QUEUE_VISIBLE_JOBS, certQueueHasLive, certQueueIsBusy, certQueueMoreCount } from '@/utils/certQueue'
import DialogHeader from '@/components/DialogHeader.vue'
import LogStorageBar from '@/components/LogStorageBar.vue'
import type { APIResponse } from '@/types'


interface TaskRunInfo { started_at: string; finished_at: string; duration_ms: number; trigger: string; operator?: string; result: string; message?: string }
interface TaskInfo {
  id: string; name: string; description?: string; cadence?: string; category: string
  kind: 'scheduled' | 'daemon' | 'periodic' | 'oneshot'
  status: string; cancellable: boolean; controllable?: boolean; triggerable?: boolean
  last_run?: TaskRunInfo; next_run_at?: string; runs_24h: number; success_24h: number; fail_24h: number
  loop_on?: boolean; started_at?: string; business_driven?: boolean // 常驻族：循环启停态/引擎启动时刻
}
interface RunRecord {
  id: number; task_id: string; family: string; trigger: string; operator?: string; status: string
  started_at: string; finished_at: string; duration_ms: number
  // 历史修复（历史）：stage/entry_count 恒零死列已随后端删除——不再声明。
  message?: string
}

// 24h 分小时桶（GET /system/tasks/stats-24h-series；配置时区墙面小时，后端已对齐）
interface TaskHourlyStat { hour: string; success: number; failed: number }

const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')
const tasks = ref<TaskInfo[]>([])
const certJobsTruncated = ref(false)
const loaded = ref(false)
const series24h = ref<TaskHourlyStat[]>([])
const refreshing = ref(false)
// 历史问题（历史）：只读判定统一走全局 fail-closed 契约（authStore.
// readOnlyReason===null=可写；曾本地 isSlave fetch-open 且不随角色切换刷新，
// 违反 历史问题——全站 14 页唯一偏离者）
const readOnly = computed(() => authStore.readOnlyReason !== null)
const canOperate = computed(() => isAdmin.value && !readOnly.value)

// 历史修复：200 但缺 data 是契约违约，不得静默渲染成「0 任务 / 空图表」——与
// CertJobs.vue 同口径抛 TypeError，才能进入 usePollingErrorState 的契约退避与
// 错误横幅（原 `res.data?.tasks || []` 把违约伪装成合法空集）。
const fetchTasks = async (signal?: AbortSignal) => {
  const res = await request.get<APIResponse<{ tasks: TaskInfo[]; cert_jobs_truncated?: boolean }>>('/system/tasks', { silent: true, signal })
  if (!res.data) throw new TypeError('任务列表响应缺少 data')
  tasks.value = res.data.tasks || []
  // 审计项：cert-job 动态行上限 100——后端回传截断标记，页面显性提示，
  // 避免把「只有这些任务」误读成全量（更老的记录请在证书任务页按规则查看）。
  certJobsTruncated.value = !!res.data.cert_jobs_truncated
  loaded.value = true
}
const fetchSeries = async (signal?: AbortSignal) => {
  const res = await request.get<APIResponse<{ series: TaskHourlyStat[] }>>('/system/tasks/stats-24h-series', { silent: true, signal })
  if (!res.data) throw new TypeError('任务统计响应缺少 data')
  series24h.value = res.data.series || []
}
const refreshNow = async () => {
  refreshing.value = true
  try {
    await Promise.all([fetchTasks(), fetchSeries(), fetchCertQueue()])
    pollingError.clear()
  } catch (error: unknown) {
    // 历史问题：原实现无 catch——网络/5xx 时按钮无反馈且产生 unhandled
    // rejection；与轮询失败同口径记录到可见横幅。
    pollingError.recordError(error)
  } finally { refreshing.value = false }
}
onMounted(() => {
  void polling.run() // 首跑立即（start() 只设定时器；证书队列横幅已入轮询闭包随首跑）
  polling.start()
})
onUnmounted(() => polling.stop())

// 历史修复：轮询失败可见化（此前只落 console）。契约性失败（TypeError）退避
// 期间轮询闭包经 canRun 门跳过；横幅「立即重试」重置退避立即拉取。
const pollingError = usePollingErrorState()
const pollingErrorDescription = computed(() => {
  const lastError = formatDate(pollingError.lastErrorAt.value)
  const retryAt = formatDate(pollingError.retryAt.value)
  return retryAt
    ? `最后错误：${lastError}；契约响应异常，自动重试已退避至 ${retryAt}`
    : `最后错误：${lastError}`
})
const polling = usePollingTask(async ({ signal }) => {
  // 历史问题-4：证书队列横幅与任务列表同频 10s（曾只在 mounted/手动刷新拉取，横幅最长陈旧一个会话）
  if (!pollingError.canRun()) return
  // 历史问题：消费每轮 abort signal——pause/stop（含组件卸载）可取消在途请求。
  await Promise.all([fetchTasks(signal), fetchSeries(signal), fetchCertQueue(signal)])
  pollingError.clear()
}, {
  interval: 10000,
  onError: (e) => {
    console.error('task monitor poll failed:', e)
    pollingError.recordError(e)
  },
})
const retryPolling = async (): Promise<void> => {
  pollingError.resetBackoff()
  await polling.run()
}
// ===== 证书队列状态（独立卡——非任务族） =====
interface CertJobRow { id: number; domain: string; status: string; updated_at?: string | null; ca_provider_name?: string }
// 历史修复（历史）：certQueue.loaded 死字段删除（写字段零消费方）。
const certQueue = ref<{ queued: number; running: number; waiting: number; total: number; jobs: CertJobRow[]; truncated: boolean }>({
  queued: 0, running: 0, waiting: 0, total: 0, jobs: [], truncated: false,
})
// 历史问题：队列加载失败不得呈现为「全 0 / 空闲」——显式错误态（下一轮轮询自愈）
const certQueueError = ref(false)
// 历史修复：列表只用于横幅列 4 个域名 chip——page_size=6 即够（原 200，每 10s
// 让后端逐行截取 cert_pem/解析 issuer/算到期状态后丢弃）。计数仍以
// status_counts 聚合为真源；该字段缺席时才退回「首页可见行推导 + total 超页
// 声明 ≥」（历史问题 的降级路径保留）。
const CERT_QUEUE_PAGE_SIZE = 6
// 历史修复：接入轮询 AbortSignal——pause/stop（含组件卸载）可取消在途请求，
// 与 fetchTasks/fetchSeries 同口径（补齐 :409 注释承诺）。
const fetchCertQueue = async (signal?: AbortSignal) => {
  try {
    const res = await request.get<APIResponse<{ list: CertJobRow[]; total: number; status_counts?: Record<string, number> }>>('/certificates/jobs', { params: { page: 1, page_size: CERT_QUEUE_PAGE_SIZE }, silent: true, signal })
    // 历史修复：缺 data 为契约违约（同 fetchTasks/fetchSeries），下面向上抛。
    if (!res.data) throw new TypeError('证书队列响应缺少 data')
    const list = res.data.list || []
    const counts = res.data?.status_counts
    const statusCount = (statuses: string[]): number => statuses.reduce((sum, s) => sum + (counts?.[s] || 0), 0)
    let liveCount: number
    let queued: number
    let waiting: number
    if (counts) {
      const terminal = statusCount(['issued', 'failed', 'disabled'])
      liveCount = Object.values(counts).reduce((sum, n) => sum + n, 0) - terminal
      queued = statusCount(['queued', 'pending'])
      waiting = statusCount(['waiting_ca'])
    } else {
      const live = list.filter(j => !['issued', 'failed', 'disabled'].includes(j.status))
      liveCount = live.length
      queued = live.filter(j => ['queued', 'pending'].includes(j.status)).length
      waiting = live.filter(j => j.status === 'waiting_ca').length
    }
    const liveJobs = list.filter(j => !['issued', 'failed', 'disabled'].includes(j.status))
    certQueueError.value = false
    certQueue.value = {
      total: liveCount,
      // status_counts 为空时才依赖首页下界；有聚合计数则完整。
      truncated: !counts && (res.data?.total ?? 0) > list.length,
      queued,
      running: Math.max(0, liveCount - queued - waiting),
      waiting,
      jobs: liveJobs.slice(0, 6),
    }
  } catch (error: unknown) {
    // 静默自动重试（下一轮轮询），但错误态必须显性——0 值会被误读为「无排队」；
    // pause/stop 触发的取消不是失败（历史修复）
    if (!axios.isCancel(error)) certQueueError.value = true
    // 历史修复：契约违约（缺 data）与其余两份请求同语义——向上抛，交由轮询入口
    // 记录并进入 TypeError 退避；普通网络/5xx 仍在本层吞掉（下一轮自愈）。
    if (error instanceof TypeError) throw error
  }
}

// ===== 概览统计 =====
const runningCount = computed(() => tasks.value.filter(t => t.status === 'running').length)
const total24h = computed(() => tasks.value.reduce((s, t) => s + (t.runs_24h || 0), 0))
const fail24h = computed(() => tasks.value.reduce((s, t) => s + (t.fail_24h || 0), 0))

// ===== 筛选 + 分页 =====
const kindFilter = ref('all')
// 历史问题：分类筛选原为 el-table 列级 filter（作用在 pagedTasks 切片上=
// 只过滤当前页），现提升到 filteredTasks 参与计数/分页。
const categoryFilter = ref('all')
const categoryOptions = computed(() => [...new Set(tasks.value.map(t => t.category))].sort())
const filteredTasks = computed(() => {
  const list = tasks.value
    .filter(t => kindFilter.value === 'all' || t.kind === kindFilter.value)
    .filter(t => categoryFilter.value === 'all' || !categoryFilter.value || t.category === categoryFilter.value)
  // 默认按分类排序（安全防护→证书→备份→集群→系统→触发），类内稳定
  return [...list].sort((a, b) => (categoryOrder[a.category] ?? 9) - (categoryOrder[b.category] ?? 9))
})
const page = ref(1)
const pageSize = ref(20)
// 历史问题：页码夹紧单源（useClampedPagination）——任务列表收缩（cert-job 动态行
// 完成消失）或增大 pageSize 后自动回夹，不再停留在空页。原 slice 无夹紧，仅筛选
// 变化复位。
const { pagedItems: pagedTasks } = useClampedPagination(filteredTasks, page, pageSize)
// 筛选条件变化回第 1 页（避免高页码 + 收窄结果落在空页）
watch([kindFilter, categoryFilter], () => { page.value = 1 })

// ===== 图表（引擎真数据） =====
const statusPieOption = computed<EChartsOption>((): EChartsOption => {
  const counts = new Map<string, number>()
  for (const t of tasks.value) counts.set(t.status, (counts.get(t.status) || 0) + 1)
  return {
    tooltip: { trigger: 'item' },
    legend: { bottom: 0, type: 'scroll' },
    series: [{
      type: 'pie',
      radius: ['50%', '72%'],
      center: ['50%', '44%'],
      itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
      label: { show: false },
      data: [...counts.entries()].map(([k, v]) => ({
        name: statusLabel(k), value: v, itemStyle: { color: statusColor[k] || '#4f8cff' },
      })),
    }],
  }
})
// 近 24 小时执行（成功/失败）——24h 分小时桶堆叠面积时间序列（2026-10-11
// 用户裁定方案 A）：任务名柱状图被手动证书任务高频执行压扁其他任务；时间
// 序列既消除频次压制，又新增「何时跑/何时挂」的分布信息。数据源
// GET /system/tasks/stats-24h-series（配置时区墙面小时，24 桶升序零填）。
const statsBarOption = computed<EChartsOption>((): EChartsOption => {
  const buckets = series24h.value
  return {
    animation: false,
    tooltip: { trigger: 'axis' },
    legend: { top: 0, itemGap: 24 },
    grid: { left: 8, right: 12, top: 36, bottom: 8, containLabel: true },
    xAxis: { type: 'category', boundaryGap: false, data: buckets.map(b => b.hour.slice(11, 16)), axisLabel: { interval: 3 } },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      { name: '成功', type: 'line', stack: 'runs', smooth: true, symbol: 'none', areaStyle: { opacity: 0.35 }, data: buckets.map(b => b.success), itemStyle: { color: '#34d399' }, lineStyle: { color: '#34d399' } },
      { name: '失败', type: 'line', stack: 'runs', smooth: true, symbol: 'none', areaStyle: { opacity: 0.35 }, data: buckets.map(b => b.failed), itemStyle: { color: '#f87171' }, lineStyle: { color: '#f87171' } },
    ],
  }
})

// ===== 操作 =====
// 历史问题：请求调用原在 confirm 的 try 之外 → 失败产生 unhandled
// rejection；且无重入守卫（快速双击叠加多个确认框/重复请求）。统一范式：
// pending 守卫 → confirm → try/catch 包住请求 → finally 释放。
const taskActionPendingId = ref<string | null>(null)

interface TaskActionOptions {
  /** 可选确认框（占位在其之前完成——快速双击只出现一个框）。 */
  confirm?: { message: string; title: string; type?: 'warning' | 'info'; confirmButtonText: string }
  request: () => Promise<APIResponse>
  successFallback: string
  failureLabel: string
  /** 失败后回读服务端真实状态（开关类操作用）。 */
  refreshOnError?: boolean
}

/**
 * 任务操作统一执行器（历史问题）：占位守卫 → 确认 → 请求 → 记录失败
 * → 释放占位。原实现把 request 放在 confirm 的 try 之外（失败 unhandled
 * rejection）且无重入守卫（双击叠加确认框/重复请求）。
 */
async function runTaskAction(row: TaskInfo, options: TaskActionOptions): Promise<void> {
  if (taskActionPendingId.value !== null) return
  taskActionPendingId.value = row.id
  try {
    if (options.confirm) {
      try {
        await ElMessageBox.confirm(options.confirm.message, options.confirm.title, {
          type: options.confirm.type ?? 'warning',
          confirmButtonText: options.confirm.confirmButtonText,
        })
      } catch {
        return // 用户取消：不请求
      }
    }
    const res = await options.request()
    ElMessage.success(res.message || options.successFallback)
    void fetchTasks().catch(() => {})
  } catch (error: unknown) {
    // 全局拦截器已 toast；仅记录，避免 unhandled rejection
    console.error(`${options.failureLabel} failed`, error)
    if (options.refreshOnError) void fetchTasks().catch(() => {})
  } finally {
    if (taskActionPendingId.value === row.id) taskActionPendingId.value = null
  }
}

const onTrigger = (row: TaskInfo): Promise<void> => runTaskAction(row, {
  confirm: { message: `立即执行「${row.name}」？`, title: '手动触发', type: 'info', confirmButtonText: '执行' },
  request: () => request.post<APIResponse>(`/system/tasks/${row.id}/trigger`),
  successFallback: '已触发',
  failureLabel: 'trigger task',
})

const onToggle = async (row: TaskInfo, enabled: boolean): Promise<void> => {
  if (isBusinessDrivenTask(row)) {
    ElMessage.warning('该任务由对应业务页自动更新控制，请在业务页修改')
    return
  }
  // 常驻族停止前确认（功能中断影响大——如安全事件采集停摆）
  const needConfirm = !enabled && row.kind === 'daemon'
  await runTaskAction(row, {
    confirm: needConfirm
      ? { message: `确认停止「${row.name}」？停止后相关功能将中断，可随时重新启动。`, title: '常驻任务控制', confirmButtonText: '停止' }
      : undefined,
    request: () => request.post<APIResponse>(`/system/tasks/${row.id}/toggle`, { enabled }),
    successFallback: '已更新',
    failureLabel: 'toggle task',
    refreshOnError: true,
  })
}

const onCancel = (row: TaskInfo): Promise<void> => runTaskAction(row, {
  confirm: { message: `取消运行中的「${row.name}」？下载阶段将中断，已完成部分保留。`, title: '手动取消', confirmButtonText: '取消任务' },
  request: () => request.post<APIResponse>(`/system/tasks/${row.id}/cancel`),
  successFallback: '已发出取消信号',
  failureLabel: 'cancel task',
})

// 历史问题-6e：常驻行操作列「重启」（control restart——启停已由调度列开关承担）
const onRestart = (row: TaskInfo): Promise<void> => runTaskAction(row, {
  confirm: { message: `确认重启「${row.name}」？重启期间相关功能将短暂中断。`, title: '常驻任务控制', confirmButtonText: '重启' },
  request: () => request.post<APIResponse>(`/system/tasks/${row.id}/control`, { action: 'restart' }),
  successFallback: '已重启',
  failureLabel: 'restart task',
})

// ===== 详情 =====
const detailVisible = ref(false)
// 历史修复：详情按 id 从最新 tasks 派生（此前持有打开时的行快照——轮询每轮整体替换
// tasks 后，状态/24h 计数/下次执行在弹框内永远不再更新）。行从列表消失（cert-job
// 完成退役）时退回打开时的行，避免正文瞬间清空。
const detailTaskId = ref<string | null>(null)
const detailSeed = ref<TaskInfo | null>(null)
const detailTask = computed<TaskInfo | null>(() => {
  const id = detailTaskId.value
  if (!id) return null
  return tasks.value.find(t => t.id === id) ?? detailSeed.value
})
const history = ref<RunRecord[]>([])
const detailIcon = computed(() => (detailTask.value?.category === '证书' ? Lock : detailTask.value?.category === '备份' ? Box : Monitor))
const detailTone = computed((): 'primary' | 'success' | 'warning' | 'danger' | undefined => {
  const st = detailTask.value?.status
  if (st === 'failed') return 'danger'
  if (st === 'running') return 'primary'
  if (st === 'disabled') return 'warning' // 仅 cert-job 退役行（方案 A：stopped 已退役）
  return undefined
})
const isCertJobRow = (id: string): boolean => id.startsWith('cert-job:')
// cert-job 动态行无引擎运行历史——历史区域接 cert_jobs 数据源（每规则+域名
// 单行在册，展示该签发任务当前记录）
const historyTitle = computed(() =>
  detailTask.value && isCertJobRow(detailTask.value.id) ? '签发任务记录（cert_jobs）' : `运行历史（最近 ${history.value.length} 次）`)
// cert-job 详情数据源（GET /certificates/jobs/:id——与 CertJobs 页同源字段）
interface CertJobDetail { id: number; rule_id: string; domain: string; status: string; message: string; created_at?: string; updated_at?: string | null }
const fetchCertJobHistory = async (jobId: number): Promise<RunRecord[]> => {
  const res = await request.get<APIResponse<CertJobDetail>>(`/certificates/jobs/${jobId}`, { silent: true })
  const j = res.data
  if (!j) return []
  const start = j.created_at ? Date.parse(j.created_at) : NaN
  const end = j.updated_at ? Date.parse(j.updated_at) : NaN
  return [{
    id: j.id, task_id: `cert-job:${j.id}`, family: 'cert-job', trigger: 'queue', status: j.status,
    // 历史修复：cert_jobs 为 UTC 存储族（RFC3339Z）——映射时经 formatDate 转配置
    // 时区墙串再入列（fmtTime 对墙串原样渲染）；同页引擎族 last_run 为配置时区
    // 墙串不经此处。duration 用原始 RFC3339 串 Date.parse 差值，不受格式化影响。
    started_at: j.created_at ? formatDate(j.created_at) : '',
    finished_at: j.updated_at ? formatDate(j.updated_at) : '',
    duration_ms: !isNaN(start) && !isNaN(end) && end > start ? end - start : 0,
    message: j.message || undefined,
  }]
}
let detailSeq = 0
// 历史修复：详情历史加载失败显性化（原静默 catch 呈现为空「运行历史」，与
// 无记录不可区分）
const detailHistoryError = ref(false)
const openDetail = async (row: TaskInfo) => {
  const seq = ++detailSeq
  detailTaskId.value = row.id
  detailSeed.value = row
  detailVisible.value = true
  history.value = []
  detailHistoryError.value = false
  try {
    let runs: RunRecord[] = []
    if (isCertJobRow(row.id)) {
      runs = await fetchCertJobHistory(Number(row.id.slice(9)))
    } else {
      const res = await request.get<APIResponse<{ runs: RunRecord[] }>>(`/system/tasks/${row.id}/history`, { silent: true })
      runs = res.data?.runs || []
    }
    if (seq === detailSeq) history.value = runs
  } catch {
    if (seq === detailSeq) detailHistoryError.value = true
  }
}

// ===== 日志抽屉（content 纯文本解析） =====
const logsVisible = ref(false)
const logsText = ref('')
const logsTask = ref<TaskInfo | null>(null)
const logsTaskStorageKey = computed(() => logsTask.value ? `task:${logsTask.value.id}` : 'tasks')
const logContainerRef = ref<HTMLElement | null>(null)
// 历史修复：日志加载失败显性化（原静默）；历史修复：轮询收敛
// useLogTailPolling 单源——补上本页原缺的后台标签页暂停。
const logsLoadError = ref(false)
const taskLogEndpoint = (id: string): string =>
  id.startsWith('cert-job:') ? `/certificates/jobs/${id.slice(9)}/logs` : `/system/tasks/${id}/logs`
const logsTail = useLogTailPolling({
  interval: 5000,
  content: logsText,
  container: logContainerRef,
  isActive: () => logsVisible.value && logsTask.value !== null,
  fetch: async () => {
    const task = logsTask.value
    if (!task) return null
    const res = await request.get<APIResponse<{ content: string }>>(taskLogEndpoint(task.id), { silent: true })
    logsLoadError.value = false
    if (logsTask.value?.id !== task.id) return null
    return (res.data?.content || '').trim()
  },
  onError: () => { logsLoadError.value = true },
})
const openLogs = (row: TaskInfo): void => {
  // 历史问题：先清空上一任务内容并同步装定时器（start 内部即此序）——不再清空
  // 残留，也不会出现「首拉未完成就关闭 → await 后续体又装 interval」的关闭后
  // 永久轮询。
  logsTask.value = row
  logsVisible.value = true
  logsText.value = ''
  logsLoadError.value = false
  logsTail.start()
}
const closeLogs = (): void => {
  logsTail.stop()
  logsTask.value = null
  logsText.value = ''
}
onUnmounted(closeLogs)



// ===== 文案 =====
// 状态列方案 A（2026-10-12 用户裁定）：只承载执行语义——running/idle/failed
// （cert-job 行另走 certJobStatusLabel 全状态集：queued/waiting_ca/disabled=已禁用）。
// stopped/disabled 已从引擎族状态产出退役（调度语义归开关列 loop_on&&enabled）。
const statusLabels: Record<string, string> = {
  running: '运行中', idle: '空闲', failed: '失败',
}
// 状态列兜底只回显原值——禁止把 cert_jobs 业务生命周期态（issued/waiting_ca…）
// 经证书标签兜底渲染进状态列（2026-10-22 用户裁定三态词表）。
const statusLabel = (s: string) => statusLabels[s] || s
// v2.0 四类型：定时(蓝)/常驻(绿)/循环(青)/触发(橙)
const kindLabels: Record<string, string> = { scheduled: '定时', daemon: '常驻', periodic: '循环', oneshot: '触发' }
const kindLabel = (k: string) => kindLabels[k] || k
const kindTag = (k: string): 'primary' | 'success' | 'info' | 'warning' =>
  k === 'scheduled' ? 'primary' : k === 'daemon' ? 'success' : k === 'periodic' ? 'info' : 'warning'
const kindTagClass = (k: string) => (k === 'periodic' ? 'tm-tag-periodic' : '')
const isBusinessDrivenTask = (row: TaskInfo) => !!row.business_driven
const categoryOrder: Record<string, number> = { '安全防护': 0, '证书': 1, '备份': 2, '集群': 3, '系统': 4, '触发': 5 }
const categoryTagType = (c: string): 'primary' | 'success' | 'warning' | 'info' =>
  c === '安全防护' ? 'primary' : c === '证书' ? 'success' : c === '备份' ? 'warning' : c === '触发' ? 'info' : 'info'
// 历史修复（历史）：caddy-restart（Caddy 崩溃自愈 watcher 通道）此前裸显
// 英文 token——补中文标签，未列触发值仍回退原文。
const triggerLabels: Record<string, string> = { manual: '手动', auto: '自动', schedule: '排程', queue: '队列', 'slave-sync': '从节点同步', startup: '启动', 'caddy-restart': 'Caddy重启' }
const triggerLabel = (t: string) => triggerLabels[t] || t || '—'
// 结果串双源：引擎 task_runs 结果（success/failed/…/skipped）+ cert-job 动态行
// 的 cert_jobs 状态机（issued/validating/…）——前者未命中时回退 certJobStatusLabel
const statusResultLabel = (r: string): string =>
  ({ success: '成功', failed: '失败', cancelled: '已取消', interrupted: '中断', running: '运行中', skipped: '已跳过' }[r] ?? certJobStatusLabel(r as CertJobStatus))
const resultTagType = (r: string): 'success' | 'danger' | 'info' | 'warning' =>
  r === 'success' || r === 'issued' ? 'success' : r === 'failed' ? 'danger' : r === 'cancelled' ? 'warning' : 'info'

// 时间显示（时区基本原则 2026-10-11 用户重申）：task_runs 由引擎按**配置时区**
// 写入无时区字符串（engineNowStr=CurrentLocation）——原样渲染即配置时区，禁止
// 再作任何时区换算。历史修复 曾委托 formatDate（其把无时区串强制按 UTC 解析再转
// 配置时区），任务时间全部被 +8h 偏移（22:12→次日 06:12 实证）；formatDate 其余
// 消费方（audit/cert_jobs/nodes 等 UTC 存储族）不受影响、保持原样。
const fmtTime = (s?: string) => {
  if (!s) return ''
  return s.replace('T', ' ').replace(/\.\d+/g, '').replace(/Z$/, '')
}
const fmtDuration = (ms?: number) => {
  if (!ms || ms <= 0) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`
}
</script>

<style scoped>
.tm-root { display: flex; flex-direction: column; gap: 20px; max-width: 1500px; margin: 0 auto; width: 100%; }
.card-header { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
.tm-category-filter { width: 150px; }
.card-title { display: flex; align-items: center; gap: 8px; font-size: 14px; font-weight: 600; color: #111827; }
.title-icon { font-size: 16px; color: #3b82f6; }

/* KPI 四卡 */
.tm-kpis { margin-bottom: 0; }
.tm-kpi { text-align: center; }
.tm-kpi :deep(.el-card__body) { padding: 18px 12px; }
.tm-kpi-num { font-size: 30px; font-weight: 800; color: #111827; line-height: 1.1; }
.tm-kpi-run { color: #3b82f6; }
.tm-kpi-bad { color: #f87171; }
.tm-kpi-label { font-size: 12.5px; color: #6b7280; margin-top: 6px; display: flex; align-items: center; justify-content: center; gap: 4px; }
.tm-kpi-lock { font-size: 12px; color: #b45309; }

/* 队列横幅 */
.tm-cq-banner :deep(.el-card__body) { padding: 12px 20px; }
.tm-cq-banner-inner { display: flex; align-items: center; gap: 16px; }
.tm-cq-banner-title { display: flex; align-items: center; gap: 6px; font-size: 14px; font-weight: 600; color: #111827; white-space: nowrap; }
.tm-cq-banner-stats { display: flex; gap: 12px; }
.tm-cq-chip { font-size: 12.5px; color: #6b7280; white-space: nowrap; }
.tm-cq-chip b { font-weight: 700; color: #111827; margin-left: 2px; }
.tm-c-run { color: #4f8cff !important; } .tm-c-wait { color: #38e1ff !important; }
.tm-cq-banner-live { flex: 1; min-width: 0; display: flex; align-items: center; gap: 8px; overflow: hidden; }
.tm-cq-domain-chip { font-size: 12px; color: #374151; background: #f3f4f6; border-radius: 999px; padding: 3px 10px; white-space: nowrap; display: inline-flex; align-items: center; gap: 5px; }
.tm-cq-dot { width: 6px; height: 6px; border-radius: 50%; background: #4f8cff; }
.tm-cq-dot--queued, .tm-cq-dot--pending { background: #fbbf24; }
.tm-cq-dot--waiting_ca { background: #38e1ff; }
.tm-cq-idle { font-size: 12.5px; color: #9aa0b5; }
.tm-cq-more { font-size: 12px; color: #9aa0b5; text-align: center; padding-top: 4px; }

.tm-chart { height: 230px; width: 100%; }
.tm-skeleton { background: linear-gradient(90deg, rgba(0,0,0,.03) 25%, rgba(0,0,0,.06) 50%, rgba(0,0,0,.03) 75%); background-size: 200% 100%; animation: tm-shimmer 1.2s infinite; border-radius: 8px; }
@keyframes tm-shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
.tm-count { font-size: 12px; color: #6b7280; font-weight: 400; background: #f3f4f6; border-radius: 999px; padding: 1px 8px; }

/* 表格 */
:deep(.tm-nowrap-table .cell) { white-space: nowrap; }
.tm-task-name { font-weight: 500; }
.tm-status { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; }
.tm-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--tm-c, #9aa0b5); box-shadow: 0 0 6px var(--tm-c, transparent); }
.tm-status[data-status="running"] { --tm-c: #4f8cff; }
.tm-status[data-status="failed"] { --tm-c: #f87171; }
.tm-status[data-status="disabled"] { --tm-c: #62687f; } /* 方案 A：stopped 退役；disabled 仅 cert-job 退役行 */
.tm-status[data-status="idle"] { --tm-c: #9aa0b5; }
.tm-tag-periodic {
  --el-tag-bg-color: rgba(0, 168, 168, 0.1);
  --el-tag-border-color: rgba(0, 168, 168, 0.35);
  --el-tag-text-color: #009393;
}
.tm-tag-periodic.el-tag--dark,
.tm-tag-periodic.el-tag--plain {
  background-color: var(--el-tag-bg-color);
  border-color: var(--el-tag-border-color);
  color: var(--el-tag-text-color);
}
.tm-dim { color: var(--el-text-color-placeholder); }
.tm-ok { color: #34d399; font-weight: 600; }
.tm-bad { color: #f87171; font-weight: 600; }
.tm-pagination { display: flex; justify-content: flex-end; margin-top: 12px; }

/* tooltip 提示 */
:global(.tm-name-tip) { max-width: 380px; }
.tm-tip-title { font-weight: 600; margin-bottom: 4px; }
.tm-tip-cadence { font-size: 12px; opacity: .85; margin-bottom: 2px; }
.tm-tip-desc { font-size: 12px; line-height: 1.6; }
.tm-tip-sep { height: 6px; }

/* 详情 */
.tm-detail { display: flex; flex-direction: column; gap: 14px; }
.tm-detail-desc { font-size: 13px; color: var(--el-text-color-regular); line-height: 1.7; background: var(--el-fill-color-lighter); border-radius: 8px; padding: 10px 14px; }
.tm-detail-descs :deep(.el-descriptions__label) { white-space: nowrap; }
.tm-detail-descs :deep(.el-descriptions__content .el-tag) { vertical-align: middle; margin-left: 4px; }
.tm-inline-flex { display: inline-flex; align-items: center; gap: 2px; }
.tm-detail-msg { font-size: 12.5px; color: var(--el-text-color-secondary); }
.tm-detail-section { font-size: 13px; font-weight: 600; color: var(--el-text-color-primary); margin-top: 4px; padding-top: 12px; border-top: 1px solid var(--el-border-color-lighter); }

/* 日志 */
.tm-log-stats { display: flex; align-items: center; margin-bottom: 10px; }
.tm-log-container { max-height: 60vh; overflow: auto; background: #0f172a; border-radius: 8px; padding: 16px; border: 1px solid #1e293b; }
.tm-log-content { margin: 0; color: #e2e8f0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; line-height: 1.7; white-space: pre-wrap; }
</style>

