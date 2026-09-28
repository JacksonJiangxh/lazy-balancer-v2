<template>
  <div class="tm-root">
    <!-- 顶部图表区 -->
    <div class="tm-charts">
      <div class="tm-chart-card">
        <div class="tm-chart-title">任务状态分布</div>
        <v-chart v-if="loaded" :option="statusPieOption" autoresize class="tm-chart" />
        <div v-else class="tm-chart tm-skeleton"></div>
      </div>
      <div class="tm-chart-card">
        <div class="tm-chart-title">最近执行耗时（毫秒）</div>
        <v-chart v-if="loaded" :option="durationBarOption" autoresize class="tm-chart" />
        <div v-else class="tm-chart tm-skeleton"></div>
      </div>
      <div class="tm-chart-card">
        <div class="tm-chart-title">24 小时执行统计</div>
        <v-chart v-if="loaded" :option="statsBarOption" autoresize class="tm-chart" />
        <div v-else class="tm-chart tm-skeleton"></div>
      </div>
    </div>

    <!-- 任务列表 -->
    <div class="tm-table-card">
      <div class="tm-table-head">
        <div>
          <h3 class="tm-table-title">全部任务</h3>
          <p class="tm-table-desc">系统全部定时与后台任务族——排程、执行、完成与下次触发时间；下载类任务运行中可手动取消</p>
        </div>
        <el-button :icon="Refresh" circle :loading="refreshing" @click="refreshNow" title="立即刷新" />
      </div>
      <el-table :data="pagedTasks" v-loading="!loaded" size="default" row-key="id">
        <el-table-column label="任务" min-width="220">
          <template #default="{ row }">
            <div class="tm-task-name">
              <span>{{ row.name }}</span>
              <span class="tm-cat">{{ row.category }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="类型" width="86">
          <template #default="{ row }">
            <el-tag size="small" :type="kindTag(row.kind)" effect="plain">{{ kindLabel(row.kind) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="96">
          <template #default="{ row }">
            <span class="tm-status" :data-status="row.status">
              <span class="tm-dot"></span>{{ statusLabel(row.status) }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="自动调度" width="88">
          <template #default="{ row }">
            <el-tag v-if="row.kind === 'continuous'" size="small" type="info" effect="plain">常驻</el-tag>
            <el-switch
              v-else-if="toggleable(row.id)"
              :model-value="row.enabled"
              :disabled="!canOperate"
              @change="(v: string | number | boolean) => onToggle(row, !!v)"
            />
            <span v-else class="tm-dim">—</span>
          </template>
        </el-table-column>
        <el-table-column label="最近执行" width="150">
          <template #default="{ row }">
            <span v-if="row.last_run?.started_at">{{ fmtTime(row.last_run.started_at) }}</span>
            <span v-else class="tm-dim">—</span>
          </template>
        </el-table-column>
        <el-table-column label="完成时间" width="150">
          <template #default="{ row }">
            <span v-if="row.last_run?.finished_at">{{ fmtTime(row.last_run.finished_at) }}</span>
            <span v-else-if="row.status === 'running'" class="tm-running-text">进行中</span>
            <span v-else class="tm-dim">—</span>
          </template>
        </el-table-column>
        <el-table-column label="耗时" width="90">
          <template #default="{ row }">
            <span v-if="row.last_run?.duration_ms > 0">{{ fmtDuration(row.last_run.duration_ms) }}</span>
            <span v-else class="tm-dim">—</span>
          </template>
        </el-table-column>
        <el-table-column label="下次执行" min-width="150">
          <template #default="{ row }">
            <span v-if="row.next_run_at">{{ row.next_run_at }}</span>
            <span v-else class="tm-dim">—</span>
          </template>
        </el-table-column>
        <el-table-column label="24h 成功/失败" width="120">
          <template #default="{ row }">
            <span class="tm-ok">{{ row.success_24h }}</span> / <span :class="{ 'tm-bad': row.fail_24h > 0 }">{{ row.fail_24h }}</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="230" fixed="right">
          <template #default="{ row }">
            <el-button
              v-if="triggerable(row.id)"
              link type="primary" size="small" :disabled="!canOperate || row.status === 'running'"
              @click="onTrigger(row)"
            >立即执行</el-button>
            <el-button
              v-if="row.id === 'threat' || row.id === 'crs' || row.id === 'ip2region'"
              link type="info" size="small" @click="openLogs(row)"
            >日志</el-button>
            <el-button link type="info" size="small" @click="openDetail(row)">详情</el-button>
            <el-button
              v-if="row.cancellable"
              link type="danger" size="small" :disabled="!isAdmin"
              @click="onCancel(row)"
            >取消</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="tm-pagination">
        <el-pagination
          v-model:current-page="page"
          :page-size="pageSize"
          :page-sizes="[10, 20, 50]"
          :total="tasks.length"
          layout="total, sizes, prev, pager, next"
          @size-change="(s: number) => pageSize = s"
        />
      </div>
    </div>

    <!-- 任务详情弹框 -->
    <el-dialog v-model="detailVisible" :title="`任务详情 · ${detailTask?.name || ''}`" width="560px">
      <el-descriptions v-if="detailTask" :column="2" border size="small">
        <el-descriptions-item label="任务 ID">{{ detailTask.id }}</el-descriptions-item>
        <el-descriptions-item label="分类">{{ detailTask.category }}</el-descriptions-item>
        <el-descriptions-item label="类型">{{ kindLabel(detailTask.kind) }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ statusLabel(detailTask.status) }}</el-descriptions-item>
        <el-descriptions-item label="自动调度">{{ detailTask.kind === 'continuous' ? '常驻' : detailTask.enabled ? '开启' : '暂停' }}</el-descriptions-item>
        <el-descriptions-item label="下次执行">{{ detailTask.next_run_at || '—' }}</el-descriptions-item>
        <el-descriptions-item v-if="detailTask.last_run" label="开始时间" :span="1">{{ fmtTime(detailTask.last_run.started_at) || '—' }}</el-descriptions-item>
        <el-descriptions-item v-if="detailTask.last_run" label="完成时间">{{ fmtTime(detailTask.last_run.finished_at) || '进行中' }}</el-descriptions-item>
        <el-descriptions-item v-if="detailTask.last_run" label="耗时">{{ fmtDuration(detailTask.last_run.duration_ms) }}</el-descriptions-item>
        <el-descriptions-item v-if="detailTask.last_run" label="触发源">{{ triggerLabel(detailTask.last_run.trigger) }}</el-descriptions-item>
        <el-descriptions-item v-if="detailTask.last_run" label="执行结果" :span="2">
          <el-tag size="small" :type="resultTagType(detailTask.last_run.result)">{{ detailTask.last_run.result || '—' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item v-if="detailTask.last_run?.message" label="信息" :span="2">{{ detailTask.last_run.message }}</el-descriptions-item>
        <el-descriptions-item label="24h 成功/失败" :span="2">{{ detailTask.success_24h }} / {{ detailTask.fail_24h }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <!-- 更新日志抽屉 -->
    <el-drawer v-model="logsVisible" :title="`更新日志 · ${logsTask?.name || ''}`" size="520px">
      <div v-if="logsLoading" class="tm-logs-loading"><el-icon class="is-loading"><Loading /></el-icon> 加载中…</div>
      <el-timeline v-else-if="logs.length">
        <el-timeline-item
          v-for="(l, i) in logs" :key="i"
          :type="logTimelineType(l.level)" :timestamp="l.time" placement="top"
        >
          <div class="tm-log-stage">{{ l.stage }}</div>
          <div>{{ l.message }}</div>
        </el-timeline-item>
      </el-timeline>
      <el-empty v-else description="暂无日志" />
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import { PieChart, BarChart } from 'echarts/charts'
import { GridComponent, TooltipComponent, LegendComponent } from 'echarts/components'
import type { EChartsOption } from 'echarts'
import VChart from 'vue-echarts'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, Loading } from '@element-plus/icons-vue'
import { request } from '@/utils/api'
import { useAuthStore } from '@/stores/auth'
import { usePollingTask } from '@/composables/usePollingTask'
import { seriesColors, statusColor, baseGrid, baseTooltip, baseAxis } from '@/utils/chartTheme'
import type { APIResponse } from '@/types'

use([CanvasRenderer, PieChart, BarChart, GridComponent, TooltipComponent, LegendComponent])

interface TaskRunInfo {
  started_at: string
  finished_at: string
  duration_ms: number
  trigger: string
  result: string
  message?: string
}
interface TaskInfo {
  id: string
  name: string
  category: string
  kind: 'scheduled' | 'continuous' | 'queue'
  status: string
  enabled: boolean
  cancellable: boolean
  last_run?: TaskRunInfo
  next_run_at?: string
  runs_24h: number
  success_24h: number
  fail_24h: number
}

const authStore = useAuthStore()
const isAdmin = computed(() => authStore.user?.role === 'admin')
const tasks = ref<TaskInfo[]>([])
const loaded = ref(false)
const refreshing = ref(false)
const isSlave = ref(false)

const canOperate = computed(() => isAdmin.value && !isSlave.value)

const triggerableIds = new Set(['threat', 'crs', 'ip2region'])
const toggleableIds = new Set(['threat', 'crs', 'ip2region'])
const triggerable = (id: string) => triggerableIds.has(id)
const toggleable = (id: string) => toggleableIds.has(id)

// 分页(客户端)
const page = ref(1)
const pageSize = ref(20)
const pagedTasks = computed(() => {
  const start = (page.value - 1) * pageSize.value
  return tasks.value.slice(start, start + pageSize.value)
})

// 详情弹框
const detailVisible = ref(false)
const detailTask = ref<TaskInfo | null>(null)
const openDetail = (row: TaskInfo) => {
  detailTask.value = row
  detailVisible.value = true
}
const resultTagType = (r: string): 'success' | 'danger' | 'info' | 'warning' =>
  r === 'success' || r === 'issued' ? 'success' : r === 'failed' ? 'danger' : r === 'cancelled' ? 'warning' : 'info'

const fetchTasks = async () => {
  const res = await request.get<APIResponse<{ tasks: TaskInfo[] }>>('/system/tasks', { silent: true })
  tasks.value = res.data?.tasks || []
  loaded.value = true
}

const polling = usePollingTask(async () => fetchTasks(), {
  interval: 10000,
  onError: (e) => console.error('task monitor poll failed:', e),
})

const fetchClusterState = async () => {
  try {
    const res = await request.get<APIResponse<{ node_mode: string }>>('/cluster/status', { silent: true })
    isSlave.value = res.data?.node_mode === 'slave'
  } catch {
    isSlave.value = false
  }
}

const refreshNow = async () => {
  refreshing.value = true
  try {
    await Promise.all([fetchTasks(), fetchClusterState()])
  } finally {
    refreshing.value = false
  }
}

onMounted(() => {
  // 首跑立即——usePollingTask.start() 只设定时器，首轮要等满 interval（10s），
  // 页面会空转圈整轮（用户实测 network 全快但仍转圈的根因）。
  void polling.run()
  polling.start()
  fetchClusterState()
})
onUnmounted(() => polling.stop())

// ===== 图表 =====
const statusPieOption = computed<EChartsOption>(() => {
  const counts = new Map<string, number>()
  for (const t of tasks.value) counts.set(t.status, (counts.get(t.status) || 0) + 1)
  const labels: Record<string, string> = {
    running: '运行中', idle: '空闲', queued: '排队', failed: '失败', cancelled: '已取消',
    disabled: '已暂停', passive: '常驻', no_runs: '未运行',
  }
  return {
    tooltip: { ...baseTooltip, trigger: 'item' },
    legend: { bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { color: '#6b7280', fontSize: 11 } },
    series: [{
      type: 'pie',
      radius: ['52%', '74%'],
      center: ['50%', '44%'],
      itemStyle: { borderRadius: 5, borderColor: '#fff', borderWidth: 2 },
      label: { show: false },
      data: [...counts.entries()].map(([k, v]) => ({
        name: labels[k] || k,
        value: v,
        itemStyle: { color: statusColor[k] || seriesColors[0] },
      })),
    }],
  }
})

const durationBarOption = computed<EChartsOption>(() => {
  const rows = tasks.value.filter((t) => t.last_run && t.last_run.duration_ms > 0)
    .sort((a, b) => (b.last_run!.duration_ms) - (a.last_run!.duration_ms)).slice(0, 8)
  return {
    tooltip: { ...baseTooltip, trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { ...baseGrid, left: 8 },
    xAxis: { type: 'value', ...baseAxis },
    yAxis: { type: 'category', data: rows.map((t) => t.name.replace(/（.*）/, '')), ...baseAxis, axisLabel: { ...baseAxis.axisLabel, width: 84, overflow: 'truncate' } },
    series: [{
      type: 'bar',
      data: rows.map((t) => ({
        value: t.last_run!.duration_ms,
        itemStyle: { color: t.status === 'failed' ? '#f87171' : '#4f8cff', borderRadius: [0, 4, 4, 0] },
      })),
      barMaxWidth: 14,
    }],
  }
})

const statsBarOption = computed<EChartsOption>(() => {
  const rows = tasks.value.filter((t) => t.runs_24h > 0 || t.fail_24h > 0).slice(0, 8)
  return {
    tooltip: { ...baseTooltip, trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { top: 0, right: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { color: '#6b7280', fontSize: 11 } },
    grid: { ...baseGrid, left: 8 },
    xAxis: { type: 'category', data: rows.map((t) => t.name.replace(/（.*）/, '')), ...baseAxis, axisLabel: { ...baseAxis.axisLabel, interval: 0, width: 76, overflow: 'truncate' } },
    yAxis: { type: 'value', ...baseAxis, minInterval: 1 },
    series: [
      { name: '成功', type: 'bar', data: rows.map((t) => t.success_24h), itemStyle: { color: '#34d399', borderRadius: [4, 4, 0, 0] }, barMaxWidth: 14 },
      { name: '失败', type: 'bar', data: rows.map((t) => t.fail_24h), itemStyle: { color: '#f87171', borderRadius: [4, 4, 0, 0] }, barMaxWidth: 14 },
    ],
  }
})

// ===== 操作 =====
const onTrigger = async (row: TaskInfo) => {
  try {
    await ElMessageBox.confirm(`立即执行「${row.name}」？`, '手动触发', { type: 'info', confirmButtonText: '执行' })
  } catch { return }
  const res = await request.post<APIResponse>(`/system/tasks/${row.id}/trigger`)
  ElMessage.success(res.message || '已触发')
  fetchTasks()
}

const onToggle = async (row: TaskInfo, enabled: boolean) => {
  const res = await request.post<APIResponse>(`/system/tasks/${row.id}/toggle`, { enabled })
  ElMessage.success(res.message || '已更新')
  fetchTasks()
}

const onCancel = async (row: TaskInfo) => {
  try {
    await ElMessageBox.confirm(`取消运行中的「${row.name}」？下载阶段将中断，已完成部分保留。`, '手动取消', { type: 'warning', confirmButtonText: '取消任务' })
  } catch { return }
  const res = await request.post<APIResponse>(`/system/tasks/${row.id}/cancel`)
  ElMessage.success(res.message || '已发出取消信号')
  fetchTasks()
}

// ===== 日志抽屉 =====
const logsVisible = ref(false)
const logsLoading = ref(false)
const logs = ref<{ time: string; level: string; stage: string; message: string }[]>([])
const logsTask = ref<TaskInfo | null>(null)

const logEndpoints: Record<string, string> = {
  threat: '/security/threat-lib/update/logs',
  crs: '/security/crs/update/logs',
  ip2region: '/security/ip2region/update/logs',
}

const openLogs = async (row: TaskInfo) => {
  logsTask.value = row
  logsVisible.value = true
  logsLoading.value = true
  logs.value = []
  try {
    const res = await request.get<APIResponse<{ logs: { time: string; level: string; stage: string; message: string }[] }>>(logEndpoints[row.id], { silent: true })
    logs.value = (res.data?.logs || []).slice().reverse().slice(0, 100)
  } catch (e) {
    ElMessage.error('日志加载失败')
  } finally {
    logsLoading.value = false
  }
}

const logTimelineType = (level: string) => {
  if (level === 'ERROR' || level === 'WARN') return 'danger'
  if (level === 'success' || level === 'unchanged') return 'success'
  return 'primary'
}

// ===== 文案 =====
const statusLabels: Record<string, string> = {
  running: '运行中', idle: '空闲', queued: '排队中', failed: '失败', cancelled: '已取消',
  disabled: '已暂停', passive: '常驻', no_runs: '未运行',
}
const statusLabel = (s: string) => statusLabels[s] || s
const kindLabels: Record<string, string> = { scheduled: '定时', continuous: '常驻', queue: '队列' }
const kindLabel = (k: string) => kindLabels[k] || k
const kindTag = (k: string): 'primary' | 'success' | 'warning' =>
  k === 'scheduled' ? 'primary' : k === 'continuous' ? 'success' : 'warning'
const triggerLabels: Record<string, string> = { manual: '手动', auto: '自动', schedule: '排程', queue: '队列', 'slave-sync': '从节点同步' }
const triggerLabel = (t: string) => triggerLabels[t] || t || '—'

const fmtTime = (s?: string) => {
  if (!s) return ''
  const m = s.match(/(\d{2}:\d{2}:\d{2})/)
  const d = s.match(/(\d{2}-\d{2})/)?.[1] || ''
  return m ? `${d ? d + ' ' : ''}${m[1]}` : s
}
const fmtDuration = (ms?: number) => {
  if (!ms || ms <= 0) return '—'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`
}
</script>

<style scoped>
.tm-root { display: flex; flex-direction: column; gap: 16px; }
.tm-charts { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.tm-chart-card { background: var(--el-bg-color); border: 1px solid var(--el-border-color-lighter); border-radius: 10px; padding: 14px 16px 8px; }
.tm-chart-title { font-size: 13px; font-weight: 600; color: var(--el-text-color-primary); margin-bottom: 4px; }
.tm-chart { height: 210px; width: 100%; }
.tm-skeleton { background: linear-gradient(90deg, rgba(0,0,0,.03) 25%, rgba(0,0,0,.06) 50%, rgba(0,0,0,.03) 75%); background-size: 200% 100%; animation: tm-shimmer 1.2s infinite; border-radius: 8px; }
@keyframes tm-shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
.tm-table-card { background: var(--el-bg-color); border: 1px solid var(--el-border-color-lighter); border-radius: 10px; padding: 16px; }
.tm-table-head { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }
.tm-table-title { margin: 0; font-size: 15px; font-weight: 600; }
.tm-table-desc { margin: 4px 0 0; font-size: 12px; color: var(--el-text-color-secondary); }
.tm-task-name { display: flex; flex-direction: column; gap: 2px; font-weight: 500; }
.tm-cat { font-size: 11px; color: var(--el-text-color-secondary); }
.tm-status { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; }
.tm-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--tm-c, #9aa0b5); box-shadow: 0 0 6px var(--tm-c, transparent); }
.tm-status[data-status="running"] { --tm-c: #4f8cff; }
.tm-status[data-status="failed"] { --tm-c: #f87171; }
.tm-status[data-status="queued"] { --tm-c: #fbbf24; }
.tm-status[data-status="cancelled"] { --tm-c: #8b5cf6; }
.tm-status[data-status="disabled"] { --tm-c: #62687f; }
.tm-status[data-status="idle"], .tm-status[data-status="no_runs"] { --tm-c: #9aa0b5; }
.tm-status[data-status="passive"] { --tm-c: #38e1ff; }
.tm-run { display: flex; flex-direction: column; gap: 2px; font-size: 12.5px; }
.tm-run-line { color: var(--el-text-color-regular); }
.tm-run-msg { color: var(--el-text-color-secondary); font-size: 12px; max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tm-dim { color: var(--el-text-color-placeholder); }
.tm-ok { color: #34d399; font-weight: 600; }
.tm-bad { color: #f87171; font-weight: 600; }
.tm-logs-loading { display: flex; align-items: center; gap: 8px; color: var(--el-text-color-secondary); padding: 16px 0; }
.tm-log-stage { font-size: 11px; color: var(--el-text-color-secondary); margin-bottom: 2px; text-transform: uppercase; letter-spacing: .5px; }
.tm-pagination { display: flex; justify-content: flex-end; margin-top: 12px; }
.tm-running-text { color: #4f8cff; font-size: 12px; }
@media (max-width: 1100px) { .tm-charts { grid-template-columns: 1fr; } }
</style>
