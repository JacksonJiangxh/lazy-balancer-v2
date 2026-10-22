<template>
  <div class="page">
    <div class="page-header">
      <div class="header-left">
        <h2 class="page-title">
          <el-icon class="title-icon"><Document /></el-icon>
          操作日志
        </h2>
        <p class="page-desc">记录系统中所有写操作和配置变更</p>
      </div>
    </div>

    <!-- 家族口径——列表失败必须显性化（「暂无操作日志」不得
         同时代表空库与故障），并给重试入口。 -->
    <el-alert v-if="loadError" type="error" :closable="false" show-icon class="polling-error-alert error-banner">
      <template #title>
        <div class="polling-error-title">
          <span>操作日志加载失败：列表为空不代表没有日志</span>
          <el-button link type="danger" @click="fetchLogs">立即重试</el-button>
        </div>
      </template>
    </el-alert>

    <el-card>
      <div class="filter-bar">
        <el-date-picker
          v-model="filters.timeRange"
          name="audit-time-range"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          format="YYYY-MM-DD HH:mm:ss"
          value-format="YYYY-MM-DD HH:mm:ss"
          :default-time="[new Date(2000, 0, 1, 0, 0, 0), new Date(2000, 0, 1, 23, 59, 59)]"
          class="audit-filter-date-range"
        />
        <el-select v-model="filters.username" :placeholder="optionsIncomplete ? '操作人（选项加载失败）' : '操作人'" clearable filterable style="width: 130px">
          <el-option v-for="o in usernameOptions" :key="o" :label="o" :value="o" />
        </el-select>
        <el-select v-model="filters.action" :placeholder="optionsIncomplete ? '操作（选项加载失败）' : '操作'" clearable filterable style="width: 120px">
          <el-option v-for="o in actionOptions" :key="o" :label="o" :value="o" />
        </el-select>
        <el-select v-model="filters.resource" :placeholder="optionsIncomplete ? '对象（选项加载失败）' : '对象'" clearable filterable allow-create style="width: 150px">
          <el-option v-for="o in resourceOptions" :key="o" :label="o" :value="o" />
        </el-select>
        <el-input v-model="filters.ip" placeholder="IP" clearable style="width: 120px" @keyup.enter="applyFilters" />
        <el-input v-model="filters.keyword" placeholder="详情关键词" clearable style="width: 160px" @keyup.enter="applyFilters" />
        <div class="filter-actions">
          <el-button type="primary" @click="applyFilters">筛选</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </div>
        <!-- 消费后端 partial=true（部分下拉）与整体失败——下拉缺项必须可见，
             且不得与「真空库」混淆。 -->
        <el-text v-if="optionsIncomplete" type="warning" size="small">
          筛选选项未完整加载，下拉列表可能缺项
          <el-button link type="warning" size="small" @click="fetchOptions">重试</el-button>
        </el-text>
      </div>
      <el-table :data="logs" v-loading="loading" stripe :header-cell-style="{ background: '#f9fafb' }" empty-text="" :tooltip-options="{ popperClass: 'log-overflow-popper' }">
        <template #empty>
          <el-empty :description="loadError ? '日志加载失败' : '暂无操作日志'" :image-size="60" />
        </template>
        <el-table-column prop="created_at" label="时间" width="190" :formatter="(row: AuditLogEntry) => formatDate(row.created_at)" />
        <el-table-column label="操作人" width="200">
          <template #default="{ row }">
            <el-tooltip v-if="row.display_name && row.display_name !== row.username" :content="`${row.display_name}（${row.username}）`" placement="top">
              <span class="operator-cell">{{ row.display_name }}<span class="operator-email">（{{ row.username }}）</span></span>
            </el-tooltip>
            <span v-else class="operator-cell">{{ row.username || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="action" label="操作" width="90">
          <template #default="{ row }">
            <el-tag :type="actionTagType(row.action)" size="small">{{ row.action }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="resource" label="对象" width="160" />
        <el-table-column prop="detail" label="详情" show-overflow-tooltip />
        <el-table-column prop="ip_address" label="IP" width="160" show-overflow-tooltip />
      </el-table>

      <div style="margin-top: 16px; display: flex; align-items: center; flex-wrap: wrap; row-gap: 8px;">
        <LogStorageBar log-key="audit" style="margin-right: auto" />
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[20, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @size-change="applyFilters"
          @current-change="fetchLogs"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted } from 'vue'
import { request } from '@/utils/api'
import { formatDate } from '@/utils/date'
import { Document } from '@element-plus/icons-vue'
import LogStorageBar from '@/components/LogStorageBar.vue'

import { buildAuditLogParams } from '@/utils/auditLogFilters'

interface AuditLogEntry {
  id: number
  username?: string | null
  display_name?: string | null
  action: string
  resource: string
  detail: string
  ip_address: string
  created_at: string
}

const logs = ref<AuditLogEntry[]>([])
const loading = ref(false)
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)
let requestSeq = 0

const filters = ref({
  timeRange: null as [string, string] | null,
  username: '',
  action: '',
  resource: '',
  ip: '',
  keyword: '',
})

const usernameOptions = ref<string[]>([])
const actionOptions = ref<string[]>([])
const resourceOptions = ref<string[]>([])
// 列表请求失败与「确实没有日志」必须可区分。
const loadError = ref(false)
// 后端在任一 option 查询失败时下发 partial=true（auditlog.go）——原实现
// 只映射三列、把「部分下拉」渲染成「下拉为空」。optionsError 覆盖请求整体失败。
const optionsPartial = ref(false)
const optionsError = ref(false)
const optionsIncomplete = computed(() => optionsPartial.value || optionsError.value)

const fetchOptions = async () => {
  try {
    const res = await request.get<{ data?: { partial?: boolean; usernames?: { value: string }[]; actions?: { value: string }[]; resources?: { value: string }[] } }>('/audit-logs/options')
    const d = res.data
    usernameOptions.value = (d?.usernames || []).map((o) => o.value)
    actionOptions.value = (d?.actions || []).map((o) => o.value)
    resourceOptions.value = (d?.resources || []).map((o) => o.value)
    optionsPartial.value = d?.partial === true
    optionsError.value = false
  } catch (e) {
    console.error('Failed to fetch audit log options:', e)
    optionsError.value = true
  }
}

const buildParams = () => buildAuditLogParams(filters.value, page.value, pageSize.value)

const applyFilters = () => {
  page.value = 1
  fetchLogs()
}

const resetFilters = () => {
  filters.value = { timeRange: null, username: '', action: '', resource: '', ip: '', keyword: '' }
  page.value = 1
  fetchLogs()
}

// 表驱动(原 60+ 字面量 if 链——后端新增动作词时手改链易漏)
const ACTION_TAG_TABLE: Record<string, string> = {
  '删除': 'danger',
  '检测失败': 'danger',
  '自动检测': 'success',
  '禁用': 'danger',
  '停止': 'danger',
  '重启': 'danger',
  '拒绝': 'danger',
  '签发失败': 'danger',
  '测试失败': 'danger',
  '登录失败': 'danger',
  '同步失败': 'danger',
  '重载失败': 'danger',
  '渲染跳过': 'danger',
  '写入失败': 'danger',
  '启用失败': 'danger',
  '创建失败': 'danger',
  '复制失败': 'danger',
  '删除失败': 'danger',
  '禁用失败': 'danger',
  '恢复失败': 'danger',
  '切换失败': 'danger',
  '注册失败': 'danger',
  '上报失败': 'danger',
  '导入失败': 'danger',
  '还原失败': 'danger',
  '备份失败': 'danger',
  '备份删除': 'danger',
  '配置漂移': 'danger',
  '清理失败': 'danger',
  '部分失败': 'danger',
  '应用失败': 'danger',
  '应用降级': 'warning',
  '部署失败': 'danger',
  '认证拒绝': 'danger',
  '提升失败': 'danger',
  '校验失败': 'danger',
  '更新失败': 'danger',
  '校验阻断': 'danger',
  '清除失败': 'danger',
  '触发失败': 'danger',
  '更新': 'warning',
  '手动更新': 'warning',
  '更新信息': 'warning',
  '修改状态': 'warning',
  '重置密码': 'warning',
  '重置': 'success',
  '重载': 'warning',
  '续签': 'warning',
  '重试': 'warning',
  '签发限流': 'warning',
  '切换': 'warning',
  '提升': 'warning',
  '提升完成': 'warning',
  '同步': 'warning',
  '同步下发': 'warning',
  '手动同步': 'warning',
  '同步自愈': 'warning',
  '同步警告': 'warning',
  '注册': 'warning',
  '生成': 'warning',
  '导出': 'warning',
  '导入': 'warning',
  '导入警告': 'warning',
  '还原': 'warning',
  '还原警告': 'warning',
  '自动备份': 'warning',
  '手动备份': 'warning',
  '备份设置': 'warning',
  '备份下载': 'warning',
  '复制': 'warning',
  '触发签发': 'warning',
  '触发': 'warning',
  '写入': 'warning',
  '恢复排队': 'warning',
  '续签排队': 'warning',
  '重新排队': 'warning',
  '重试排队': 'warning',
  '更新地址': 'warning',
  '校验告警': 'warning',
  '下载校验': 'warning',
  '清理': 'warning',
  '清除': 'warning',
  '启动': 'warning',
  '启动警告': 'warning',
  '同步应用': 'warning',
  '同步跳过': 'warning',
  '登出': 'warning',
  '重建': 'warning',
  '启动迁移': 'warning',
  '警告': 'warning',
  '脱离': 'warning',
  '服务控制': 'warning',
  '创建': 'success',
  '启用': 'success',
  '审批': 'success',
  '签发成功': 'success',
  '测试成功': 'success',
  '登录成功': 'success',
  '恢复': 'success',
  '暂停': 'warning',
  '取消': 'warning',
  '配置恢复': 'success',
  '载入': 'success',
  '校验成功': 'success',
  // 自动封禁：封禁=阻断（danger），到期自动解封=恢复（success）。
  '自动封禁': 'danger',
  '自动解封': 'success',
  // 容量收敛：名单触顶挤出/丢弃的告警性系统动作（warning——不是错误，但需关注）。
  '容量收敛': 'warning',
}
const actionTagType = (action: string): string => ACTION_TAG_TABLE[action] ?? 'info'

const fetchLogs = async () => {
  const targetPage = page.value
  const targetPageSize = pageSize.value
  const currentRequestSeq = ++requestSeq
  loading.value = true
  try {
    const res = await request.get<{ data?: { list?: AuditLogEntry[]; total?: number } }>('/audit-logs', { params: buildParams() })
    if (currentRequestSeq !== requestSeq || page.value !== targetPage || pageSize.value !== targetPageSize) return
    logs.value = res.data?.list || []
    total.value = res.data?.total || 0
    loadError.value = false
  } catch (e) {
    console.error('Failed to fetch audit logs:', e)
    // 仅最新请求可置错误态（陈旧请求的失败不得覆盖新结果）。
    if (currentRequestSeq === requestSeq) loadError.value = true
  } finally {
    if (currentRequestSeq === requestSeq) loading.value = false
  }
}

onMounted(() => {
  fetchLogs()
  fetchOptions()
})
</script>

<style scoped>
.operator-cell {
  display: inline-block;
  max-width: 100%;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  vertical-align: bottom;
}
.operator-email { font-size: 11.5px; color: var(--el-text-color-secondary); }

.filter-bar { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 14px; align-items: center; }
.polling-error-alert { margin-bottom: 16px; }
.filter-actions { display: flex; gap: 0; margin-left: 8px; }
.filter-actions .el-button + .el-button { margin-left: 8px; }
</style>

<style>
.audit-filter-date-range.el-date-editor {
  --el-date-editor-width: 360px;
  width: 360px;
  flex: 0 0 auto;
}
</style>

<style>
.log-overflow-popper { max-width: 420px; word-break: break-all; }
.log-overflow-popper .el-tooltip__popper { max-width: 420px; }
</style>
