<template>
  <el-dialog
    :model-value="visible"
    width="min(560px, 94vw)"
    :close-on-click-modal="false"
    :close-on-press-escape="!saving"
    :show-close="!saving"
    class="node-site-dialog"
    @update:model-value="handleVisibilityChange"
    @closed="resetForm"
  >
    <template #header>
      <DialogHeader :icon="Location" title="节点站点坐标" subtitle="该从节点威胁大屏的本站信标位置，由主节点统一配置" />
    </template>
    <el-form label-position="top" :model="form">
      <el-form-item label="所在地区">
        <div style="display: flex; align-items: center; gap: 12px; flex-wrap: wrap;">
          <el-select
            v-model="form.siteLocationKey"
            filterable
            clearable
            placeholder="选择省份或国家"
            style="width: 260px"
            :disabled="saving"
            @change="applySiteLocation"
          >
            <el-option-group label="中国省份">
              <el-option v-for="item in CHINA_SITE_CHOICES" :key="item.key" :label="item.label" :value="item.key" />
            </el-option-group>
            <el-option-group label="海外国家">
              <el-option v-for="item in COUNTRY_SITE_CHOICES" :key="item.key" :label="item.label" :value="item.key" />
            </el-option-group>
          </el-select>
          <span class="form-tip-inline" style="white-space: nowrap;">{{ coordSummary }}</span>
          <el-tag v-if="node?.site_inherited" type="info" size="small" effect="plain">主节点默认</el-tag>
        </div>
        <div class="form-tip-line">保存后下一同步周期下发到该从节点；清空并保存 = 跟随主节点默认坐标（主节点也未配置时显示未配置）。各节点坐标互不影响。</div>
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button :disabled="saving" @click="close">取消</el-button>
      <el-button type="primary" :loading="saving" @click="save">保存</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, watch } from 'vue'
import { Location } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { CHINA_SITE_CHOICES, COUNTRY_SITE_CHOICES, coordsForSiteLocation, initialNodeSiteForm, nearestSiteLocation, nodeSiteCoordsChanged } from '@/utils/siteLocation'
import type { ClusterNode } from '@/types'

interface NodeSiteForm {
  siteLocationKey: string
  lat: number
  lon: number
}

const props = defineProps<{
  readonly visible: boolean
  readonly node: ClusterNode | null
  readonly saving: boolean
}>()

const emit = defineEmits<{
  (event: 'close'): void
  (event: 'save', coords: { lat: number; lon: number }): void
}>()

const form = reactive<NodeSiteForm>({ siteLocationKey: '', lat: 0, lon: 0 })
// 打开时的坐标基线：保存前对比判定 no-op（A86 历史问题）。
const baseline = reactive({ lat: 0, lon: 0 })

watch(
  () => [props.visible, props.node] as const,
  ([visible, node]) => {
    if (!visible || !node) return
    // A86 历史问题：继承节点还原为 0,0 + 空选择——列表接口返回的坐标是主节点
    // 默认值副本，预填会把「打开即保存」变成继承的静默固化。
    const initial = initialNodeSiteForm(node)
    form.lat = initial.lat
    form.lon = initial.lon
    form.siteLocationKey = initial.siteLocationKey
    baseline.lat = initial.lat
    baseline.lon = initial.lon
  },
  { immediate: true },
)

const coordSummary = computed(() => {
  if (form.lat === 0 && form.lon === 0) return '跟随主节点默认坐标'
  return `纬度 ${form.lat.toFixed(4)} · 经度 ${form.lon.toFixed(4)}`
})

const applySiteLocation = (key: string): void => {
  if (!key) {
    form.lat = 0
    form.lon = 0
    return
  }
  const coords = coordsForSiteLocation(key)
  if (!coords) {
    form.siteLocationKey = nearestSiteLocation(form.lat, form.lon)
    return
  }
  form.lat = coords.lat
  form.lon = coords.lon
}

const resetForm = (): void => {
  form.siteLocationKey = ''
  form.lat = 0
  form.lon = 0
  baseline.lat = 0
  baseline.lon = 0
}

const close = (): void => {
  if (!props.saving) emit('close')
}

const handleVisibilityChange = (visible: boolean): void => {
  if (!visible) close()
}

const save = (): void => {
  if (props.saving) return
  // A86 历史问题：无变更保存=no-op——直接关闭，不发 PUT、不 bump 集群版本。
  if (!nodeSiteCoordsChanged(baseline, form)) {
    emit('close')
    return
  }
  emit('save', { lat: form.lat, lon: form.lon })
}
</script>
