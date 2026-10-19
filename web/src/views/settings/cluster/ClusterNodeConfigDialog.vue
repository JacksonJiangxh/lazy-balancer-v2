<template>
  <el-dialog
    :model-value="visible"
    width="min(560px, 94vw)"
    :close-on-click-modal="false"
    :close-on-press-escape="!saving"
    :show-close="!saving"
    class="node-config-dialog"
    @update:model-value="handleVisibilityChange"
    @opened="focusInput"
    @closed="resetForm"
  >
    <template #header>
      <DialogHeader :icon="Setting" title="节点配置" subtitle="访问地址与威胁大屏本站信标位置由主节点统一配置" />
    </template>
    <el-form ref="formRef" :model="form" :rules="rules" label-position="top" @submit.prevent="save">
      <el-form-item label="访问地址" prop="access_url">
        <el-input
          ref="inputRef"
          v-model="form.access_url"
          placeholder="例如：https://127.0.0.1:8001"
          clearable
          :disabled="saving"
          @keyup.enter="save"
        />
        <div class="form-tip-line">
          {{ form.access_url.trim() ? '请输入可从浏览器访问的 HTTP 或 HTTPS 地址' : '留空将回退使用注册地址' }}
        </div>
      </el-form-item>
      <el-form-item label="站点坐标">
        <div class="site-location-row">
          <el-select
            v-model="form.siteLocationKey"
            filterable
            clearable
            placeholder="选择省份或国家"
            class="site-location-select"
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
          <span class="form-tip-inline">{{ coordSummary }}</span>
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
import { computed, nextTick, reactive, ref, watch } from 'vue'
import type { FormInstance, FormRules, InputInstance } from 'element-plus'
import { Setting } from '@element-plus/icons-vue'
import DialogHeader from '@/components/DialogHeader.vue'
import { CHINA_SITE_CHOICES, COUNTRY_SITE_CHOICES, coordsForSiteLocation, initialNodeSiteForm, nearestSiteLocation, nodeSiteCoordsChanged } from '@/utils/siteLocation'
import type { ClusterNode } from '@/types'

interface NodeConfigForm {
  access_url: string
  siteLocationKey: string
  lat: number
  lon: number
}

interface NodeConfigPayload {
  accessUrl: string
  lat: number
  lon: number
  siteChanged: boolean
}

const props = defineProps<{
  readonly visible: boolean
  readonly node: ClusterNode | null
  readonly saving: boolean
}>()

const emit = defineEmits<{
  (event: 'close'): void
  (event: 'save', payload: NodeConfigPayload): void
}>()

const formRef = ref<FormInstance>()
const inputRef = ref<InputInstance>()
const form = reactive<NodeConfigForm>({ access_url: '', siteLocationKey: '', lat: 0, lon: 0 })
// 打开时的坐标基线：保存前对比判定站点坐标是否真实变更（A86 历史问题）。
const baseline = reactive({ lat: 0, lon: 0 })

const validateAccessUrl = (_rule: unknown, value: string, callback: (error?: Error) => void): void => {
  const normalized = value.trim()
  if (!normalized) {
    callback()
    return
  }
  if (!/^https?:\/\//.test(normalized)) {
    callback(new Error('访问地址必须使用 HTTP 或 HTTPS'))
    return
  }
  try {
    const parsed = new URL(normalized)
    if (!parsed.host) {
      callback(new Error('访问地址必须包含主机'))
      return
    }
    if (parsed.username || parsed.password) {
      callback(new Error('访问地址不能包含用户名或密码'))
      return
    }
    if (parsed.hash) {
      callback(new Error('访问地址不能包含片段'))
      return
    }
    if (parsed.search) {
      callback(new Error('访问地址不能包含查询参数'))
      return
    }
    callback()
  } catch {
    // new URL() 仅抛 TypeError；其余异常同样视为地址非法，走统一提示，不向外抛。
    callback(new Error('访问地址格式不正确'))
  }
}

const rules: FormRules<NodeConfigForm> = {
  access_url: [{ validator: validateAccessUrl, trigger: ['blur', 'change'] }],
}

watch(
  () => [props.visible, props.node] as const,
  ([visible, node]) => {
    if (!visible || !node) return
    form.access_url = node.access_url
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

const focusInput = async (): Promise<void> => {
  await nextTick()
  inputRef.value?.focus()
}

const resetForm = (): void => {
  form.access_url = ''
  form.siteLocationKey = ''
  form.lat = 0
  form.lon = 0
  baseline.lat = 0
  baseline.lon = 0
  formRef.value?.clearValidate()
}

const close = (): void => {
  if (!props.saving) emit('close')
}

const handleVisibilityChange = (visible: boolean): void => {
  if (!visible) close()
}

const save = async (): Promise<void> => {
  if (props.saving || !props.node || !formRef.value) return
  let valid = false
  await formRef.value.validate((result) => {
    valid = result
  })
  if (!valid) return
  const accessUrl = form.access_url.trim()
  const siteChanged = nodeSiteCoordsChanged(baseline, form)
  if (accessUrl === (props.node.access_url ?? '') && !siteChanged) {
    emit('close')
    return
  }
  emit('save', { accessUrl, lat: form.lat, lon: form.lon, siteChanged })
}
</script>

<style scoped>
.site-location-row { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.site-location-select { width: 260px; }
</style>
