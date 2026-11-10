<template>
  <div class="proxy-timeout-fields">
    <el-form-item v-for="field in fields" :key="field.key" :label="field.label">
      <el-input-number
        :model-value="value[field.key]"
        :min="field.min"
        :placeholder="inheritLabel"
        :disabled="disabled || fieldOverrides?.[field.key]?.disabled === true"
        controls-position="right"
        class="number-input"
        @update:model-value="update(field.key, $event)"
      />
      <span v-if="fieldOverrides?.[field.key]" class="form-tip-inline">
        <TakeoverBadge v-if="fieldOverrides[field.key]!.badge" :label="fieldOverrides[field.key]!.badge" />
        {{ fieldOverrides[field.key]!.note }}
      </span>
      <span v-else class="form-tip-inline">
        秒，0 = {{ inheritLabel }}<template v-if="showSuggested && field.suggest">；非流式建议 {{ field.suggest }}</template><template v-if="field.desc">；{{ field.desc }}</template>
      </span>
    </el-form-item>
  </div>
</template>

<script setup lang="ts">
import TakeoverBadge from '@/components/common/TakeoverBadge.vue'
import type { ProxyTimeoutConfig } from '@/types'
import { PROXY_TIMEOUT_FIELDS } from '@/utils/proxyTimeouts.ts'

withDefaults(defineProps<{
  readonly value: ProxyTimeoutConfig
  readonly inheritLabel: string
  readonly disabled?: boolean
  readonly showSuggested?: boolean
  // 逐字段接管态（如 NTLM 兼容）：disabled=禁用输入；note 存在时以接管说明
  // 替换默认 tip；badge 为前置徽标文案
  readonly fieldOverrides?: Partial<Record<keyof ProxyTimeoutConfig, {
    readonly disabled?: boolean
    readonly badge?: string
    readonly note?: string
  }>>
}>(), { showSuggested: false })

const emit = defineEmits<{
  (event: 'update', field: keyof ProxyTimeoutConfig, value: number): void
}>()

type TimeoutField = (typeof PROXY_TIMEOUT_FIELDS)[number]

// 字段定义（标签/下限/说明/建议值）与向导预览摘要同源，见 utils/proxyTimeouts.ts。
const fields: readonly TimeoutField[] = PROXY_TIMEOUT_FIELDS

const update = (field: keyof ProxyTimeoutConfig, value: number | undefined): void => {
  emit('update', field, value ?? 0)
}
</script>

<style scoped>
.number-input { width: 120px; }
</style>
