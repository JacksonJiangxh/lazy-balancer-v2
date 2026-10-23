<template>
  <pre class="prism-code" :class="`language-${language}`" :style="height ? { height, maxHeight: 'none' } : undefined" v-html="highlighted"></pre>
</template>

<script setup lang="ts">
import { shallowRef } from 'vue'
import { watchDebounced } from '@vueuse/core'
import { highlightCode } from '@/utils/highlight'
import { escapeHtml } from '@/utils/escape'

const props = defineProps<{
  readonly content: string
  readonly language: string
  readonly height?: string
}>()

// 首帧只渲染「转义后的纯文本」，Prism 全文高亮推迟到停顿后补水：被消费于整份
// Caddy 配置 JSON 与整份 CRS 规则文件（百 KB 级），同步 computed 会在弹框打开
// 瞬间阻塞主线程数十~百毫秒（页面卡白）。与 CodeEditor 同策略（160ms 防抖 /
// 500ms 最大等待），两条高亮路径不再分叉。
// 注意：首帧不得直接 v-html 原文（未转义即注入面），故用 escapeHtml 兜底。
const highlighted = shallowRef(escapeHtml(props.content))
watchDebounced(
  () => [props.content, props.language] as const,
  ([content, language]) => {
    highlighted.value = highlightCode(content, language)
  },
  { debounce: 160, maxWait: 500, immediate: true },
)
</script>

<style scoped>
.prism-code {
  margin: 0;
  padding: 16px;
  border-radius: 6px;
  background: #1e293b;
  font-family: 'SF Mono', 'Monaco', 'Menlo', 'Consolas', monospace;
  font-size: 13px;
  line-height: 1.6;
  overflow: auto;
  max-height: 70vh;
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
