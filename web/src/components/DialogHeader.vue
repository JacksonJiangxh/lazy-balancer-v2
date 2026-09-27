<template>
  <div class="dh-header">
    <div class="dh-icon" :class="toneClass">
      <el-icon :size="18"><component :is="icon" /></el-icon>
    </div>
    <div>
      <div class="dh-title">{{ title }}</div>
      <div v-if="subtitle" class="dh-sub">{{ subtitle }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, type Component } from 'vue'

const props = defineProps<{
  icon: Component
  title: string
  subtitle?: string
  tone?: 'primary' | 'success' | 'warning' | 'danger'
}>()

const toneClass = computed(() => (props.tone ? `dh-icon--${props.tone}` : ''))
</script>

<style scoped>
/* 与 BasicSettings.backup-dialog-header 同款视觉（共享组件化消除 scoped 跨文件失效） */
.dh-header { display: flex; align-items: center; gap: 12px; }
.dh-icon {
  width: 38px; height: 38px; border-radius: 10px;
  display: flex; align-items: center; justify-content: center;
  background: var(--el-color-primary-light-9); color: var(--el-color-primary);
  font-size: 18px; flex-shrink: 0;
}
.dh-icon--success { background: var(--el-color-success-light-9); color: var(--el-color-success); }
.dh-icon--warning { background: var(--el-color-warning-light-9); color: var(--el-color-warning); }
.dh-icon--danger { background: var(--el-color-danger-light-9); color: var(--el-color-danger); }
.dh-title { font-size: 16px; font-weight: 600; color: var(--el-text-color-primary); }
.dh-sub { font-size: 12.5px; color: var(--el-text-color-secondary); margin-top: 2px; }
</style>
