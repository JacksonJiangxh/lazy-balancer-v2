<template>
  <!-- 视觉沿用 el-link；语义必须是可聚焦控件。无 href 的 <a> 不进 Tab 序、回车
       无动作（element-plus 的 link 只在 href 存在时渲染 href，也不补
       tabindex/role）——键盘与读屏用户会丢失该操作入口。键盘激活统一合成
       click，复用调用方已有的 @click（不引入第二套回调契约）。 -->
  <el-link
    role="button"
    tabindex="0"
    @keydown.enter.prevent="activate"
    @keydown.space.prevent="activate"
  >
    <slot />
  </el-link>
</template>

<script setup lang="ts">
// 键盘激活：Enter/Space → 合成 click（浏览器对无 href 的 <a> 不提供默认激活行为）。
const activate = (event: KeyboardEvent): void => {
  const target = event.currentTarget
  if (target instanceof HTMLElement) target.click()
}
</script>

<style scoped>
/* 键盘焦点必须可见：el-link 默认无焦点环 */
.el-link:focus-visible { outline: 2px solid var(--el-color-primary); outline-offset: 2px; border-radius: 2px; }
</style>
