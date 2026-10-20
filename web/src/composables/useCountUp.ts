import { ref, watch, onUnmounted, type Ref } from 'vue'

// 数字滚动（威胁大屏统计卡）：源值变化时经 rAF 缓动补间到新值。
// - 首次/大跨度用 ease-out（先快后慢的滚动感）
// - 页签隐藏即停帧（后台 rAF 被浏览器节流/冻结，继续排程只会在不可见时积压）；
//   隐藏期源值变化直接落值，恢复可见时直接落到源值（无积压补间）
// - 整数展示（大屏计数无小数语义），源值为非有限数时落 0
export function useCountUp(source: Ref<number>, durationMs = 800): Ref<number> {
  const targetOf = (value: number): number => Math.max(0, Math.floor(Number.isFinite(value) ? value : 0))
  const display = ref(targetOf(source.value))
  const isHidden = (): boolean => typeof document !== 'undefined' && document.hidden
  let rafId = 0

  const stop = (): void => {
    if (rafId) {
      cancelAnimationFrame(rafId)
      rafId = 0
    }
  }

  // 恢复可见落到源值：隐藏期间源值可能已跳变多次，补间中间态对用户无意义。
  const onVisibilityChange = (): void => {
    stop()
    if (!isHidden()) display.value = targetOf(source.value)
  }

  watch(source, (target) => {
    stop()
    const goal = targetOf(target)
    const from = display.value
    if (goal === from) {
      display.value = goal
      return
    }
    // 隐藏期不排帧（见文件头第二条）：直接落值，恢复可见后无需再补间
    if (isHidden()) {
      display.value = goal
      return
    }
    const startAt = performance.now()
    const step = (now: number): void => {
      const t = Math.min(1, (now - startAt) / durationMs)
      const eased = 1 - Math.pow(1 - t, 3)
      display.value = Math.round(from + (goal - from) * eased)
      if (t < 1) rafId = requestAnimationFrame(step)
      else rafId = 0
    }
    rafId = requestAnimationFrame(step)
  })

  if (typeof document !== 'undefined') document.addEventListener('visibilitychange', onVisibilityChange)

  onUnmounted(() => {
    if (typeof document !== 'undefined') document.removeEventListener('visibilitychange', onVisibilityChange)
    stop()
  })
  return display
}
