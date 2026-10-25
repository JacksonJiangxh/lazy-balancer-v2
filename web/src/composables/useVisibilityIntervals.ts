// 页面隐藏时间隔任务停摆/恢复单源：威胁大屏曾只暂停渲染，
// 采集租约心跳在后台持续续租让 Caddy 空计数、时钟/弧光间隔空转。本模块把
// 「hidden 停止全部间隔 + 回调（如释放租约）；visible 重启并立即补 tick」
// 收敛为一处可行为测试的实现，组件侧不再直挂 visibilitychange。
//
// 框架无关（不依赖 Vue）：node --test 下用假 document/window 驱动真实代码。

interface VisibilityIntervalSpec {
  /** 每个周期执行的回调 */
  tick: () => void
  /** 周期毫秒 */
  ms: number
  /** start/恢复可见时立即补一次 tick（时钟首刷、租约即时重取） */
  immediate?: boolean
}

interface VisibilityDocumentHost {
  readonly hidden: boolean
  addEventListener: (type: 'visibilitychange', listener: () => void) => void
  removeEventListener: (type: 'visibilitychange', listener: () => void) => void
}

interface VisibilityWindowHost {
  setInterval: (handler: () => void, timeout: number) => number
  clearInterval: (id: number) => void
}

interface VisibilityIntervalsOptions {
  intervals: readonly VisibilityIntervalSpec[]
  /** 转入隐藏（含挂载即隐藏）：全部间隔停止后调用——释放采集租约/暂停渲染 */
  onHidden?: () => void
  /** 恢复可见：间隔重启（含 immediate 补 tick）后调用——游标补偿/恢复渲染 */
  onVisible?: () => void
  /**
   * 测试注入；缺省惰性取全局 document/window。无 document 时只退化为「无监听」
   * （间隔仍由注入或缺省的 window 驱动）；无 window 时（node/SSR）不启动任何
   * 间隔——tick 不会执行，仅登记 document 监听（若注入）。
   */
  doc?: VisibilityDocumentHost
  win?: VisibilityWindowHost
}

export interface VisibilityIntervals {
  /** 挂监听并按当前可见性启动间隔；幂等 */
  start: () => void
  /** 摘监听并清全部间隔；幂等。不触发 onHidden（卸载收尾由调用方自行释放资源） */
  stop: () => void
}

export function createVisibilityIntervals(options: VisibilityIntervalsOptions): VisibilityIntervals {
  const timers: number[] = Array.from({ length: options.intervals.length }, () => 0)
  let doc: VisibilityDocumentHost | undefined
  let win: VisibilityWindowHost | undefined
  let started = false
  let running = false

  const startTimers = (): void => {
    if (running || win === undefined) return
    const w = win
    options.intervals.forEach((spec, i) => {
      if (spec.immediate) spec.tick()
      timers[i] = w.setInterval(spec.tick, spec.ms)
    })
    running = true
  }

  const stopTimers = (): void => {
    if (!running || win === undefined) return
    const w = win
    options.intervals.forEach((_, i) => {
      w.clearInterval(timers[i])
      timers[i] = 0
    })
    running = false
  }

  const onVisibilityChange = (): void => {
    if (doc?.hidden) {
      stopTimers()
      options.onHidden?.()
    } else {
      startTimers()
      options.onVisible?.()
    }
  }

  return {
    start() {
      if (started) return
      started = true
      doc = options.doc ?? (typeof document !== 'undefined' ? document : undefined)
      win = options.win ?? (typeof window !== 'undefined' ? window : undefined)
      doc?.addEventListener('visibilitychange', onVisibilityChange)
      // 挂载即 hidden 与运行中转入隐藏同语义：不起间隔、不取租约、按 hidden 回调
      if (doc?.hidden) options.onHidden?.()
      else startTimers()
    },
    stop() {
      if (!started) return
      started = false
      doc?.removeEventListener('visibilitychange', onVisibilityChange)
      stopTimers()
    },
  }
}
