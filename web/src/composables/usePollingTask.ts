import { onUnmounted } from 'vue'

interface PollingTaskContext {
  readonly signal: AbortSignal
  readonly sequence: number
  readonly isCurrent: () => boolean
}

interface PollingTaskOptions {
  readonly interval?: number
  readonly onError?: (error: unknown) => void
}

export interface PollingTask {
  readonly signal: AbortSignal
  readonly run: () => Promise<void>
  readonly start: () => void
  readonly stop: () => void
  readonly pause: () => void
  readonly resume: () => void
  /** 诊断/测试用：生产代码零消费（pollingSignal 用例验证中止终态）。 */
  readonly isDisposed: () => boolean
}

export const usePollingTask = (
  task: (context: PollingTaskContext) => Promise<void>,
  options: PollingTaskOptions = {},
): PollingTask => {
  const controller = new AbortController()
  const taskControllers = new Set<AbortController>()
  let disposed = false
  let sequence = 0
  let inFlight: Promise<void> | null = null
  let pending = false
  let timer: ReturnType<typeof setInterval> | null = null
  let visibilityHandler: (() => void) | null = null

  const drain = async (): Promise<void> => {
    while (!disposed && pending) {
      pending = false
      const taskSequence = ++sequence
      // 每轮独立 AbortController：pause/stop 可取消真实请求，resume 后下一轮
      // 自动获得未 abort 的新 signal；永久 signal 仍只随 stop 终止。
      const taskController = new AbortController()
      taskControllers.add(taskController)
      const isCurrent = (): boolean => !disposed && !taskController.signal.aborted && taskSequence === sequence
      try {
        await task({ signal: taskController.signal, sequence: taskSequence, isCurrent })
      } catch (error: unknown) {
        // onError 是消费方回调——若其自身抛错，异常会经 drain→run() 的
        // Promise 拒绝逃逸，而定时器/可见性处用 void run() 丢弃 Promise，成为
        // unhandled rejection。回调异常就地记录并吞掉，不中断 drain、不影响下一轮。
        if (!controller.signal.aborted && !taskController.signal.aborted) {
          try {
            options.onError?.(error)
          } catch (callbackError: unknown) {
            console.error('usePollingTask onError callback threw:', callbackError)
          }
        }
      } finally {
        taskControllers.delete(taskController)
      }
    }
  }

  const run = (): Promise<void> => {
    if (disposed) return Promise.resolve()
    pending = true
    if (!inFlight) {
      const drainPromise = drain().finally(() => {
        if (inFlight === drainPromise) inFlight = null
      })
      inFlight = drainPromise
      return inFlight
    }
    // drain 末次 while 判空返回与 .finally 清 inFlight 之间存在微任务窗口：
    // 此刻 run() 置位 pending 却已无 drain 消费，「立即刷新」要等到下个定时器
    // tick。链到在途 drain 之后补跑——每轮只前进一步（pending 被 drain 消费后
    // 即停），不会递归爆栈。
    return inFlight.then(async () => {
      if (pending) await run()
    })
  }

  // 后台标签页暂停定时轮询（手动 run() 不受影响）；回到可见时恢复定时器并立即刷新补齐数据。
  const beginInterval = (): void => {
    if (disposed || timer !== null || options.interval === undefined) return
    if (typeof document !== 'undefined' && document.hidden) return
    timer = setInterval(() => void run(), options.interval)
  }

  const pauseInterval = (): void => {
    if (timer !== null) {
      clearInterval(timer)
      timer = null
    }
  }

  const ensureVisibilityPause = (): void => {
    if (visibilityHandler !== null || typeof document === 'undefined') return
    visibilityHandler = (): void => {
      if (disposed) return
      if (document.hidden) {
        pauseInterval()
      } else {
        beginInterval()
        void run()
      }
    }
    document.addEventListener('visibilitychange', visibilityHandler)
  }

  const start = (): void => {
    if (disposed || options.interval === undefined) return
    ensureVisibilityPause()
    beginInterval()
  }

  const invalidate = (): void => {
    sequence += 1
    pending = false
  }

  const stop = (): void => {
    if (disposed) return
    disposed = true
    invalidate()
    controller.abort()
    for (const active of taskControllers) active.abort()
    pauseInterval()
    if (visibilityHandler !== null && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', visibilityHandler)
      visibilityHandler = null
    }
  }

  // 非终态暂停/恢复——stop() 永久置位 disposed,弹框级
  // stop/start 循环的消费方(SecurityRules 更新进度)首轮 stop 后轮询永久
  // 失效。pause 停定时器、作废序列并 abort 每轮在途任务，resume 可反复调用；
  // 与 stop 的区别是不 abort 永久 signal、非终态（自此同步摘除 visibility 监听）。
  const pause = (): void => {
    invalidate()
    for (const active of taskControllers) active.abort()
    pauseInterval()
    // 同步摘除 visibility 监听——否则暂停期间标签页
    // 可见性翻转会在 handler 里 beginInterval() 复活定时器(违反 pause
    // 契约);resume→start→ensureVisibilityPause 会重挂,前 5 个不 pause
    // 的消费方不受影响。
    if (visibilityHandler !== null && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', visibilityHandler)
      visibilityHandler = null
    }
  }

  const resume = (): void => {
    start()
    // 恢复即刷新：与 visibilitychange 恢复路径（beginInterval + void run()）
    // 同口径——pause 的 invalidate 已丢弃 pending，run 内 inFlight 去重，不会重复执行。
    void run()
  }

  onUnmounted(stop)

  return { signal: controller.signal, run, start, stop, pause, resume, isDisposed: () => disposed }
}
