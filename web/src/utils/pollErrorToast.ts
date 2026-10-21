/**
 * 静默轮询失败 toast 判定单源（历史修复）：自动备份「立即备份」的 2s quiet
 * 轮询失败此前逐轮弹窗——60s 窗口可堆 ~30 条相同错误。判定：只有「从未加载
 * 成功」（保存本就不可用，用户需要知道原因）且距上次提示超过 windowMs 时提示
 * 一次；已加载成功时保持静默（列表刷新失败不影响已加载的门控与保存）。
 * 非 quiet 轮失败由调用方无条件提示，不进本判定。
 * 抽成纯函数供 node --test 行为断言，避免源码正则把「节流分支」误当成「非 quiet
 * 分支」（历史修复：原断言实际匹配的是 quiet 分支自身的 toast，删掉
 * 非 quiet 的提示仍然通过）。
 */
export const shouldToastQuietPollError = (
  loaded: boolean,
  now: number,
  lastToastAt: number,
  windowMs = 30_000,
): boolean => !loaded && now - lastToastAt > windowMs
