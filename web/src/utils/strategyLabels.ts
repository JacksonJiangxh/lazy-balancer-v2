// FE40-D1-2：负载策略→文案映射（Rules/Dashboard 共用）。
// 键集与后端 httpStrategies 全集对齐（weighted_round_robin/least_conn/
// ip_hash/random/first/cookie/chain_fallback）；Dashboard 原死键 round_robin
// 与 Rules 原死键 header 已删除（后端不接受该两形态）。
// FE65-6：映射对象收窄为模块内私有（外泄面只剩 getStrategyLabel 一个函数，
// 消费方禁止绕过函数直读映射，防第二份映射/直改键值）
const strategyLabels: Record<string, string> = {
  weighted_round_robin: '轮询',
  least_conn: '最少连接',
  ip_hash: 'IP 哈希',
  cookie: '粘滞',
  first: '首个可用',
  random: '随机',
  // 链式回退（2026-10-09）：权重降序回退链 + 竞速 + 兜底截断，仅 HTTP。
  chain_fallback: '链式回退',
}

export const getStrategyLabel = (strategy: string): string => strategyLabels[strategy] || strategy
