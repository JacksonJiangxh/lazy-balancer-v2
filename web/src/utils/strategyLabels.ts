// 负载策略→文案映射（Rules/Dashboard 共用）。
// 键集与后端 httpStrategies 全集对齐（weighted_round_robin/least_conn/
// ip_hash/random/first/cookie）；Dashboard 原死键 round_robin 与 Rules 原
// 死键 header 已删除（后端不接受该两形态）。
// 映射对象收窄为模块内私有（外泄面只剩 getStrategyLabel 一个函数，
// 消费方禁止绕过函数直读映射，防第二份映射/直改键值）
const strategyLabels: Record<string, string> = {
  weighted_round_robin: '轮询',
  least_conn: '最少连接',
  ip_hash: 'IP 哈希',
  cookie: '粘滞',
  first: '首个可用',
  random: '随机',
}

export const getStrategyLabel = (strategy: string): string => strategyLabels[strategy] || strategy

// ── 向导策略卡片与提交白名单单源 ──
// 卡片可见集与 submitWizard 的 allowedStrategies 原各自维护：白名单放行了
// random/first（后端 httpStrategies/tcpStrategies 同放行），卡片却没有这两张
// ——API/MCP/导入产生的 random/first 规则在向导内无高亮、点任意卡片即静默改写。
// 键集与后端 validateStrategyForProtocol（rule_features.go）逐协议对齐。
interface StrategyCardOption {
  readonly value: string
  readonly title: string
  readonly desc: string
  /** cookie 粘滞仅 HTTP 可用（后端 TCP 白名单不含 cookie）。 */
  readonly httpOnly?: boolean
}

export const STRATEGY_CARD_OPTIONS: readonly StrategyCardOption[] = [
  { value: 'weighted_round_robin', title: '轮询', desc: '按上游权重比例分配，权重相同即为普通轮询' },
  { value: 'least_conn', title: '最少连接', desc: '优先分配给连接数最少的服务器' },
  { value: 'ip_hash', title: 'IP 哈希', desc: '按客户端 IP 固定分配' },
  { value: 'random', title: '随机', desc: '随机分配给一个可用上游' },
  { value: 'first', title: '首个可用', desc: '始终使用列表中第一个可用上游' },
  { value: 'cookie', title: 'Cookie 粘滞', desc: '通过 Cookie 实现精确会话粘滞', httpOnly: true },
]

/** 该协议可选的策略卡片（TCP 剔除 cookie）。 */
export const strategyCardsForProtocol = (protocol: 'http' | 'tcp'): readonly StrategyCardOption[] =>
  STRATEGY_CARD_OPTIONS.filter((card) => !(card.httpOnly && protocol === 'tcp'))

/** 该协议的合法策略值集——提交白名单与卡片集同源派生。 */
export const strategyValuesForProtocol = (protocol: 'http' | 'tcp'): readonly string[] =>
  strategyCardsForProtocol(protocol).map((card) => card.value)
