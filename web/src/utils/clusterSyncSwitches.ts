// 集群同步开关三分类单源：ClusterMasterPanel 的开关行（label+tip）与
// ClusterSettings 的变更确认文案（label）原各持一份「系统数据/负载均衡规则/
// 安全防护」，改名/新增必漏一侧。此处收敛为唯一事实源，两侧只做取值。

export interface ClusterSyncSwitch {
  readonly key: string
  readonly label: string
  readonly tip: string
  /** true=恒同步、不可禁用（元数据承载，避免消费方写死 key 特例） */
  readonly locked?: boolean
}

export const CLUSTER_SYNC_SWITCHES = [
  // (三分类合并:全局配置并入系统数据节)确保系统基本运行的数据不可禁用同步。
  // 2026-09-19 文案整理:「证书文件随负载规则开关同步」属 rules 开关管辖
  // 不在本行尾注。
  { key: 'sync_users', label: '系统数据', tip: '用户账号、API 密钥、ACME 配置与全局设置（恒同步，不可禁用）', locked: true },
  // 证书任务行与证书文件随本开关:关闭时从节点保留本地规则,
  // 其证书行/文件不按主节点快照删改。
  { key: 'sync_rules', label: '负载均衡规则', tip: '规则、上游、路径规则与证书任务（证书文件随本开关同步）', locked: false },
  // 三分类合并:规则库文件差量通道并入安全防护开关(单开关统策略行与文件)。
  { key: 'sync_security', label: '安全防护', tip: '安全策略、自定义规则与 CRS/IP2Region 规则库（文件哈希一致时跳过传输）', locked: false },
] as const satisfies readonly ClusterSyncSwitch[]
