// 备份分类清单单源：导出/自动备份/还原共用同一份声明（后端 configBackupSections
// 为其镜像）。SFC 内声明会让测试只能靠正则剥类型求值——本模块是可 import 的纯
// 数据模块，前后端对表测试直接消费。

/** 备份分类键 → 展示标签；顺序即 UI 顺序。 */
export const BACKUP_SECTIONS = [
  { key: 'users', label: '系统数据' },
  { key: 'rules', label: '负载规则' },
  { key: 'security', label: '安全防护' },
  { key: 'cluster', label: '节点拓扑' },
] as const

/** legacy 分类键别名：升级前的 global_config/waf_files 读出即归一。 */
export const LEGACY_SECTION_ALIASES: Record<string, string> = { global_config: 'users', waf_files: 'security' }

/** 归一分类键（映射 legacy 别名、去重、保序、未知键透传）。 */
export const normalizeBackupSectionKeys = (keys: string[]): string[] => {
  const seen = new Set<string>()
  const out: string[] = []
  for (const key of keys) {
    const normalized = LEGACY_SECTION_ALIASES[key] ?? key
    if (seen.has(normalized)) continue
    seen.add(normalized)
    out.push(normalized)
  }
  return out
}
