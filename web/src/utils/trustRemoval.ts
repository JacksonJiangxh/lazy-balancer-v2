// 「取消信任」处置计划单源（历史问题 行为化）：原逻辑内联在 IPLocationAction，
// 且残余信任判定只在「无内联精确条目」分支生效——IP 同时由内联精确条目与引用
// 列表 CIDR 信任时跳过守卫，移除后仍持续信任却弹「已取消信任/恢复拦截」。
//
// 本函数返回：
// - inlineExact：策略内联名单存在该 IP 的精确条目（可移除）
// - exactRefListIds：命中引用列表中存在精确条目且允许本弹窗移除的列表（可移除）
// - residualSources：移除后仍提供信任的 CIDR 条目来源（不可移除，须人工到
//   策略/列表编辑处理）；空 = 移除后信任真正解除
// - hasRemovable：是否存在可移除条目（false = 本弹窗无可执行动作）
import { entryMatchesIp, parseIPList, parseRefIds } from './securityStages.ts'

export interface TrustRemovalList {
  readonly id: number
  readonly name: string
}

export interface TrustRemovalPlan {
  readonly inlineExact: boolean
  readonly exactRefListIds: readonly number[]
  readonly residualSources: readonly string[]
  readonly hasRemovable: boolean
}

export const planTrustRemoval = (input: {
  readonly ip: string
  readonly inlineWhitelist: string | undefined
  readonly whitelistRefs: string | undefined
  readonly lists: readonly TrustRemovalList[]
  readonly removableListIds: readonly number[]
  readonly listEntries: (listId: number) => readonly string[]
}): TrustRemovalPlan => {
  const ip = input.ip.trim()
  const inline = parseIPList(input.inlineWhitelist)
  const refIds = parseRefIds(input.whitelistRefs)
  const removable = new Set(input.removableListIds)

  const inlineExact = inline.includes(ip)
  const exactRefListIds = input.lists
    .filter((l) => refIds.includes(l.id) && removable.has(l.id)
      && input.listEntries(l.id).some((e) => e.trim() === ip))
    .map((l) => l.id)

  // 残余信任 = 移除后仍匹配该 IP 的非精确条目（内联 CIDR / 引用列表 CIDR）
  const residualSources: string[] = []
  if (inline.some((e) => e.trim() !== ip && entryMatchesIp(e, ip))) {
    residualSources.push('策略内联 CIDR 条目')
  }
  for (const list of input.lists) {
    if (!refIds.includes(list.id)) continue
    if (input.listEntries(list.id).some((e) => e.trim() !== ip && entryMatchesIp(e, ip))) {
      residualSources.push(`引用列表「${list.name}」的 CIDR 条目`)
    }
  }

  return {
    inlineExact,
    exactRefListIds,
    residualSources,
    hasRemovable: inlineExact || exactRefListIds.length > 0,
  }
}
