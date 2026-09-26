import { ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { request } from '@/utils/api'
import { showSaveResult } from '@/utils/saveResult'
import { parseRefIds } from '@/utils/securityStages'
import { useIpListAdd, type IpListOption } from '@/composables/useIpListAdd'
import type { APIResponse } from '@/types'

// 第 58 轮（用户裁定）：名单直接动作的共享实现——IP 快捷弹框黑/白/信任三侧
// 单击动作共用。语义：
//   1) 策略已关联同侧非系统地址列表 → 直接把 IP 加入该列表（确认+幂等+反馈
//      复用 useIpListAdd，与事件处置入口同一链路）；
//   2) 策略尚无同侧列表 → 自动创建「{策略名}{后缀}」（category=custom、空条目）
//      → 关联到策略对应 refs 字段 → 加入 IP，一步完成「创建并加入」；
//   3) 移除 = 从引用列表 remove-ip（关联保留，仅移除条目）。
// 信任侧未启用（ip_whitelist_enabled=false）时不阻断操作，仅提示「暂不生效」。
export type ListSide = 'deny' | 'allow' | 'trust'

const SIDE_CONFIG: Record<ListSide, {
  refField: 'ip_acl_list_refs' | 'ip_whitelist_refs'
  suffix: string
  verb: string
}> = {
  deny: { refField: 'ip_acl_list_refs', suffix: '-黑名单', verb: '拦截' },
  allow: { refField: 'ip_acl_list_refs', suffix: '-白名单', verb: '放行' },
  trust: { refField: 'ip_whitelist_refs', suffix: '-信任', verb: '信任' },
}

export interface TrustPolicyLike {
  id: number
  name: string
  ip_acl_list?: string
  ip_acl_list_refs?: string
  ip_whitelist?: string
  ip_whitelist_refs?: string
  ip_whitelist_enabled?: boolean
}

export interface TrustListRef {
  id: number
  name: string
  entry_count?: number
  /** system=内置威胁名单（只读）——两种组件来源的类型宽窄不一，故此处放宽 */
  system?: number | boolean
}

export const useTrustAssociation = (options: {
  /** 组件当前的地址列表选项（用于把 refs 解析为名单对象） */
  getList: () => TrustListRef[]
  /** 动作成功后的组件侧刷新（重拉策略/条目缓存等） */
  onChanged?: () => void | Promise<void>
}) => {
  const { adding, addIpToList } = useIpListAdd()
  const creating = ref(false)

  /** 策略既有同侧列表：对应 refs 字段中第一个非系统列表 */
  const resolveSideList = (policy: TrustPolicyLike, side: ListSide): TrustListRef | null => {
    const refs = parseRefIds(policy[SIDE_CONFIG[side].refField])
    return options.getList().find((l) => refs.includes(l.id) && !l.system) ?? null
  }
  /** 兼容别名：信任侧列表解析 */
  const resolveTrustList = (policy: TrustPolicyLike): TrustListRef | null => resolveSideList(policy, 'trust')

  /** 同侧全部非系统列表（第 60 轮用户验收：多列表绑定时逐列表出按钮，不再只取第一个） */
  const resolveSideLists = (policy: TrustPolicyLike, side: ListSide): IpListOption[] => {
    const refs = parseRefIds(policy[SIDE_CONFIG[side].refField])
    return options.getList()
      .filter((l) => refs.includes(l.id) && !l.system)
      .map((l) => ({ id: l.id, name: l.name, entry_count: l.entry_count ?? 0 }))
  }

  /** 加入指定列表（确认+幂等+反馈，第 60 轮暴露供逐列表按钮直调） */
  const joinSpecificList = async (list: IpListOption, ip: string, verb = '加入'): Promise<boolean> => {
    const done = await addIpToList(ip, list, { verb, successText: `已${verb}——已加入列表「${list.name}」` })
    if (done) await options.onChanged?.()
    return done
  }

  /** 单击动作：把 IP 加入策略指定侧的列表（自动解析/创建目标列表并关联） */
  const ensureListAndJoin = async (policy: TrustPolicyLike, ip: string, side: ListSide): Promise<void> => {
    const cfg = SIDE_CONFIG[side]
    const existing = resolveSideList(policy, side)
    if (existing) {
      const opt: IpListOption = { id: existing.id, name: existing.name, entry_count: 0 }
      const done = await addIpToList(ip, opt, { verb: cfg.verb, successText: `已${cfg.verb}——已加入列表「${existing.name}」` })
      if (done) await options.onChanged?.()
      return
    }
    const tip = side === 'trust' && policy.ip_whitelist_enabled === false ? '（注意：该策略信任名单当前未启用，加入后暂不生效）' : ''
    try {
      await ElMessageBox.confirm(
        `策略「${policy.name}」尚未关联${cfg.verb}用地址列表，将创建「${policy.name}${cfg.suffix}」并把 ${ip} 加入${tip}。是否继续？`,
        `创建列表并${cfg.verb}`,
        { confirmButtonText: '确定', cancelButtonText: '取消', type: 'info' },
      )
    } catch {
      return
    }
    creating.value = true
    try {
      // 第 59 轮 R59-P5：同侧已有同名未引用列表（历史创建后解绑）时复用而非
      // 重复创建——按名称在现有列表中查找（category 无关，仅看名字精确相等）。
      const wantName = `${policy.name}${cfg.suffix}`
      const sameName = options.getList().find((l) => l.name === wantName && !l.system)
      let newId: number | undefined = sameName?.id
      if (!newId) {
        const created = await request.post<APIResponse<{ id: number }>>('/security/ip-lists', {
          name: wantName,
          category: 'custom',
          entries: '[]',
        } as never)
        newId = created.data?.id
      }
      if (!newId) {
        ElMessage.error(`列表「${wantName}」创建响应异常，请重试`)
        return
      }
      const refs = parseRefIds(policy[cfg.refField])
      if (!refs.includes(newId)) {
        await request.put(`/security/policies/${policy.id}`, { [cfg.refField]: JSON.stringify([...refs, newId]) })
      }
      const added = await request.post<APIResponse<{ added: boolean }>>(`/security/ip-lists/${newId}/ips`, { value: ip })
      showSaveResult(added as unknown as { message?: string }, `已${sameName ? '关联既有' : '创建'}「${policy.name}${cfg.suffix}」并加入 ${ip}`)
      await options.onChanged?.()
    } catch {
      // 失败提示由全局拦截器弹出
    } finally {
      creating.value = false
    }
  }

  /** 兼容别名：信任侧加入 */
  const joinTrust = async (policy: TrustPolicyLike, ip: string): Promise<void> => {
    await ensureListAndJoin(policy, ip, 'trust')
  }

  /** 从引用列表移除 IP（关联保留） */
  const removeFromSideRef = async (list: TrustListRef, ip: string): Promise<void> => {
    try {
      await ElMessageBox.confirm(
        `将从地址列表「${list.name}」移除 ${ip}。是否继续？`,
        '从列表移除',
        { confirmButtonText: '确定', cancelButtonText: '取消', type: 'warning' },
      )
    } catch {
      return
    }
    creating.value = true
    try {
      await request.post(`/security/ip-lists/${list.id}/remove-ip`, { value: ip })
      ElMessage.success(`已从「${list.name}」移除`)
      await options.onChanged?.()
    } catch {
      // 全局拦截器已提示
    } finally {
      creating.value = false
    }
  }

  /** 兼容别名：信任侧移除 */
  const removeFromTrustRef = async (list: TrustListRef, ip: string): Promise<void> => {
    await removeFromSideRef(list, ip)
  }

  return { busyTrust: adding, creating, resolveTrustList, resolveSideList, resolveSideLists, joinSpecificList, ensureListAndJoin, joinTrust, removeFromSideRef, removeFromTrustRef }
}
