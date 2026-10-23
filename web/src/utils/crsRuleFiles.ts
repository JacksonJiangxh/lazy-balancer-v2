// GET /security/crs/rules 全量分页取回单源。
//
// 后端 page_size 上限为 50（internal/handlers/security.go）。单页取回会让
// 文件数 >50 时组名映射静默回退裸组码，且策略页会把握手不到的存量响应阶段组
// 判成「当前 CRS 已无此规则组」而允许删除——两处消费（流程弹框/策略页）
// 必须共用同一份全量实现。
import { request } from './api'
import type { APIResponse } from '@/types'
import type { CrsRuleFileOption } from './securityStages'

export const CRS_RULE_PAGE_SIZE = 50
// 上限 40 页（2000 个文件）：防御异常 total/分页不收敛；当前 CRS 约 40 个文件。
export const CRS_RULE_MAX_PAGES = 40

/** 全量取回 CRS 规则文件清单（按 filename/category 逐页拼接，网络错误向上抛）。 */
export const fetchAllCrsRuleFiles = async (): Promise<CrsRuleFileOption[]> => {
  const all: CrsRuleFileOption[] = []
  for (let page = 1; page <= CRS_RULE_MAX_PAGES; page++) {
    const res = await request.get<APIResponse<{ rules: CrsRuleFileOption[]; total?: number }>>(
      `/security/crs/rules?page_size=${CRS_RULE_PAGE_SIZE}&page=${page}`,
      { silent: true },
    )
    const rules = res.data?.rules ?? []
    all.push(...rules)
    const total = res.data?.total
    if (rules.length < CRS_RULE_PAGE_SIZE) break
    if (typeof total === 'number' && all.length >= total) break
  }
  return all
}
