/**
 * 集群地址校验单源（WS-18，历史）。
 *
 * 主节点地址（注册弹框）与节点访问地址（节点配置弹框）在后端共用
 * `models.ValidateClusterAccessURL`：scheme ∈ {http, https}、host 非空、
 * 不允许 userinfo / query / fragment。此前前端是两份实现——主节点地址只校验
 * scheme，访问地址才校验完整规则——同一地址会在注册表单通过、提交时被后端以
 * 同一中文错误拒绝（晚失败）。现两处共用本函数，规则逐条与后端对齐。
 */

export interface ClusterUrlValidationOptions {
  /** 错误文案前缀，如「主节点地址」/「访问地址」。 */
  readonly label: string
  /** 空值错误文案；不传 = 空值合法（对应后端 AccessURL 允许空串）。 */
  readonly emptyMessage?: string
}

/** 返回错误文案；合法返回 null。 */
export const validateClusterUrl = (
  value: string,
  options: ClusterUrlValidationOptions,
): string | null => {
  const normalized = value.trim()
  if (!normalized) return options.emptyMessage ?? null
  let parsed: URL
  try {
    parsed = new URL(normalized)
  } catch {
    // new URL() 仅抛 TypeError；其余异常同样视为地址非法，走统一提示，不向外抛。
    return `${options.label}格式不正确`
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return `${options.label}必须使用 HTTP 或 HTTPS`
  if (!parsed.host) return `${options.label}必须包含主机`
  if (parsed.username || parsed.password) return `${options.label}不能包含用户名或密码`
  if (parsed.search) return `${options.label}不能包含查询参数`
  if (parsed.hash) return `${options.label}不能包含片段`
  return null
}
