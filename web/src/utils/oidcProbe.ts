export interface OidcProbeValues {
  issuer: string
  clientId: string
  clientSecret: string
}

export interface OidcProbeToken {
  key: string
  generation: number
}

export const oidcProbeKey = (values: OidcProbeValues): string => JSON.stringify([
  values.issuer.trim(),
  values.clientId.trim(),
  values.clientSecret,
])

/**
 * 已成功且快照键与当前表单值一致 → 探测结果可复用。
 * （issuer 失焦曾无条件重发 discovery+JWKS 外部请求；输入变化已由
 * watcher 推进世代并清空 ok，因此「ok && key 相同」等价于结果仍对应当前值。）
 */
export const isOidcProbeFresh = (
  probe: { readonly ok: boolean; readonly key?: string },
  values: OidcProbeValues,
): boolean => probe.ok && probe.key === oidcProbeKey(values)

/** 每次输入失效/关闭/load 都推进世代；旧响应即使恢复成同值也不得落地。 */
export const createOidcProbeGuard = () => {
  let generation = 0
  return {
    token(values: OidcProbeValues): OidcProbeToken {
      return { key: oidcProbeKey(values), generation }
    },
    invalidate(): void {
      generation++
    },
    isCurrent(token: OidcProbeToken, values: OidcProbeValues): boolean {
      return token.generation === generation && token.key === oidcProbeKey(values)
    },
  }
}
