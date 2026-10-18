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
