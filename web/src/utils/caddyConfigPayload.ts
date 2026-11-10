// Caddy 全局配置保存载荷单源。
//
// 后端跨字段门（internal/handlers/caddy.go 的 resolveAccessLogFormatGate）：
// access_log_json=false 且同一请求携带非空 access_log_format → 400
// 「访问日志 JSON 输出已关闭，自定义字段映射不生效」；而 json=false + **缺键**
// + 存量非空 → 后端清空存量并在保存响应 message 中说明。
//
// 因此「关闭自定义 JSON」时前端必须把该键从白名单载荷中剔除：表单里格式
// 编辑器的 v-if 已随开关隐藏，用户无法就地清空；若照常携带存量值，保存会被
// 400 拦在预览阶段。剔除后需要把「库中自定义格式将被清空」显性告知用户——
// 判定与告知同源于本函数返回的 accessLogFormatCleared。
type CaddyAccessLogSettings = {
  readonly access_log_json: boolean
  readonly access_log_format: string
}

type CaddyConfigPayload<Settings, Key extends keyof Settings> = {
  readonly payload: Partial<Pick<Settings, Key>>
  /** 关闭自定义 JSON 且存量格式非空：该键已从载荷剔除，库中映射将被清空。 */
  readonly accessLogFormatCleared: boolean
}

export const buildCaddyConfigPayload = <Settings extends CaddyAccessLogSettings, Key extends keyof Settings>(
  settings: Settings,
  keys: readonly Key[],
): CaddyConfigPayload<Settings, Key> => {
  // 与后端门同口径的保守判定：只要有存量内容（含纯空白——后端按「存量非空
  // 即清空」处理）就剔除该键，让后端走「缺键 + 存量非空 → 清空并说明」分支。
  const formatOmitted = !settings.access_log_json && String(settings.access_log_format ?? '') !== ''
  const payload: Partial<Pick<Settings, Key>> = {}
  for (const key of keys) {
    if (formatOmitted && (key as string) === 'access_log_format') continue
    payload[key] = settings[key]
  }
  return { payload, accessLogFormatCleared: formatOmitted }
}
