/**
 * 管理面板 HTTPS「配置证书」弹框的确认门（零 Vue 依赖，node --test 可直接求值）。
 *
 * 后端 PUT /admin-tls 默认继承库内证书材料，仅在 `mode=upload` 且本次携带
 * cert_file/key_file 时才替换（internal/handlers/admintls.go），即「已保存的
 * 上传证书」本可被直接沿用。前端曾把「弹框里有 certInfo」当作唯一放行条件，
 * 而 staged 证书在保存成功后即清空——于是「关闭强制加密 → 再开启」时「确定」
 * 恒灰，用户只能重传文件或改用自签（后者会按后端语义清空上传证书材料）。
 */

export interface AdminTlsStoredCertState {
  /** GET /admin-tls 的 mode：库内已保存形态（不受弹框内未提交切换影响） */
  readonly savedMode: string
  /** 库内证书可解析（cert_info 非空）或 selfsigned（由渲染层自愈） */
  readonly hasSavedCert: boolean
  /** 库内证书解析失败原因（后端 cert_info_error）；非空=必须重传 */
  readonly certError: string
}

export interface AdminTlsDialogCertState {
  readonly mode: string
  readonly certFile: unknown
  readonly keyFile: unknown
  readonly certInfo: { readonly days_left: number } | null
}

/**
 * 是否沿用库内已保存的上传证书：库内证书可解析且未损坏，且用户本次未选择
 * 新文件（选了文件但解析失败时不得静默回退到旧证书——那会与用户意图相反）。
 */
export const adminTlsReusesSavedCert = (
  stored: AdminTlsStoredCertState,
  form: AdminTlsDialogCertState,
): boolean =>
  stored.savedMode === 'upload' &&
  stored.hasSavedCert &&
  stored.certError === '' &&
  form.mode === 'upload' &&
  form.certFile == null &&
  form.keyFile == null

/**
 * 「确定」禁用判据：上传模式须「新证书已校验且未过期」或「沿用库内证书」。
 * 自签模式无需材料。
 */
export const adminTlsConfirmDisabled = (
  stored: AdminTlsStoredCertState,
  form: AdminTlsDialogCertState,
): boolean => {
  if (form.mode !== 'upload') return false
  if (adminTlsReusesSavedCert(stored, form)) return false
  return form.certInfo == null || form.certInfo.days_left <= 0
}
