/**
 * PATCH /users/me 的唯一业务 401：当前密码校验失败。
 * 同一路径的其它 401 仍是会话失效，必须继续走全局重新登录流程。
 */
export const isCurrentPasswordRejection = (
  method: string | undefined,
  url: string | undefined,
  status: number | undefined,
  message: string,
): boolean => status === 401
  && message === '当前密码错误'
  && (method ?? '').toLowerCase() === 'patch'
  && /\/users\/me(\?|$)/.test(url ?? '')
