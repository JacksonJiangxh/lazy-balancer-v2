// 更新者/创建者显示名单源：Rules/SecurityRules/
// SecurityBlockPages/SecurityPolicies 原各持一份同构 getUpdaterName——
// display_name 优先、空串回落 username、缺省/零/未命中一律 '-'。
interface UpdaterUserLike {
  id: number
  display_name?: string | null
  username?: string
}

export const updaterName = (users: readonly UpdaterUserLike[], userId?: number): string => {
  if (!userId || userId === 0) return '-'
  const user = users.find((u) => u.id === userId)
  return user?.display_name || user?.username || '-'
}
