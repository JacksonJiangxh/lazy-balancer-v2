/** 水合期间保留库值；只有用户主动关闭 DNS 服务器才清空。 */
export const dnsServerAfterToggle = (current: string, enabled: boolean, hydrating: boolean): string => {
  if (hydrating || enabled) return current
  return ''
}
