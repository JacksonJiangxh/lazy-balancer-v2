package services

// 保留地址（内网/回环/文档示例等）判定的单源：安全事件的大屏聚合、feed、
// 活跃源与攻击光流环必须在**同一判据**上排除这些来源，否则会出现「同一屏
// 四面口径不一致」——尤其是攻击光流：若在入口不排除、只在出口丢弃，内网
// 扫描会挤占 4096 条环形缓冲与单轮 limit 配额，真实外网攻击弧被挤出窗口
// （且这种挤占在客户端表现为「攻击变少」，不是报错）。

import "net/netip"

// reservedIPPrefixes 保留/特殊用途网段（不覆盖 IsLoopback/IsPrivate 等
// netip 内建判定，二者叠加使用）。
var reservedIPPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // 本网络/未指定
	netip.MustParsePrefix("100.64.0.0/10"),   // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF 协议分配
	netip.MustParsePrefix("192.0.2.0/24"),    // RFC 5737 文档示例（TEST-NET-1，公网不可路由）
	netip.MustParsePrefix("198.51.100.0/24"), // RFC 5737 文档示例（TEST-NET-2）
	netip.MustParsePrefix("203.0.113.0/24"),  // RFC 5737 文档示例（TEST-NET-3）
	netip.MustParsePrefix("198.18.0.0/15"),   // 基准测试
	netip.MustParsePrefix("240.0.0.0/4"),     // 保留/广播
	netip.MustParsePrefix("2001:db8::/32"),   // 文档示例
}

// IsReservedClientIP 判定保留/私网/回环/链路本地/未指定/组播及特殊用途地址。
// 解析失败按「非保留」处理（与历史判定一致：无法解析的地址不会被打上
// 内网扫描的语义，交由其它层处理）。
func IsReservedClientIP(ip string) bool {
	parsed, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	parsed = parsed.Unmap()
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() || parsed.IsUnspecified() || parsed.IsMulticast() {
		return true
	}
	for _, prefix := range reservedIPPrefixes {
		if prefix.Contains(parsed) {
			return true
		}
	}
	return false
}
