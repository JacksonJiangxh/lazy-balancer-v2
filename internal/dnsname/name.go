// Package dnsname 提供 DNS 名的单一归一实现。
//
// 归一（去首尾空白、小写、去掉一个末尾点）被三个互不成环的包共同消费：
//   - acme.Issuer 的权威应答比较（额外补 FQDN 末尾点）；
//   - dnsprovider 的挑战值在途登记键（challenge_claims）；
//   - dnsprovider/ownership 的清理账本匹配/去重。
//
// 三处各写一份时，同一次挑战以不同书写形态（大小写/尾点）出现会让登记键与
// 账本键不一致：同值并发判定失效、清理归属落空，只能等 StaleOwnershipAge
// 兜底。放在叶子包而非任一消费者内，是因为 dnsprovider → dnspod → ownership
// 的既有依赖方向不允许 ownership 反向导入父包。
package dnsname

import "strings"

// NormalizeName 归一 DNS 名：去首尾空白、小写、去掉一个末尾点（DNS 名大小写
// 不敏感且尾点可省略）。只去一个尾点——连续尾点（畸形输入）不是合法 FQDN，
// 保留一个可让上层按自身口径拒绝，而不是在这里静默吞掉。
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}
