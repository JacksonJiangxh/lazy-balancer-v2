package dnsprovider

import (
	"strings"
	"sync"
	"time"
)

// 同域名并发签发的互斥：RFC 8555 允许 CA 复用同账号同标识的 pending 授权，
// 两条订单因此可能拿到同一 token → 同一 keyAuth（Let's Encrypt reuseValidAuthz
// 长期开启）。此时按值清理（CleanUpValue）只能看到「同名同值」，无法从记录本身
// 区分两条在途签发——先结束的一方的预清理/deferred 清理会把另一条仍在等待验证
// 的 TXT 删掉，表现为「DNS 传播超时」并白烧 CA 配额。
//
// 单写者进程内的在途挑战值登记表是这里的权威判据：签发链（acme.Issuer）在
// Present 前登记、deferred 清理后注销；「有他人在途同名同值」时跳过按值清理，
// 由最后结束的一方统一回收（两笔记录同值，删一次即全清）。签发只在主节点
// （checkCertificateIssuanceRole）且每进程单队列管理，故进程内登记即可覆盖真实
// 并发面；跨进程并存属部署错误，账本/预清理的既有保守口径不变。

// challengeClaimTTL 是登记的兜底有效期：正常路径由签发链的 deferred 清理注销，
// TTL 只防御调用方异常退出（panic 捕获外的进程内泄漏）后残留的登记永久压制
// 同值清理。取值覆盖 CA 队列单任务执行上限（60min）并留余量。
const challengeClaimTTL = 90 * time.Minute

// challengeClaim 是一次在途挑战值的登记句柄。句柄身份（指针）是注销的唯一
// 凭据——重复调用 Release 不得二次扣减其他在途签发的计数。
type ChallengeClaim struct {
	key challengeClaimKey

	mu       sync.Mutex
	released bool
}

type challengeClaimKey struct {
	zone, fqdn, value string
}

type challengeClaimRecord struct {
	claimedAt time.Time
}

var challengeClaims = struct {
	mu     sync.Mutex
	owners map[challengeClaimKey]map[*ChallengeClaim]challengeClaimRecord
}{owners: map[challengeClaimKey]map[*ChallengeClaim]challengeClaimRecord{}}

// challengeClaimKeyOf 归一 zone/challenge 名（DNS 名大小写不敏感、尾点可省略），
// 让预清理与 deferred 清理即使传入不同书写形态也命中同一条登记。
func challengeClaimKeyOf(zone, tokenFQDN, value string) challengeClaimKey {
	normalize := func(s string) string {
		return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	}
	return challengeClaimKey{zone: normalize(zone), fqdn: normalize(tokenFQDN), value: value}
}

// ClaimChallengeValue 登记一次在途 DNS-01 挑战值（Present 之前调用）。返回的
// 句柄必须在清理完成后 Release；返回的 first 报告登记时没有其他在途同值挑战
// ——false 表示另一条签发仍持有同名同值记录，调用方 MUST NOT 执行按值预清理
// （会删掉对方仍在等待验证的 TXT）。
func ClaimChallengeValue(zone, tokenFQDN, value string) (claim *ChallengeClaim, first bool) {
	key := challengeClaimKeyOf(zone, tokenFQDN, value)
	claim = &ChallengeClaim{key: key}
	now := time.Now()
	challengeClaims.mu.Lock()
	defer challengeClaims.mu.Unlock()
	owners := challengeClaims.owners[key]
	cleaned := make(map[*ChallengeClaim]challengeClaimRecord, len(owners)+1)
	for owner, record := range owners {
		if now.Sub(record.claimedAt) > challengeClaimTTL {
			// 兜底：异常未注销的登记不得永久压制清理。
			continue
		}
		cleaned[owner] = record
	}
	first = len(cleaned) == 0
	cleaned[claim] = challengeClaimRecord{claimedAt: now}
	challengeClaims.owners[key] = cleaned
	return claim, first
}

// Release 注销本次登记，返回是否已无其他在途同值挑战（true=调用方可以执行
// 按值清理）。重复调用返回 false（首次调用已完成注销，第二次没有新的判定权）。
func (c *ChallengeClaim) Release() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released {
		return false
	}
	c.released = true
	challengeClaims.mu.Lock()
	defer challengeClaims.mu.Unlock()
	owners := challengeClaims.owners[c.key]
	delete(owners, c)
	if len(owners) == 0 {
		delete(challengeClaims.owners, c.key)
	}
	return len(owners) == 0
}

// ResetChallengeClaimsForTest 清空在途登记表。仅供测试隔离（生产代码不得调用）。
func ResetChallengeClaimsForTest() {
	challengeClaims.mu.Lock()
	challengeClaims.owners = map[challengeClaimKey]map[*ChallengeClaim]challengeClaimRecord{}
	challengeClaims.mu.Unlock()
}
