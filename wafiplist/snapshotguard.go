package wafiplist

import "time"

// 名单快照的「代际守卫」单源。两个快照加载器共用同一组判定：
//   - 策略/威胁名单文件加载器（iplistfast.go，stat 形态 + 失败 fail-stale）；
//   - 爬虫 IP 段快照加载器（caddygeoip/crawler_verify.go，JSON 快照 + 10min/10s
//     双 TTL）。
//
// 两者缓存策略（TTL/单飞/失败语义）按各自消费面不同而**有意**保留差异，但
// 「并发读到的旧内容/失败不得覆盖更新代际」的判定必须同源——此前两处各写一份
// 比较逻辑，任一侧演进（例如加上 CommittedAt 失败守卫）就会出现「一侧修复、
// 另一侧仍可旧内容回流」的静默分叉。
//
// 代际 = 打开 inode 时的 stat 形态（mtime+size）：写侧经 rename 换文件，慢读者
// 可能读到 rename 前的旧 inode 并在新快照落定后才提交；已打开 fd 的 stat 如实
// 标识所读内容（不得读后按路径再 stat）。
type SnapshotGeneration struct {
	// ModTime/Size 标识内容代际。
	ModTime time.Time
	Size    int64
	// CommittedAt 是该快照在缓存中落定的时刻（失败候选读取开始时刻的先后
	// 判定依据）。零值表示未记录。
	CommittedAt time.Time
}

// SameSnapshotGeneration 判定两份快照是否同代际（同内容，可直接复用）。
func SameSnapshotGeneration(a, b SnapshotGeneration) bool {
	return a.ModTime.Equal(b.ModTime) && a.Size == b.Size
}

// StaleSnapshotGeneration 判定 candidate 的内容代际是否比 current 旧：
// current 的 mtime 更晚，或 mtime 相同但 current 更大（rename 换代 + 同秒
// 截断场景下的保守判定）。成立时 candidate 是并发慢读者读到的旧内容，必须
// 丢弃（否则旧名单回流）。
func StaleSnapshotGeneration(candidate, current SnapshotGeneration) bool {
	if current.ModTime.After(candidate.ModTime) {
		return true
	}
	return current.ModTime.Equal(candidate.ModTime) && current.Size > candidate.Size
}

// StaleFailureDowngrade 判定「以 startedAt 开始读取的失败候选」是否会降级
// current：current 是成功快照且在本轮读取开始之后才落定 → 失败不覆盖
// （瞬时读错不得把刚刷新的名单降级成空集/fail-closed 空快照）。
func StaleFailureDowngrade(current SnapshotGeneration, startedAt time.Time) bool {
	return !current.CommittedAt.IsZero() && current.CommittedAt.After(startedAt)
}
