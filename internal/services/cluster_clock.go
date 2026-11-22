package services

// 主从时钟偏移测量与票据校验校正（JJC-20261122-001）。
//
// 背景：集群登录票据与服务控制票据由主节点以其本机时钟签发 ExpiresAt（Unix
// 秒），从节点按自身时钟判过期（ExpiresAt <= 本机 Unix 秒）。两侧宿主机内核
// 时钟偏差超过签发侧预留的 90s 容差时，票据刚签出即被判「已过期」——且该
// 失效是全从节点同时、每次必现的（离群时钟源那一侧决定全体失败面），仅靠
// TTL 无法根治。
//
// 机制：主节点在集群快照响应（200/304 均）携带 X-Cluster-Server-Time 头
// （主节点 Unix 秒）；从节点每轮 Pull 成功后测量偏移 offset = 主节点时间 -
// 本机时间 并记录。票据校验侧用 masterAdjustedNow 把本机时刻校正到主节点
// 时钟基准后再比对 ExpiresAt——无论哪一侧时钟漂移，校验都与签发同基准。
//
// 安全边界：
//   - 偏移仅来自持有集群令牌认证 + TOFU 钉扎 TLS 的快照端点响应；
//   - 校正量钳制 ±24h（防异常值放大票据窗口）；
//   - 测量新鲜度 10 分钟（超时回退零偏移——主节点长期不可达时保守按本机时钟）；
//   - 偏移只影响「票据过期判定时刻」，不参与签名/绑定校验，无法据此伪造票据。

import (
	"sync/atomic"
	"time"
)

const (
	// masterClockOffsetClamp 单次测量偏移的绝对值上限：正常时钟偏差不可能
	// 达到该量级，超限视为异常测量（恶意/故障），按零偏移处理。
	masterClockOffsetClamp = 24 * time.Hour
	// masterClockOffsetFreshFor 测量新鲜度：超过该时长未测得新偏移（主节点
	// 同步持续失败等）回退零偏移，按本机时钟校验。
	masterClockOffsetFreshFor = 10 * time.Minute
	// masterClockOffsetWarnAt 偏移告警阈值：超过该偏差在同步日志落一条 WARN。
	masterClockOffsetWarnAt = 30 * time.Second
)

var (
	// masterClockOffsetNanos 最近一次测得的偏移（主节点时钟 - 本机时钟）。
	masterClockOffsetNanos atomic.Int64
	// masterClockOffsetAtUnix 最近测量发生时的本机 Unix 秒（新鲜度判定）。
	masterClockOffsetAtUnix atomic.Int64
	// masterClockOffsetLastWarnSec 上次告警的偏移秒数（告警去重：同一偏差
	// 不逐轮重复；偏差变化超过阈值粒度才再告警）。
	masterClockOffsetLastWarnSec atomic.Int64
)

// RecordMasterClockOffset 记录一次主从时钟偏移测量。serverUnix 为主节点
// X-Cluster-Server-Time 值（<=0 视为无校验头，忽略）；localNow 为测量时刻的
// 本机时间（注入以便测试）。
func RecordMasterClockOffset(serverUnix int64, localNow time.Time) {
	if serverUnix <= 0 {
		return
	}
	offset := time.Duration(serverUnix-localNow.Unix()) * time.Second
	if offset < -masterClockOffsetClamp || offset > masterClockOffsetClamp {
		Logf("warn", "主从时钟偏移测量异常（%v 超出 ±%v 钳制），本轮忽略", offset, masterClockOffsetClamp)
		return
	}
	masterClockOffsetNanos.Store(int64(offset))
	masterClockOffsetAtUnix.Store(localNow.Unix())
	// 告警去重：按整秒粒度，偏差变化才重复落日志。
	offsetSec := int64(offset / time.Second)
	last := masterClockOffsetLastWarnSec.Load()
	if absDuration(offset) >= masterClockOffsetWarnAt && last != offsetSec {
		if masterClockOffsetLastWarnSec.CompareAndSwap(last, offsetSec) {
			Logf("warn", "主从时钟偏差 %v（主节点时钟 %s / 本机 %s）——超过票据容差会导致服务控制与登录跳转全节点失败，请校准各节点 NTP",
				offset, time.Unix(serverUnix, 0).UTC().Format("2006-01-02 15:04:05"), localNow.Format("2006-01-02 15:04:05"))
		}
	}
}

// MasterClockOffsetSeconds 返回当前生效偏移的整秒值（仅供状态展示/测试）。
func MasterClockOffsetSeconds() int64 {
	return int64(time.Duration(masterClockOffsetNanos.Load()) / time.Second)
}

// masterAdjustedNow 把本机时刻校正到主节点时钟基准：存在新鲜偏移测量时
// now += offset，否则原样返回。票据签发在主节点侧（其自身时钟）、消费在
// 从节点侧，校验侧用本函数对齐签发基准。
func masterAdjustedNow(local time.Time) time.Time {
	at := masterClockOffsetAtUnix.Load()
	if at == 0 || local.Sub(time.Unix(at, 0)) > masterClockOffsetFreshFor || local.Before(time.Unix(at, 0)) {
		return local
	}
	return local.Add(time.Duration(masterClockOffsetNanos.Load()))
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
