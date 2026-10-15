package caddygeoip

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"time"
)

// securityTimingHeader 是耗时关联头——blocked_counter 注入、coraza 审计日志
// request.headers 收录、审计写插件（auditwriter.go）从审计事务头提取后作
// 进程内计时注册表（auditTiming*）的关联键。该头在本进程内即完成全部关联
// （注册表+审计注入同进程），不再跨进程——耗时侧车文件已于
// 历史退役，耗时随审计行 lb_timing 字段内嵌流转。渲染链在该头抵达
// reverse_proxy 前删除（caddy.go 渲染层），不上泄上游。
const securityTimingHeader = "X-Lb-Security-Timing-Id"

// securityTimingStartHeader 是起始纳秒时间戳头——blocked_counter 注入(注入原值
// 兼作「链未过预检收点」判定基准:拦截检出时头仍=原值即预检段拦);SecurityTimingPre
// 记 :pre 后把它重写为预检完成锚点,SecurityTimingEnd 读锚点计算 logged 事件的
// WAF 段耗时(拦截事件的耗时由 blocked_counter 写,不经此头)。与 timing ID 头
// 同清单剥离。
const securityTimingStartHeader = "X-Lb-Security-Timing-Start-Ns"

// 计时分段键（注册表 segment 参数；审计行内 pre_us/end_us 字段）。
const (
	timingSegmentPre = "pre"
	timingSegmentEnd = "end"
)

// recordSecurityTiming 读耗时关联头对（timing ID + 起始纳秒）并把一段耗时写入
// 进程内计时注册表——PLUG-R1（历史 历史问题）：SecurityTimingPre/End 两 ServeHTTP
// 原逐字重复，收敛为 本 helper，segment 区分收点。分段键语义（历史）：
// pre=预检段（放行由 timing_pre 记；预检拦由 blocked_counter 代记，决策口径）；
// end 二态——拦截事件=链首→中断全链（blocked_counter），logged 事件=预检完成后
// →链末（timing_end 读重写后的分段锚点）。头对缺失或起始时间戳不可解析时静默
// 跳过（耗时是增强信息，不产生请求路径错误）。
//
// 历史：写入目标从侧车文件 旧侧车逐行追加（有界 channel 非阻塞丢行）
// 改为进程内注册表（auditTimingRecord）——写入恒成功，由审计写插件的 drain
// goroutine 注入审计行后落盘（零丢弃）。
func recordSecurityTiming(r *http.Request, segment string) {
	timingID := r.Header.Get(securityTimingHeader)
	startNsStr := r.Header.Get(securityTimingStartHeader)
	if timingID != "" && startNsStr != "" {
		if startNs, perr := strconv.ParseInt(startNsStr, 10, 64); perr == nil {
			auditTimingRecord(timingID, segment, (time.Now().UnixNano()-startNs)/1000) // ns→µs
		}
	}
}

// securityTimingID 生成 16 字符随机 hex 作 timing 关联 ID(历史 历史问题:
// 原 4 字节生日界下 1 万在途即 ~1.2% 任意对碰撞概率——扩到 8 字节对齐
// coraza tx.ID 长度,碰撞面消除;rand 失败返回空串=该请求不计耗时,静默降级)。
func securityTimingID() string {
	b := make([]byte, 8)
	if _, err := cryptorand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
