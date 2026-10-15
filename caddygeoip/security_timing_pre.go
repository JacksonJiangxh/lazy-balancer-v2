package caddygeoip

import (
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(SecurityTimingPre{})
}

// SecurityTimingPre 是预检段耗时收点(2026-09-27 分段计时):
// 置于 IP 预检 handler 之后、请求体限额/限流/WAF 之前——记录「链首→预检完成」
// 的耗时,写进程内计时注册表分段键 pre（第 76 轮起经审计写插件注入审计行
// lb_timing.pre_us, 侧车已退役）。摄取管道按规则归属选值:
// 预检段规则(IP ACL/GeoIP/信任/威胁,id 1-14 与 800xxx)取 pre;WAF 段规则
// (CRS 9xxxxx/自定义)取 end-pre(隔离 WAF 评估成本,不含预检开销)。
//
// 拦截语义（第 75 轮修正）：预检拦了（id:2 deny 等）链在本 handler 之前中断，
// 本收点不执行——blocked_counter 检出中断时起始头仍=注入原值，据此代写
// pre（=预检决策耗时，此刻 403 尚未写出）；end 兜底仅剩头对缺失/不可解析
// 的降级形态（读侧查 pre 优先、miss 回退 end 的契约不变）。
type SecurityTimingPre struct{}

// CaddyModule returns the caddy module information.
func (SecurityTimingPre) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_security_timing_pre",
		New: func() caddy.Module { return &SecurityTimingPre{} },
	}
}

// ServeHTTP 记录预检段耗时（注册表分段键 pre）并交接分段锚点，原样透传下游。
// 计时读头逻辑收敛于 recordSecurityTiming（PLUG-R1，security_timing.go）。
//
// 分段锚点交接（第 75 轮，预检拦耗时口径）：记录 pre 后把起始纳秒头重写为
// 当前时刻——下游 SecurityTimingEnd 的 end 自此从预检完成后起算（=WAF 段值，
// 读侧 logged 事件直接取用）；blocked_counter 以「起始头是否仍等于注入原值」
// 判定拦截出处（原值=链未抵达本收点=预检段拦 → 写 pre 决策耗时；已重写=
// WAF/限流段拦 → 写 end 全链）。ID 头不动（审计写插件的注册表关联键）。
func (h *SecurityTimingPre) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	recordSecurityTiming(r, timingSegmentPre)
	if r.Header.Get(securityTimingHeader) != "" {
		// 锚点必须严格大于注入原值——时钟分辨率下连续两次 Now() 可能同值，
		// 同值会被 blocked_counter 的「仍=注入原值」判定误归类为预检段拦。
		anchor := time.Now().UnixNano()
		if old, perr := strconv.ParseInt(r.Header.Get(securityTimingStartHeader), 10, 64); perr == nil && anchor <= old {
			anchor = old + 1
		}
		r.Header.Set(securityTimingStartHeader, strconv.FormatInt(anchor, 10))
	}
	return next.ServeHTTP(w, r)
}

// Interface guards(编译期契约,零运行时成本)。计时写入目标是进程内注册表
// （auditTimingRecord，auditwriter.go）——无 fd、无后台管线生命周期，本
// handler 不再持有 Provision/Cleanup（第 76 轮侧车退役）。
var (
	_ caddyhttp.MiddlewareHandler = (*SecurityTimingPre)(nil)
)
