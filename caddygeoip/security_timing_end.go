package caddygeoip

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(SecurityTimingEnd{})
}

// SecurityTimingEnd 是安全链末尾的耗时收点(2026-09-27 双点计时;历史起
// :end 呈二态——logged 事件读本收点,拦截事件由 blocked_counter 写):
// logged 事件(检测记录/放行)在链尾读「起始纳秒头」计算耗时——该头已被
// SecurityTimingPre 重写为预检完成锚点,故此处 :end=预检后→链末=WAF 段值
// (读侧直接取用,不再减 :pre);拦截事件链未达本收点,:end 由 blocked_counter
// 在中断检出点写(链首→中断全链,读侧 - :pre 得 WAF 段)。两态都只含安全
// 评估,不含 reverse_proxy 上游往返。
//
// 覆盖:放行+检测记录(logged)事件在 coraza ProcessLogging 之前已完成
// 全部策略评估,此处读值即纯安全链耗时;信任直通(passthrough)时安全链
// 整体跳过,本处理器在 subroute 内不执行,无计时(无事件,无关联缺口)。
//
// 稳定设计:零 Provision/零失败模式;读请求头+写侧车文件,任何失败静默
// 降级(该事件耗时报「—」);next 原样透传,链语义与无插件时一致。
type SecurityTimingEnd struct{}

// CaddyModule returns the caddy module information.
func (SecurityTimingEnd) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.lb_security_timing_end",
		New: func() caddy.Module { return &SecurityTimingEnd{} },
	}
}

// ServeHTTP 计算 logged 事件耗时（键 <timing_id>:end，自预检完成锚点起算=
// WAF 段值）写入侧车文件，原样透传下游（reverse_proxy）。计时读头逻辑收敛于
// recordSecurityTiming（PLUG-R1，security_timing.go）。
func (h *SecurityTimingEnd) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	recordSecurityTiming(r, ":end")
	return next.ServeHTTP(w, r)
}

// Provision/Cleanup 启停耗时侧车写管线（PLUG-N1 历史，引用计数——
// blocked_counter/timing_pre/timing_end 三写点共享一份，重载期不断）。
func (h *SecurityTimingEnd) Provision(ctx caddy.Context) error {
	securityTimingWriterAcquire()
	return nil
}

// Cleanup 释放本 handler 的写管线引用。
func (h *SecurityTimingEnd) Cleanup() error {
	securityTimingWriterRelease()
	return nil
}

// Interface guards(编译期契约,零运行时成本)。
var (
	_ caddy.Provisioner           = (*SecurityTimingEnd)(nil)
	_ caddy.CleanerUpper          = (*SecurityTimingEnd)(nil)
	_ caddyhttp.MiddlewareHandler = (*SecurityTimingEnd)(nil)
)
