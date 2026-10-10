package services

import "sync"

// 代理默认监听口（HTTP_PORT / HTTPS_PORT env，见 internal/config）。
//
// 语义边界（2026-10-10 用户裁定，ISSUE #7）：这两个值只决定「默认语义」——
//   - 渲染兜底站的监听口（原硬编码 :80）
//   - HTTP→HTTPS 跳转 Location 的自引用端口判定（原硬编码 443）
//   - 规则侧 80/443 保留端口判定与跳转遮蔽比对（handlers 侧读同一来源）
//
// 不决定存量规则：lb_rules.listen_port 是持久化数据，渲染时原样使用。
// 想要「全项目换口」的用户需在面板逐条改规则后保存——保存即落新端口。
//
// 与 SetDefaultLandingBody 同模式：boot 时注入一次，渲染期只读；测试不注入
// 时取出厂默认 80/443（等价旧硬编码行为）。
var (
	defaultPortsMu   sync.RWMutex
	defaultHTTPPort  = 80
	defaultHTTPSPort = 443
)

// SetDefaultProxyPorts 注入部署侧 HTTP/HTTPS 默认监听口（boot 时由 config 调用）。
// 非法值（<=0 或 >65535）忽略，保出厂默认——渲染出 :0 监听比默认口危险得多。
func SetDefaultProxyPorts(httpPort, httpsPort int) {
	defaultPortsMu.Lock()
	defer defaultPortsMu.Unlock()
	if httpPort >= 1 && httpPort <= 65535 {
		defaultHTTPPort = httpPort
	}
	if httpsPort >= 1 && httpsPort <= 65535 {
		defaultHTTPSPort = httpsPort
	}
}

// DefaultHTTPPort 返回部署侧 HTTP 默认监听口（出厂 80）。
func DefaultHTTPPort() int {
	defaultPortsMu.RLock()
	defer defaultPortsMu.RUnlock()
	return defaultHTTPPort
}

// DefaultHTTPSPort 返回部署侧 HTTPS 默认监听口（出厂 443）。
func DefaultHTTPSPort() int {
	defaultPortsMu.RLock()
	defer defaultPortsMu.RUnlock()
	return defaultHTTPSPort
}
