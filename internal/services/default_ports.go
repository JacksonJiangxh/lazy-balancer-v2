package services

import "sync"

// 代理默认监听口（HTTP_PORT / HTTPS_PORT env）：只决定「默认语义」，不迁移存量规则。
// 详见 docs/fork-notes/ports-and-config.md §1
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
