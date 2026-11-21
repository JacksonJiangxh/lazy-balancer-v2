package services

import "sync"

// 面板监听口（PANEL_PORT env，boot 时由 config 注入）：逐上游健康检查聚合探针
// 渲染（JJC-20261121-001）需要把 Caddy 的 health_upstream 指向面板回环地址，
// 渲染层与 config 无依赖（与 SetDefaultProxyPorts 同款注入模式）。
var (
	panelPortMu sync.RWMutex
	panelPort   = 8000
)

// SetPanelPort 注入面板监听口（boot 时由 config 调用）。非法值（<=0 或 >65535）
// 忽略，保出厂默认——渲染出 :0 的 health_upstream 比 keeps 默认口危险得多。
func SetPanelPort(port int) {
	panelPortMu.Lock()
	defer panelPortMu.Unlock()
	if port >= 1 && port <= 65535 {
		panelPort = port
	}
}

// PanelPort 返回面板监听口（出厂 8000）。仅渲染 health_upstream 聚合探针消费。
func PanelPort() int {
	panelPortMu.RLock()
	defer panelPortMu.RUnlock()
	return panelPort
}
