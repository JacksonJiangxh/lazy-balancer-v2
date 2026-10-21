// Package netutil 收纳跨包共享的网络语义小工具（无业务依赖，避免
// mcpserver → services 的反向引用）。
package netutil

import "net/http"

// IsTLSUpgradeRedirect 判定状态码是否属于「面板启用管理 HTTPS 后明文端口整体
// 重定向到 https」的升级信号集合：301/302/307/308。嗅探层（cmd/server 的
// http_redirect_mux）按此形态回写，MCP 回环转发与集群同步客户端的重放判定
// 必须同语义（历史修复：两处曾各自写字面量，一侧新增状态码即静默分叉）。
func IsTLSUpgradeRedirect(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}
