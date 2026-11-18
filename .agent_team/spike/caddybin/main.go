// Spike 专用 Caddy 二进制入口：等价于生产 Dockerfile 的 xcaddy build 最小形态。
// 仅用于 S0 技术验证，不进生产代码路径。
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// 标准模块（与生产镜像一致的底座）
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// 生产镜像已启用的 layer4 插件
	_ "github.com/mholt/caddy-l4"

	// JJC-20261118-002 S4：生产镜像经 xcaddy --with 编入的自研 chain 模块
	//（chain_proxy handler：race/wrr 两模式，混布池逐上游独立 transport）。
	_ "lazy-balancer-v2/caddychain"

	caddy "github.com/caddyserver/caddy/v2"
)

func main() {
	caddy.TrapSignals()
	caddycmd.Main()
}
