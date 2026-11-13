// Spike 辅助：T-2/T-4 共用的「L4 前置 + 透传/终结双路由」Caddy 拓扑装配。
package harness

import (
	"context"
	"fmt"
	"os"
	"time"
)

// L4Lab 描述 T-2/T-4 拓扑参数。
type L4Lab struct {
	StorageDir   string // caddy storage 目录
	CaddyLogPath string // caddy 运行日志
	AccessLog    string // 站点访问日志（json）；为空则不写
	L4Port       int    // layer4 前置端口（生产 443 的替身）
	LocalPort    int    // 本地终结端口（生产 7443）
	UpPort       int    // 透传上游端口（生产 10443 示例）
	PassDomain   string // 透传域名
	LocalDomain  string // 本地终结域名
}

// WriteCaddyfile 渲染 T-2/T-4 拓扑的 Caddyfile。
// 关键：listener_wrappers 顺序必须 proxy_protocol 在前、tls 占位在后——
// caddyhttp/app.go:350-352 会把未显式声明 tls 占位的 wrapper 全部放到 TLS 终结之后。
func (l L4Lab) WriteCaddyfile(path string) error {
	tpl := `{
	admin off
	skip_install_trust
	storage file_system %s
	servers :%d {
		listener_wrappers {
			proxy_protocol {
				allow 127.0.0.1/32
				fallback_policy reject
			}
			tls
		}
	}

	layer4 {
		:%d {
			@passthrough tls sni %s
			route @passthrough {
				proxy 127.0.0.1:%d
			}
			route {
				proxy 127.0.0.1:%d {
					proxy_protocol v2
				}
			}
		}
	}
}

https://%s:%d {
%s	tls internal
	respond "LOCAL-OK" 200
}
`
	access := ""
	if l.AccessLog != "" {
		access = fmt.Sprintf("\tlog {\n\t\toutput file %s\n\t\tformat json\n\t}\n", l.AccessLog)
	}
	body := fmt.Sprintf(tpl, l.StorageDir, l.LocalPort, l.L4Port,
		l.PassDomain, l.UpPort, l.LocalPort, l.LocalDomain, l.LocalPort, access)
	return os.WriteFile(path, []byte(body), 0o644)
}

// StartCaddy 启动 caddy 并等待指定端口就绪；任一端口未就绪即停止进程并附带日志报错。
func StartCaddy(bin, cfgPath, dir, logPath string, ports ...int) (*Proc, error) {
	p, err := Start("caddy", bin, []string{"run", "--config", cfgPath, "--adapter", "caddyfile"}, nil, dir)
	if err != nil {
		return nil, err
	}
	for _, port := range ports {
		if err := WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", port), 30*time.Second); err != nil {
			p.Stop()
			out := p.Output()
			if len(out) > 4000 {
				out = out[len(out)-4000:]
			}
			return nil, fmt.Errorf("caddy port %d not ready: %v\nlogs:\n%s", port, err, out)
		}
	}
	return p, nil
}
