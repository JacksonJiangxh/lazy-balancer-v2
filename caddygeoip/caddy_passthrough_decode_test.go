package caddygeoip

// ── TLS 透传渲染产物解码链（JJC-20261112-01 S4-b）────────────────────────────
//
// 本文件回答的问题：S1-b 渲染链吐出的**透传产物**（Layer4 SNI 分流 + 内部端口
// 迁移 + listener_wrappers），Caddy 的解码机制到底认不认？
//
// 与 caddy_decode_generated_config_test.go 的分工：那份解码的是 http app 的
// routes（caddyhttp.Route.UnmarshalJSON → Provision 一条路）；layer4 是独立
// app，解码路径不同——layer4.Route 的 match 是 ModuleMap（对象按 matcher 短名
// 分派到 layer4.matchers.*），handle 按 "handler" 键分派到 layer4.handlers.*。
//
// 为什么分层解码而不是 caddy.Load：caddy.Load 需要完整 config 且会启动全部
// apps（layer4 app 会真监听 :443），测试沙箱不可行。改用分层：
//   - layer4 侧：apps.layer4.servers["tls_443"].routes 逐条取 matchers/handlers，
//     按 module ID 用 caddy.Context.LoadModuleByID 分派（与 caddy load 同一条
//     模块表查找路）；
//   - http 侧：listener_wrappers 用 caddy 官方装载机制——镜像 caddyhttp.Server
//     的结构标签（caddy:"namespace=caddy.listeners inline_key=wrapper"）+
//     ctx.LoadModule，与 caddyhttp app.go 装载 ListenerWrappersRaw 逐字同路。
//
// 模块注册面（本进程实测，逐条见测试内 t.Logf）：
//   - caddy.listeners.tls：caddyhttp 包 init 注册（caddygeoip 非测试代码已依赖
//     caddyhttp，测试进程必然注册）→ tls 占位 wrapper **真实解码**。
//   - caddy.listeners.proxy_protocol：同为 caddy v2.11.9 内建（生产镜像 xcaddy
//     build v2.11.9 未引入外部 proxyprotocol 插件，用的就是这份内建实现），但
//     注册它的 caddyhttp/proxyprotocol 包在本模块依赖树未被任何包 import——
//     import 它会把 github.com/pires/go-proxyproto 牵进构建（go.mod/go.sum 增
//     条目，不在本任务白名单）→ LoadModuleByID 报 unknown module →
//     **降级为结构断言**（任务令 ④ 的最低 bar 即结构断言；升级路径：依赖树
//     引入该包后本测试自动恢复真实解码）。
//   - layer4.matchers.tls / layer4.handlers.proxy：来自 mholt/caddy-l4（生产
//     镜像经 xcaddy --with 编入，见 Dockerfile），本模块依赖树没有该模块 →
//     LoadModuleByID 报 unknown module → **降级为结构断言**（任务令预案，原因
//     在测试输出标注）。断言的 "handler"/matcher/wrapper 键正是真实解码的
//     分派键，改名即红（判别力自证见台账 S4-b 记录）。

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// ptRenderedFixtureJSON：生产渲染链产物快照（自包含内嵌，测试不依赖外部文件）。
//
// 生成方法（internal/services 渲染链，种子与
// TestPassthroughRender_layer4SNISplitAndInternalPortMigration 同族）：
// 库内种两条**启用**透传规则落 HTTPS 默认口（443）——
//
//	lb_pt_dec_a：pass.example.test   → 10.0.0.9:10443
//	lb_pt_dec_w：*.wild.example.test → 10.0.0.10:10443
//
// 无 HTTP 规则（无证书路径，产物确定性最好），generateCaddyConfigFromStore 渲染
// 后 json.Marshal 落盘。重生成手法：在 internal/services 建临时测试文件调
// newClusterTestService + seedPassthroughRuleForRender + mustRenderOK（均为该
// 包既有测试辅助），产物经本常量内嵌后删除临时文件。
//
// 与渲染原物的唯一差异：JSON 对象键经 sort_keys 排序（便于评审；对象键序对
// JSON 语义无影响，routes/listen/sni/upstreams/wrappers 等**数组**顺序原样
// 保留——数组序是语义的一部分）。透传规则不含证书字段，无 certDir 归一化。
const ptRenderedFixtureJSON = `{
  "admin": {
    "listen": "127.0.0.1:2019"
  },
  "apps": {
    "http": {
      "metrics": {
        "observe_catchall_hosts": true,
        "per_host": true
      },
      "servers": {
        "http_443": {
          "automatic_https": {
            "disable": true
          },
          "idle_timeout": "120s",
          "listen": [
            "tcp/127.0.0.1:7443",
            "udp/:443"
          ],
          "listener_wrappers": [
            {
              "allow": [
                "127.0.0.1/32"
              ],
              "fallback_policy": "reject",
              "wrapper": "proxy_protocol"
            },
            {
              "wrapper": "tls"
            }
          ],
          "read_timeout": "60s",
          "routes": null,
          "write_timeout": "60s"
        },
        "http_80": {
          "automatic_https": {
            "disable": true
          },
          "idle_timeout": "120s",
          "listen": [
            ":80"
          ],
          "read_timeout": "60s",
          "routes": [
            {
              "handle": [
                {
                  "body": "Lazy Balancer V2 is running!",
                  "handler": "static_response"
                }
              ]
            }
          ],
          "write_timeout": "60s"
        }
      }
    },
    "layer4": {
      "servers": {
        "tls_443": {
          "listen": [
            ":443"
          ],
          "routes": [
            {
              "@id": "lb_pt_dec_a",
              "handle": [
                {
                  "handler": "proxy",
                  "health_checks": {
                    "passive": {
                      "fail_duration": "30s",
                      "max_fails": 3
                    }
                  },
                  "upstreams": [
                    {
                      "dial": [
                        "10.0.0.9:10443"
                      ]
                    }
                  ]
                }
              ],
              "match": [
                {
                  "tls": {
                    "sni": [
                      "pass.example.test"
                    ]
                  }
                }
              ]
            },
            {
              "@id": "lb_pt_dec_w",
              "handle": [
                {
                  "handler": "proxy",
                  "health_checks": {
                    "passive": {
                      "fail_duration": "30s",
                      "max_fails": 3
                    }
                  },
                  "upstreams": [
                    {
                      "dial": [
                        "10.0.0.10:10443"
                      ]
                    }
                  ]
                }
              ],
              "match": [
                {
                  "tls": {
                    "sni": [
                      "*.wild.example.test"
                    ]
                  }
                }
              ]
            },
            {
              "handle": [
                {
                  "handler": "proxy",
                  "proxy_protocol": "v2",
                  "upstreams": [
                    {
                      "dial": [
                        "127.0.0.1:7443"
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      }
    }
  },
  "logging": {
    "logs": {
      "caddy_proxy": {
        "encoder": {
          "format": "console"
        },
        "include": [
          "http.handlers.reverse_proxy"
        ],
        "level": "INFO",
        "writer": {
          "filename": "/app/logs/caddy-proxy.log",
          "output": "file",
          "roll_keep": 5,
          "roll_size_mb": 100
        }
      },
      "caddy_server": {
        "encoder": {
          "format": "console"
        },
        "exclude": [
          "admin",
          "tls",
          "events",
          "http.log.access",
          "http.handlers.reverse_proxy",
          "http.handlers.waf"
        ],
        "level": "INFO",
        "writer": {
          "filename": "/app/logs/caddy-server.log",
          "output": "file",
          "roll_keep": 5,
          "roll_size_mb": 100
        }
      },
      "caddy_tls": {
        "encoder": {
          "format": "console"
        },
        "include": [
          "tls"
        ],
        "level": "INFO",
        "writer": {
          "filename": "/app/logs/caddy-tls.log",
          "output": "file",
          "roll_keep": 5,
          "roll_size_mb": 100
        }
      },
      "default": {
        "encoder": {
          "format": "console"
        },
        "exclude": [
          "http",
          "tls"
        ],
        "level": "INFO",
        "writer": {
          "filename": "/app/logs/caddy.log",
          "output": "file",
          "roll_keep": 5,
          "roll_size_mb": 100
        }
      }
    }
  }
}`

// ── layer4 侧：SNI 分流路由解码 ─────────────────────────────────────────────

// TestCaddyPassthroughDecodeChain_layer4RoutesDecode 拿透传渲染产物快照走
// layer4 解码路径：routes 逐条取 matchers/handlers，按 module ID 尝试
// LoadModuleByID（caddy load 同一条模块表查找路），再对产物结构逐项断言。
//
// 断言清单（对应任务令 ①②③）：
//  1. SNI 集合：两条 SNI 路由的 layer4.matchers.tls sni 集合正确（含通配形）；
//  2. dial：透传路由 → 各自上游（10.0.0.9:10443 / 10.0.0.10:10443），
//     兜底路由 → 127.0.0.1:7443（内部终结口）；
//  3. 兜底路由 proxy_protocol=v2 在位（注入真实源 IP）。
//
// 附加判别面：matcher 分派键恰为 "tls"、handler 分派键恰为 "proxy"、
// 兜底路由无 match 且殿后（恒匹配语义）、透传路由带 @id。
func TestCaddyPassthroughDecodeChain_layer4RoutesDecode(t *testing.T) {
	var tree struct {
		Apps struct {
			Layer4 struct {
				Servers map[string]json.RawMessage `json:"servers"`
			} `json:"layer4"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(ptRenderedFixtureJSON), &tree); err != nil {
		t.Fatalf("透传渲染产物不是合法 JSON（Caddy 加载第一步就会失败）: %v", err)
	}
	rawServer, ok := tree.Apps.Layer4.Servers["tls_443"]
	if !ok {
		t.Fatalf("layer4 servers 缺少 tls_443（产物异常或取错 fixture）: 键集=%v",
			sortedKeys(tree.Apps.Layer4.Servers))
	}
	var server struct {
		Listen []string          `json:"listen"`
		Routes []json.RawMessage `json:"routes"`
	}
	if err := json.Unmarshal(rawServer, &server); err != nil {
		t.Fatalf("tls_443 server 解码失败: %v", err)
	}
	if !reflect.DeepEqual(server.Listen, []string{":443"}) {
		t.Fatalf("tls_443 listen=%v, want [\":443\"]（Layer4 前置接管公网口）", server.Listen)
	}
	if len(server.Routes) != 3 {
		t.Fatalf("tls_443 routes 条数=%d, want 3（两条 SNI 路由 + 一条兜底）", len(server.Routes))
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	// 模块注册面统计：loaded=本进程已注册且解码成功；unknown=未注册（降级）。
	loadedByID := map[string]int{}
	unknownByID := map[string]int{}

	// wantSNDial 与 fixture 种子同源（两条启用透传规则）。
	wantSNDial := map[string]string{
		"pass.example.test":   "10.0.0.9:10443",
		"*.wild.example.test": "10.0.0.10:10443",
	}
	gotSNDial := map[string]string{}
	fallbackIdx := -1

	for i, rawRoute := range server.Routes {
		var route struct {
			ID     string                       `json:"@id"`
			Match  []map[string]json.RawMessage `json:"match"`
			Handle []json.RawMessage            `json:"handle"`
		}
		if err := json.Unmarshal(rawRoute, &route); err != nil {
			t.Fatalf("tls_443 route[%d] 解码失败（caddy load 会同样失败）: %v\nroute=%s",
				i, err, truncate(rawRoute, 800))
		}

		if len(route.Match) == 0 {
			// 兜底路由：无 match = 恒匹配，必须殿后（SNI 命中优先）。
			if i != len(server.Routes)-1 {
				t.Fatalf("兜底路由在 route[%d]，但恒匹配路由必须殿后（共 %d 条）", i, len(server.Routes))
			}
			if fallbackIdx >= 0 {
				t.Fatalf("兜底路由多于一条（route[%d] 重复）", i)
			}
			fallbackIdx = i
			if len(route.Handle) != 1 {
				t.Fatalf("兜底路由 handle 条数=%d, want 1", len(route.Handle))
			}
			kind := handlerKindOf(t, route.Handle[0], "tls_443", i, 0)
			if kind != "proxy" {
				t.Fatalf("兜底路由 handler=%q, want proxy（layer4.handlers.proxy 分派键）", kind)
			}
			tryLoadL4Module(t, ctx, "layer4.handlers."+kind, stripHandlerKey(t, route.Handle[0]), loadedByID, unknownByID)
			dial := l4ProxyDial(t, route.Handle[0], "兜底路由")
			if dial != "127.0.0.1:7443" {
				t.Fatalf("兜底路由 dial=%q, want 127.0.0.1:7443（内部终结口）", dial)
			}
			var proxy struct {
				ProxyProtocol string `json:"proxy_protocol"`
			}
			if err := json.Unmarshal(route.Handle[0], &proxy); err != nil {
				t.Fatalf("兜底路由 handler 解码失败: %v", err)
			}
			if proxy.ProxyProtocol != "v2" {
				t.Fatalf("兜底路由 proxy_protocol=%q, want v2（注入真实源 IP）", proxy.ProxyProtocol)
			}
			continue
		}

		// SNI 路由：match 恰一个 matcher 集合，集合内恰 layer4.matchers.tls。
		if len(route.Match) != 1 {
			t.Fatalf("route[%d] match 集合数=%d, want 1", i, len(route.Match))
		}
		matchSet := route.Match[0]
		if keys := sortedKeys(matchSet); len(keys) != 1 || keys[0] != "tls" {
			t.Fatalf("route[%d] matcher 分派键=%v, want [tls]（layer4.matchers.tls）", i, keys)
		}
		tryLoadL4Module(t, ctx, "layer4.matchers.tls", matchSet["tls"], loadedByID, unknownByID)
		var tlsMatcher struct {
			SNI []string `json:"sni"`
		}
		if err := json.Unmarshal(matchSet["tls"], &tlsMatcher); err != nil {
			t.Fatalf("route[%d] tls matcher 解码失败: %v", i, err)
		}
		if len(tlsMatcher.SNI) != 1 {
			t.Fatalf("route[%d] sni=%v, want 恰一项（聚合按 route 分列）", i, tlsMatcher.SNI)
		}
		if len(route.Handle) != 1 {
			t.Fatalf("route[%d] handle 条数=%d, want 1", i, len(route.Handle))
		}
		kind := handlerKindOf(t, route.Handle[0], "tls_443", i, 0)
		if kind != "proxy" {
			t.Fatalf("route[%d] handler=%q, want proxy（layer4.handlers.proxy 分派键）", i, kind)
		}
		tryLoadL4Module(t, ctx, "layer4.handlers."+kind, stripHandlerKey(t, route.Handle[0]), loadedByID, unknownByID)
		if route.ID == "" {
			t.Fatalf("route[%d] 缺 @id（透传路由必须带规则 ID 供审计/重载定位）", i)
		}
		gotSNDial[tlsMatcher.SNI[0]] = l4ProxyDial(t, route.Handle[0], "route["+route.ID+"]")
	}

	if fallbackIdx < 0 {
		t.Fatalf("缺兜底路由（本地终结 + ACME 挑战必须经 7443）")
	}
	if !reflect.DeepEqual(gotSNDial, wantSNDial) {
		t.Fatalf("解码后 SNI→dial 映射=%v, want %v", gotSNDial, wantSNDial)
	}

	// 注册面结论（降级原因标注——任务令要求如实记录，不臆造）。
	if len(unknownByID) > 0 {
		t.Logf("layer4 模块注册面：已加载=%v；未注册（降级结构断言）=%v", loadedByID, unknownByID)
		t.Logf("降级原因：layer4.* 模块来自 mholt/caddy-l4，本模块（caddygeoip）依赖树无该模块"+
			"（生产镜像经 xcaddy --with github.com/mholt/caddy-l4@v0.1.2 编入，见 Dockerfile；"+
			"spike/caddybin 的 blank-import 属 spike 独立 go.mod，测试进程不继承）——"+
			"分派键/结构断言照常生效，真实解码待 caddy-l4 入依赖树后自动升级")
	} else {
		t.Logf("layer4 模块全部真实加载：%v", loadedByID)
	}
}

// ── http 侧：listener_wrappers 真实解码 ─────────────────────────────────────

// TestCaddyPassthroughDecodeChain_httpListenerWrappersDecode 断言透传端口的
// HTTP server 监听迁移与 listener_wrappers（任务令 ④）。wrapper 逐个按
// inline_key（"wrapper" 键）分派到 caddy.listeners.* 命名空间尝试真实加载：
// tls 占位 wrapper 在本进程注册（真实解码）；proxy_protocol 未注册（降级，
// 原因见文件头注册面说明）。结构断言钉住顺序与字段契约。
func TestCaddyPassthroughDecodeChain_httpListenerWrappersDecode(t *testing.T) {
	var tree struct {
		Apps struct {
			HTTP struct {
				Servers map[string]json.RawMessage `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(ptRenderedFixtureJSON), &tree); err != nil {
		t.Fatalf("透传渲染产物不是合法 JSON: %v", err)
	}
	rawServer, ok := tree.Apps.HTTP.Servers["http_443"]
	if !ok {
		t.Fatalf("http servers 缺少 http_443（透传端口必须保留 HTTP server 承接内部终结）: 键集=%v",
			sortedKeys(tree.Apps.HTTP.Servers))
	}

	var server struct {
		Listen           []string          `json:"listen"`
		ListenerWrappers []json.RawMessage `json:"listener_wrappers"`
	}
	if err := json.Unmarshal(rawServer, &server); err != nil {
		t.Fatalf("http_443 server 解码失败: %v", err)
	}

	// 监听迁移：TCP 退内部回环（Layer4 兜底经 PROXY v2 进来）、UDP 留公网
	// （HTTP/3 不经 Layer4）。servers 挂载键与 listen 地址逐字一致是 spike T-5
	// 实证的要点（否则 wrapper 静默不生效）。
	wantListen := []string{"tcp/127.0.0.1:7443", "udp/:443"}
	if !reflect.DeepEqual(server.Listen, wantListen) {
		t.Fatalf("http_443 listen=%v, want %v", server.Listen, wantListen)
	}
	if len(server.ListenerWrappers) != 2 {
		t.Fatalf("listener_wrappers 条数=%d, want 2（proxy_protocol + tls）", len(server.ListenerWrappers))
	}

	// 顺序契约：wrapper[0]=proxy_protocol（TLS 握手前剥 PROXY 头）、
	// wrapper[1]=tls。"wrapper" 键是 caddy 装载 listener_wrappers 的 inline_key
	// 分派键（caddy:"namespace=caddy.listeners inline_key=wrapper"），改名即
	// 真实装载失败。
	wantWrapperKeys := []string{"proxy_protocol", "tls"}
	for i, raw := range server.ListenerWrappers {
		var probe struct {
			Wrapper string `json:"wrapper"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("listener_wrappers[%d] 不是合法 JSON: %v", i, err)
		}
		if probe.Wrapper == "" {
			t.Fatalf("listener_wrappers[%d] 缺 wrapper 键（caddy 无法分派）: %s", i, truncate(raw, 400))
		}
		if probe.Wrapper != wantWrapperKeys[i] {
			t.Fatalf("listener_wrappers[%d]=%q, want %q（PROXY 头必须在 TLS 握手前剥除）",
				i, probe.Wrapper, wantWrapperKeys[i])
		}
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	loadedByID := map[string]int{}
	unknownByID := map[string]int{}

	// wrapper[0] 字段契约（proxy_protocol 未注册 → 结构断言）：allow 只信
	// Layer4 出站回环、fallback_policy=reject（外部伪造头在解析阶段即被拒）。
	var ppWrapper struct {
		Allow          []string `json:"allow"`
		FallbackPolicy string   `json:"fallback_policy"`
	}
	if err := json.Unmarshal(server.ListenerWrappers[0], &ppWrapper); err != nil {
		t.Fatalf("proxy_protocol wrapper 解码失败: %v", err)
	}
	if !reflect.DeepEqual(ppWrapper.Allow, []string{"127.0.0.1/32"}) {
		t.Fatalf("proxy_protocol allow=%v, want [127.0.0.1/32]（仅信 Layer4 出站）", ppWrapper.Allow)
	}
	if ppWrapper.FallbackPolicy != "reject" {
		t.Fatalf("proxy_protocol fallback_policy=%q, want reject（外部伪造头必须被拒）", ppWrapper.FallbackPolicy)
	}

	// 逐 wrapper 真实加载尝试（caddy load 同一条模块表查找路）。
	for i, raw := range server.ListenerWrappers {
		var probe struct {
			Wrapper string `json:"wrapper"`
		}
		if err := json.Unmarshal(raw, &probe); err != nil {
			t.Fatalf("listener_wrappers[%d] 不是合法 JSON: %v", i, err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("listener_wrappers[%d] 不是 JSON 对象: %v", i, err)
		}
		delete(fields, "wrapper") // inline_key 只用于分派，不属于模块自身字段
		stripped, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("重编码 listener_wrappers[%d]: %v", i, err)
		}
		tryLoadL4Module(t, ctx, "caddy.listeners."+probe.Wrapper, stripped, loadedByID, unknownByID)
	}

	// 注册面结论（降级原因标注——任务令要求如实记录，不臆造）。
	if len(unknownByID) > 0 {
		t.Logf("listener wrapper 注册面：已加载=%v；未注册（降级结构断言）=%v", loadedByID, unknownByID)
		t.Logf("降级原因：caddy.listeners.proxy_protocol 的注册包 caddyhttp/proxyprotocol 在本模块"+
			"依赖树未被 import——import 它会把 pires/go-proxyproto 牵进构建（go.mod/go.sum 增条目，"+
			"不在本任务白名单）；生产镜像用的是同一份 caddy v2.11.9 内建实现（无外部插件），"+
			"依赖树引入该包后本测试自动恢复真实解码")
	} else {
		t.Logf("listener wrapper 全部真实加载：%v", loadedByID)
	}
}

// ── fixture 来源守卫 ────────────────────────────────────────────────────────

// TestCaddyPassthroughDecodeChain_fixtureProvenance 断言内嵌产物来自**生产
// 渲染链**而非手拼 JSON：必须同时携带透传双规则 @id、layer4 server 键、
// 内部终结口监听迁移三组标记，且不含渲染失败键（渲染失败键出现即说明拿到的
// 是坏产物，解码无意义）。
func TestCaddyPassthroughDecodeChain_fixtureProvenance(t *testing.T) {
	text := ptRenderedFixtureJSON
	for _, want := range []string{
		"tls_443",            // Layer4 SNI 分流 server
		"lb_pt_dec_a",        // 透传规则 @id（生产渲染链发射）
		"lb_pt_dec_w",        // 透传规则 @id（生产渲染链发射）
		"tcp/127.0.0.1:7443", // 内部终结口监听迁移标记
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("fixture 缺 %q——说明输入不是生产渲染链的透传场景产物", want)
		}
	}
	if strings.Contains(text, generationErrorKey) {
		t.Fatalf("fixture 里带渲染失败键 %s（渲染链报错，解码无意义）", generationErrorKey)
	}
	var probe map[string]any
	if err := json.Unmarshal([]byte(text), &probe); err != nil {
		t.Fatalf("fixture 不是合法 JSON: %v", err)
	}
	if _, has := probe["apps"]; !has {
		t.Fatalf("fixture 缺 apps 顶层键（不是完整 Caddy config 形态）")
	}
}

// ── 测试辅助 ────────────────────────────────────────────────────────────────

// tryLoadL4Module 按 module ID 尝试真实加载（caddy load 同一条模块表查找路）。
//   - 加载成功 → loaded 计数（未来 caddy-l4 入依赖树时自动升级为真实解码）；
//   - unknown module（本进程未注册）→ unknown 计数，调用方降级为结构断言；
//   - 已注册但解码失败 → 真实缺陷，直接红（caddy load 会同样失败）。
func tryLoadL4Module(t *testing.T, ctx caddy.Context, moduleID string, raw json.RawMessage, loaded, unknown map[string]int) {
	t.Helper()
	if _, err := ctx.LoadModuleByID(moduleID, raw); err != nil {
		if strings.Contains(err.Error(), "unknown module") {
			unknown[moduleID]++
			return
		}
		t.Fatalf("模块 %s 已注册但解码失败（caddy load 会同样失败）: %v\nraw=%s", moduleID, err, truncate(raw, 600))
	}
	loaded[moduleID]++
}

// stripHandlerKey 剔除 handler 原始字节里的 "handler" 分派键（该键只用于分派，
// 不属于模块自身字段——漏剔会得到 json: unknown field "handler"，与既有
// loadHandlerModule 手法一致，仅不绑定 http.handlers 命名空间）。
func stripHandlerKey(t *testing.T, raw json.RawMessage) json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("handler 原始字节不是 JSON 对象: %v", err)
	}
	delete(fields, "handler")
	stripped, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("重编码 handler 字段: %v", err)
	}
	return stripped
}

// l4ProxyDial 取 layer4 proxy handler 的首个 upstream dial（透传上游单值）。
func l4ProxyDial(t *testing.T, rawHandler json.RawMessage, label string) string {
	t.Helper()
	var proxy struct {
		Upstreams []struct {
			Dial []string `json:"dial"`
		} `json:"upstreams"`
	}
	if err := json.Unmarshal(rawHandler, &proxy); err != nil {
		t.Fatalf("%s handler 解码失败: %v", label, err)
	}
	if len(proxy.Upstreams) != 1 || len(proxy.Upstreams[0].Dial) != 1 {
		t.Fatalf("%s upstreams 形态非法（透传上游单值）: %v", label, proxy.Upstreams)
	}
	return proxy.Upstreams[0].Dial[0]
}
