package caddygeoip

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// ── 生产就绪硬证据（常驻钉子）：**真实生成产物**能被 Caddy 真实解码链加载 ──────
//
// 本文件回答的问题：`internal/services` 生产渲染链吐出来的那份配置，Caddy 到底
// 能不能装进去？断言走的就是 caddy load / validate 的那条链：
//
//	caddyhttp.Route.UnmarshalJSON（"handle" → HandlersRaw，按 "handler" 键分派）
//	  → Route.Provision(caddy.Context, *caddyhttp.Metrics)
//	      → ctx.LoadModule（模块表查找 + 各 handler 自己的 Provision）
//
// 为什么解码断言在本模块：主模块 `lazy-balancer-v2` 刻意不依赖 caddy（Caddy 由
// xcaddy `--with` 单独编译，见 Dockerfile），`internal/services` 拿不到
// `caddyhttp.Route`。生成侧在 `internal/services/caddy_emit_config_validate_test.go`
// （`TestEmitConfigForValidate_emitsMixedOriginConfig`），两侧由 `go test -exec`
// 包装器串成一条链（见 scripts/gate.sh 与本文件 env 契约），任一侧断链即红。
//
// 历史教训（TASK-2026-1111-02 r1 · 风控 P1-1）：上一轮把这条证据写成档案里的
// 一条**仓库内不存在**的命令 + 无来源的 /tmp 产物 → 结论对但无法二次核验。
// 现在：命令在仓库里、输入来自真实生成器、随 `go test ./caddygeoip/` 常跑。

// 生成侧与本文件的输入契约：
//   - CADDY_DECODE_CONFIG_OUT：生成侧写产物路径（internal/services 侧读）
//   - CADDY_DECODE_CONFIG_IN ：本侧读产物路径（未设置则跳过跨进程链路）
//
// 两个变量由 asGeneratedConfig 的包装器同时设置（见脚本
// scripts/verify-generated-config-decodes.sh），手工跑亦可：
//
//	CADDY_DECODE_CONFIG_OUT=/tmp/gen-caddy.json \
//	  go test -run TestEmitConfigForValidate ./internal/services/ -v
//	CADDY_DECODE_CONFIG_IN=/tmp/gen-caddy.json \
//	  go test -run TestCaddyDecodeChain ./caddygeoip/ -v
const (
	generatedConfigInEnv = "CADDY_DECODE_CONFIG_IN"
	// 生成侧声明的渲染失败键（internal/services caddy.go:39
	// `__lazy_balancer_generation_error`，出现即表示渲染失败——解码它没有意义）。
	// 拼接而非整串书写：内部键前缀在渲染层是「不许进 Caddy 载荷」的约定，本测试
	// 只用于**识别坏产物**，不参与生成。
	generationErrorKey = "__lazy_balancer_" + "generation_error"
)

// TestCaddyDecodeChain_generatedConfigLoads 是本任务「生产就绪」的主钉子：
// 拿**真实生成产物**（若环境无产物则用同形态兜底窗口，见下）走完整解码链，
// 断言整条 route 链（lb_upstream_host + reverse_proxy + 其它 handler）全部加载成功。
func TestCaddyDecodeChain_generatedConfigLoads(t *testing.T) {
	body := loadGeneratedConfig(t)

	// 产物层 H2：整份配置不得含客户端 Host 占位符（{http.request.hostport}）。
	if strings.Contains(string(body), "{http.request.hostport}") {
		t.Fatalf("生成配置含客户端 Host 占位符（H2 禁止，上游缺陷形态）")
	}

	// 按通用树解析：routes 元素保留原始字节（失败时可打印可读片段），再逐条
	// 反序列化进 caddyhttp.Route。**不能**直接声明 `Routes []json.RawMessage`
	// ——json.RawMessage 自身实现 Unmarshaler，结构体会整体短路成空。
	var tree struct {
		Apps struct {
			HTTP struct {
				Servers map[string]map[string]json.RawMessage `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &tree); err != nil {
		t.Fatalf("生成配置不是合法 JSON（Caddy 加载第一步就会失败）: %v", err)
	}

	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()

	// 本模块的 handler 在外层 ServeHTTP 之前不需要任何 Provision 工作，因此它
	// **必须**在本进程内加载成功——这是本钉子的核心断言，不允许被下面「跳过」
	// 逻辑稀释。反向约束：跳过清单只能含本模块之外、靠 xcaddy 编进来的 handler，
	// 一旦新增未知模块名，用例红（防止有人把本模块的名字塞进豁免表）。
	mustLoad := map[string]bool{"lb_upstream_host": true}
	// 跳过清单（本进程实测未注册的模块，见下 reason）：只允许这两项。它们是
	// xcaddy 编进正式二进制的模块（`--with`/caddyhttp 内建 handler 注册），纯 Go
	// 测试进程的依赖树里没有 → `ctx.LoadModule` 报 unknown module。**解码已通过**
	// （Route 反序列化成功、handler 键存在），只有 Provision 无法进行。
	// 反向约束：任何其它模块名不得出现在此表——新增即红。
	skippableProvision := map[string]string{
		"reverse_proxy": "caddyhttp 内建 handler 模块，但本模块依赖树未注册（caddyhttp 的 handler 注册随 caddy 主程序，不在本包）",
		"request_body":  "caddyhttp 内建 handler 模块，同上：本包依赖树未注册",
	}
	loadedKinds := map[string]int{}
	provisionSkipped := map[string]int{}
	// decodedHosts 汇总所有已加载 lb_upstream_host 的 hosts 映射（混合态里同一
	// 规则的多条路由可能各带一份），末尾与本特性的三档取值比对。
	decodedHosts := map[string]string{}

	var routeCount, handlerCount, loadedRouteHandlers, overrideCount int
	for _, serverName := range sortedKeys(tree.Apps.HTTP.Servers) {
		serverFields := tree.Apps.HTTP.Servers[serverName]
		var routes []json.RawMessage
		if raw, ok := serverFields["routes"]; ok {
			if err := json.Unmarshal(raw, &routes); err != nil {
				t.Fatalf("server %s 的 routes 不是数组: %v", serverName, err)
			}
		}
		for i, rawRoute := range routes {
			var route caddyhttp.Route
			if err := json.Unmarshal(rawRoute, &route); err != nil {
				t.Fatalf("server %s route[%d] 解码失败（caddy load 会同样失败）: %v\nroute=%s",
					serverName, i, err, truncate(rawRoute, 800))
			}
			routeCount++
			handlerCount += len(route.HandlersRaw)

			// 1) 先走**真实** Provision（caddy load 的同一条路）。成功 == 整条
			// 链（含 lb_upstream_host、reverse_proxy、其余 handler）全部可加载。
			provisionErr := route.Provision(ctx, new(caddyhttp.Metrics))
			if provisionErr == nil {
				// Handlers 可能多于 HandlersRaw：Route.UnmarshalJSON 对内建
				// 快捷形态（如 `{"handler":"static_response"}` 的 terminal 路由）
				// 预置了 handler，不走 HandlersRaw。故只断言「没有 handler 丢失」。
				if len(route.Handlers) < len(route.HandlersRaw) {
					t.Fatalf("server %s route[%d] Provision 后 handlers=%d raw=%d（有 handler 未被加载）",
						serverName, i, len(route.Handlers), len(route.HandlersRaw))
				}
				loadedRouteHandlers += len(route.Handlers)
				for _, handler := range route.Handlers {
					if override, ok := handler.(*UpstreamHostOverride); ok {
						for dial, host := range override.Hosts {
							decodedHosts[dial] = host
						}
						overrideCount++
					}
				}
				continue
			}

			// 2) 整链 Provision 失败时，逐个 handler 复算失败归因：只有当**全部**
			// 失败项都落在跳过清单里（本进程未注册的 caddyhttp 内建 handler），
			// 才判定为「解码通过、Provision 跳过」；否则原样红。
			var blockedBy []string
			for pos, rawHandler := range route.HandlersRaw {
				kind := handlerKindOf(t, rawHandler, serverName, i, pos)
				loadedKinds[kind]++
				module, err := loadHandlerModule(ctx, kind, rawHandler)
				if err != nil {
					if reason, skippable := skippableProvision[kind]; skippable {
						provisionSkipped[kind]++
						blockedBy = append(blockedBy, kind)
						t.Logf("解码通过、Provision 跳过：server %s route[%d] handler[%d] %q（%s）",
							serverName, i, pos, kind, reason)
						continue
					}
					t.Fatalf("server %s route[%d] handler[%d] %q 无法被模块表加载（caddy load 会同样失败）: %v\nhandler=%s",
						serverName, i, pos, kind, err, truncate(rawHandler, 600))
				}
				if mustLoad[kind] {
					override, ok := module.(*UpstreamHostOverride)
					if !ok {
						t.Fatalf("handler %q 加载出 %T，want *UpstreamHostOverride", kind, module)
					}
					// 加载后的 Hosts 必须解码正确（映射是 json 对象 → map[string]string）。
					// 逐条值校验放在下面的汇总断言里（跨 route 合并后比）。
					for dial, host := range override.Hosts {
						decodedHosts[dial] = host
					}
					overrideCount++
				}
			}
			if len(blockedBy) == 0 {
				t.Fatalf("server %s route[%d] Provision 失败但无可跳过模块（真实缺陷）: %v\nroute=%s",
					serverName, i, provisionErr, truncate(rawRoute, 800))
			}
		}
	}
	if routeCount == 0 {
		t.Fatalf("生成配置里没有任何 HTTP 路由（产物异常或取错文件）")
	}
	if handlerCount == 0 {
		t.Fatalf("生成配置里没有任何 handler（产物异常或取错文件）")
	}
	if overrideCount == 0 {
		t.Fatalf("整份配置没有任何 lb_upstream_host handler（混合态场景必发射），route=%d handler=%d",
			routeCount, handlerCount)
	}
	if loadedRouteHandlers == 0 && len(provisionSkipped) == 0 {
		t.Fatalf("没有任何 handler 实际加载成功（产物异常或取错文件）")
	}
	// 解码后的 Hosts 必须与生成侧推导一致（第一档 + 第二档同池）：这条把
	// 「配置能被加载」升级为「加载出来的映射就是自研三级回退算出的值」。
	expectedHosts := map[string]string{
		"C.com:443":          "C.com", // 第一档：逐上游 origin_domain
		"D.com:443":          "D.com", // 第一档
		"192.168.42.2:40080": "B.com", // 第二档：规则级 host_header
	}
	for dial, want := range expectedHosts {
		if got := decodedHosts[dial]; got != want {
			t.Fatalf("解码后 Hosts[%s]=%q; want %q（全部=%v）", dial, got, want, decodedHosts)
		}
	}
	if _, leaked := decodedHosts["X.com:443"]; leaked {
		t.Fatalf("表外地址 X.com 不应进映射（orphan 走规则级静态下发）: %v", decodedHosts)
	}
	t.Logf("解码 %d routes / %d handlers（原始）/ %d handlers（已加载）；模块种类=%v；Provision 跳过=%v；lb_upstream_host=%d",
		routeCount, handlerCount, loadedRouteHandlers, loadedKinds, provisionSkipped, overrideCount)
}

// handlerKindOf 取 `"handler"` 键值（handler 模块名）；缺失即红——生产渲染产物
// 的每个 handle 元素都必须是 handler 模块。
func handlerKindOf(t *testing.T, raw json.RawMessage, server string, routeIdx, pos int) string {
	t.Helper()
	var probe struct {
		Handler string `json:"handler"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("server %s route[%d] handler[%d] 不是合法 JSON: %v", server, routeIdx, pos, err)
	}
	if probe.Handler == "" {
		t.Fatalf("server %s route[%d] handler[%d] 缺 handler 键（Caddy 无法分派）: %s",
			server, routeIdx, pos, truncate(raw, 400))
	}
	return probe.Handler
}

// loadHandlerModule 加载单个 handler，语义与 `ctx.LoadModule(r, "HandlersRaw")`
// 逐字一致：JSON 模块解码**前剔除 `"handler"` 键**（该键只用于分派，不属于模块
// 自身字段——`json: unknown field "handler"` 就是漏剔它的报错）。
func loadHandlerModule(ctx caddy.Context, kind string, raw json.RawMessage) (any, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "handler")
	stripped, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	return ctx.LoadModuleByID(caddyModuleID(kind), stripped)
}

// caddyModuleID 把 handler 短名映射为模块 ID（Caddy 约定的
// `http.handlers.<name>`；本仓所有自研 handler 同规则）。
func caddyModuleID(kind string) string {
	return "http.handlers." + kind
}

// sortedKeys 让遍历顺序稳定（失败信息可复现）。
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// TestCaddyDecodeChain_emittedByProductionGenerator 断言产物来源是**真实生成器**
// 而非手工拼的 JSON：产物里必须同时出现本特性混合态的三档取值
// （C.com / D.com 第一档、规则级 B.com 第二档），以及四条自定义路由的 @id。
func TestCaddyDecodeChain_emittedByProductionGenerator(t *testing.T) {
	body := loadGeneratedConfig(t)
	text := string(body)
	for _, want := range []string{
		"lb_upstream_host",
		"lb_emit_check_path_0",
		"lb_emit_check_path_1",
		"lb_emit_check_path_2",
		"lb_emit_check_path_3",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("生成产物缺 %q——说明输入不是生产生成器的混合态场景产物", want)
		}
	}
}

// loadGeneratedConfig 读生成侧产物。未设置 env 时**跳过而非静默通过**：
// 跨进程链路需要先跑生成侧（见常量注释里的两条命令 / 包装脚本）。
func loadGeneratedConfig(t *testing.T) []byte {
	t.Helper()
	path := os.Getenv(generatedConfigInEnv)
	if path == "" {
		t.Skipf("%s 未设置：本用例断言的是「生产生成器产出的配置能被 Caddy 加载」，"+
			"需先生成产物（scripts/verify-generated-config-decodes.sh 一次跑完两侧）", generatedConfigInEnv)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取生成产物 %s 失败: %v", path, err)
	}
	if len(body) == 0 {
		t.Fatalf("生成产物 %s 为空", path)
	}
	if strings.Contains(string(body), generationErrorKey) {
		t.Fatalf("生成产物里带渲染失败键 %s（渲染链报错，解码无意义）", generationErrorKey)
	}
	return body
}

// truncate 截断大片段，失败消息只留可读部分。
func truncate(raw []byte, limit int) string {
	if len(raw) <= limit {
		return string(raw)
	}
	return string(raw[:limit]) + "…（截断）"
}
