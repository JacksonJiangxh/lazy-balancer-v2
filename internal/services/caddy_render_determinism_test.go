package services

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"strconv"
	"testing"
)

// 同一 DB 状态必须渲染出逐字节相同的配置。发布集与按端口分组在同一 allRules
// （rowid 序）遍历内收集，不从 map 遍历重建——顺序确定化是不变量：任何未来
// 消费方（logger_names 归属、日志发射面）都不应依赖 map 序。本测试按多端口 +
// 同端口双规则形态反复渲染。
// 分辨力边界：encoding/json 对 map 键排序，逐字节相等只对**数组顺序**（routes、
// TLS 策略、错误路由）有分辨力；servers / logger_names 等 map 的键集与归属
// 不参与字节分辨，由下方结构断言独立覆盖。
func TestGenerateCaddyConfig_loggerNamesDeterministicAcrossRenders(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_lognames_first", "same-host.example.test", 8080)
	seedHTTPRuleForGeneration(t, database, "lb_lognames_second", "same-host.example.test", 8080)
	seedHTTPRuleForGeneration(t, database, "lb_lognames_other_port", "other-host.example.test", 8081)
	if _, err := database.Exec(`UPDATE lb_rules SET log_enabled=1 WHERE caddy_id IN ('lb_lognames_first','lb_lognames_second','lb_lognames_other_port')`); err != nil {
		t.Fatalf("enable rule logs: %v", err)
	}

	var first []byte
	for render := range 20 {
		cfg := generateCaddyConfigFromStore(database)
		if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
			t.Fatalf("render %d 失败: %s", render, message)
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal render %d: %v", render, err)
		}
		if render == 0 {
			first = data
			continue
		}
		if !bytes.Equal(first, data) {
			t.Fatalf("第 %d 次渲染与首次字节不同——数组顺序泄漏进配置产物", render)
		}
	}

	// 确定性提升后归属也固定：rowid 靠后的规则最后写入 logger_names。
	cfg := generateCaddyConfigFromStore(database)
	servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")
	serverKeys := make([]string, 0, len(servers))
	for name := range servers {
		serverKeys = append(serverKeys, name)
	}
	sort.Strings(serverKeys)
	assertEqual(t, serverKeys, []string{"http_80", "http_8080", "http_8081"})
	for _, want := range []struct{ server, host, logger string }{
		{server: "http_8080", host: "same-host.example.test", logger: "rule_lb_lognames_second"},
		{server: "http_8081", host: "other-host.example.test", logger: "rule_lb_lognames_other_port"},
	} {
		published := mustMap(t, servers[want.server], want.server)
		loggerNames := mustMap(t, mustMap(t, mustMap(t, published["logs"], "logs")["logger_names"], "logger_names"), "logger_names")
		if len(loggerNames) != 1 {
			t.Fatalf("%s logger_names 键集=%v, want 恰一项（同端口双规则归属唯一）", want.server, loggerNames)
		}
		if got := loggerNames[want.host]; got != want.logger {
			t.Fatalf("%s logger_names[%s]=%v, want %s（rowid 序最后者）", want.server, want.host, got, want.logger)
		}
	}
}

// 单规则渲染与全量渲染同判据：auto-HTTPS 恒关闭（含 80/443）。此前 443/80 不
// 发射 disable，是第二套约定——被真实应用时会让引擎 ACME 与项目证书链分叉。
func TestGenerateSingleRuleCaddyConfig_alwaysDisablesAutomaticHTTPS(t *testing.T) {
	for _, port := range []int{80, 443, 8080} {
		cfg := GenerateSingleRuleCaddyConfig(SingleRuleConfig{
			CaddyID:                       "lb_single_autohttps",
			Protocol:                      "http",
			Domain:                        "single.example.test",
			ListenPort:                    port,
			RequestBodyMaxSizeMB:          128,
			GlobalRequestBodyMaxSizeMB:    128,
			HealthCheckInterval:           10,
			HealthCheckTimeout:            2,
			HealthCheckUnhealthyThreshold: 3,
			HealthCheckHealthyThreshold:   2,
			Upstreams:                     []UpstreamConfig{{Host: "127.0.0.1", Port: 9000, Weight: 1, Enabled: true, Protocol: "http"}},
		})
		if message, failed := cfg["error"].(error); failed {
			t.Fatalf("port=%d 单规则渲染失败: %v", port, message)
		}
		server := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")["http_"+strconv.Itoa(port)]
		serverMap := mustMap(t, server, "server")
		autoHTTPS := mustMap(t, serverMap["automatic_https"], "automatic_https")
		if autoHTTPS["disable"] != true {
			t.Fatalf("port=%d 单规则渲染 automatic_https=%v, want disable=true", port, autoHTTPS)
		}
	}
}

// 默认 logger 的 exclude 是命名空间前缀匹配："http" 已覆盖 http.log.access，
// 重复项只增加配置字节噪声（caddy_server 的 http.log.access 因不含 http 前缀
// 而必要，不受本断言影响）。
func TestBuildCaddyLogging_defaultExcludeHasNoRedundantAccessNamespace(t *testing.T) {
	logging := buildCaddyLogging("info", 100)
	logs := mustMap(t, logging["logs"], "logs")
	defaultLogger := mustMap(t, logs["default"], "default")
	exclude, ok := defaultLogger["exclude"].([]string)
	if !ok {
		t.Fatalf("default.exclude 类型=%T, want []string", defaultLogger["exclude"])
	}
	for _, entry := range exclude {
		if entry == "http.log.access" {
			t.Fatalf("default.exclude=%v 含被 \"http\" 前缀覆盖的冗余项", exclude)
		}
	}
	if !reflect.DeepEqual(exclude, []string{"http", "tls"}) {
		t.Fatalf("default.exclude=%v, want [http tls]", exclude)
	}
	serverLogger := mustMap(t, logs["caddy_server"], "caddy_server")
	serverExclude, _ := serverLogger["exclude"].([]string)
	found := false
	for _, entry := range serverExclude {
		if entry == "http.log.access" {
			found = true
		}
	}
	if !found {
		t.Fatalf("caddy_server.exclude=%v 缺少必要的 http.log.access 排除项", serverExclude)
	}
}

// mustMap 等渲染断言辅助见同包测试文件。
