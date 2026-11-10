package services

// （旧代码只对 acme_dns 判证书就绪）——域名被 301 到无服务的 TLS 端口。
// 修复：跳转与 server 同判据（availableCerts 命中才发射），不分 tls_source。
// 可达性：保存/启用/导入侧均已拦截空证书（直改 DB/残留脏行才可达），下限。

import (
	"testing"
)

func Test_manualTLSRedirectRequiresReadyCert(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)

	// 目标形状：manual + tls_http_redirect + 空证书（脏行形态）。
	seedGenerationRule(t, database, "lb_mredir", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='mredir.example.test', enable_tls=1, tls_source='manual', tls_cert='', tls_key='', tls_http_redirect=1, listen_port=18445 WHERE caddy_id='lb_mredir'`); err != nil {
		t.Fatalf("seed manual TLS rule without cert: %v", err)
	}

	generated := generateCaddyConfigFromStore(database)
	servers := l7HTTPServers(t, generated)

	if _, ok := servers["http_18445"]; ok {
		t.Fatalf("unready manual TLS rule must not publish a server: %#v", servers["http_18445"])
	}
	// 80 端口 301 跳转也不得发射（本修复点）。默认站恒渲染——缺失即形态
	// 异常，负断言不得被存在性检查静默跳过。
	if _, ok := servers["http_80"].(map[string]interface{}); !ok {
		t.Fatalf("默认站 http_80 必须存在（301 负断言前置）: %#v", servers)
	}
	if redirect := findRouteByID(t, httpRoutesFromServer(t, generated, "http_80"), "lb_mredir_redirect"); redirect != nil {
		t.Fatalf("证书未就绪的 manual TLS 规则不得发射 301 跳转: %#v", redirect)
	}

	// 回归形状：证书物化后 server 与跳转同时出现（同判据的另一面）。
	certPEM, keyPEM := matchingCertificatePair(t, "mredir.example.test")
	if _, err := database.Exec(`UPDATE lb_rules SET tls_cert=?, tls_key=? WHERE caddy_id='lb_mredir'`, certPEM, keyPEM); err != nil {
		t.Fatalf("materialize cert: %v", err)
	}
	generated = generateCaddyConfigFromStore(database)
	servers = l7HTTPServers(t, generated)
	if _, ok := servers["http_18445"]; !ok {
		t.Fatal("证书就绪后 server 必须发布")
	}
	if redirect := findRouteByID(t, httpRoutesFromServer(t, generated, "http_80"), "lb_mredir_redirect"); redirect == nil {
		t.Fatal("证书就绪后 301 跳转必须发射")
	}
}
