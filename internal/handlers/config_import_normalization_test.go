package handlers

// 两处「归一可见性/判据源」收口的行为钉：
//  ① 全局配置数值归一进链——预览与导入对同一份备份看到同一组归一事实；
//  ② 证书任务 CA 提供商悬挂计数的规则源按「lb_rules 是否随包」二选一，
//     provider 存在性读取走传入 querier（导入路径=事务视图）。

import (
	"context"
	"testing"
)

// 越界/非法形态的全局配置键在链内归一并产生带值回显的说明；预览与导入
// 消费同一结果（前者 warnings，后者审计），因此本用例只钉链内唯一归一点。
func TestImportChain_normalizeGlobalConfigNumbersProducesVisibleNotes(t *testing.T) {
	backup := &configBackup{
		Config: map[string]any{
			"cert_renewal_days":        float64(3650),
			"request_body_max_size_mb": float64(100000),
		},
		Tables: map[string][]map[string]any{},
	}
	chain := &importValidationChain{ctx: context.Background(), backup: backup}
	if err := chain.normalizeGlobalConfigNumbers(); err != nil {
		t.Fatalf("normalizeGlobalConfigNumbers: %v", err)
	}
	if len(chain.result.ConfigClampNotes) < 2 {
		t.Fatalf("归一说明=%v, want 证书续签天数与请求体上限各一条", chain.result.ConfigClampNotes)
	}
	if got, _ := backupInteger(backup.Config["request_body_max_size_mb"]); got != 4096 {
		t.Fatalf("request_body_max_size_mb=%v, want 钳到 4096", backup.Config["request_body_max_size_mb"])
	}

	// 合法值：零说明（预览不得对正常备份刷警告）。
	clean := &configBackup{Config: map[string]any{"request_body_max_size_mb": float64(128), "cert_renewal_days": float64(30)}, Tables: map[string][]map[string]any{}}
	cleanChain := &importValidationChain{ctx: context.Background(), backup: clean}
	if err := cleanChain.normalizeGlobalConfigNumbers(); err != nil {
		t.Fatalf("normalizeGlobalConfigNumbers(clean): %v", err)
	}
	if len(cleanChain.result.ConfigClampNotes) != 0 {
		t.Fatalf("合法值产生归一说明: %v", cleanChain.result.ConfigClampNotes)
	}
}

// 计数面：非终态 ∧ 启用 ACME 规则；disabled/missing 分档；终态行不计。
// 规则源随包时用备份行（导入后视图），否则回退 live JOIN。
func TestCertJobProviderDanglingCounts_shapesAndRuleSource(t *testing.T) {
	database := initializeRuleFeatureTestDB(t)
	ctx := context.Background()
	if _, err := database.Exec(`INSERT OR IGNORE INTO global_config (id, caddy_config) VALUES (1,'{}')`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_dangle_acme','dangle','http','dangle.example.test',443,1,1,'acme_dns'),
		       ('lb_dangle_missing','dangle2','http','dangle2.example.test',443,1,1,'acme_dns'),
		       ('lb_dangle_terminal','dangle3','http','dangle3.example.test',443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,enabled)
		VALUES (11,'disabled-provider','letsencrypt','https://acme.example/dir','{}',0)`); err != nil {
		t.Fatalf("seed disabled provider: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,created_at,updated_at)
		VALUES ('lb_dangle_acme','dangle.example.test','issued',11,datetime('now'),datetime('now')),
		       ('lb_dangle_missing','dangle2.example.test','issued',12,datetime('now'),datetime('now')),
		       ('lb_dangle_terminal','dangle3.example.test','failed',13,datetime('now'),datetime('now'))`); err != nil {
		t.Fatalf("seed cert jobs: %v", err)
	}

	sectionTables := map[string]bool{"ca_providers": true}
	disabled, missing, err := certJobProviderDanglingCounts(ctx, database, map[string][]map[string]any{}, sectionTables)
	if err != nil {
		t.Fatalf("live source: %v", err)
	}
	if disabled != 1 || missing != 1 {
		t.Fatalf("live source disabled/missing=%d/%d, want 1/1（failed 终态行不计）", disabled, missing)
	}

	// lb_rules 随包：live 规则被禁用，备份行启用——判据必须取备份视图，
	// 否则「导入前规则态」与「导入后任务行」组合会漏计。
	if _, err := database.Exec(`UPDATE lb_rules SET enabled=0 WHERE caddy_id='lb_dangle_acme'`); err != nil {
		t.Fatalf("disable live rule: %v", err)
	}
	backupEnabled := map[string][]map[string]any{"lb_rules": {
		{"caddy_id": "lb_dangle_acme", "protocol": "http", "enabled": float64(1), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle"},
		{"caddy_id": "lb_dangle_missing", "protocol": "http", "enabled": float64(1), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle2"},
		{"caddy_id": "lb_dangle_terminal", "protocol": "http", "enabled": float64(1), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle3"},
	}}
	disabled, missing, err = certJobProviderDanglingCounts(ctx, database, backupEnabled, sectionTables)
	if err != nil {
		t.Fatalf("carried rules source: %v", err)
	}
	if disabled != 1 || missing != 1 {
		t.Fatalf("carried rules disabled/missing=%d/%d, want 1/1（按备份启用规则计数）", disabled, missing)
	}

	// 备份行禁用 → 不参与续签，零计数。
	backupDisabled := map[string][]map[string]any{"lb_rules": {
		{"caddy_id": "lb_dangle_acme", "protocol": "http", "enabled": float64(0), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle"},
		{"caddy_id": "lb_dangle_missing", "protocol": "http", "enabled": float64(0), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle2"},
		{"caddy_id": "lb_dangle_terminal", "protocol": "http", "enabled": float64(0), "enable_tls": float64(1), "tls_source": "acme_dns", "name": "dangle3"},
	}}
	disabled, missing, err = certJobProviderDanglingCounts(ctx, database, backupDisabled, sectionTables)
	if err != nil {
		t.Fatalf("carried disabled rules: %v", err)
	}
	if disabled != 0 || missing != 0 {
		t.Fatalf("carried disabled rules disabled/missing=%d/%d, want 0/0", disabled, missing)
	}
}
