package handlers

import (
	"context"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 锁内复核必须覆盖 security_policy_bindings：初检对绑定采用「备份携带则备份行、
// 缺席则 live」回退，而绑定表无外键——初检到加锁窗口（等导入锁/排干/WAF 锁，
// 可达秒级）内管理员删除被引用策略，锁内不复验会让绑定原样落库且不触发剪枝，
// 该规则查不到策略即按无策略渲染（WAF/限流/GeoIP 静默失效）。
func TestRevalidateImportLiveDependencies_rejectsBindingToVanishedPolicy(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port) VALUES ('lb_live_rule','live-rule','http','live.example.test',80)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	// 备份未携带策略表（策略保持 live）——但窗口内策略已被删空。
	if _, err := db.DB.Exec(`DELETE FROM security_policies`); err != nil {
		t.Fatalf("clear policies: %v", err)
	}
	backup := &configBackup{Tables: map[string][]map[string]any{
		"security_policy_bindings": {
			{"rule_caddy_id": "lb_live_rule", "policy_id": int64(42)},
		},
	}}
	sectionTables := map[string]bool{"lb_rules": false, "security_policies": false, "security_policy_bindings": true}

	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	err = revalidateImportLiveDependencies(context.Background(), tx, backup, sectionTables)
	if err == nil {
		t.Fatal("绑定引用的策略在导入窗口内被删除时必须拒绝（否则该规则零防护而 UI 显示已绑定）")
	}
	if !strings.Contains(err.Error(), "security_policy_bindings") || !strings.Contains(err.Error(), "42") {
		t.Fatalf("error=%v, want 点名表/行/策略 ID（与初检同口径）", err)
	}
}

// 反向：绑定的规则与策略均存活时不得误拒（锁内复核只补缺口，不放宽成过度拒绝）。
func TestRevalidateImportLiveDependencies_acceptsBindingToLiveRuleAndPolicy(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port) VALUES ('lb_live_rule','live-rule','http','live.example.test',80)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	var policyID int64
	if err := db.DB.QueryRow(`INSERT INTO security_policies (name,mode) VALUES ('live-policy','off') RETURNING id`).Scan(&policyID); err != nil {
		t.Fatalf("seed live policy: %v", err)
	}
	backup := &configBackup{Tables: map[string][]map[string]any{
		"security_policy_bindings": {
			{"rule_caddy_id": "lb_live_rule", "policy_id": policyID},
		},
	}}
	sectionTables := map[string]bool{"lb_rules": false, "security_policies": false, "security_policy_bindings": true}

	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	if err := revalidateImportLiveDependencies(context.Background(), tx, backup, sectionTables); err != nil {
		t.Fatalf("存活引用不得误拒: %v", err)
	}
}
