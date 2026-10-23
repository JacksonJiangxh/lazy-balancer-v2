package handlers

// 导入的两类「语义变更无可观测信号」必须并入响应 warnings 与审计：
//   - off→custom_only 归一（自定义规则从全关变生效）；
//   - 「系统数据」替换 CA 提供商而证书任务未随包时，live 任务显式 provider
//     变禁用/缺失（续签会转 failed 终态）。
// 行为均不改变（与启动迁移「行为零突变」同哲学），只补可观测性。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

type importWarningsEnvelope struct {
	Code int `json:"code"`
	Data struct {
		Warnings []string `json:"warnings"`
	} `json:"data"`
}

func decodeImportWarnings(t *testing.T, recorder *httptest.ResponseRecorder) []string {
	t.Helper()
	var envelope importWarningsEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode import response: %v (body=%s)", err, recorder.Body.String())
	}
	return envelope.Data.Warnings
}

func warningsContain(warnings []string, needle string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, needle) {
			return true
		}
	}
	return false
}

// Given 备份「安全防护」携带 mode=off 且挂启用自定义规则的策略（旧世界数据）。
// When 导入。Then 归一生效（custom_only），且归一在响应 warnings 与审计双通道可见。
func TestImportConfigBackup_customOnlyNormalizationIsVisible(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'live-admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed live admin: %v", err)
	}
	body := buildBackup(t, backupFixtureOptions{
		Sections: []string{"security"},
		Tables: map[string][]map[string]any{
			"security_policies":     {{"id": 1, "name": "off-legacy", "mode": "off", "custom_rules": "[1]", "enabled": 1}},
			"security_custom_rules": {{"id": 1, "name": "legacy", "conditions": "[{\"target\":\"uri\",\"operator\":\"contains\",\"pattern\":\"/legacy\"}]", "action": "block", "enabled": 1}},
			"security_block_pages":  {{"id": 1, "name": "默认拦截页", "content": "<html>default</html>", "is_default": 1}},
		},
		EmptyConfigIfNil: true,
	})
	response := postImportShared(t, h.ImportConfigBackup, "/config/import", body)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var mode string
	if err := db.DB.QueryRow(`SELECT COALESCE(mode,'') FROM security_policies WHERE id=1`).Scan(&mode); err != nil {
		t.Fatalf("read policy mode: %v", err)
	}
	if mode != "custom_only" {
		t.Fatalf("mode=%q, want custom_only（旧语义归一行为不变）", mode)
	}
	if warnings := decodeImportWarnings(t, response); !warningsContain(warnings, "归一为 custom_only") {
		t.Fatalf("warnings=%v, want 含归一提示（自定义规则开始生效必须可观测）", warnings)
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE '%警告' AND resource='配置备份' AND detail LIKE '%custom_only%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("归一未落操作审计")
	}
}

// 回归形状：mode=off 且无启用自定义规则 → 不归一、无该 warning。
func TestImportConfigBackup_customOnlyNormalizationSkippedWhenNoEnabledRule(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'live-admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed live admin: %v", err)
	}
	body := buildBackup(t, backupFixtureOptions{
		Sections: []string{"security"},
		Tables: map[string][]map[string]any{
			"security_policies":     {{"id": 1, "name": "off-clean", "mode": "off", "custom_rules": "[]", "enabled": 1}},
			"security_custom_rules": {{"id": 1, "name": "legacy", "conditions": "[{\"target\":\"uri\",\"operator\":\"contains\",\"pattern\":\"/legacy\"}]", "action": "block", "enabled": 0}},
			"security_block_pages":  {{"id": 1, "name": "默认拦截页", "content": "<html>default</html>", "is_default": 1}},
		},
		EmptyConfigIfNil: true,
	})
	response := postImportShared(t, h.ImportConfigBackup, "/config/import", body)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	var mode string
	if err := db.DB.QueryRow(`SELECT COALESCE(mode,'') FROM security_policies WHERE id=1`).Scan(&mode); err != nil {
		t.Fatalf("read policy mode: %v", err)
	}
	if mode != "off" {
		t.Fatalf("mode=%q, want off（无启用自定义规则不得归一）", mode)
	}
	if warnings := decodeImportWarnings(t, response); warningsContain(warnings, "归一为 custom_only") {
		t.Fatalf("warnings=%v, want 无归一提示", warnings)
	}
}

// Given live 证书任务显式选了 CA 提供商 #2；备份「系统数据」携带的 #2 为禁用。
// When 导入（cert_jobs 未随包）。Then live 任务 provider 悬挂进 warnings + 审计。
func TestImportConfigBackup_warnsDanglingLiveCertJobProvider(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	if _, err := db.DB.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,enabled)
		VALUES (5,'live-ca','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','{}',1);
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,ca_provider_id)
		VALUES ('lb_certjob','certjob','http','certjob.example.test',18443,1,1,'acme_dns',5);
		INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_certjob','certjob.example.test','issued',5);`); err != nil {
		t.Fatalf("seed live cert state: %v", err)
	}
	body := buildBackup(t, backupFixtureOptions{
		Sections: []string{"users"},
		Tables: map[string][]map[string]any{
			"users": {{"id": 1, "username": "backup-admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
			"ca_providers": {{"id": 5, "name": "disabled-ca", "provider": "letsencrypt",
				"directory_url": "https://acme-v02.api.letsencrypt.org/directory", "credentials": "{}", "enabled": 0}},
		},
		EmptyConfigIfNil: true,
	})
	response := postImportShared(t, h.ImportConfigBackup, "/config/import", body)
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
	}
	if warnings := decodeImportWarnings(t, response); !warningsContain(warnings, "证书任务的 CA 提供商已禁用或不存在") {
		t.Fatalf("warnings=%v, want 含证书任务 provider 悬挂提示", warnings)
	}
	var auditCount int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='配置备份' AND detail LIKE '%证书任务的 CA 提供商%'`).Scan(&auditCount); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("证书任务 provider 悬挂未落操作审计")
	}
	// 回归形状：导入不阻断、不改写 live 任务行（只告警）。
	var providerID int
	if err := db.DB.QueryRow(`SELECT COALESCE(ca_provider_id,0) FROM cert_jobs WHERE rule_id='lb_certjob'`).Scan(&providerID); err != nil {
		t.Fatalf("read cert job: %v", err)
	}
	if providerID != 5 {
		t.Fatalf("cert_jobs.ca_provider_id=%d, want 5（导入侧只告警不改写）", providerID)
	}
}
