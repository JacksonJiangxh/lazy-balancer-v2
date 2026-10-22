package handlers

// 导入侧证书任务清理缺口——备份可携带「规则存在但已非
// ACME 自动签发态」的 cert_jobs 行（如 manual 来源规则带任务行）。导入侧的
// 孤儿清理只删「rule_id 不在 lb_rules 中」的行，对这类「规则仍在但已非 ACME」
// 的行不覆盖；残留任务会被续签扫描/任务列表当作活任务（与续签扫描口径
// `enable_tls=1 AND tls_source='acme_dns'` 相悖；禁用但 acme 态的规则任务行保留
// （DisableRule 再启用续期语义，cert_jobs 无补建路径——主审裁定收窄）。
// 修复=导入后追加同谓词清理（v2 导入事务 + v1 协调器后处理两处同语句）。

import (
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestImportConfigBackup_purgesCertJobsOfNonACMERules(t *testing.T) {
	// Given：备份含一条 manual 来源规则 + 其 cert_jobs 行（规则非 ACME 态）
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_manualrule", "name": "manualrule", "protocol": "http", "domain": "manual.example.test",
				"listen_port": 8080, "enabled": 1, "enable_tls": 0, "tls_source": "manual"},
		},
		"cert_jobs": {
			{"rule_id": "lb_manualrule", "domain": "manual.example.test", "status": "issued"},
		},
	}, EmptyConfigIfNil: true})

	// When
	response := postBackupImport(t, h, backup)

	// Then：导入成功、规则保留，但其证书任务行被清理（0 行）
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var ruleCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_manualrule'`).Scan(&ruleCount); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if ruleCount != 1 {
		t.Fatalf("manual rule rows=%d, want 1（规则本身须保留）", ruleCount)
	}
	var jobCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_manualrule'`).Scan(&jobCount); err != nil {
		t.Fatalf("read cert_jobs: %v", err)
	}
	if jobCount != 0 {
		t.Fatalf("非 ACME 规则的 cert_jobs 行=%d, want 0（导入须清理失效任务）", jobCount)
	}
}

// 收窄裁定（主审，2026-10-13）：禁用但仍 acme_dns 态的规则，其 disabled 任务行
// **保留**——DisableRule 刻意保留行供再启用续期（cert_jobs 无自动补建路径）。
func TestImportConfigBackup_keepsDisabledACMERuleCertJobs(t *testing.T) {
	// Given：备份含一条禁用但 acme_dns 态规则 + 其 cert_jobs 行
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {
			{"caddy_id": "lb_disabledacme", "name": "disabledacme", "protocol": "http", "domain": "disacme.example.test",
				"listen_port": 8081, "enabled": 0, "enable_tls": 1, "tls_source": "acme_dns"},
		},
		"cert_jobs": {
			{"rule_id": "lb_disabledacme", "domain": "disacme.example.test", "status": "disabled"},
		},
	}, EmptyConfigIfNil: true})

	// When
	response := postBackupImport(t, h, backup)

	// Then：导入成功且任务行保留（再启用续期链不断）
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var jobCount int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE rule_id='lb_disabledacme'`).Scan(&jobCount); err != nil {
		t.Fatalf("read cert_jobs: %v", err)
	}
	if jobCount != 1 {
		t.Fatalf("禁用 ACME 规则的 cert_jobs 行=%d, want 1（保留供再启用续期）", jobCount)
	}
}

func TestValidateV2BackupCertJobs_canonicalizesStoredDomain(t *testing.T) {
	const rawDomain = "WWW.JobDomain.example.test,JOBDOMAIN.example.test"
	if got := canonicalACMEDomainForJobLookup(rawDomain); got != "jobdomain.example.test,www.jobdomain.example.test" {
		t.Fatalf("canonical helper returned %q", got)
	}
	tables := map[string][]map[string]any{
		"lb_rules": {{
			"caddy_id": "lb_jobdomain", "name": "jobdomain", "protocol": "http",
			"domain": "WWW.JobDomain.example.test, jobdomain.example.test", "enabled": 0,
			"enable_tls": 1, "tls_source": "acme_dns",
		}},
		"cert_jobs": {{
			"rule_id": "lb_jobdomain", "domain": " WWW.JobDomain.example.test, JOBDOMAIN.example.test ", "status": "disabled",
		}},
	}
	if _, err := validateV2BackupCertJobs(tables); err != nil {
		t.Fatalf("validate cert jobs: %v", err)
	}
	if got := tables["cert_jobs"][0]["domain"]; got != "jobdomain.example.test,www.jobdomain.example.test" {
		t.Fatalf("normalized domain=%v, want canonical", got)
	}
}

func TestImportConfigBackup_canonicalizesACMEJobDomains(t *testing.T) {
	// Given a disabled ACME rule whose resumable job uses a case/order-variant domain.
	h := newBackupTestHandlers(t)
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {{
			"caddy_id": "lb_jobdomain", "name": "jobdomain", "protocol": "http",
			"domain": "WWW.JobDomain.example.test, jobdomain.example.test", "listen_port": 8082,
			"enabled": 0, "enable_tls": 1, "tls_source": "acme_dns",
		}},
		"cert_jobs": {{
			"rule_id": "lb_jobdomain", "domain": " WWW.JobDomain.example.test, JOBDOMAIN.example.test ", "status": "disabled",
		}},
	}, EmptyConfigIfNil: true})

	// When importing the backup.
	response := postBackupImport(t, h, backup)

	// Then the sole resumable job is stored under the canonical lookup key.
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var domain string
	var count int
	if err := db.DB.QueryRow(`SELECT domain, COUNT(*) FROM cert_jobs WHERE rule_id='lb_jobdomain'`).Scan(&domain, &count); err != nil {
		t.Fatalf("read imported cert job: %v", err)
	}
	if count != 1 || domain != "jobdomain.example.test,www.jobdomain.example.test" {
		t.Fatalf("cert jobs count=%d domain=%q, want one canonical domain", count, domain)
	}
}

// cert_jobs.ca_provider_id 参与导入期可解析性校验：悬挂/已禁用引用会让
// 非终态任务首次入队即落 failed 终态（loadCAProvider 对「存在但禁用」显性
// 报错）——导入期归一为 0（跟随默认）并产出警告，而不是静默带入运行态。
func TestValidateV2BackupCertJobs_normalizesDanglingCAProvider(t *testing.T) {
	enabledACMERule := map[string]any{
		"caddy_id": "bak-acme", "name": "bak-acme", "protocol": "http",
		"domain": "jobdomain.example.test", "enabled": int64(1), "enable_tls": int64(1), "tls_source": "acme_dns",
		"acme_config_id": int64(3),
	}
	jobWithProvider := func(id any) map[string]any {
		return map[string]any{"rule_id": "bak-acme", "domain": "jobdomain.example.test", "status": "queued", "ca_provider_id": id}
	}

	t.Run("已禁用提供商归一为跟随默认", func(t *testing.T) {
		job := jobWithProvider(int64(9))
		tables := map[string][]map[string]any{
			"lb_rules":            {enabledACMERule},
			"cert_jobs":           {job},
			"ca_providers":        {{"id": int64(9), "enabled": int64(0)}},
			"certificate_configs": {{"id": int64(3), "enabled": int64(1)}},
		}
		warnings, err := validateV2BackupCertJobs(tables)
		if err != nil {
			t.Fatalf("unexpected rejection: %v", err)
		}
		if got := job["ca_provider_id"]; got != 0 {
			t.Fatalf("ca_provider_id=%v, want 0（归一跟随默认）", got)
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "CA 提供商") {
			t.Fatalf("warnings=%v, want 1 条提供商归一警告", warnings)
		}
	})

	t.Run("悬挂引用同样归一", func(t *testing.T) {
		job := jobWithProvider(int64(99))
		tables := map[string][]map[string]any{
			"lb_rules":            {enabledACMERule},
			"cert_jobs":           {job},
			"ca_providers":        {{"id": int64(9), "enabled": int64(1)}},
			"certificate_configs": {{"id": int64(3), "enabled": int64(1)}},
		}
		warnings, err := validateV2BackupCertJobs(tables)
		if err != nil {
			t.Fatalf("unexpected rejection: %v", err)
		}
		if got := job["ca_provider_id"]; got != 0 {
			t.Fatalf("ca_provider_id=%v, want 0（悬挂归一）", got)
		}
		if len(warnings) != 1 {
			t.Fatalf("warnings=%v, want 1 条警告", warnings)
		}
	})

	t.Run("启用提供商不受影响", func(t *testing.T) {
		job := jobWithProvider(int64(9))
		tables := map[string][]map[string]any{
			"lb_rules":            {enabledACMERule},
			"cert_jobs":           {job},
			"ca_providers":        {{"id": int64(9), "enabled": int64(1)}},
			"certificate_configs": {{"id": int64(3), "enabled": int64(1)}},
		}
		warnings, err := validateV2BackupCertJobs(tables)
		if err != nil {
			t.Fatalf("unexpected rejection: %v", err)
		}
		if got := job["ca_provider_id"]; got != int64(9) {
			t.Fatalf("ca_provider_id=%v, want 9（启用引用保持）", got)
		}
		if len(warnings) != 0 {
			t.Fatalf("warnings=%v, want 空", warnings)
		}
	})

	t.Run("无提供商引用零告警零数据库依赖", func(t *testing.T) {
		job := map[string]any{"rule_id": "bak-acme", "domain": "jobdomain.example.test", "status": "queued"}
		tables := map[string][]map[string]any{
			"lb_rules":            {enabledACMERule},
			"cert_jobs":           {job},
			"certificate_configs": {{"id": int64(3), "enabled": int64(1)}},
		}
		warnings, err := validateV2BackupCertJobs(tables)
		if err != nil || len(warnings) != 0 {
			t.Fatalf("warnings=%v err=%v, want 空/nil（无引用不得触碰 ca_providers）", warnings, err)
		}
	})
}
