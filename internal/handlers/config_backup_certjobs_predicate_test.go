package handlers

// X-1（历史 历史问题）：导入侧证书任务清理缺口——备份可携带「规则存在但已非
// ACME 自动签发态」的 cert_jobs 行（如 manual 来源规则带任务行）。导入侧的
// 孤儿清理只删「rule_id 不在 lb_rules 中」的行，对这类「规则仍在但已非 ACME」
// 的行不覆盖；残留任务会被续签扫描/任务列表当作活任务（与续签扫描口径
// `enable_tls=1 AND tls_source='acme_dns'` 相悖；禁用但 acme 态的规则任务行保留
// （DisableRule 再启用续期语义，cert_jobs 无补建路径——主审裁定收窄）。
// 修复=导入后追加同谓词清理（v2 导入事务 + v1 协调器后处理两处同语句）。

import (
	"net/http"
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
	if err := validateV2BackupCertJobs(tables); err != nil {
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
