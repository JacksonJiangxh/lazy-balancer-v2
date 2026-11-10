package services

// 签发执行期两处修复的钉测：
//  1. 首查（任务状态快照）瞬时读失败不得静默回落完整签发（会白烧 CA 订单 +
//     DNS 写入）；保持现态、交补扫/对账接管。
//  2. 规则域名变更导致的旧任务退役是「并发兜底」分支，用户可见状态变化
//     （issued/downloaded→disabled）必须进操作审计（此前只有 warn 日志）。

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// Given 任务行存在但首查出现瞬时 DB 故障（非 ErrNoRows）。
// When 执行签发。
// Then 返回部署类错误保持现态（队列不改写状态），不得进入 ACME 完整签发流程。
func TestCertIssuerIssue_initialStateReadFailureKeepsStateWithoutReissue(t *testing.T) {
	useCertSweepTickTestEnv(t)
	ResetCAQueueManagerForTest()
	t.Cleanup(ResetCAQueueManagerForTest)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_read_fail','rf','http','example.com',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id)
		VALUES ('lb_read_fail','example.com','downloaded',1)`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	// 瞬时读故障注入：关闭库句柄是所有非 ErrNoRows 错误的代表形态（SQLITE_BUSY/
	// IO 与 database is closed 在分流上同型）。关闭后本用例不再查询该库。
	if err := db.DB.Close(); err != nil {
		t.Fatalf("close db to inject read failure: %v", err)
	}

	issueErr := NewCertIssuer(func() error { return nil }).Issue(context.Background(), int(jobID), "lb_read_fail", "example.com", models.CAProvider{ID: 1})

	var deploymentErr *certificateDeploymentError
	if !errors.As(issueErr, &deploymentErr) {
		t.Fatalf("err=%v, want certificateDeploymentError（首查失败必须保持现态，不得回落完整签发）", issueErr)
	}
	if strings.Contains(issueErr.Error(), "CA provider test failed") {
		t.Fatalf("err=%v, 首查失败不得进入 CA 预检/完整签发流程", issueErr)
	}
}

// Given 任务行域名与规则当前域名不一致（并发域名变更窗口）。
// When 执行签发命中「带材料但不适用」的旧任务。
// Then 旧任务转 disabled + 一条「禁用/证书任务」审计（来源=规则域名变更），
// 不为该行重新签发。
func TestCertIssuerIssue_domainMismatchRetireIsAudited(t *testing.T) {
	useCertSweepTickTestEnv(t)
	ResetCAQueueManagerForTest()
	t.Cleanup(ResetCAQueueManagerForTest)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules
		(caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_domain_drift','drift','http','new.example.com',8443,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	result, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,ca_provider_id,cert_pem,key_pem)
		VALUES ('lb_domain_drift','old.example.com','downloaded',1,'CERT','KEY')`)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	jobID, err := result.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	issueErr := NewCertIssuer(func() error { return nil }).Issue(context.Background(), int(jobID), "lb_domain_drift", "new.example.com", models.CAProvider{ID: 1})
	if issueErr != nil {
		t.Fatalf("issue: %v（域名不匹配分支必须平稳退役，不上抛）", issueErr)
	}

	var status, message string
	if err := db.DB.QueryRow(`SELECT status, COALESCE(message,'') FROM cert_jobs WHERE id=?`, jobID).Scan(&status, &message); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "disabled" || !strings.Contains(message, "规则域名已变更") {
		t.Fatalf("job=(%q,%q), want disabled/规则域名已变更", status, message)
	}

	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log
		WHERE action='禁用' AND resource='证书任务' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read retire audit: %v（域名漂移退役必须留审计行）", err)
	}
	if !strings.Contains(detail, "lb_domain_drift") || !strings.Contains(detail, "来源：规则域名变更") {
		t.Fatalf("audit detail=%q, want 规则归因 + 中文来源", detail)
	}
}

// Given 保存/启用/导入侧的签发域名校验。
// When 提交公共 CA 必然拒绝的域名形态。
// Then 必须拒绝；结构层比较口径保持宽松（历史下划线行不得被判「规则不适用」）。
func TestValidateACMEDomainsForIssuance(t *testing.T) {
	for _, tc := range []struct {
		in      string
		wantErr bool
	}{
		{"example.com", false},
		{"example.com,www.example.com", false},
		{"www.example.com,example.com", false},
		{"foo_bar.example.com", true},
		{"localhost", true},
		{"例子.example.com", true},
		{"a.com,b.org", true},
		{"", true},
	} {
		err := ValidateACMEDomainsForIssuance(tc.in)
		if tc.wantErr && err == nil {
			t.Fatalf("ValidateACMEDomainsForIssuance(%q)=nil, want error", tc.in)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("ValidateACMEDomainsForIssuance(%q)=%v, want nil", tc.in, err)
		}
	}
	// 比较层（CanonicalACMEDomains / certJobRuleApplicable）继续接受历史下划线
	// 行——否则老行会被判「规则不适用」而遭退役/断链。
	if _, err := CanonicalACMEDomains("foo_bar.example.com"); err != nil {
		t.Fatalf("CanonicalACMEDomains 必须保持结构层宽松: %v", err)
	}
}
