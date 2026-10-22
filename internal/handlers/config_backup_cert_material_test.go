package handlers

import (
	"strings"
	"testing"
)

// 启用 ACME 规则可在导入中携带 issued + 未来到期 + 空 PEM 的任务；渲染侧
// 无证书即不发射 TLS 策略，EnableRule 又走 Keep 不补签。
func TestValidateV2BackupCertJobs_rejectsIssuedWithoutMaterial(t *testing.T) {
	tables := map[string][]map[string]any{
		"lb_rules": {{
			"caddy_id": "lb_cert", "name": "cert", "protocol": "http",
			"enabled": true, "enable_tls": true, "tls_source": "acme_dns",
			"domain": "cert.example.com",
		}},
		"cert_jobs": {{
			"rule_id": "lb_cert", "domain": "cert.example.com", "status": "issued",
			"expires_at": "2099-01-01 00:00:00", "cert_pem": "", "key_pem": "",
		}},
	}
	_, err := validateV2BackupCertJobs(tables)
	if err == nil || !strings.Contains(err.Error(), "证书材料") {
		t.Fatalf("err=%v, want empty certificate material rejection", err)
	}
}

func TestValidateV2BackupCertJobs_acceptsIssuedWithMaterialOrQueued(t *testing.T) {
	baseRule := map[string]any{
		"caddy_id": "lb_cert", "name": "cert", "protocol": "http",
		"enabled": true, "enable_tls": true, "tls_source": "acme_dns",
		"domain": "cert.example.com",
	}
	cases := []struct {
		name string
		job  map[string]any
	}{
		{"issued with pem", map[string]any{"rule_id": "lb_cert", "domain": "cert.example.com", "status": "issued", "cert_pem": "CERT", "key_pem": "KEY"}},
		{"queued will issue", map[string]any{"rule_id": "lb_cert", "domain": "cert.example.com", "status": "queued"}},
		{"failed will retry", map[string]any{"rule_id": "lb_cert", "domain": "cert.example.com", "status": "failed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tables := map[string][]map[string]any{"lb_rules": {baseRule}, "cert_jobs": {tc.job}}
			if _, err := validateV2BackupCertJobs(tables); err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}
