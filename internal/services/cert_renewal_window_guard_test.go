package services

import (
	"database/sql"
	"testing"
	"time"
)

func setRenewalDays(t *testing.T, database *sql.DB, days int) {
	t.Helper()
	if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=? WHERE id=1", days); err != nil {
		t.Fatalf("set renewal days: %v", err)
	}
}

func seedRenewalWindowJob(t *testing.T, database *sql.DB, ruleID, domain string, notBefore, notAfter time.Time) {
	t.Helper()
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source) VALUES (?, 'window', ?, 'http', 8080, 1, 1, 'acme_dns')`, ruleID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	certPEM, keyPEM := certificatePairForDomains(t, notBefore, notAfter, domain)
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at,ca_provider_id)
		VALUES (?, ?, 'issued', ?, ?, ?, 1)`, ruleID, domain, certPEM, keyPEM, notAfter.UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatalf("seed job: %v", err)
	}
}

// 续签窗口覆盖证书寿命时（days*24h >= NotAfter-NotBefore）不得每轮重签：
// 此时「选中证书 NotAfter 晚于 now+days」的去抖门在成功签发后恒假，6h 扫描
// 会把刚签下的证书反复入队；CA 重复证书限流后任务落 failed（只能手动重试），
// 约一个寿命周期后证书到期、TLS 中断。写侧 0-90 与 90 天证书寿命重合是常态，
// 因此防线在扫描侧，且剩余 ≤ 7 天的保护区必须放行续签。
func TestCheckExpiration_skipsRenewalWindowCoveringCertificateLifetime(t *testing.T) {
	now := time.Now()

	t.Run("90 day lifetime with 90 day window", func(t *testing.T) {
		_, database := newClusterTestService(t)
		setRenewalDays(t, database, 90)
		seedRenewalWindowJob(t, database, "lb_window_90", "window90.example.com",
			now.Add(-time.Hour), now.Add(89*24*time.Hour+23*time.Hour))

		jobs, _, err := NewCertificateService().CheckExpiration()
		if err != nil {
			t.Fatalf("check expiration: %v", err)
		}
		if len(jobs) != 0 {
			t.Fatalf("candidates=%d, want 0（窗口覆盖整张寿命，刚签发不得再入队）", len(jobs))
		}
	})

	t.Run("20 day lifetime with 30 day window", func(t *testing.T) {
		_, database := newClusterTestService(t)
		setRenewalDays(t, database, 30)
		seedRenewalWindowJob(t, database, "lb_window_30", "window30.example.com",
			now.Add(-time.Hour), now.Add(19*24*time.Hour))

		jobs, _, err := NewCertificateService().CheckExpiration()
		if err != nil {
			t.Fatalf("check expiration: %v", err)
		}
		if len(jobs) != 0 {
			t.Fatalf("candidates=%d, want 0（30 天窗口 ≥ 20 天寿命）", len(jobs))
		}
	})

	t.Run("protection zone still renews", func(t *testing.T) {
		// 同一「窗口 ≥ 寿命」配置，但证书只剩 1 天：必须放行，避免配置越界
		// 演变成证书到期中断。
		_, database := newClusterTestService(t)
		setRenewalDays(t, database, 30)
		seedRenewalWindowJob(t, database, "lb_window_protect", "windowprotect.example.com",
			now.Add(-19*24*time.Hour), now.Add(24*time.Hour))

		jobs, _, err := NewCertificateService().CheckExpiration()
		if err != nil {
			t.Fatalf("check expiration: %v", err)
		}
		if len(jobs) != 1 {
			t.Fatalf("candidates=%d, want 1（剩余 ≤7 天保护区必须续签）", len(jobs))
		}
	})
}
