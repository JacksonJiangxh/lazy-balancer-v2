package services

import (
	"log"
	"strings"
	"testing"
)

// U7-P5-2（第 62 轮审计）：checkManualCertExpiration 的 cert_expiry_days 读取
// 收敛到既有 helper GetCertExpiryThreshold（certinfo.go）——读取失败告警由内联
// warn 级统一为 error 级（与 cert_renewal_days 读取族 CERT42-5 口径一致）。
func TestU7_P5_2_checkManualCertExpiration_expiryReadFailureLogsAtErrorLevel(t *testing.T) {
	// Given a broken global_config read（表被改名，读取必失败）
	_, database := newClusterTestService(t)
	if _, err := database.Exec("ALTER TABLE global_config RENAME TO global_config_u752_bak"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := database.Exec("ALTER TABLE global_config_u752_bak RENAME TO global_config"); err != nil {
			t.Errorf("restore global_config: %v", err)
		}
	})
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When
	NewCertificateService().checkManualCertExpiration()

	// Then：降级读取经 helper 以 error 级告警，内联 warn 级旧消息消失
	if !strings.Contains(buf.String(), "ERROR: GetCertExpiryThreshold: failed to read global_config") {
		t.Fatalf("degraded cert_expiry_days read must log at error level via GetCertExpiryThreshold, log:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "cert expiration check: read cert_expiry_days failed") {
		t.Fatalf("legacy inline warn-level read must be gone, log:\n%s", buf.String())
	}
}

// U7-P5-2：GetCertRenewalDays 契约钉——配置值原样生效；读库失败降级 30 且恰好
// 一条 error 告警（CERT42-5 家族口径，R42 钉的 helper 侧镜像）；0/负值回退 30
// （2026-09-07 C2：UI 输入 min=1，0/负值仅 API 直写/导入可达，按 30 天兜底）。
func TestU7_P5_2_GetCertRenewalDays_contract(t *testing.T) {
	_, database := newClusterTestService(t)

	if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=7 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := GetCertRenewalDays(); got != 7 {
		t.Fatalf("GetCertRenewalDays()=%d, want 7", got)
	}

	if _, err := database.Exec("UPDATE global_config SET cert_renewal_days=0 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got := GetCertRenewalDays(); got != 30 {
		t.Fatalf("GetCertRenewalDays()=%d, want 30 for non-positive config", got)
	}

	if _, err := database.Exec("ALTER TABLE global_config RENAME TO global_config_u752_bak"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := database.Exec("ALTER TABLE global_config_u752_bak RENAME TO global_config"); err != nil {
			t.Errorf("restore global_config: %v", err)
		}
	})
	var buf strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	if got := GetCertRenewalDays(); got != 30 {
		t.Fatalf("GetCertRenewalDays()=%d, want 30 on read failure", got)
	}
	if got := strings.Count(buf.String(), "GetCertRenewalDays: failed to read global_config"); got != 1 {
		t.Fatalf("degraded read alert count=%d, want 1, log:\n%s", got, buf.String())
	}
}
