package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 续签窗口必须比证书寿命至少小一整天（90 天规划寿命 ⇒ ≤88 天），否则窗口门
// 会让相邻两次自动续签的间隔退化到日级：证书一签发就落进窗口，每轮扫描整轮
// 重签 → CA 重复证书限流 → 任务 failed → 约一个寿命后到期中断。写侧拒绝、
// 导入钳制共用 services.CertRenewalDaysMax 单源（CA 实际寿命短于规划值时由
// 扫描侧 services.certRenewalWindowForLifetime 再收敛）。
func TestUpdateConfig_rejectsRenewalWindowAboveSafeMax(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", h.UpdateConfig)
	router.POST("/config/preview", h.PreviewConfigUpdate)
	call := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	readStored := func() int {
		t.Helper()
		var stored int
		if err := db.DB.QueryRow(`SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1`).Scan(&stored); err != nil {
			t.Fatalf("read cert_renewal_days: %v", err)
		}
		return stored
	}
	before := readStored()

	for _, days := range []int{services.CertRenewalDaysMax + 1, services.CertRenewalLifetimeDays} {
		body := `{"source":"basic","cert_renewal_days":` + strconv.Itoa(days) + `}`
		save := call(http.MethodPut, "/config", body)
		if save.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d resp=%s, want 400（窗口接近寿命会日级重签）", body, save.Code, save.Body.String())
		}
		if !strings.Contains(save.Body.String(), strconv.Itoa(services.CertRenewalDaysMax)) {
			t.Fatalf("body=%s resp=%s, want 点名安全上限 %d", body, save.Body.String(), services.CertRenewalDaysMax)
		}
		if stored := readStored(); stored != before {
			t.Fatalf("body=%s 拒绝后 stored=%d, want 原值 %d（不得部分落库）", body, stored, before)
		}
	}
	// 预览与保存同组校验：预览也必须 400。
	preview := call(http.MethodPost, "/config/preview",
		`{"source":"basic","cert_renewal_days":`+strconv.Itoa(services.CertRenewalDaysMax+1)+`}`)
	if preview.Code != http.StatusBadRequest {
		t.Fatalf("preview status=%d resp=%s, want 400（与保存同口径）", preview.Code, preview.Body.String())
	}

	// 安全上限本身必须被接受。
	valid := `{"source":"basic","cert_renewal_days":` + strconv.Itoa(services.CertRenewalDaysMax) + `}`
	if save := call(http.MethodPut, "/config", valid); save.Code != http.StatusOK {
		t.Fatalf("body=%s status=%d resp=%s, want 200", valid, save.Code, save.Body.String())
	}
	if stored := readStored(); stored != services.CertRenewalDaysMax {
		t.Fatalf("stored=%d, want %d", stored, services.CertRenewalDaysMax)
	}
}

func TestImportConfigBackup_clampsRenewalWindowToSafeMax(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := legacyBackupJSON(t, nil, map[string]any{"cert_renewal_days": services.CertRenewalDaysMax + 1}, nil)
	rec := importBackupShared(h, t, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（钳制不阻断导入）", rec.Code, rec.Body.String())
	}
	var stored int
	if err := db.DB.QueryRow(`SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != services.CertRenewalDaysMax {
		t.Fatalf("cert_renewal_days=%d, want %d（导入钳制到安全上限）", stored, services.CertRenewalDaysMax)
	}
	var clampAudits int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE resource='配置备份' AND detail LIKE '%cert_renewal_days 越界%'`).Scan(&clampAudits); err != nil {
		t.Fatalf("read import audit: %v", err)
	}
	if clampAudits == 0 {
		var sample string
		_ = db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE resource='配置备份' ORDER BY id DESC LIMIT 1`).Scan(&sample)
		t.Fatalf("钳制留痕审计缺失（显式而非静默改写），最新 detail=%q", sample)
	}
}
