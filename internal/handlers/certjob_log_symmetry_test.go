package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// 恢复/启用侧必须与禁用侧同通道留痕：禁用写 [WARN] cancelled，
// 重新启用却没有对应行时，用户无法从 certjob-<rule>.log 判断任务何时恢复。
// 断言一律读真实日志文件（与写入端同源 services.CertJobLogPath）。

const (
	certJobLogResumedEnable = "[INFO] resumed - 规则已启用，证书任务已恢复"
	certJobLogResumedUpdate = "[INFO] resumed - 规则已启用，证书任务已恢复（更新规则时重新启用）"
	certJobLogKept          = "[INFO] kept - 规则已启用，证书仍有效，保持现有任务"
	certJobLogQueued        = "[INFO] queued - 规则已启用，已创建证书任务"
)

func useTempCertJobLogDir(t *testing.T) {
	t.Helper()
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(filepath.Join(t.TempDir(), "tasks"))
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
}

func readCertJobLogContent(t *testing.T, ruleID string) string {
	t.Helper()
	content, err := os.ReadFile(services.CertJobLogPath(ruleID))
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read cert job log for %s: %v", ruleID, err)
	}
	return string(content)
}

// seedCertJobLogRule 复用 ACME 规则夹具并落到「规则禁用 + 证书任务持有效材料」
// 形态（证书 90 天后到期，不在续签窗口）。返回任务 id。
func seedCertJobLogRule(t *testing.T, caddyID, domain, jobStatus string) int {
	t.Helper()
	jobID := seedACMEManualSwitchFixture(t, caddyID, domain, jobStatus)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET enabled=0 WHERE caddy_id=?`, caddyID); err != nil {
		t.Fatalf("disable seeded rule: %v", err)
	}
	certPEM, keyPEM := selfSignedPEM(t, domain)
	expiresAt := time.Now().UTC().Add(90 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem=?, key_pem=?, expires_at=? WHERE id=?`, certPEM, keyPEM, expiresAt, jobID); err != nil {
		t.Fatalf("attach certificate material: %v", err)
	}
	return jobID
}

func TestEnableRule_resumeWritesCertJobLog(t *testing.T) {
	// Given：禁用规则 + status=disabled 的任务 + 有效证书 → Resume 分支
	h := newUpdateAuditRuleHandlers(t, "lb_log_resume", 0, false)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	useTempCertJobLogDir(t)
	seedCertJobLogRule(t, "lb_log_resume", "log-resume.example.test", "disabled")
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", h.handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_log_resume/enable", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if log := readCertJobLogContent(t, "lb_log_resume"); !strings.Contains(log, certJobLogResumedEnable) {
		t.Fatalf("cert job log=%q, want %q", log, certJobLogResumedEnable)
	}
}

func TestEnableRule_keepWritesCertJobLog(t *testing.T) {
	// Given：禁用规则 + status=issued 的任务 + 有效证书 → Keep 分支
	h := newUpdateAuditRuleHandlers(t, "lb_log_keep", 0, false)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	useTempCertJobLogDir(t)
	seedCertJobLogRule(t, "lb_log_keep", "log-keep.example.test", "issued")
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", h.handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_log_keep/enable", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if log := readCertJobLogContent(t, "lb_log_keep"); !strings.Contains(log, certJobLogKept) {
		t.Fatalf("cert job log=%q, want %q", log, certJobLogKept)
	}
}

func TestEnableRule_createWritesCertJobLog(t *testing.T) {
	// Given：禁用规则且无任务行 → Create 分支（入队经测试缝返回成功）
	handler, _, _ := newAuditRuleHandlers(t, 0)
	useTempCertJobLogDir(t)
	seedAuditRule(t, "lb_log_create", "log-create", "log-create.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_log_create")
	if _, err := db.DB.Exec("UPDATE lb_rules SET acme_config_id=? WHERE caddy_id='lb_log_create'", seedR52CertificateConfig(t)); err != nil {
		t.Fatalf("bind certificate config: %v", err)
	}
	oldCreate := createOrRequeueCertJobVerified
	createOrRequeueCertJobVerified = func(string, string, int, *services.CAQueueManager) (int, bool, error) {
		return 42, true, nil
	}
	t.Cleanup(func() { createOrRequeueCertJobVerified = oldCreate })
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_log_create/enable", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if log := readCertJobLogContent(t, "lb_log_create"); !strings.Contains(log, certJobLogQueued) {
		t.Fatalf("cert job log=%q, want %q", log, certJobLogQueued)
	}
}

func TestUpdateRule_reEnableWritesCertJobLogResumed(t *testing.T) {
	// Given：禁用规则 + status=disabled 的任务 + 有效证书，PUT 重新启用
	harness := newUpdateAuditRuleHandlers(t, "lb_log_reupdate", 0, false)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	useTempCertJobLogDir(t)
	seedCertJobLogRule(t, "lb_log_reupdate", "log-reupdate.example.test", "disabled")

	// When
	response := putUpdateRule(t, harness, "lb_log_reupdate", `{"enabled":true}`)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if log := readCertJobLogContent(t, "lb_log_reupdate"); !strings.Contains(log, certJobLogResumedUpdate) {
		t.Fatalf("cert job log=%q, want %q", log, certJobLogResumedUpdate)
	}
}

func TestUpdateRule_editWithoutReEnableWritesNoResumedLog(t *testing.T) {
	// Given：规则保持禁用，仅改名（wasReEnabled=false）
	harness := newUpdateAuditRuleHandlers(t, "lb_log_noresume", 0, false)
	t.Cleanup(services.SetCertDirForTest(t.TempDir()))
	useTempCertJobLogDir(t)
	seedCertJobLogRule(t, "lb_log_noresume", "log-noresume.example.test", "disabled")

	// When
	response := putUpdateRule(t, harness, "lb_log_noresume", `{"name":"renamed"}`)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if log := readCertJobLogContent(t, "lb_log_noresume"); strings.Contains(log, "[INFO] resumed") {
		t.Fatalf("cert job log=%q, 未启用变化不得写 resumed 行", log)
	}
}
