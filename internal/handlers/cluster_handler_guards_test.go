package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 装配缺失必须 fail-closed 503（与 Pull/ForgetPins/mode/sync 同族），
// 而不是 nil 解引用走 Gin recovery 的空体 500——运维无法区分「服务未装配」
// 与真实内部故障。
func TestRequireMaster_missingClusterServiceReturns503(t *testing.T) {
	h := &Handlers{}
	router := gin.New()
	router.GET("/nodes", h.ListClusterNodes)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/nodes", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "集群服务未初始化") {
		t.Fatalf("body=%s, want 集群服务未初始化", recorder.Body.String())
	}
}

// 服务控制失败审计的节点编号必须经 registerAuditField 清洗：
// 已认证管理员可经路径参数注入换行/控制字符伪造审计段落。
func TestControlClusterNodeService_auditDetailSanitizesNodeID(t *testing.T) {
	setupClusterServiceControlDB(t)
	router := newMasterTestRouter(t)

	request := httptest.NewRequest(http.MethodPost, "/nodes/a%0Aforged%3A%20admin/service", strings.NewReader(`{"action":"bogus"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}

	details := auditDetailsServiceControlRows(t)
	if len(details) != 1 {
		t.Fatalf("audit details=%v, want 1 failure row", details)
	}
	detail := details[0]
	if strings.ContainsAny(detail, "\n\r\t\x00") {
		t.Fatalf("审计 detail 仍含控制字符: %q", detail)
	}
	// 可打印原值保留供取证（只清洗控制字符，不回退为丢弃原值）。
	if !strings.Contains(detail, "aforged: admin") {
		t.Fatalf("审计 detail=%q, want 保留可打印原值", detail)
	}
}

// 导入窗口内下发票据/文件必须 409 fast-fail：本端点打包时取 WafFileLock，
// 与导入会话（排空阶段即预持该锁）互斥，不接门会阻塞到导入结束。
func TestGetClusterWafFiles_409DuringImportWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("UPDATE global_config SET is_master=1 WHERE id=1"); err != nil {
		t.Fatal(err)
	}

	configImportBeginMu.Lock()
	busyRecorder := httptest.NewRecorder()
	h.GetClusterWafFiles(ginTestContext(busyRecorder))
	configImportBeginMu.Unlock()
	if busyRecorder.Code != http.StatusConflict {
		t.Fatalf("导入窗口内 status=%d body=%s, want 409", busyRecorder.Code, busyRecorder.Body.String())
	}

	// 窗口外放行：具体落点必须是 404「主节点无安全数据」（无文件形态），
	// 只断言「不是 409」会让 500/503 同样通过——装配缺失或打包故障会静默混过。
	freeRecorder := httptest.NewRecorder()
	h.GetClusterWafFiles(ginTestContext(freeRecorder))
	if freeRecorder.Code != http.StatusNotFound {
		t.Fatalf("导入窗口外 status=%d body=%s, want 404（主节点无安全数据）", freeRecorder.Code, freeRecorder.Body.String())
	}
	if !strings.Contains(freeRecorder.Body.String(), "主节点无安全数据") {
		t.Fatalf("导入窗口外 body=%s, want 点名无安全数据", freeRecorder.Body.String())
	}
}

func ginTestContext(recorder *httptest.ResponseRecorder) *gin.Context {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/cluster/waf/files", nil)
	context, _ := gin.CreateTestContext(recorder)
	context.Request = request
	return context
}
