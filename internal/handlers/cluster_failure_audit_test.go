package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 集群写端点的失败面必须留痕/映射正确：
//   - 非法 access_url 是客户端可修正输入 → 400（此前落 500，从端包成 502 误判
//     主节点故障）；
//   - 审批/拒绝/删除失败（404/409/5xx）此前零审计（中间件对 explicit 路由无条件
//     早退），现由 auditFailure 单点留痕。

func TestClusterRegistrationHandler_invalidAccessURLMapped400(t *testing.T) {
	h := newBackupTestHandlers(t)
	body := `{"token":"whatever","name":"slave-a","ip_address":"10.0.0.9","port":9000,"access_url":"ftp://evil.example"}`
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.RemoteAddr = "10.0.0.9:5555"

	h.RegisterClusterNode(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（非法访问地址属客户端输入）", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "访问地址无效") {
		t.Fatalf("响应必须直指访问地址，got %s", recorder.Body.String())
	}
}

func TestClusterNodeAction_failureLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/999999/approve", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "999999"}}

	h.ApproveClusterNode(ctx)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
	var detail string
	err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='审批' AND resource='集群节点' ORDER BY id DESC LIMIT 1`).Scan(&detail)
	if err != nil {
		t.Fatalf("失败分支必须留痕（审计行缺失）: %v", err)
	}
	if !strings.Contains(detail, "失败") {
		t.Fatalf("审计详情必须标明失败，got %q", detail)
	}
	if !strings.Contains(detail, fmt.Sprintf("节点 %d", 999999)) {
		t.Fatalf("审计详情必须点名节点，got %q", detail)
	}
}

func TestClusterNodeAction_invalidIDLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/abc/approve", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "abc"}}

	h.ApproveClusterNode(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", recorder.Code)
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='审批' AND detail LIKE '%失败%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("非法编号失败面审计行数=%d, want 1", count)
	}
}

// 站点坐标端点是 Explicit 路由：审计中间件对其失败面无条件早退，handler 必须
// 逐条补记（与 clusterNodeAction 的 auditFailure 同构）。
func TestUpdateClusterNodeSiteCoordinates_failureLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/nodes/999999/site", strings.NewReader(`{"server_map_lat":1.5,"server_map_lon":2.5}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "999999"}}

	h.UpdateClusterNodeSiteCoordinates(ctx)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='集群节点' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("站点坐标失败面必须留痕（审计行缺失）: %v", err)
	}
	if !strings.Contains(detail, "节点 999999") || !strings.Contains(detail, "失败") {
		t.Fatalf("审计详情必须点名节点并标明失败，got %q", detail)
	}
}

func TestUpdateClusterNodeSiteCoordinates_invalidCoordinatesAudited(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/nodes/1/site", strings.NewReader(`{"server_map_lat":999,"server_map_lon":2.5}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}

	h.UpdateClusterNodeSiteCoordinates(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='更新' AND resource='集群节点' AND detail LIKE '%请求格式错误%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("越界坐标失败面审计行数=%d, want 1", count)
	}
}

// 登录票据端点的失败面此前零审计：MFA 未启用/step-up 缺失/节点离线/DB 故障
// 在操作审计页不可回溯，只剩 stdout clusterError 日志。
func TestGenerateClusterLoginTicket_mfaDisabledLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled) VALUES (1,'admin','x','admin',1,0)"); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/1/login-ticket", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	ctx.Set("user_id", 1)

	h.GenerateClusterLoginTicket(ctx)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403（未启用 MFA）", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='生成失败' AND resource='登录票据' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("票据签发失败面必须留痕（审计行缺失）: %v", err)
	}
	if !strings.Contains(detail, "未启用 MFA") {
		t.Fatalf("审计详情必须点明失败原因，got %q", detail)
	}
}

// step-up 缺失（MFA 已启用但 10 分钟内未验证）此前同样零审计：428 属客户端
// 可自愈分支，但仍需可追溯。
func TestGenerateClusterLoginTicket_missingStepUpLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("INSERT INTO users (id,username,password_hash,role,is_enabled,mfa_enabled) VALUES (1,'admin','x','admin',1,1)"); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/1/login-ticket", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "1"}}
	ctx.Set("user_id", 1)
	ctx.Set("auth_type", "jwt")
	ctx.Set("auth_method", "password")

	h.GenerateClusterLoginTicket(ctx)

	if recorder.Code != http.StatusPreconditionRequired {
		t.Fatalf("status=%d body=%s, want 428（step-up 未完成）", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='生成失败' AND resource='登录票据' AND detail LIKE '%step-up%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("step-up 缺失失败面审计行数=%d, want 1", count)
	}
}

// 注册端点的请求绑定失败此前零审计，与同 handler 其余失败面（无效令牌/非法名/
// 缺地址/非法地址）不一致。
func TestRegisterClusterNode_bindFailureLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(`{"name":`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.RemoteAddr = "10.0.0.9:5555"

	h.RegisterClusterNode(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='注册失败' AND resource='集群节点' AND detail='注册请求格式错误'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("绑定失败审计行数=%d, want 1", count)
	}
}

// 访问地址端点同样是 Explicit 路由：请求体绑定失败此前零审计（同族站点坐标
// 端点已补），探测/前端旧缓存提交在操作审计页不可回溯。
func TestUpdateClusterNodeAccessURL_bindFailureLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/cluster/nodes/7/access-url", strings.NewReader(`{"access_url":123}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "id", Value: "7"}}

	h.UpdateClusterNodeAccessURL(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新失败' AND resource='集群节点' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("访问地址绑定失败面必须留痕（审计行缺失）: %v", err)
	}
	if !strings.Contains(detail, "节点 7") || !strings.Contains(detail, "访问地址格式错误") {
		t.Fatalf("审计详情必须点名节点与失败原因，got %q", detail)
	}
}

// 单节点指纹清除的编号非法分支此前零审计：同函数其余失败面（无钉/失败/
// 成功）均有留痕，仅 400 早退分支空白。
func TestForgetClusterNodePin_invalidIDLeavesAuditTrail(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/abc/forget-pin", nil)
	ctx.Params = gin.Params{{Key: "id", Value: "abc"}}

	h.ForgetClusterNodePin(ctx)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='清除失败' AND resource='证书指纹' AND detail LIKE '%节点编号无效（abc）%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("编号非法失败面审计行数=%d, want 1", count)
	}
}
