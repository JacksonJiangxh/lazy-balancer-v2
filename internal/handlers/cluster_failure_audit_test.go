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
