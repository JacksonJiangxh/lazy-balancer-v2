package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 节点已被主节点删除后，从端重试上报/脱离通知必须得到「身份不存在」语义：
// 非 detached 上报 404（停止重试），detached 更通知按幂等成功 200；
// 此前统一 500 会让从端按「服务端故障」持续重试并写入 last_sync_error。
func TestReportClusterNode_nodeNotFoundMapping(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/cluster/nodes/report", func(c *gin.Context) {
		c.Set("cluster_node_id", 999) // 库中不存在/已删除的节点身份
		h.ReportClusterNode(c)
	})
	post := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cluster/nodes/report", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(rec, req)
		return rec
	}

	rec := post(`{"detached":true,"service_status":"ok"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("detached report status=%d body=%s, want 200（重复脱离通知幂等）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "节点已不在集群") {
		t.Fatalf("detached body=%s, want 节点已不在集群", rec.Body.String())
	}

	rec = post(`{"service_status":"ok"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status report status=%d body=%s, want 404（节点身份已不存在）", rec.Code, rec.Body.String())
	}
}
