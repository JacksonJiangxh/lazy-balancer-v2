package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 节点已被主节点删除后，从端重试上报/脱离通知必须得到语义正确的应答：
// 非 detached 上报 404（身份不存在；上报循环的终止由下一轮 Pull 的 401 令牌
// 撤销承担，本端点不承担「停手」职责），detached 更通知按幂等成功 200；
// 此前统一 500 会让从端把「节点已删」误报为「服务端故障」并持续写入
// last_sync_error。
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
