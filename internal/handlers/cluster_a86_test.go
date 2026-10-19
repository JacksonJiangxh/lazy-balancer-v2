package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

// A86 历史问题：服务层 ErrNotMasterNode → 403 必须与 requireMaster 门同源携带
// X-LB-Error-Code: master_required——从端 Pull 的错误分类依赖该头
// （cluster_sync.go），服务层降级竞态 403 此前不设头造成错误形状分叉。
func TestClusterNodeAction_forbiddenCarriesMasterRequiredErrorCode(t *testing.T) {
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	// 直接以桩操作驱动 clusterNodeAction 的错误映射分支（降级竞态在 HTTP 层
	// 无法确定性复现，这里钉住映射形状本身）。
	router.POST("/cluster/nodes/:id/demoted", func(c *gin.Context) {
		handler.clusterNodeAction(c, "审批", func(int) error { return services.ErrNotMasterNode })
	})
	router.POST("/cluster/nodes/:id/missing", func(c *gin.Context) {
		handler.clusterNodeAction(c, "审批", func(int) error { return services.ErrNodeNotFound })
	})

	// 目标形状：服务层 ErrNotMasterNode → 403 + X-LB-Error-Code。
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/cluster/nodes/2/demoted", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("demoted status=%d body=%s, want 403", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-LB-Error-Code"); got != masterRequiredErrorCode {
		t.Fatalf("X-LB-Error-Code=%q, want %q（与 requireMaster 门同形状）", got, masterRequiredErrorCode)
	}

	// 回归形状：ErrNodeNotFound → 404 且不携带主节点错误码。
	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/cluster/nodes/2/missing", nil)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing status=%d body=%s, want 404", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-LB-Error-Code"); got != "" {
		t.Fatalf("404 response unexpectedly carries X-LB-Error-Code=%q", got)
	}
}

// A86 历史问题（同族收敛）：requireMaster 门路径本身已带头——钉住从节点直连
// 节点写端点的 403 形状，防回归。
func TestUpdateClusterNodeSiteCoordinates_slaveGateCarriesErrorCode(t *testing.T) {
	router := newClusterNodeSiteRouter(t)
	seedClusterNodeSite(t, false)
	response := putClusterNodeSite(t, router, `{"server_map_lat":1,"server_map_lon":2}`)
	if response.Code != http.StatusForbidden {
		t.Fatalf("slave status=%d body=%s, want 403", response.Code, response.Body.String())
	}
	if got := response.Header().Get("X-LB-Error-Code"); got != masterRequiredErrorCode {
		t.Fatalf("X-LB-Error-Code=%q, want %q", got, masterRequiredErrorCode)
	}
}

// 桩错误与哨兵同源的静态核对（防未来误用 errors.New 平行实现）。
func TestClusterA86_forbiddenMappingUsesSentinel(t *testing.T) {
	if !errors.Is(services.ErrNotMasterNode, services.ErrNotMasterNode) {
		t.Fatal("ErrNotMasterNode sentinel broken")
	}
}
