package handlers

// 大屏本站坐标配置面（v3 规格第 3 项：面板设置里的公网坐标，缺省用地图视觉
// 中心）——主节点坐标为节点级默认值；未单独配置的从节点通过集群 node_sites
// 快照继承主节点坐标，主节点自身字段仍不进入 global_config 通用同步列。
// 写侧范围校验（纬度 ±90 / 经度 ±180），0,0=未设置（前端回退视觉中心）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func newServerMapConfigRouter(t *testing.T) *gin.Engine {
	t.Helper()
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)
	router.GET("/config", handler.GetConfig)
	return router
}

func putConfigJSON(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func readServerMapCoords(t *testing.T, router *gin.Engine) (float64, float64) {
	t.Helper()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET /config status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data models.GlobalConfig `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	return payload.Data.ServerMapLat, payload.Data.ServerMapLon
}

func TestPutConfig_serverMapCoordsPersistAndOmissionKeepsValue(t *testing.T) {
	preserveApplicationLogLevel(t, "")
	// Given: 全新配置（0,0=未设置 → 前端回退地图视觉中心）
	router := newServerMapConfigRouter(t)
	if lat, lon := readServerMapCoords(t, router); lat != 0 || lon != 0 {
		t.Fatalf("初始坐标=(%v,%v), want (0,0) 未设置", lat, lon)
	}

	// When: 提交本站坐标
	if response := putConfigJSON(t, router, `{"server_map_lat":31.23,"server_map_lon":121.47}`); response.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", response.Code, response.Body.String())
	}

	// Then: 回读同级值（写侧入库 + 读侧直读，非兜底常量）
	if lat, lon := readServerMapCoords(t, router); lat != 31.23 || lon != 121.47 {
		t.Fatalf("回读坐标=(%v,%v), want (31.23,121.47)", lat, lon)
	}

	// 省略字段（只改日志级别）→ 坐标保持现值（COALESCE 语义）
	if response := putConfigJSON(t, router, `{"log_level":"warn"}`); response.Code != http.StatusOK {
		t.Fatalf("PUT omit status=%d body=%s", response.Code, response.Body.String())
	}
	if lat, lon := readServerMapCoords(t, router); lat != 31.23 || lon != 121.47 {
		t.Fatalf("省略提交后坐标=(%v,%v), want 保持 (31.23,121.47)", lat, lon)
	}
}

func TestPutConfig_serverMapCoordsRangeValidation(t *testing.T) {
	// Given: 已设置坐标
	router := newServerMapConfigRouter(t)
	if response := putConfigJSON(t, router, `{"server_map_lat":31.23,"server_map_lon":121.47}`); response.Code != http.StatusOK {
		t.Fatalf("seed PUT status=%d", response.Code)
	}

	// When/Then: 越界坐标 400 且不改库值（fail-visible，不静默钳位）
	for _, body := range []string{
		`{"server_map_lat":91}`,
		`{"server_map_lat":-90.5}`,
		`{"server_map_lon":181}`,
		`{"server_map_lon":-180.5}`,
	} {
		response := putConfigJSON(t, router, body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d body=%s, want 400", body, response.Code, response.Body.String())
		}
	}
	if lat, lon := readServerMapCoords(t, router); lat != 31.23 || lon != 121.47 {
		t.Fatalf("越界提交后坐标被改写=(%v,%v), want 保持 (31.23,121.47)", lat, lon)
	}

	// 边界值合法（±90 / ±180）
	for _, body := range []string{
		`{"server_map_lat":90,"server_map_lon":180}`,
		`{"server_map_lat":-90,"server_map_lon":-180}`,
	} {
		if response := putConfigJSON(t, router, body); response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s, want 200（边界值合法）", body, response.Code, response.Body.String())
		}
	}
	if lat, lon := readServerMapCoords(t, router); lat != -90 || lon != -180 {
		t.Fatalf("边界提交后坐标=(%v,%v), want (-90,-180)", lat, lon)
	}
}

func TestPutConfig_serverMapCoordsBumpClusterVersion(t *testing.T) {
	// Given: 主节点坐标作为未配置从节点的默认值
	router := newServerMapConfigRouter(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET cluster_version=7 WHERE id=1`); err != nil {
		t.Fatalf("seed version: %v", err)
	}

	// When: 保存主节点坐标
	if response := putConfigJSON(t, router, `{"server_map_lat":31.23,"server_map_lon":121.47}`); response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	// Then: 版本递增一次，从节点下次拉取才能拿到新的默认坐标
	var version int
	if err := db.DB.QueryRow(`SELECT cluster_version FROM global_config WHERE id=1`).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != 8 {
		t.Fatalf("cluster_version=%d, want 8", version)
	}
}

func TestServerMapCoords_areNodeLocalNotGenericClusterColumns(t *testing.T) {
	// Given: server_map_lat/lon 是节点级坐标：主节点通过 nodes 表为每个从节点
	// 独立配置，快照以 node_sites 映射下发（见 cluster_node_site_test.go）。
	// When/Then: 它们仍不得进入 global_config 通用列/触发器——否则任一节点
	// 坐标变化会走全量配置节并以主节点单值覆盖所有从节点。
	content, err := os.ReadFile("../middleware/cluster_version.go")
	if err != nil {
		t.Fatalf("read cluster_version.go: %v", err)
	}
	if strings.Contains(string(content), "server_map_lat") {
		t.Errorf("cluster_version.go 出现 server_map_lat——站点坐标不得进入 global_config 通用同步触发器")
	}
}
