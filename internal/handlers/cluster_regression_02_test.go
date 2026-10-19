package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

type closeIdleCountingTransport struct {
	closed atomic.Int32
}

func (t *closeIdleCountingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	_ = request
	return nil, errors.New("transport unreachable in test")
}

func (t *closeIdleCountingTransport) CloseIdleConnections() { t.closed.Add(1) }

func TestCallClusterServiceControl_closesIdleConnections(t *testing.T) {
	// Given：工厂每次构造新客户端（其 Transport 自带连接池，IdleConnTimeout=90s）
	transport := &closeIdleCountingTransport{}
	oldFactory := clusterServiceControlClientFactory
	clusterServiceControlClientFactory = func(string) *http.Client {
		return &http.Client{Transport: transport}
	}
	t.Cleanup(func() { clusterServiceControlClientFactory = oldFactory })
	h := &Handlers{cfg: &config.Config{}}

	// When：一次服务控制调用（传输层失败也要走清理路径）
	if _, err := h.callClusterServiceControl(context.Background(), "http://slave.example:8000", models.ClusterServiceActionRestartCaddy, "ticket", "admin"); err == nil {
		t.Fatal("expected transport failure")
	}

	// Then：空闲连接必须被关闭，而不是留到 90s 空闲超时
	if transport.closed.Load() == 0 {
		t.Fatal("per-request client pool must be closed after use")
	}
}

func TestRegisterClusterNode_rejectsOversizedName(t *testing.T) {
	// Given：101 字符节点名（schema VARCHAR(100) 上限）
	h := newBackupTestHandlers(t)
	body := fmt.Sprintf(`{"token":"t","name":%q,"ip_address":"10.0.0.1","port":8000}`, strings.Repeat("x", models.ClusterNodeNameMaxLen+1))
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	// When
	h.RegisterClusterNode(ctx)

	// Then
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
}

func TestRegisterClusterNode_surfacesIgnoredAccessURL(t *testing.T) {
	// Given：有效注册令牌 + 指向第三方主机的自述 access_url
	h := newBackupTestHandlers(t)
	token, _, err := h.clusterService.GenerateRegisterToken(context.Background(), 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"token":%q,"name":"edge-a","ip_address":"10.0.0.21","port":8000,"access_url":"https://attacker.example/collect"}`, token)
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/cluster/register", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")

	// When
	h.RegisterClusterNode(ctx)

	// Then：注册成功但显性告知忽略（不静默）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "已忽略") {
		t.Fatalf("response must disclose the ignored self-declared address: %s", recorder.Body.String())
	}
	var accessURL string
	if err := db.DB.QueryRow("SELECT COALESCE(access_url,'') FROM nodes WHERE ip_address='10.0.0.21'").Scan(&accessURL); err != nil {
		t.Fatal(err)
	}
	if accessURL != "" {
		t.Fatalf("foreign access_url must not be persisted, got %q", accessURL)
	}
	var detail string
	if err := db.AuditDB.QueryRow("SELECT detail FROM audit_log WHERE action='注册' ORDER BY id DESC LIMIT 1").Scan(&detail); err != nil {
		t.Fatalf("read audit detail: %v", err)
	}
	if !strings.Contains(detail, "已忽略") {
		t.Fatalf("audit detail must record the ignored address: %q", detail)
	}
}
