package handlers

// LBS/：UpdateCertificateConfig 旧行读取与动态 UPDATE 必须
// 同事务。本测试直接记录真实 SQLite driver 的 BEGIN/旧行 SELECT 顺序，避免用
// 固定 sleep 制造并发交错：旧实现会先 SELECT 后 BEGIN/UPDATE，契约顺序即失败。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	sqlitedriver "github.com/glebarez/go-sqlite"

	"lazy-balancer-v2/internal/db"
)

type certificateTxOrder struct {
	mu         sync.Mutex
	statements []string
}

func (o *certificateTxOrder) add(statement string) {
	o.mu.Lock()
	o.statements = append(o.statements, statement)
	o.mu.Unlock()
}

type certificateTxOrderConnector struct {
	dsn   string
	inner driver.Driver
	order *certificateTxOrder
}

func (c certificateTxOrderConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &certificateTxOrderConn{Conn: conn, order: c.order}, nil
}

func (c certificateTxOrderConnector) Driver() driver.Driver { return c.inner }

type certificateTxOrderConn struct {
	driver.Conn
	order *certificateTxOrder
}

func (c *certificateTxOrderConn) Begin() (driver.Tx, error) {
	c.order.add("begin")
	return c.Conn.Begin()
}

func (c *certificateTxOrderConn) Prepare(query string) (driver.Stmt, error) {
	if strings.Contains(query, "SELECT name, dns_provider") {
		c.order.add("read-old")
	}
	return c.Conn.Prepare(query)
}

func TestUpdateCertificateConfig_readsOldRowInsideTransaction(t *testing.T) {
	// Given 一个只含本端点所需真实表结构的 SQLite 库与语句顺序探针。
	order := &certificateTxOrder{}
	database := sql.OpenDB(certificateTxOrderConnector{dsn: t.TempDir() + "/certificates.db", inner: &sqlitedriver.Driver{}, order: order})
	if _, err := database.Exec(`CREATE TABLE certificate_configs (
		id INTEGER PRIMARY KEY, name TEXT, dns_provider TEXT, dns_credentials TEXT, enabled BOOLEAN
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES
		(1,'concurrent','dnspod','{"auth_mode":"dnspod","app_id":"old-id","app_token":"old-token"}',1)`); err != nil {
		t.Fatal(err)
	}
	oldDB := db.DB
	db.DB = database
	db.SetDB(database)
	t.Cleanup(func() {
		_ = database.Close()
		db.DB = oldDB
		db.SetDB(oldDB)
	})
	h := &Handlers{}
	router := gin.New()
	router.PUT("/certificate-configs/:id", h.UpdateCertificateConfig)

	// When 提交与库中现值相同的名称，触发旧行读取和无变化收尾。
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/certificate-configs/1", strings.NewReader(`{"name":"concurrent"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	// Then 响应不变，且 BEGIN 必须先于旧行 SELECT；不依赖 goroutine 时序。
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "unchanged") {
		t.Fatalf("status=%d body=%s, want 200 unchanged", recorder.Code, recorder.Body.String())
	}
	order.mu.Lock()
	defer order.mu.Unlock()
	if len(order.statements) != 2 || order.statements[0] != "begin" || order.statements[1] != "read-old" {
		t.Fatalf("statement order=%v, want [begin read-old]", order.statements)
	}
}
