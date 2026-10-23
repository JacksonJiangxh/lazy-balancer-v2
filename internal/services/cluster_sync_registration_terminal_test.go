package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/config"
)

// 注册确认终止轨道的两条不变量：
//   - 5 连败的终止文案（含次数与人工介入指引）必须最终留在 last_sync_error，
//     不得被随后落库的通用「已被拒绝」文案覆盖；
//   - 计数读取失败是暂时性故障，不得按「已达上限」处理而清空注册态。

func TestSyncService_pollRegistration_terminalMessageOutlivesGenericMessage(t *testing.T) {
	_, database := newClusterTestService(t)
	setNodeMasterRole(t, database, false)
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusUnauthorized)
	}))
	defer master.Close()
	// 第 5 次失败即终止：计数从 4 起，轮询一次写 5。
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url=?, registration_id=7,
		registration_secret='pending-secret', cluster_token='approved-token', registration_confirm_failures=4 WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	service.pollRegistration(context.Background())

	var stored string
	var failures int
	var secret string
	if err := database.QueryRow(`SELECT COALESCE(last_sync_error,''),
		COALESCE(registration_confirm_failures,0), COALESCE(registration_secret,'') FROM global_config WHERE id=1`).
		Scan(&stored, &failures, &secret); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, "已停止自动重试") || !strings.Contains(stored, "连续失败 5 次") {
		t.Fatalf("last_sync_error=%q, want terminal guidance preserved", stored)
	}
	if failures != 0 || secret != "" {
		t.Fatalf("terminal track=(failures=%d secret=%q), want cleared", failures, secret)
	}
}

// registrationCountReadFailConn 模拟「失败计数读取失败」：计数查询返回迭代
// 错误，写语句被记录以便断言未执行破坏性清空。
type registrationCountReadFailConn struct {
	mu    sync.Mutex
	execs []string
}

func (c *registrationCountReadFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("未实现 Prepare")
}
func (c *registrationCountReadFailConn) Close() error              { return nil }
func (c *registrationCountReadFailConn) Begin() (driver.Tx, error) { return fakeIterErrTx{}, nil }

func (c *registrationCountReadFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "registration_confirm_failures") {
		return &fakeIterErrRows{columns: []string{"a"}, err: errors.New("注入的计数读取失败")}, nil
	}
	return &fakeEmptyRows{columns: []string{"a"}}, nil
}

func (c *registrationCountReadFailConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.execs = append(c.execs, query)
	return driver.RowsAffected(1), nil
}

func (c *registrationCountReadFailConn) executedWrites() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.execs...)
}

type registrationCountReadFailConnector struct {
	conn *registrationCountReadFailConn
}

func (c *registrationCountReadFailConnector) Connect(context.Context) (driver.Conn, error) {
	return c.conn, nil
}
func (c *registrationCountReadFailConnector) Driver() driver.Driver { return fakeIterErrDriver{} }

func TestSyncService_bumpRegistrationConfirmFailure_readFailureKeepsRegistrationState(t *testing.T) {
	conn := &registrationCountReadFailConn{}
	fake := sql.OpenDB(&registrationCountReadFailConnector{conn: conn})
	t.Cleanup(func() { _ = fake.Close() })
	service := &SyncService{db: fake}

	service.bumpRegistrationConfirmFailure(context.Background(), "approved-token", "confirm 端点返回 401")

	for _, query := range conn.executedWrites() {
		// 读失败（未知）时唯一允许的写是计数自增本身；任何清空注册态/
		// 令牌的语句都意味着把瞬时 DB 故障升级为需要人工重新注册。
		if strings.Contains(query, "registration_secret=''") || strings.Contains(query, "cluster_token=''") {
			t.Fatalf("读失败时不得执行破坏性清空，实际执行: %s", query)
		}
	}
}
