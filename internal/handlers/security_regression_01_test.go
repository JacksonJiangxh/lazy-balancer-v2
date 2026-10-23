package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// openNoBusyWaitDB 打开与当前测试库同文件、busy_timeout=0 的独立连接：
// 写锁被持有时写操作立即返回 SQLITE_BUSY（不等待），用作确定性交错屏障。
// 驱动 DSN 的 _txlock=immediate 让事务一开始就持写锁——写锁来源是 DSN 选项，
// 与 sql.LevelSerializable 无关。
func openNoBusyWaitDB(t *testing.T) *sql.DB {
	t.Helper()
	rows, err := db.DB.Query(`PRAGMA database_list`)
	if err != nil {
		t.Fatalf("database_list: %v", err)
	}
	defer rows.Close()
	path := ""
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			t.Fatalf("scan database_list: %v", err)
		}
		if name == "main" {
			path = file
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate database_list: %v", err)
	}
	if path == "" {
		t.Fatal("main database file not found")
	}
	conn, err := sql.Open("sqlite", path+"?_txlock=immediate&_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatalf("open no-busy-wait connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.Ping(); err != nil {
		t.Fatalf("ping no-busy-wait connection: %v", err)
	}
	return conn
}

// TestBindDeleteRace_immediateTxBlocksConcurrentDelete 串行模拟交错：绑定事务的
// 存在性 COUNT 之后、INSERT 之前，并发的策略删除不得提交。写锁来自 DSN
// `_txlock=immediate`（事务开始即 BEGIN IMMEDIATE），因此独立 busy_timeout=0
// 连接上的删除会立即 SQLITE_BUSY——不需要固定 sleep 的时间窗。
func TestBindDeleteRace_immediateTxBlocksConcurrentDelete(t *testing.T) {
	// Given a policy and a rule eligible for binding
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	policyID := createTestPolicy(t, router, map[string]any{"name": "竞态策略", "mode": "blocking", "enabled": true})
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port) VALUES ('lb_race1', '竞态规则', 'http', 8081)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	ctx := context.Background()
	// bind 侧事务：与 BindRuleToPolicy 同形态（BeginTx(nil)，默认隔离）
	bindTx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin bind tx: %v", err)
	}
	defer bindTx.Rollback()
	var n int
	if err := bindTx.QueryRowContext(ctx, "SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_race1'").Scan(&n); err != nil || n == 0 {
		t.Fatalf("rule count in tx: n=%d err=%v", n, err)
	}

	// Then the concurrent delete cannot commit between bind's COUNT and INSERT：
	// 独立连接（busy_timeout=0）上的写立即被拒。
	concurrent := openNoBusyWaitDB(t)
	if _, err := concurrent.ExecContext(ctx, "DELETE FROM security_policies WHERE id=?", policyID); err == nil {
		t.Fatal("并发删除在 bind 事务持锁期间完成（必须在校验与写入之间被写锁拒绝）")
	} else if !strings.Contains(strings.ToLower(err.Error()), "locked") {
		t.Fatalf("并发删除错误=%v, want database is locked（写锁屏障）", err)
	}

	// bind 事务完成绑定 INSERT + Commit
	if _, err := bindTx.ExecContext(ctx, "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_race1', ?)", policyID); err != nil {
		t.Fatalf("insert binding: %v", err)
	}
	if err := bindTx.Commit(); err != nil {
		t.Fatalf("commit bind tx: %v", err)
	}

	// 屏障解除后同一删除必须成功——证明上面的失败确实来自写锁而非其他错误
	if _, err := concurrent.ExecContext(ctx, "DELETE FROM security_policy_bindings WHERE policy_id=?", policyID); err != nil {
		t.Fatalf("delete bindings after commit: %v", err)
	}
	if _, err := concurrent.ExecContext(ctx, "DELETE FROM security_policies WHERE id=?", policyID); err != nil {
		t.Fatalf("delete policy after bind commit: %v", err)
	}

	// And no dangling binding survives the interleave
	var dangling int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings b LEFT JOIN security_policies p ON p.id=b.policy_id WHERE p.id IS NULL`).Scan(&dangling); err != nil {
		t.Fatalf("count dangling: %v", err)
	}
	if dangling != 0 {
		t.Fatalf("dangling bindings=%d, want 0", dangling)
	}
}

// failingMetricsConnector 返回一个每次查询都失败的 *sql.DB，用于注入
// metrics 库故障。
type failingMetricsConnector struct{}

func (failingMetricsConnector) Connect(context.Context) (driver.Conn, error) {
	return failingMetricsConn{}, nil
}

func (failingMetricsConnector) Driver() driver.Driver { return failingMetricsDriver{} }

type failingMetricsDriver struct{}

func (failingMetricsDriver) Open(string) (driver.Conn, error) { return failingMetricsConn{}, nil }

type failingMetricsConn struct{}

func (failingMetricsConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("注入的 metrics 库查询失败")
}

func (failingMetricsConn) Close() error { return nil }

func (failingMetricsConn) Begin() (driver.Tx, error) {
	return nil, errors.New("注入的 metrics 库查询失败")
}

// TestGetSecurityOverview_metricsDBErrorReturns500 验证 metrics 库查询失败时
// 安全总览显式返回 500，而不是静默给出全零「无攻击」面板。
func TestGetSecurityOverview_metricsDBErrorReturns500(t *testing.T) {
	// Given a working security DB but a failing metrics store
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	broken := sql.OpenDB(failingMetricsConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	orig := db.MetricsDB
	db.MetricsDB = broken
	t.Cleanup(func() { db.MetricsDB = orig })

	// When the overview is requested while the metrics store is down
	recorder := getRequest(t, router, "/security/overview")

	// Then it fails loudly instead of returning an all-zero "no attacks" dashboard
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "安全总览查询失败") {
		t.Fatalf("body=%s, want explicit overview failure message", recorder.Body.String())
	}
}

// TestListSecurityEvents_scanErrorReturns500 验证行 Scan 失败时事件列表显式
// 返回 500，而不是把部分零值的事件行当作真实事件返回。
func TestListSecurityEvents_scanErrorReturns500(t *testing.T) {
	// Given a metrics row whose anomaly_score cannot scan into int
	// （SQLite 动态类型下向 INTEGER 列写入了文本）
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, action, anomaly_score)
		VALUES ('2099-01-01 00:00:00', '192.0.2.1', 'GET', '/bad', 'blocked', 'not-a-number')`); err != nil {
		t.Fatalf("seed bogus event: %v", err)
	}

	// When the events list is requested
	recorder := getRequest(t, router, "/security/events")

	// Then the scan failure surfaces as 500 instead of a zero-valued event row
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "安全事件查询失败") {
		t.Fatalf("body=%s, want explicit query failure message", recorder.Body.String())
	}
}
