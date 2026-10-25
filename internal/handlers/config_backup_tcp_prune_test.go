package handlers

// TCP 规则安全策略绑定清理（pruneTCPRuleBindings）的两形态：
//   - 正常库：只删 TCP 规则的绑定，计数即实际删除条数（HTTP 绑定不动）；
//   - 计数读取失败：DELETE 已成功，错误不得独吞——按 0 计并在日志留痕
//     （同一族清理在悬挂绑定处早已判错，本处曾长期丢弃 RowsAffected 错误）。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestPruneTCPRuleBindings_countsOnlyTCPBindings(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port) VALUES
		('lb_prune_tcp','prune-tcp','tcp','0.0.0.0',9000),
		('lb_prune_http','prune-http','http','example.com',80)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_prune_tcp',1),('lb_prune_tcp',2),('lb_prune_http',1)`); err != nil {
		t.Fatalf("seed bindings: %v", err)
	}

	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()
	dropped, err := pruneTCPRuleBindings(context.Background(), tx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if dropped != 2 {
		t.Fatalf("dropped=%d, want 2（仅 TCP 规则的两条绑定）", dropped)
	}
	var remaining string
	if err := tx.QueryRow(`SELECT rule_caddy_id FROM security_policy_bindings`).Scan(&remaining); err != nil {
		t.Fatalf("read remaining binding: %v", err)
	}
	if remaining != "lb_prune_http" {
		t.Fatalf("剩余绑定=%q, want lb_prune_http（HTTP 绑定不得被清理）", remaining)
	}
}

// tcpPruneCountFailConn 模拟「Exec 成功但读不出影响行数」的驱动形态：
// 事务提交与否无关，用例只走 Exec + RowsAffected 两步。
type tcpPruneCountFailConn struct{}

func (tcpPruneCountFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (tcpPruneCountFailConn) Close() error              { return nil }
func (tcpPruneCountFailConn) Begin() (driver.Tx, error) { return tcpPruneCountFailTx{}, nil }
func (tcpPruneCountFailConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return tcpPruneCountFailTx{}, nil
}
func (tcpPruneCountFailConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return tcpPruneCountFailResult{}, nil
}

type tcpPruneCountFailTx struct{}

func (tcpPruneCountFailTx) Commit() error   { return nil }
func (tcpPruneCountFailTx) Rollback() error { return nil }

type tcpPruneCountFailResult struct{}

func (tcpPruneCountFailResult) LastInsertId() (int64, error) {
	return 0, errors.New("no last insert id")
}
func (tcpPruneCountFailResult) RowsAffected() (int64, error) {
	return 0, errors.New("rows affected unavailable")
}

type tcpPruneCountFailDriver struct{}

func (tcpPruneCountFailDriver) Open(string) (driver.Conn, error) { return tcpPruneCountFailConn{}, nil }

var tcpPruneCountFailRegister sync.Once

func TestPruneTCPRuleBindings_warnsWhenRowsAffectedFails(t *testing.T) {
	tcpPruneCountFailRegister.Do(func() { sql.Register("tcp-prune-count-fail", tcpPruneCountFailDriver{}) })
	database, err := sql.Open("tcp-prune-count-fail", "")
	if err != nil {
		t.Fatalf("open fake driver: %v", err)
	}
	defer database.Close()
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	var logs strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldWriter)

	dropped, err := pruneTCPRuleBindings(context.Background(), tx)
	if err != nil {
		t.Fatalf("计数失败不得把已成功的清理判为失败: %v", err)
	}
	if dropped != 0 {
		t.Fatalf("dropped=%d, want 0（计数失败按 0 计）", dropped)
	}
	out := logs.String()
	if !strings.Contains(out, "读取影响行数失败") || !strings.Contains(out, "TCP") {
		t.Fatalf("计数失败必须留痕（warn 点名 TCP 绑定清理），got %q", out)
	}
}
