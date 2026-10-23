package handlers

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// TestPolicyWriteTx_immediateTxBlocksConcurrentRuleDelete 串行模拟
// 策略写入事务的引用校验 SELECT 之后、INSERT 之前的交错：并发的规则删除不得
// 提交。写锁来自 DSN `_txlock=immediate`（事务开始即持写锁），独立
// busy_timeout=0 连接上的删除会立即 SQLITE_BUSY——校验与写入之间不存在插队
// 窗口，写入的策略绝不会引用「校验与写入之间」被删的规则（悬空引用）。
func TestPolicyWriteTx_immediateTxBlocksConcurrentRuleDelete(t *testing.T) {
	// Given a custom rule referenced by no policy yet (delete would be legal)
	setupSecurityPolicyTestDB(t)
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('竞态规则', '[]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// 写入侧事务（同 CreateSecurityPolicy 语义）：引用校验 SELECT 即持写锁
	polTx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin policy tx: %v", err)
	}
	defer polTx.Rollback()
	var exists int
	if err := polTx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_custom_rules WHERE id=?", ruleID).Scan(&exists); err != nil {
		t.Fatalf("reference check: %v", err)
	}
	if exists != 1 {
		t.Fatalf("rule exists=%d, want 1", exists)
	}

	// Then 并发删除立即被写锁拒绝（不能提交在校验与 INSERT 之间）
	concurrent := openNoBusyWaitDB(t)
	if _, err := concurrent.ExecContext(ctx, "DELETE FROM security_custom_rules WHERE id=?", ruleID); err == nil {
		t.Fatal("并发删除已在校验与写入之间完成（必须被写锁拒绝）")
	} else if !strings.Contains(strings.ToLower(err.Error()), "locked") {
		t.Fatalf("并发删除错误=%v, want database is locked（写锁屏障）", err)
	}

	// 写入侧完成 INSERT + Commit（提交时规则必然仍在，无悬空引用）
	if _, err := polTx.ExecContext(ctx, "INSERT INTO security_policies (name, custom_rules, enabled) VALUES ('竞态写入策略', ?, 1)", fmt.Sprintf("[%d]", ruleID)); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	if err := polTx.Commit(); err != nil {
		t.Fatalf("commit policy tx: %v", err)
	}

	// 屏障解除后同一删除必须成功——证明上面失败源自写锁而非其他错误
	if _, err := concurrent.ExecContext(ctx, "DELETE FROM security_custom_rules WHERE id=?", ruleID); err != nil {
		t.Fatalf("并发删除 after policy commit: %v", err)
	}

	// And the enabled policy references a rule that existed at write time —
	// the delete could only commit after the write, never between check and write
	var enabledPolicies int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE enabled=1 AND custom_rules LIKE ?", fmt.Sprintf("%%[%d]%%", ruleID)).Scan(&enabledPolicies); err != nil {
		t.Fatal(err)
	}
	if enabledPolicies != 1 {
		t.Fatalf("enabled policies referencing rule=%d, want 1", enabledPolicies)
	}
}
