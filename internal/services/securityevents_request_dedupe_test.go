package services

// 摄取期请求级去重：多策略绑定下同一请求会被每个绑定策略的 coraza 实例各写
// 一条审计事务（transaction_id 各不相同），必须归并为一条事件，否则事件列表
// 成对重复、计数与自动封禁阈值按引擎数放大。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// securityEventsDedupeFixture 生成一条最小 Coraza 审计事务。
// timingID 为空=旧版本审计日志（无请求级计时头），走指纹回退路径。
func securityEventsDedupeFixture(txID, timingID, uri, action string, ruleID int) string {
	headers := `"host": ["go029.com"]`
	if timingID != "" {
		headers += fmt.Sprintf(`, "X-Lb-Security-Timing-Id": [%q]`, timingID)
	}
	msg := fmt.Sprintf("dedupe rule %d", ruleID)
	if action == "blocked" {
		msg = fmt.Sprintf("Inbound Anomaly Score Exceeded (Total Score: 5) rule %d", ruleID)
	}
	return fmt.Sprintf(`{
  "transaction": {
    "unix_timestamp": 1786447017841320426,
    "id": %q,
    "client_ip": "203.0.113.9",
    "server_id": "go029.com",
    "request": { "method": "GET", "uri": %q, "headers": { %s } },
    "is_interrupted": %t
  },
  "messages": [ { "message": %q, "data": { "id": %d, "raw": "id:%d,phase:2,deny,log" } } ]
}`, txID, uri, headers, action == "blocked", msg, ruleID, ruleID)
}

// seedSecurityEventsDedupeDB 写入规则/策略/绑定，返回审计日志与偏移路径。
func seedSecurityEventsDedupeDB(t *testing.T) (logPath, offsetPath string) {
	t.Helper()
	dataDir := t.TempDir()
	if err := initSecurityEventsTestDB(t, dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','test rule','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups) VALUES (7,'policy-seven',1,'blocking','[]','[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',7)`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return filepath.Join(dir, "audit.log"), filepath.Join(dir, "security_events.offset")
}

func writeSecurityEventsDedupeLog(t *testing.T, logPath string, docs ...string) {
	t.Helper()
	if err := os.WriteFile(logPath, []byte(strings.Join(docs, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// runSecurityEventsDedupeTick 跑一轮摄取（失败即终止用例）。
func runSecurityEventsDedupeTick(t *testing.T, tailer *securityEventsTailer) {
	t.Helper()
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
}

func readSecurityEventsRows(t *testing.T) []struct {
	id, policyID, score                         int
	action, triggered, transactionID, ruleCaddy string
} {
	t.Helper()
	rows, err := db.MetricsDB.Query(`SELECT id, COALESCE(policy_id,0), anomaly_score, action, COALESCE(rule_triggered,''), COALESCE(transaction_id,''), COALESCE(rule_caddy_id,'') FROM security_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []struct {
		id, policyID, score                         int
		action, triggered, transactionID, ruleCaddy string
	}
	for rows.Next() {
		var r struct {
			id, policyID, score                         int
			action, triggered, transactionID, ruleCaddy string
		}
		if err := rows.Scan(&r.id, &r.policyID, &r.score, &r.action, &r.triggered, &r.transactionID, &r.ruleCaddy); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// 同一请求（共享请求级计时头）的检测事务后跟拦截事务：只落一条事件，
// 且结论、触发规则与评分按拦截引擎改判。
func TestSecurityEventsTick_mergesMultiEngineTransactionsPerRequest(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-engine-a", "6f1c0d9a2b3e4f57", "/api/orders", "logged", 942100),
		securityEventsDedupeFixture("tx-engine-b", "6f1c0d9a2b3e4f57", "/api/orders", "blocked", 949110),
	)
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)

	rows := readSecurityEventsRows(t)
	if len(rows) != 1 {
		t.Fatalf("rows=%d, want 1 (one event per request): %+v", len(rows), rows)
	}
	got := rows[0]
	if got.transactionID != "tx-engine-a" {
		t.Errorf("transaction_id=%q, want tx-engine-a (首次落库行的幂等键)", got.transactionID)
	}
	if got.action != "blocked" || got.triggered != "949110" || got.score != 5 {
		t.Errorf("row=(%s,%s,%d), want blocked/949110/5（拦截结论覆盖检测结论）", got.action, got.triggered, got.score)
	}
	if got.policyID != 7 || got.ruleCaddy != "lb_rule1" {
		t.Errorf("attribution=(%d,%s), want (7,lb_rule1)", got.policyID, got.ruleCaddy)
	}
	if tailer.lastIngested != 1 {
		t.Errorf("lastIngested=%d, want 1（归并的事务不计入摄取条数）", tailer.lastIngested)
	}

	// 重放同一份日志（offset 归零）=幂等：不新增行、不改判出第二条。
	if _, err := securityEventsIngestDeltaFrom(logPath, 0, true); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if rows := readSecurityEventsRows(t); len(rows) != 1 {
		t.Fatalf("rows after replay=%d, want 1", len(rows))
	}
}

// 拦截事务先写、检测事务后写：后到的弱结论不得把已落库的拦截行降级。
func TestSecurityEventsTick_mergeKeepsBlockedWhenLoggedArrivesLater(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-first", "aa11bb22cc33dd44", "/search", "blocked", 949110),
		securityEventsDedupeFixture("tx-second", "aa11bb22cc33dd44", "/search", "logged", 942100),
	)
	runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))

	rows := readSecurityEventsRows(t)
	if len(rows) != 1 {
		t.Fatalf("rows=%d, want 1: %+v", len(rows), rows)
	}
	if rows[0].action != "blocked" || rows[0].triggered != "949110" {
		t.Errorf("row=(%s,%s), want blocked/949110（弱结论不降级）", rows[0].action, rows[0].triggered)
	}
}

// 不同请求（计时头不同）即使落在同一秒、同一 URI、同一规则也各落一条。
func TestSecurityEventsTick_keepsDistinctRequestsWithDifferentTimingIDs(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-req-1", "1111222233334444", "/api/orders", "blocked", 949110),
		securityEventsDedupeFixture("tx-req-2", "5555666677778888", "/api/orders", "blocked", 949110),
	)
	runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))

	if rows := readSecurityEventsRows(t); len(rows) != 2 {
		t.Fatalf("rows=%d, want 2（不同请求不得归并）: %+v", len(rows), rows)
	}
}

// 同一请求的两个引擎事务被 tick 边界拆开（第二个事务在下一轮才写全）：
// 归并记忆跨 pass 保留，仍只落一条事件，且结论按后到的拦截改判。
func TestSecurityEventsTick_mergesAcrossPassesForSameRequest(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-split-a", "9988776655443322", "/split", "logged", 942100),
	)
	tailer := securityEventsNewTailer(logPath, offsetPath)
	runSecurityEventsDedupeTick(t, tailer)

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(securityEventsDedupeFixture("tx-split-b", "9988776655443322", "/split", "blocked", 949110) + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	runSecurityEventsDedupeTick(t, tailer)

	rows := readSecurityEventsRows(t)
	if len(rows) != 1 {
		t.Fatalf("rows=%d, want 1（跨 pass 同一请求仍归并）: %+v", len(rows), rows)
	}
	if rows[0].action != "blocked" {
		t.Errorf("action=%q, want blocked（后到拦截改判）", rows[0].action)
	}
}

// 旧版本审计行（无请求级计时头）没有请求级自然键：按原样逐条入库，
// 绝不按「秒+四元组」指纹猜测归并（独立请求会被误并）。
func TestSecurityEventsTick_keepsLegacyTransactionsWithoutTimingHeader(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	writeSecurityEventsDedupeLog(t, logPath,
		securityEventsDedupeFixture("tx-legacy-a", "", "/legacy", "logged", 942100),
		securityEventsDedupeFixture("tx-legacy-b", "", "/legacy", "logged", 942100),
		securityEventsDedupeFixture("tx-legacy-c", "", "/legacy-other", "logged", 942100),
	)
	runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))

	rows := readSecurityEventsRows(t)
	if len(rows) != 3 {
		t.Fatalf("rows=%d, want 3（无请求级键不得归并）: %+v", len(rows), rows)
	}
}
