package handlers

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// fakeApplyThenDropServer 模拟「Caddy 已读完候选配置、处理后才断连」的传输
// 第 N 次（1 基）/load 在收满请求体后直接掐断连接。
type fakeApplyThenDropServer struct {
	mu     sync.Mutex
	loads  []string
	dropAt []int
}

func newApplyThenDropServer(t *testing.T, dropAt ...int) (*fakeApplyThenDropServer, *httptest.Server) {
	t.Helper()
	rec := &fakeApplyThenDropServer{dropAt: dropAt}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/load" && r.Method == http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			rec.mu.Lock()
			rec.loads = append(rec.loads, string(body))
			drop := false
			for _, n := range rec.dropAt {
				if len(rec.loads) == n {
					drop = true
				}
			}
			rec.mu.Unlock()
			if drop {
				if hj, ok := w.(http.Hijacker); ok {
					if conn, _, err := hj.Hijack(); err == nil {
						_ = conn.Close()
						return
					}
				}
				panic(http.ErrAbortHandler)
			}
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/config/" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"apps":{}}`))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return rec, srv
}

func seedCommittedRuleForApplyTest(t *testing.T, caddyID, domain string) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		VALUES (?, 'stmt', 'http', ?, 18451, 1)`, caddyID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES (?, '10.9.9.9', 18451, 1, 1, 'http')`, caddyID); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
}

func beginPendingDomainTx(t *testing.T, caddyID string) *sql.Tx {
	t.Helper()
	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if _, err := tx.Exec(`UPDATE lb_rules SET domain='pending.example.test' WHERE caddy_id=?`, caddyID); err != nil {
		t.Fatalf("tx update: %v", err)
	}
	return tx
}

func newApplyTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/config", nil)
	c.Set("username", "tester")
	return c, rec
}

func readApplyError(t *testing.T) string {
	t.Helper()
	var banner string
	if err := db.DB.QueryRow("SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1").Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	return banner
}

// 分支必须回滚到已提交视图运行配置，并持久化失败横幅——仅回滚 DB/投影会让
// 安全域写静默分叉（看门狗只比对路由 id，策略/限流变化不触发漂移）。
func TestFinishTxApply_unvalidatedApplyRestoresCommittedRuntime(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder, fake := newApplyThenDropServer(t, 1)
	h.caddyService = services.NewCaddyService(fake.URL)
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return services.ErrCLIValidatorUnavailable })
	seedCommittedRuleForApplyTest(t, "lb_p1b", "committed.example.test")
	tx := beginPendingDomainTx(t, "lb_p1b")
	c, rec := newApplyTestContext()

	h.finishTxApply(c, tx, txApplyFinish{Resource: "安全策略", AuditAction: "更新", AuditDetail: "策略保存", SuccessMsg: "已保存"})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "运行配置不受影响") {
		t.Fatalf("响应仍在未回滚时宣称运行配置不受影响: %s", body)
	}
	if !strings.Contains(body, "已回滚") {
		t.Fatalf("响应未说明已回滚到已提交运行配置: %s", body)
	}
	if err := tx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("失败分支必须已回滚事务, Rollback err=%v", err)
	}
	var domain string
	if err := db.DB.QueryRow("SELECT domain FROM lb_rules WHERE caddy_id='lb_p1b'").Scan(&domain); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if domain != "committed.example.test" {
		t.Fatalf("未提交变更落库: domain=%q", domain)
	}
	recorder.mu.Lock()
	loads := append([]string(nil), recorder.loads...)
	recorder.mu.Unlock()
	if len(loads) != 2 {
		t.Fatalf("/load 次数=%d, want 2（候选 + 已提交视图回滚）: %v", len(loads), loads)
	}
	if !strings.Contains(loads[0], "pending.example.test") {
		t.Fatalf("第一次 /load 应为候选视图: %s", loads[0])
	}
	if !strings.Contains(loads[1], "committed.example.test") || strings.Contains(loads[1], "pending.example.test") {
		t.Fatalf("回滚 /load 未回到已提交视图: %s", loads[1])
	}
	if banner := readApplyError(t); banner == "" {
		t.Fatal("传输失败后未持久化 caddy_apply_error 横幅（分叉不可见）")
	}
	var auditCount int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='更新失败' AND resource='安全策略' AND detail LIKE '%CLI 校验不可用%'").Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("失败分支缺少操作审计")
	}
}

// 恢复本身也失败（双故障）：必须显式告知回滚失败且持久化横幅，不得静默。
func TestFinishTxApply_unvalidatedApplyReportsRestoreFailure(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder, fake := newApplyThenDropServer(t, 1, 2)
	h.caddyService = services.NewCaddyService(fake.URL)
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return services.ErrCLIValidatorUnavailable })
	seedCommittedRuleForApplyTest(t, "lb_p1b2", "committed2.example.test")
	tx := beginPendingDomainTx(t, "lb_p1b2")
	c, rec := newApplyTestContext()

	h.finishTxApply(c, tx, txApplyFinish{Resource: "安全策略", AuditAction: "更新", AuditDetail: "策略保存", SuccessMsg: "已保存"})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "回滚到已提交运行配置失败") {
		t.Fatalf("双故障响应未点名回滚失败: %s", rec.Body.String())
	}
	recorder.mu.Lock()
	n := len(recorder.loads)
	recorder.mu.Unlock()
	if n != 2 {
		t.Fatalf("/load 次数=%d, want 2", n)
	}
	if banner := readApplyError(t); banner == "" {
		t.Fatal("双故障未持久化横幅")
	}
}

// ——恢复 /load 也失败（双故障）时，LKG 仍必须回到已提交视图字节；旧实现用
// restoreImportRuntime（运行时快照），恢复失败会让 LKG 滞留候选内容。
func TestCreateRule_commitFailureRestoresLKGToCommittedView(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder, fake := newApplyThenDropServer(t, 2) // 仅第 2 次 /load（恢复）掐断
	h.caddyService = services.NewCaddyService(fake.URL)
	lkgPath := t.TempDir() + "/last-good.json"
	h.caddyService.SetLastGoodPath(lkgPath)
	seedCommittedRuleForApplyTest(t, "lb_committed", "committed.example.test")
	if _, err := db.DB.Exec(`PRAGMA foreign_keys=ON;
		CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);
		CREATE TABLE commit_rule_guard(parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER fail_rule_commit AFTER INSERT ON lb_rules BEGIN INSERT INTO commit_rule_guard(parent_id) VALUES (999); END`); err != nil {
		t.Fatalf("install deferred commit failure: %v", err)
	}

	router := gin.New()
	router.POST("/rules", h.CreateRule)
	body := `{"name":"commit-fail","protocol":"http","domain":"new.example.test","listen_port":18461,"health_check_interval":10,"health_check_timeout":2,"health_check_unhealthy_threshold":3,"health_check_healthy_threshold":2,"upstreams":[{"host":"127.0.0.1","port":9000,"enabled":true}]}`
	request := httptest.NewRequest(http.MethodPost, "/rules", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, request)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE domain='new.example.test'").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("commit 失败后规则仍落库 rows=%d", count)
	}
	recorder.mu.Lock()
	loads := append([]string(nil), recorder.loads...)
	recorder.mu.Unlock()
	if len(loads) != 2 {
		t.Fatalf("/load 次数=%d, want 2（候选 + 已提交视图恢复尝试）", len(loads))
	}
	if !strings.Contains(loads[0], "new.example.test") {
		t.Fatalf("第一次 /load 应为候选视图: %s", loads[0])
	}
	if strings.Contains(loads[1], "new.example.test") || !strings.Contains(loads[1], "committed.example.test") {
		t.Fatalf("恢复尝试未使用已提交视图: %s", loads[1])
	}
	lkg, err := os.ReadFile(lkgPath)
	if err != nil {
		t.Fatalf("read LKG: %v", err)
	}
	if strings.Contains(string(lkg), "new.example.test") || !strings.Contains(string(lkg), "committed.example.test") {
		t.Fatalf("LKG 未回退到已提交视图（双故障残留未提交字节）: %s", lkg)
	}
}

// 源码钉测：规则×5 / UpdateConfig / PutCaddyConfig 的 commit
// 失败分支必须统一走 recoverCommittedViewAfterCommitFailure(tx)，禁止再回退
// 到 restoreImportRuntime / ApplyConfig(oldRuntimeConfig)（恢复 /load 失败时
// LKG 滞留未提交字节）。
func TestCommitFailureRecoveryFamilyUsesUnifiedRecovery(t *testing.T) {
	read := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		return string(data)
	}
	if got := strings.Count(read("rules.go"), "h.recoverCommittedViewAfterCommitFailure(tx)"); got < 5 {
		t.Fatalf("rules.go commit 失败分支使用统一恢复 %d 处, want >=5（创建/更新/删除/启用/禁用）", got)
	}
	if got := strings.Count(read("caddy.go"), "h.recoverCommittedViewAfterCommitFailure(tx)"); got < 2 {
		t.Fatalf("caddy.go commit 失败分支使用统一恢复 %d 处, want >=2（UpdateConfig/PutCaddyConfig）", got)
	}
	// 必须清理该规则物化文件，但判据是「已提交视图是否引用该规则」：Commit
	// 返回错误无法区分未提交与已提交但确认丢失，无条件删除会切断提交实际生效
	// 时的运行证书。分支内不得再出现无条件 RemoveCertFiles。
	rulesSrc := read("rules.go")
	branch := rulesSrc
	if idx := strings.Index(rulesSrc, "CreateRule transaction commit error"); idx >= 0 {
		start := idx - 800
		if start < 0 {
			start = 0
		}
		branch = rulesSrc[start:idx]
	}
	if !strings.Contains(branch, "cleanupUncommittedRuleCertsAfterCommitFailure(caddyID)") {
		t.Fatal("CreateRule commit 失败分支缺少按已提交视图判定的证书清理（渲染物化的新规则证书文件滞留）")
	}
	if strings.Contains(branch, "services.RemoveCertFiles(caddyID)") {
		t.Fatal("CreateRule commit 失败分支不得无条件删除证书文件（提交可能已生效）")
	}
}

// commit 失败会留下一条描述「从未提交配置」的降级事件；成功收尾由
// recordCaddyApplyResult 补落且只落一次。
func TestTxApplyDefersRenderDegradationAuditUntilCommit(t *testing.T) {
	h := newBackupTestHandlers(t)
	rec := &fakeCaddyRecorder{}
	fake := newFakeCaddyServer(t, rec)
	h.caddyService = services.NewCaddyService(fake.URL)
	t.Cleanup(func() {
		// 复位进程级降级状态与横幅（全局单例，避免污染后续测试）。
		if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=0, trusted_proxy_ranges='[]' WHERE id=1`); err == nil {
			_ = h.caddyService.GenerateAndApplyConfig()
			h.recordCaddyApplyResult(nil)
		}
	})

	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Logf("rollback: %v", err)
		}
	})
	if _, err := tx.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='not-json' WHERE id=1`); err != nil {
		t.Fatalf("tx update: %v", err)
	}
	// When：事务内 apply（persist=false；事务只写 global_config → 补查门控 false）
	if err := h.caddyService.ApplyConfigFromTx(tx, false); err != nil {
		t.Fatalf("tx apply: %v", err)
	}
	if msg := services.LastRenderDegradation(); msg == "" {
		t.Fatal("测试前置未触发渲染降级")
	}
	var auditBefore int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='应用降级'").Scan(&auditBefore); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditBefore != 0 {
		t.Fatalf("事务内 apply 立即落了 %d 条「应用降级」审计（commit 失败=虚假事件）", auditBefore)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// Then：commit 成功后的唯一收口补落审计（恰好一条）。
	h.recordCaddyApplyResult(nil)
	var auditAfter int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='应用降级'").Scan(&auditAfter); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditAfter != 1 {
		t.Fatalf("commit 后降级审计=%d, want 1", auditAfter)
	}
	if banner := readApplyError(t); banner == "" {
		t.Fatal("commit 后未持久化降级横幅")
	}
}
