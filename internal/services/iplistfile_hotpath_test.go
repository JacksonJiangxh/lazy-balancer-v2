package services

// 投影热路径（2026-10-15 用户裁定）：名单投影文件改稳定命名后，名单内容变化
// 不再改变配置字节——RefreshIPListProjectionsFromTxInLock 以事务视图全量渲染
//（投影文件为渲染副作用，原子落盘）后与运行配置做结构级比对：
//   - 字节一致 → 名单-only 变更零发射面变化，投影已落盘即收敛（零 /load，
//     @ipListFast 匹配器 ≤1s stat 热感知）→ 返回 true；
//   - 字节不一致（发射面变化：仅剩否定算子/非投影面形态）→ 返回 false，调用方
//     回退既有全量渲染+应用链；
//   - 运行配置不可读 → 返回 false（无法证实零变化即不轻率跳过 /load，
//     fail-open 与同字节短路同向）。
//
// 始终发射收敛（2026-10-15 用户裁定）：空名单也投影空文件并恒发射 @ipListFast
//（空集=匹配器永不命中，与无规则语义等价）——空↔非空与中段同为纯内容变化，
// 全走热路径。存量运行配置（空名单无指令）升级后首次渲染因发射面新增触发一次
// 全量重载，自愈收敛。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// hotPathTestAdmin 回显最近一次 /load 载荷的 fake admin（GET /config/ 末尾补
// 换行，caddy_sameconfig_test.go 同款生产形态）+ /load 计数。
type hotPathTestAdmin struct {
	mu       sync.Mutex
	srv      *httptest.Server
	posts    int
	lastBody []byte
}

func newHotPathTestAdmin(t *testing.T) *hotPathTestAdmin {
	t.Helper()
	a := &hotPathTestAdmin{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			_, _ = w.Write(append(a.lastBody, '\n'))
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			a.posts++
			a.lastBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *hotPathTestAdmin) loadCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.posts
}

// seedHotPathPolicy 建「http 规则 + deny ACL 策略（仅引用名单）+ 绑定」夹具，
// 返回策略 id（投影文件名 p<id>-acl.txt 的身份段）。
func seedHotPathPolicy(t *testing.T, listID int64) int64 {
	t.Helper()
	seedHTTPRuleForGeneration(t, db.DB, "lb-hot", "hot.example.test", 8080)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, enabled, policy_type, ip_acl_enabled, ip_acl_mode, ip_acl_list, ip_acl_list_refs)
		VALUES ('热路径夹具', 'off', 1, 'stage1', 1, 'deny', '[]', ?)`, "["+strconv.FormatInt(listID, 10)+"]")
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb-hot', ?)`, policyID); err != nil {
		t.Fatalf("bind policy: %v", err)
	}
	return policyID
}

func seedHotPathList(t *testing.T, entries string) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('热路径名单', '测试', ?)`, entries)
	if err != nil {
		t.Fatalf("seed list: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustReadProjection(t *testing.T, policyID int64) string {
	t.Helper()
	path := filepath.Join(IPListDataDir, "p"+strconv.FormatInt(policyID, 10)+"-acl.txt")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读投影文件 %s: %v", path, err)
	}
	return string(raw)
}

// Given：规则+deny ACL 策略（引用名单）已渲染应用一次（运行配置与投影就位）。
// When：事务内给名单追加条目 → RefreshIPListProjectionsFromTxInLock。
// Then：hot=true、零新增 /load、投影文件已含新条目（事务视图）。
func TestRefreshIPListProjectionsFromTx_hotPathZeroLoad(t *testing.T) {
	stubSecurityLibsAvailable(t)
	newClusterTestService(t)
	admin := newHotPathTestAdmin(t)
	s := NewCaddyService(admin.srv.URL)

	listID := seedHotPathList(t, `[{"value":"203.0.113.5","remark":""}]`)
	policyID := seedHotPathPolicy(t, listID)

	// 首轮全量渲染应用（建立运行配置与投影）
	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("首次 /load 次数=%d, want 1", got)
	}
	if content := mustReadProjection(t, policyID); !strings.Contains(content, "203.0.113.5/32") {
		t.Fatalf("首轮投影内容=%q, want 含 203.0.113.5/32", content)
	}

	// When：事务内追加条目 + 热路径刷新
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`,
		`[{"value":"203.0.113.5","remark":""},{"value":"192.0.2.44","remark":""}]`, listID); err != nil {
		t.Fatal(err)
	}
	hot, err := s.RefreshIPListProjectionsFromTxInLock(tx)
	if err != nil {
		t.Fatalf("热路径刷新: %v", err)
	}
	if hot != ProjectionConverged {
		t.Fatal("名单-only 追加（发射面不变）应走热路径 hot=ProjectionConverged")
	}
	// Then：零 /load（核心契约）+ 投影文件已按事务视图重写
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("热路径后 /load 次数=%d, want 仍 1（零重载）", got)
	}
	content := mustReadProjection(t, policyID)
	if !strings.Contains(content, "192.0.2.44/32") || !strings.Contains(content, "203.0.113.5/32") {
		t.Fatalf("热路径投影内容=%q, want 含新旧全部条目", content)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// 空→首条（2026-10-15 始终发射收敛）：空名单策略首轮即恒发射 @ipListFast
// （空文件投影就位），追加首条为纯内容变化——hot=true、零新增 /load。
func TestRefreshIPListProjectionsFromTx_emptyToFirstEntryHotPath(t *testing.T) {
	stubSecurityLibsAvailable(t)
	newClusterTestService(t)
	admin := newHotPathTestAdmin(t)
	s := NewCaddyService(admin.srv.URL)

	listID := seedHotPathList(t, `[]`)
	policyID := seedHotPathPolicy(t, listID)

	// 跨测试隔离：包级共享投影目录 + 每测试新库 policyID 重叠——清掉同名
	// 旧投影，首轮「空文件已投影」断言才不受前序测试文件残留污染。
	_ = os.Remove(filepath.Join(IPListDataDir, "p"+strconv.FormatInt(policyID, 10)+"-acl.txt"))

	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("首次 /load 次数=%d, want 1", got)
	}
	if content := mustReadProjection(t, policyID); content != "" {
		t.Fatalf("首轮空名单投影=%q, want 空文件已投影", content)
	}

	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`,
		`[{"value":"203.0.113.5","remark":""}]`, listID); err != nil {
		t.Fatal(err)
	}
	hot, err := s.RefreshIPListProjectionsFromTxInLock(tx)
	if err != nil {
		t.Fatalf("热路径刷新: %v", err)
	}
	if hot != ProjectionConverged {
		t.Fatal("空→首条（恒发射下为纯内容变化）应走热路径 hot=ProjectionConverged")
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("热路径后 /load 次数=%d, want 仍 1（零重载）", got)
	}
	if content := mustReadProjection(t, policyID); !strings.Contains(content, "203.0.113.5/32") {
		t.Fatalf("热路径投影内容=%q, want 含首条", content)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// 清空 N→0（2026-10-15 始终发射收敛）：规则恒在，名单文件清空为纯内容变化
// ——hot=true、零 /load、投影文件归零字节（匹配器空集永不命中=与无规则等价）。
func TestRefreshIPListProjectionsFromTx_clearToEmptyHotPath(t *testing.T) {
	stubSecurityLibsAvailable(t)
	newClusterTestService(t)
	admin := newHotPathTestAdmin(t)
	s := NewCaddyService(admin.srv.URL)

	listID := seedHotPathList(t, `[{"value":"203.0.113.5","remark":""}]`)
	policyID := seedHotPathPolicy(t, listID)
	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("首次 /load 次数=%d, want 1", got)
	}

	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE security_ip_lists SET entries='[]' WHERE id=?`, listID); err != nil {
		t.Fatal(err)
	}
	hot, err := s.RefreshIPListProjectionsFromTxInLock(tx)
	if err != nil {
		t.Fatalf("刷新: %v", err)
	}
	if hot != ProjectionConverged {
		t.Fatal("清空 N→0（恒发射下为纯内容变化）应走热路径 hot=ProjectionConverged")
	}
	if got := admin.loadCount(); got != 1 {
		t.Fatalf("热路径后 /load 次数=%d, want 仍 1（零重载）", got)
	}
	if content := mustReadProjection(t, policyID); content != "" {
		t.Fatalf("清空后投影内容=%q, want 0 字节空文件", content)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// 运行配置不可读（Caddy admin 不可达）→ 无法证实零变化 → hot=false 回退
// 全量链（fail-open 与同字节短路同向），刷新方不报错。
func TestRefreshIPListProjectionsFromTx_unreadableRunningConfigFallsBack(t *testing.T) {
	stubSecurityLibsAvailable(t)
	newClusterTestService(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	s := NewCaddyService(srv.URL)

	listID := seedHotPathList(t, `[{"value":"203.0.113.5","remark":""}]`)
	seedHotPathPolicy(t, listID)

	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE security_ip_lists SET entries='[{"value":"192.0.2.44","remark":""}]' WHERE id=?`, listID); err != nil {
		t.Fatal(err)
	}
	hot, err := s.RefreshIPListProjectionsFromTxInLock(tx)
	if err != nil {
		t.Fatalf("运行配置不可读应回退而非报错: %v", err)
	}
	if hot != ProjectionFallback {
		t.Fatal("运行配置不可读时不得宣称热路径收敛, want ProjectionFallback")
	}
}
