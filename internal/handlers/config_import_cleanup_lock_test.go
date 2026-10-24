package handlers

// 提交后产物清理的阶段边界：锁内（caddyOpMu + 导入会话锁）只收集待删集并在
// 事务内完成 cert_jobs 必要删除，实际删证书文件/日志/指标的删除动作必须在两把
// 锁都释放之后执行——否则千级规则导入的文件删除会把配置写/重载阻塞在该窗口。
//
// 本钉测用 TryLock 探针证明清理执行时刻两把锁均已释放（锁仍被本 goroutine
// 持有时 TryLock 必然失败），并验证清理确实执行。

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestImportV1PostCommitCleanupRunsOutsideImportLocks(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))

	// 旧规则 + 证书文件：导入整体替换规则面后它消失，清理计划非空。
	if _, err := db.DB.Exec(`
		INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES
		('lb_lock_old','old','old.example.test','http',8570,1,1,'manual','CERT','KEY')`); err != nil {
		t.Fatalf("seed old rule: %v", err)
	}
	if err := services.WriteCertFiles("lb_lock_old", "CERT", "KEY"); err != nil {
		t.Fatalf("write old rule cert files: %v", err)
	}

	var caddyFree, sessionFree atomic.Bool
	oldHook := importPostCommitCleanupHook
	importPostCommitCleanupHook = func() {
		if h.caddyOpMu.TryLock() {
			h.caddyOpMu.Unlock()
			caddyFree.Store(true)
		}
		if configImportBeginMu.TryLock() {
			configImportBeginMu.Unlock()
			sessionFree.Store(true)
		}
	}
	t.Cleanup(func() { importPostCommitCleanupHook = oldHook })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(v1ImportFailureBackup("v1-lock-probe")))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	// Then ① 清理执行时刻 caddyOpMu 与导入会话锁都已释放
	if !caddyFree.Load() {
		t.Fatal("提交后清理仍在 caddyOpMu 临界区内执行（会阻塞配置写/重载窗口）")
	}
	if !sessionFree.Load() {
		t.Fatal("提交后清理仍在导入会话锁内执行（第二个导入无法开始）")
	}
	// Then ② 清理确实执行：消失规则的证书/私钥文件已删除
	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(certDir, "lb_lock_old"+suffix)); err == nil {
			t.Fatalf("消失规则 lb_lock_old%s 的证书材料残留（清理未执行）", suffix)
		}
	}
}
