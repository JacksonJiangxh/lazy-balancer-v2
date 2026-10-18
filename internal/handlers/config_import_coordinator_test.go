package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func TestImportFailureAuditDescriptionReflectsFailurePhase(t *testing.T) {
	tests := []struct {
		name  string
		phase importPhase
		want  string
	}{
		{name: "queue recovery after commit is partial", phase: importPhaseQueue, want: "导入部分失败"},
		{name: "Caddy validation preserves database", phase: importPhaseCaddy, want: "数据库未变更"},
		{name: "certificate failure identifies preparation", phase: importPhaseCertificate, want: "证书准备失败"},
		{name: "commit failure identifies database commit", phase: importPhaseCommit, want: "数据库提交失败"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			err := &importCoordinatorError{phase: test.phase, err: errors.New("injected")}

			// When
			detail := importFailureAuditDescription(err)

			// Then
			if !strings.Contains(detail, test.want) {
				t.Fatalf("detail=%q want fragment=%q", detail, test.want)
			}
		})
	}
}

// B3-82-历史问题 / 历史问题-历史问题：并发导入必须串行；第二个会话在第一个
// close 前不得已执行 Pause，否则第一个 Resume 会让它失去排空保护。
func TestBeginConfigImport_serializesConcurrentSessions(t *testing.T) {
	h := newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	if err := te.Register(taskengine.Descriptor{
		ID: "import-serial-probe", Family: "test", Name: "Import serialization probe",
		Kind: taskengine.KindOneshot,
		Run:  func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	first, err := h.beginConfigImport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		session *configImportSession
		err     error
	}
	secondDone := make(chan result, 1)
	go func() {
		session, err := h.beginConfigImport(context.Background())
		secondDone <- result{session: session, err: err}
	}()
	time.Sleep(100 * time.Millisecond) // 给旧实现机会执行 Pause 后阻塞在 caddyOpMu
	first.close()
	var second result
	select {
	case second = <-secondDone:
	case <-time.After(5 * time.Second):
		t.Fatal("second import did not begin after first closed")
	}
	if second.err != nil {
		t.Fatalf("second begin: %v", second.err)
	}
	err = te.Trigger("import-serial-probe", "manual", "test")
	if !errors.Is(err, taskengine.ErrSchedulingPaused) {
		second.session.close()
		t.Fatalf("second import session is not paused (trigger err=%v)", err)
	}
	second.session.close()
}

func TestBeginConfigImport_preservesStoppedCAQueue(t *testing.T) {
	// Given：cert-issuance 已被停止，CA 队列为 inactive。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil })
	services.GetCAQueueManager().Start()
	manager := services.GetCAQueueManager()
	manager.PauseAndDrain()
	if manager.IsActive() {
		t.Fatal("前置态错误：CA 队列应为 inactive")
	}

	// When：执行导入 begin/close（含 PauseAndDrain 与恢复收尾）。
	session, err := h.beginConfigImport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	session.close()

	// Then：恢复不得把 inactive 队列重新激活或启动真实签发。
	if manager.IsActive() {
		t.Fatal("导入恢复了用户停止的 CA 队列（cert-issuance 生命周期被旁路）")
	}
}

func TestConfigImport_mapsCaddyTransportAndRejectionDifferently(t *testing.T) {
	const v1Backup = `{
		"proxy_config":{"config":[{"pk":1,"fields":{"proxy_name":"new-rule","protocol":true,"listen":8443,"server_name":"example.test","status":true,"upstream_list":[1]}}]},
		"upstream_config":{"config":[{"pk":1,"fields":{"status":true,"address":"127.0.0.1","port":9000,"weight":100}}]}
	}`
	for _, format := range []string{"v2", "v1"} {
		for _, rejected := range []bool{false, true} {
			name := format + " transport"
			if rejected {
				name = format + " rejection"
			}
			t.Run(name, func(t *testing.T) {
				h := newBackupTestHandlers(t)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.Method == http.MethodPost && r.URL.Path == "/load" {
						if rejected {
							w.WriteHeader(http.StatusBadRequest)
							_, _ = w.Write([]byte("rejected"))
							return
						}
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Errorf("hijack Caddy response: %v", err)
							return
						}
						_ = conn.Close()
						return
					}
					_, _ = w.Write([]byte(`{}`))
				}))
				t.Cleanup(server.Close)
				h.caddyService = services.NewCaddyService(server.URL)
				router := gin.New()
				path, body := "/config/import", r78BackupJSON(t, nil, nil, nil)
				if format == "v1" {
					path, body = "/config/import/v1", v1Backup
					router.POST(path, h.ImportV1Config)
				} else {
					router.POST(path, h.ImportConfigBackup)
				}

				response := httptest.NewRecorder()
				request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				router.ServeHTTP(response, request)

				want := http.StatusInternalServerError
				if rejected {
					want = http.StatusBadRequest
				}
				if response.Code != want {
					t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), want)
				}
				if !rejected && strings.Contains(response.Body.String(), "未通过 Caddy 验证") {
					t.Fatalf("transport failure mislabeled as validation rejection: %s", response.Body.String())
				}
			})
		}
	}
}

func TestConfigImportAbort_restoresCommittedLKGWhenRuntimeRestoreFails(t *testing.T) {
	// Given an import that already attempted the uncommitted Caddy apply.
	harness := newImportRollbackHarness(t)
	h := harness.handler
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		VALUES ('lb_lkg','lkg','http','committed.example.test',18441,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol)
		VALUES ('lb_lkg','127.0.0.1',9000,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	lkgPath := filepath.Join(t.TempDir(), "last-good.json")
	h.caddyService.SetLastGoodPath(lkgPath)
	session, err := h.beginConfigImport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()
	session.runtime = &importRuntimeSnapshot{caddyConfig: map[string]interface{}{"marker": "before-import"}}
	session.runtimeApplyAttempted = true
	if _, err := session.tx.Exec(`UPDATE lb_rules SET domain='uncommitted.example.test' WHERE caddy_id='lb_lkg'`); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lkgPath, []byte(`{"apps":{"uncommitted":true}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	harness.failRestore()

	// When aborting while the runtime restore /load is also rejected.
	abortErr := session.abort(errors.New("injected commit failure"))

	// Then LKG still converges to committed bytes even though runtime recovery failed.
	if abortErr == nil {
		t.Fatal("abort must preserve the injected and restore errors")
	}
	lkg, err := os.ReadFile(lkgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lkg), "committed.example.test") || strings.Contains(string(lkg), "uncommitted") {
		t.Fatalf("LKG did not converge to committed view: %s", lkg)
	}
}

func TestImportConfigBackup_invalidatesTaskLogCacheAndCancelsInFlightRuns(t *testing.T) {
	// Given import side-effect spies.
	h := newBackupTestHandlers(t)
	oldInvalidate, oldCancel := invalidateImportTaskLogCache, cancelImportInFlightRuns
	invalidations, cancellations := 0, 0
	invalidateImportTaskLogCache = func() { invalidations++ }
	cancelImportInFlightRuns = func() { cancellations++ }
	t.Cleanup(func() {
		invalidateImportTaskLogCache, cancelImportInFlightRuns = oldInvalidate, oldCancel
	})
	body := r78BackupJSON(t, map[string][]map[string]any{
		"users": {{"id": 1, "username": "admin", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
	}, map[string]any{"task_log_size_mb": 20}, []string{"users"})

	// When committing an import that writes task_log_size_mb.
	rec := r78Import(h, t, body)

	// Then the task log TTL cache is invalidated and in-flight engine runs are canceled.
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	if invalidations != 1 || cancellations != 1 {
		t.Fatalf("invalidations=%d cancellations=%d, want 1/1", invalidations, cancellations)
	}
}
