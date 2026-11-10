package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// selfSignedPEM 生成自签证书对（CN=域名，NotAfter 远期）。
func selfSignedPEM(t *testing.T, cn string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(200 * 24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// 禁用→重启用（Resume 分支）后必须重渲染重应用——此前 Resume 在
// ApplyConfigFromTx 之后翻 'issued'，已应用配置缺 TLS/301 且无 re-apply，
// 看门狗只查路由存在，静默失配无上界。
func TestEnableRule_resumeTriggersReapplyWithTLS(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	restoreCertDir := services.SetCertDirForTest(t.TempDir())
	t.Cleanup(restoreCertDir)
	rec := &fakeCaddyRecorder{}
	fake := newFakeCaddyServer(t, rec)
	h.caddyService = services.NewCaddyService(fake.URL)

	certPEM, keyPEM := selfSignedPEM(t, "resume.example.test")
	farFuture := time.Now().UTC().Add(180 * 24 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('cfg','mock','',1)`); err != nil {
		t.Fatalf("seed dns config: %v", err)
	}
	var dnsCfgID int
	if err := db.DB.QueryRow("SELECT id FROM certificate_configs LIMIT 1").Scan(&dnsCfgID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,enabled,enable_tls,tls_source,acme_config_id)
		VALUES ('lb_resume','r','','http','resume.example.test',9472,0,1,'acme_dns',?)`, dnsCfgID); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_resume','10.1.1.1',9472,1,1,'http')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at) VALUES ('lb_resume','resume.example.test','disabled',?,?,?)`,
		certPEM, keyPEM, farFuture); err != nil {
		t.Fatalf("seed job: %v", err)
	}

	router := gin.New()
	router.POST("/rules/:caddy_id/enable", h.EnableRule)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_resume/enable", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}

	// Then：Resume 之后必须有 re-apply——最终一次 /load 载荷含该规则的 TLS 材料
	//（tls.load_files 非空）且不含 'disabled' 过滤态下的裸路由。
	// 原断言只查 lb_resume 字符串——无 TLS 裸路由也可通过；改为
	// 直接钉 TLS 材料（load_files + 证书路径）出现。
	if len(rec.loads) < 2 {
		t.Fatalf("/load calls=%d, want ≥2（启用应用 + Resume 重应用）", len(rec.loads))
	}
	final := rec.loads[len(rec.loads)-1]
	if !strings.Contains(final, "lb_resume") {
		t.Fatalf("最终 /load 载荷不含规则 lb_resume——Resume 后未重应用")
	}
	if !strings.Contains(final, `"load_files"`) {
		t.Fatalf("最终 /load 载荷不含 tls.load_files（TLS 材料缺失，重应用的是裸路由）: %s", final)
	}
	if !strings.Contains(final, "lb_resume.crt") {
		t.Fatalf("最终 /load 载荷不含该规则证书文件 lb_resume.crt（TLS 材料缺失）: %s", final)
	}
}

// Resume 的第二次成功应用才是最新已提交且已下发视图；首轮 note 收尾不得再把
// 启动兜底写回不含 TLS 的首轮载荷。两个入口都走真实任务恢复与两次 /load。
func TestRuleResume_lastGoodUsesLatestSuccessfulApply(t *testing.T) {
	for _, entry := range []string{"enable", "update"} {
		t.Run(entry, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			t.Cleanup(services.SetCertDirForTest(t.TempDir()))
			useTempCertJobLogDir(t)
			rec := &fakeCaddyRecorder{}
			fake := newFakeCaddyServer(t, rec)
			h.caddyService = services.NewCaddyService(fake.URL)
			lkgPath := filepath.Join(t.TempDir(), "last-good.json")
			h.caddyService.SetLastGoodPath(lkgPath)
			ruleID := "lb_resume_lkg_" + entry
			seedCertJobLogRule(t, ruleID, entry+"-lkg.example.test", "disabled")

			response := serveResumeEndpoint(t, h, ruleID, entry)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			if len(rec.loads) != 2 {
				t.Fatalf("/load calls=%d, want 2（首轮启用 + Resume 重应用）", len(rec.loads))
			}
			first, latest := rec.loads[0], rec.loads[1]
			if strings.Contains(first, `"load_files"`) {
				t.Fatal("首轮夹具不应包含 TLS 材料，无法区分新旧载荷")
			}
			if !strings.Contains(latest, `"load_files"`) || !strings.Contains(latest, ruleID+".crt") {
				t.Fatalf("第二轮载荷缺少恢复后的 TLS 材料: %s", latest)
			}
			if latest == first {
				t.Fatal("两轮载荷相同，无法验证 LKG 是否被首轮覆盖")
			}
			lastGood, err := os.ReadFile(lkgPath)
			if err != nil {
				t.Fatalf("read last-known-good: %v", err)
			}
			if string(lastGood) != latest {
				t.Fatalf("最终 LKG 不等于第二轮已下发载荷；首轮载荷被回写=%v", string(lastGood) == first)
			}
		})
	}
}

// 第二轮失败时不存在可 supersede 的成功载荷，仍走原有数据库、任务、运行配置
// 与 LKG 补偿；该用例是既有行为的基线钉。
func TestRuleResume_secondApplyFailureKeepsCompensation(t *testing.T) {
	for _, entry := range []string{"enable", "update"} {
		t.Run(entry, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			t.Cleanup(services.SetCertDirForTest(t.TempDir()))
			useTempCertJobLogDir(t)
			initial := `{"apps":{"http":{"servers":{"before":{"listen":[":8080"]}}}}}`
			current := initial
			var loads []string
			fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/config/":
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(current))
				case r.Method == http.MethodPost && r.URL.Path == "/load":
					body, _ := io.ReadAll(r.Body)
					loads = append(loads, string(body))
					if len(loads) == 2 {
						http.Error(w, "second apply failed", http.StatusInternalServerError)
						return
					}
					current = string(body)
					w.WriteHeader(http.StatusOK)
				default:
					w.WriteHeader(http.StatusOK)
				}
			}))
			t.Cleanup(fake.Close)
			h.caddyService = services.NewCaddyService(fake.URL)
			lkgPath := filepath.Join(t.TempDir(), "last-good.json")
			h.caddyService.SetLastGoodPath(lkgPath)
			ruleID := "lb_resume_fail_" + entry
			seedCertJobLogRule(t, ruleID, entry+"-fail.example.test", "disabled")

			response := serveResumeEndpoint(t, h, ruleID, entry)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
			}
			var enabled int
			var jobStatus string
			if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&enabled); err != nil {
				t.Fatal(err)
			}
			if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE rule_id=?", ruleID).Scan(&jobStatus); err != nil {
				t.Fatal(err)
			}
			// 既有恢复器在规则回到禁用态后保留当前 issued 行，避免把有效证书
			// 回滚成可重签状态；这里钉住该补偿语义，不改变任务状态机。
			if enabled != 0 || jobStatus != "issued" {
				t.Fatalf("补偿终态 enabled=%d job=%q, want 0/issued", enabled, jobStatus)
			}
			if len(loads) != 3 || current != initial {
				t.Fatalf("运行配置补偿 loads=%d current=%s, want 三次且恢复初始快照", len(loads), current)
			}
			lastGood, err := os.ReadFile(lkgPath)
			if err != nil {
				t.Fatalf("补偿后必须钉回已提交视图: %v", err)
			}
			expectedLastGood, err := json.Marshal(services.GenerateCaddyConfig())
			if err != nil {
				t.Fatalf("render committed view: %v", err)
			}
			if string(lastGood) != string(expectedLastGood) {
				t.Fatal("补偿后 LKG 必须等于当前已提交库视图")
			}
		})
	}
}

func serveResumeEndpoint(t *testing.T, h *Handlers, ruleID, entry string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	var request *http.Request
	switch entry {
	case "enable":
		router.POST("/rules/:caddy_id/enable", h.EnableRule)
		request = httptest.NewRequest(http.MethodPost, "/rules/"+ruleID+"/enable", nil)
	case "update":
		router.PUT("/rules/:caddy_id", h.UpdateRule)
		request = httptest.NewRequest(http.MethodPut, "/rules/"+ruleID, strings.NewReader(`{"enabled":true}`))
		request.Header.Set("Content-Type", "application/json")
	default:
		t.Fatalf("unknown entry %q", entry)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}
