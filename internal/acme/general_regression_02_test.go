package acme

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureProgressLogger 捕获 waitForValidation 进度行。
type captureProgressLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (logger *captureProgressLogger) Log(stage, message string) {
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if stage == "validating" {
		logger.msgs = append(logger.msgs, message)
	}
}

func (logger *captureProgressLogger) countContaining(sub string) int {
	logger.mu.Lock()
	defer logger.mu.Unlock()
	n := 0
	for _, msg := range logger.msgs {
		if strings.Contains(msg, sub) {
			n++
		}
	}
	return n
}

// challenge 命中后转 valid——轮询节拍缩短到 5ms，9 次轮询内应只在第 6 次打点
// （1 条，且必须携带真实状态）；未修时每次一条（9 条），且首条为空状态行。
func TestIssuer_waitForValidation_throttlesProgressLog(t *testing.T) {
	oldInterval := validationPollInterval
	validationPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { validationPollInterval = oldInterval })

	var mu sync.Mutex
	chalHits := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Replay-Nonce", "test-nonce")
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/directory":
			_, _ = fmt.Fprintf(response, `{"newNonce":%q,"newOrder":%q,"newAccount":%q}`, server.URL+"/nonce", server.URL+"/order", server.URL+"/account")
		case "/nonce":
			response.WriteHeader(http.StatusOK)
		case "/chal/1":
			mu.Lock()
			chalHits++
			mu.Unlock()
			_, _ = fmt.Fprintf(response, `{"type":"dns-01","status":"pending","url":%q,"token":"tok"}`, server.URL+"/chal/1")
		case "/auth/1":
			mu.Lock()
			status := "pending"
			if chalHits >= 9 {
				status = "valid"
			}
			mu.Unlock()
			_, _ = fmt.Fprintf(response, `{"status":%q,"identifier":{"type":"dns","value":"example.com"}}`, status)
		default:
			http.NotFound(response, request)
		}
	}))
	t.Cleanup(server.Close)

	client := newValidationTestClient(t, server, nil)
	logger := &captureProgressLogger{}
	issuer := &Issuer{Client: client, Logger: logger}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := issuer.waitForValidation(ctx, server.URL+"/auth/1", server.URL+"/chal/1"); err != nil {
		t.Fatalf("waitForValidation: %v", err)
	}
	mu.Lock()
	iterations := chalHits
	mu.Unlock()
	progress := logger.countContaining("仍在等待")
	if progress != 1 {
		t.Fatalf("9 轮等待应只打 1 条进度日志（第 6 轮, iterations=%d）, got %d", iterations, progress)
	}
	if empty := logger.countContaining("(challenge: , 授权: )"); empty != 0 {
		t.Fatalf("进度行不得以空状态输出, got %d 条", empty)
	}
}

// 路径用 sha256 空摘要、元数据记空串，形态保持既有语义）。
func TestEABKeyDigest_singleSource(t *testing.T) {
	key := []byte("secret-a")
	if got, want := eabKeyDigestOf(key), eabKeyDigestRaw(key); got != want {
		t.Fatalf("eabKeyDigestOf=%q, want raw=%q（双实现分叉）", got, want)
	}
	if got := eabKeyDigestOf(nil); got != "" {
		t.Fatalf("空 key 元数据摘要应为空串, got %q", got)
	}
	if got := eabKeyDigestRaw(nil); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("空 key 路径摘要应是 sha256(\"\") 的 hex, got %q", got)
	}
	path := acmeAccountKeyPath(t.TempDir(), "https://acme.example/directory", "admin@example.com", "kid", key)
	if !strings.HasSuffix(path, ".key") {
		t.Fatalf("账户密钥路径形态异常: %q", path)
	}
}
