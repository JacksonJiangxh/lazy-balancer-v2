package tencent

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// toggleDeleteFailTransport 让 DeleteRecord 一律返回 API 错误（其余委托
// 基础 transport）；failDelete 可切换，模拟删除恢复。
type toggleDeleteFailTransport struct {
	recordTransport
	flagMu     sync.Mutex
	failDelete bool
}

func (transport *toggleDeleteFailTransport) setFailDelete(v bool) {
	transport.flagMu.Lock()
	transport.failDelete = v
	transport.flagMu.Unlock()
}

func (transport *toggleDeleteFailTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.flagMu.Lock()
	fail := transport.failDelete
	transport.flagMu.Unlock()
	if fail && request.Header.Get("X-TC-Action") == "DeleteRecord" {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"Response":{"Error":{"Code":"UnauthorizedOperation","Message":"无权限"},"RequestId":"test"}}`)),
			Request:    request,
		}, nil
	}
	return transport.recordTransport.RoundTrip(request)
}

// ownership.Add 失败且回滚删除亦失败时
// 告警留痕 + 回填内存兜底表；cleanUp 的 ownership 分支排空兜底表重试删除。
func TestProvider_Present_ownershipAddAndRollbackFailureRefillsFallback(t *testing.T) {
	// Given：ownership 文件路径被目录占据（root 下也必定读写失败）→ Add 失败；
	// DeleteRecord 失败 → 回滚删除亦失败。
	dataDir := t.TempDir()
	transport := &toggleDeleteFailTransport{recordTransport: recordTransport{records: map[uint64]string{}}, failDelete: true}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	// 告警必须经包级 logf 接缝（统一日志级别/格式链），不得裸 log.Printf。
	var captured strings.Builder
	oldLogf := logf
	logf = func(level, format string, args ...any) {
		if level == "warn" {
			captured.WriteString(fmt.Sprintf(format, args...))
		}
	}
	t.Cleanup(func() { logf = oldLogf })
	ownershipPath := filepath.Join(dataDir, "acme_dns_ownership.json")
	if err := os.Mkdir(ownershipPath, 0o755); err != nil {
		t.Fatalf("block ownership file with directory: %v", err)
	}

	// When
	err = provider.Present(t.Context(), "example.com", "_acme-challenge.example.com.", "value", 600)

	// Then：双失败上报 + 记录回填内存兜底表
	if err == nil {
		t.Fatal("ownership.Add 失败 + 回滚删除失败必须上报，不得静默")
	}
	if !strings.Contains(captured.String(), "tencent: 所有权写入失败") {
		t.Fatalf("残留告警必须经 logf 接缝进入统一日志链，captured=%q", captured.String())
	}
	provider.mu.Lock()
	entries := append([]ownedRecord(nil), provider.owned["example.com|_acme-challenge"]...)
	provider.mu.Unlock()
	if len(entries) != 1 || entries[0].recordID != 200 {
		t.Fatalf("owned fallback=%+v, want 孤儿记录 200 回填", entries)
	}

	// When：存储与删除均恢复 → cleanUp 排空兜底表并重试删除
	if err := os.Remove(ownershipPath); err != nil {
		t.Fatalf("remove blocking ownership directory: %v", err)
	}
	transport.setFailDelete(false)
	if err := provider.CleanUp(t.Context(), "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("clean up after recovery: %v", err)
	}

	// Then：孤儿记录被删除且兜底表清空
	transport.mu.Lock()
	_, alive := transport.records[200]
	transport.mu.Unlock()
	if alive {
		t.Fatal("兜底条目必须在 cleanUp 中被删除（无追踪窗口未收口）")
	}
	provider.mu.Lock()
	left := provider.owned["example.com|_acme-challenge"]
	provider.mu.Unlock()
	if len(left) != 0 {
		t.Fatalf("排空成功后兜底表须清空, got %+v", left)
	}
}
