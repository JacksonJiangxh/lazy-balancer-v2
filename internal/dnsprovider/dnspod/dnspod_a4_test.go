package dnspod

// A-4（历史证书域双实现同步）：cleanUp/deleteOne 在 provider 返回非 ctx
// 错误而 ctx 已取消/超时时，须与 tencent deleteOne 同口径把 ctx.Err() 并入
// 错误链（保留原始 provider 错误）——否则取消归因丢失，诊断只剩 API 文案。
// 钉法：传输层无视 req.Context() 恒回 API 错误体（模拟「取消与 API 失败并发」
// ——若走真实 HTTP 传输，url.Error 会包裹 context.Canceled 掩盖缺口），
// CleanUp 用已取消 ctx 调用：无 join 的旧实现 errors.Is(err, context.Canceled)
// 为假=红。

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type apiErrorIgnoringCtxTransport struct {
	dnsPodRecordTransport
}

func (transport *apiErrorIgnoringCtxTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.HasSuffix(request.URL.Path, "Record.Remove") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"status":{"code":"-1","message":"mock provider failure"}}`)),
			Request:    request,
		}, nil
	}
	return transport.dnsPodRecordTransport.RoundTrip(request)
}

func TestProvider_CleanUp_joinsContextErrorOnProviderFailure(t *testing.T) {
	transport := &apiErrorIgnoringCtxTransport{dnsPodRecordTransport{records: map[string]string{}}}
	provider := New("id,token")
	provider.client.Transport = transport
	if err := provider.Present(context.Background(), "example.com", "_acme-challenge.example.com.", "value", 600); err != nil {
		t.Fatalf("present record: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := provider.CleanUp(ctx, "example.com", "_acme-challenge.example.com.")
	if err == nil {
		t.Fatal("provider 失败必须返回错误")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want 归因 context.Canceled（与 tencent deleteOne ctx join 同口径）", err)
	}
	if !strings.Contains(err.Error(), "mock provider failure") {
		t.Fatalf("err=%v, want 保留原始 provider 错误文案（整体覆写会丢失诊断信息）", err)
	}
}
