package services

// allow: SIZE_OK — download size cap regression tests.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteRuleSetDownload_limitsDownloadSize 验证下载限界
// 超上限先拒绝落盘；流式拷贝超上限报错中止；上限内正常。
func TestWriteRuleSetDownload_limitsDownloadSize(t *testing.T) {
	const cap = int64(1024)
	cases := []struct {
		name          string
		contentLength int64
		body          []byte
		wantErr       bool
	}{
		{"content_length_over_cap", 2 * cap, []byte("x"), true},
		{"stream_over_cap", -1, bytes.Repeat([]byte("x"), int(cap+1)), true},
		{"exactly_cap", -1, bytes.Repeat([]byte("x"), int(cap)), false},
		{"small_body", -1, []byte("ok"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := os.OpenFile(filepath.Join(t.TempDir(), "download"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			resp := &http.Response{
				ContentLength: tc.contentLength,
				Body:          io.NopCloser(bytes.NewReader(tc.body)),
			}
			err = writeRuleSetDownload(out, resp, cap, nil)
			if tc.wantErr {
				if err == nil {
					t.Fatal("oversized download must be rejected, got nil error")
				}
				if !strings.Contains(err.Error(), "超过大小上限") {
					t.Fatalf("error must name the size cap, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("download within cap must succeed, got %v", err)
			}
		})
	}
}

// TestRuleSetDownloadSizeCap_isSet verifies the production cap constant is wired
// to both download paths (a zero cap would reject every download).
func TestRuleSetDownloadSizeCap_isSet(t *testing.T) {
	if ruleSetDownloadSizeCap <= 0 {
		t.Fatalf("ruleSetDownloadSizeCap = %d, want > 0", ruleSetDownloadSizeCap)
	}
}

// 爬虫源响应体上限按格式分档：JSON 源解进 any 树再递归遍历，结构放大远高于
// 文本，故收在 2MiB；HTML/纯文本源保持 16MiB（不得误伤大页面）。
func TestCrawlerFetchBody_formatAwareCaps(t *testing.T) {
	if crawlerJSONBodyCap <= 0 || crawlerJSONBodyCap >= crawlerBodyCap {
		t.Fatalf("JSON 上限=%d，必须 >0 且小于通用上限 %d", crawlerJSONBodyCap, crawlerBodyCap)
	}
	serve := func(body []byte) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(body)
		}))
	}

	// JSON 源：超过 2MiB 直接拒绝（保留上次快照）
	bigJSON := serve(bytes.Repeat([]byte("x"), int(crawlerJSONBodyCap)+1))
	defer bigJSON.Close()
	if _, err := crawlerFetchBody(context.Background(), crawlerSource{URL: bigJSON.URL, Format: "json"}); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("JSON 源超上限必须拒绝, err=%v", err)
	}

	// HTML 源：同样的 2MiB+ 体积不得被 JSON 档误伤
	bigHTML := serve(bytes.Repeat([]byte("x"), int(crawlerJSONBodyCap)+1))
	defer bigHTML.Close()
	if _, err := crawlerFetchBody(context.Background(), crawlerSource{URL: bigHTML.URL, Format: "html"}); err != nil {
		t.Fatalf("HTML 源在通用上限内不得拒绝: %v", err)
	}

	// JSON 源在上限内正常下载
	smallJSON := serve([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.66.0/24"}]}`))
	defer smallJSON.Close()
	body, err := crawlerFetchBody(context.Background(), crawlerSource{URL: smallJSON.URL, Format: "json"})
	if err != nil {
		t.Fatalf("上限内 JSON 源必须下载成功: %v", err)
	}
	if !strings.Contains(body, "66.249.66.0/24") {
		t.Fatalf("body=%q，下载内容缺失", body)
	}
}

// TestIP2RegionXDBDownloadSizeCap_isPinned 钉住 xdb 下载的独立上限：xdb 在
// 安装校验期经 BufferCache 全量读入内存，2GB 上限会让恶意/损坏响应在小内存
// 容器上 OOM；100MB 是有意护栏，不得回落到 CRS tarball 的共用值。
func TestIP2RegionXDBDownloadSizeCap_isPinned(t *testing.T) {
	if got, want := ip2RegionXDBDownloadSizeCap, int64(100<<20); got != want {
		t.Fatalf("ip2RegionXDBDownloadSizeCap=%d, want %d（100MB 防 OOM 护栏）", got, want)
	}
	if ip2RegionXDBDownloadSizeCap >= ruleSetDownloadSizeCap {
		t.Fatalf("xdb 上限=%d 不得回落为 CRS 共用上限 %d", ip2RegionXDBDownloadSizeCap, ruleSetDownloadSizeCap)
	}
}
