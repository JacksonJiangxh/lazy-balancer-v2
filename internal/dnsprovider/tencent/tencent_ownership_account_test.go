package tencent

// 历史修复：所有权条目带账户身份（与 dnspod 侧同口径，判定单源在
// ownership.DecideRemoval）。换凭据后旧条目 MUST NOT 被按 record_id 删除。

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

const (
	foreignAccountID = "ffffffff"
	accountFQDN      = "_acme-challenge.example.com."
	accountZone      = "example.com"
)

func captureAccountWarnings(t *testing.T) *strings.Builder {
	t.Helper()
	var warnings strings.Builder
	oldLogf := logf
	logf = func(level, format string, args ...any) {
		if level == "warn" {
			warnings.WriteString(fmt.Sprintf(format, args...) + "\n")
		}
	}
	t.Cleanup(func() { logf = oldLogf })
	return &warnings
}

func seedAccountRecord(t *testing.T, dataDir string, record ownership.Record) {
	t.Helper()
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	if err := store.Add(record); err != nil {
		t.Fatalf("seed ownership record %+v: %v", record, err)
	}
}

// Given：同域名换用另一账户凭据，旧账户遗留条目已陈旧、值与本轮挑战值相同。
// When：新账户 Provider 执行 CleanUpValue。
// Then：MUST NOT 调 DeleteRecord，只丢弃本地条目并留一条告警。
func TestProvider_CleanUpValue_doesNotDeleteForeignAccountRecord(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	seedAccountRecord(t, dataDir, ownership.Record{
		Provider:  "tencent",
		Zone:      accountZone,
		FQDN:      accountFQDN,
		Value:     "alpha",
		RecordID:  "200",
		Account:   foreignAccountID,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})
	transport := &recordTransport{records: map[uint64]string{200: "alpha"}}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	warnings := captureAccountWarnings(t)

	// When
	err = provider.CleanUpValue(t.Context(), accountZone, accountFQDN, "alpha")

	// Then
	if err != nil {
		t.Fatalf("clean up: %v", err)
	}
	transport.mu.Lock()
	_, alive := transport.records[200]
	transport.mu.Unlock()
	if !alive {
		t.Fatal("他账户条目的 record_id 被调用删除（DeleteRecord 不应被调用）")
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen ownership store: %v", err)
	}
	left, err := store.Matching("tencent", accountZone, accountFQDN)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("ownership left=%+v, want 他账户条目被丢弃", left)
	}
	if !strings.Contains(warnings.String(), "无法归属当前账户") {
		t.Fatalf("warnings=%q, want 丢弃原因留痕", warnings.String())
	}
}

// Given：legacy 条目（Account 空）且已陈旧。
// When：当前账户执行 CleanUpValue。
// Then：只丢弃不删除（陈旧条目可能来自已换掉的账户）。
func TestProvider_CleanUpValue_dropsStaleLegacyRecordWithoutDeleting(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	seedAccountRecord(t, dataDir, ownership.Record{
		Provider:  "tencent",
		Zone:      accountZone,
		FQDN:      accountFQDN,
		Value:     "alpha",
		RecordID:  "201",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})
	transport := &recordTransport{records: map[uint64]string{201: "alpha"}}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	warnings := captureAccountWarnings(t)

	// When
	err = provider.CleanUpValue(t.Context(), accountZone, accountFQDN, "alpha")

	// Then
	if err != nil {
		t.Fatalf("clean up: %v", err)
	}
	transport.mu.Lock()
	_, alive := transport.records[201]
	transport.mu.Unlock()
	if !alive {
		t.Fatal("陈旧 legacy 条目的 record_id 被调用删除")
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen ownership store: %v", err)
	}
	left, err := store.Matching("tencent", accountZone, accountFQDN)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("ownership left=%+v, want legacy 陈旧条目被丢弃", left)
	}
	if !strings.Contains(warnings.String(), "无法归属当前账户") {
		t.Fatalf("warnings=%q, want 丢弃原因留痕", warnings.String())
	}
}

// Given：legacy 条目仍在在途窗口内。
// When：当前账户执行 CleanUpValue。
// Then：保持既有删除语义（回归形状）。
func TestProvider_CleanUpValue_stillDeletesRecentLegacyRecord(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	seedAccountRecord(t, dataDir, ownership.Record{
		Provider: "tencent",
		Zone:     accountZone,
		FQDN:     accountFQDN,
		Value:    "alpha",
		RecordID: "202",
	})
	transport := &recordTransport{records: map[uint64]string{202: "alpha"}}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)
	_ = captureAccountWarnings(t)

	// When
	err = provider.CleanUpValue(t.Context(), accountZone, accountFQDN, "alpha")

	// Then
	if err != nil {
		t.Fatalf("clean up: %v", err)
	}
	transport.mu.Lock()
	_, alive := transport.records[202]
	transport.mu.Unlock()
	if alive {
		t.Fatal("在途窗口内的 legacy 条目未被删除（回归：升级后清理失效）")
	}
}

// Given：Present 写入所有权条目。
// When：读取持久化文件。
// Then：条目带本实例凭据摘要。
func TestProvider_Present_persistsAccountDigest(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	transport := &recordTransport{records: map[uint64]string{}}
	provider, err := NewPersistent("secret-id", "secret-key", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.WithHttpTransport(transport)

	// When
	if err := provider.Present(t.Context(), accountZone, accountFQDN, "alpha", 600); err != nil {
		t.Fatalf("present: %v", err)
	}

	// Then
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen ownership store: %v", err)
	}
	records, err := store.Matching("tencent", accountZone, accountFQDN)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	want := ownership.AccountDigest("secret-id\x00secret-key")
	if len(records) != 1 || records[0].Account != want {
		t.Fatalf("records=%+v, want account=%q", records, want)
	}
	if want == "" {
		t.Fatal("account digest is empty")
	}
}
