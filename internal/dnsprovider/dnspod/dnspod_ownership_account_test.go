package dnspod

// 历史修复2：所有权条目带账户身份——换凭据后旧条目不得被新账户按
// record_id 调 provider 删除（旧账户 TXT 在新账户查无此 ID 会把「未删除」
// 当成功；ID 被同域复用时会命中无关记录）。legacy（Account 空）条目在陈旧
// 之后同样只丢弃不删除；仍在在途窗口内的 legacy 条目保持既有删除语义。

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/ownership"
)

const (
	foreignAccount   = "ffffffff"
	challengeName    = "_acme-challenge.example.com."
	challengeZoneLit = "example.com"
)

// captureWarnings 替换包级日志接缝并返回告警累计器（镜像既有 warn 断言写法）。
func captureWarnings(t *testing.T) *strings.Builder {
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

func seedOwnershipRecord(t *testing.T, dataDir string, record ownership.Record) {
	t.Helper()
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	if err := store.Add(record); err != nil {
		t.Fatalf("seed ownership record %+v: %v", record, err)
	}
}

// Given：同域名换用另一账户凭据，旧账户遗留条目仍在所有权文件里（已陈旧，
// 值与本轮挑战值相同因此会被按值清理选中）。
// When：新账户 Provider 执行 CleanUpValue。
// Then：MUST NOT 调 Record.Remove（旧 record_id 在新账户可能指向无关记录），
// 只丢弃本地条目并留一条告警。
func TestProvider_CleanUpValue_doesNotDeleteForeignAccountRecord(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	seedOwnershipRecord(t, dataDir, ownership.Record{
		Provider:  "dnspod",
		Zone:      challengeZoneLit,
		FQDN:      challengeName,
		Value:     "alpha",
		RecordID:  "500",
		Account:   foreignAccount,
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})
	transport := &dnsPodRecordTransport{records: map[string]string{"500": "alpha"}}
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
	warnings := captureWarnings(t)

	// When
	err = provider.CleanUpValue(t.Context(), challengeZoneLit, challengeName, "alpha")

	// Then：provider 删除一次都不该发生
	if err != nil {
		t.Fatalf("clean up: %v（他账户条目只丢弃，不该报错）", err)
	}
	transport.mu.Lock()
	_, alive := transport.records["500"]
	transport.mu.Unlock()
	if !alive {
		t.Fatal("他账户条目的 record_id 被调用删除（Record.Remove 不应被调用）")
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen ownership store: %v", err)
	}
	left, err := store.Matching("dnspod", challengeZoneLit, challengeName)
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

// Given：legacy 条目（旧版本写入，Account 为空）且已陈旧。
// When：当前账户执行 CleanUpValue。
// Then：同样只丢弃不删除——陈旧证明它不属于在途签发，而无法归属意味着它可能
// 来自换掉的那个账户。
func TestProvider_CleanUpValue_dropsStaleLegacyRecordWithoutDeleting(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	seedOwnershipRecord(t, dataDir, ownership.Record{
		Provider:  "dnspod",
		Zone:      challengeZoneLit,
		FQDN:      challengeName,
		Value:     "alpha",
		RecordID:  "600",
		CreatedAt: time.Now().Add(-2 * time.Hour),
	})
	transport := &dnsPodRecordTransport{records: map[string]string{"600": "alpha"}}
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
	warnings := captureWarnings(t)

	// When
	err = provider.CleanUpValue(t.Context(), challengeZoneLit, challengeName, "alpha")

	// Then
	if err != nil {
		t.Fatalf("clean up: %v", err)
	}
	transport.mu.Lock()
	_, alive := transport.records["600"]
	transport.mu.Unlock()
	if !alive {
		t.Fatal("陈旧 legacy 条目的 record_id 被调用删除")
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen ownership store: %v", err)
	}
	left, err := store.Matching("dnspod", challengeZoneLit, challengeName)
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

// Given：legacy 条目仍在在途窗口内（升级后首次清理）。
// When：当前账户执行 CleanUpValue。
// Then：保持既有删除语义（回归形状——账户维度不得让升级前的在途条目失去清理）。
func TestProvider_CleanUpValue_stillDeletesRecentLegacyRecord(t *testing.T) {
	// Given：store.Add 打当前时间戳，Account 保持空（旧版本写入形态）
	dataDir := t.TempDir()
	seedOwnershipRecord(t, dataDir, ownership.Record{
		Provider: "dnspod",
		Zone:     challengeZoneLit,
		FQDN:     challengeName,
		Value:    "alpha",
		RecordID: "700",
	})
	transport := &dnsPodRecordTransport{records: map[string]string{"700": "alpha"}}
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport
	_ = captureWarnings(t)

	// When
	err = provider.CleanUpValue(t.Context(), challengeZoneLit, challengeName, "alpha")

	// Then
	if err != nil {
		t.Fatalf("clean up: %v", err)
	}
	transport.mu.Lock()
	_, alive := transport.records["700"]
	transport.mu.Unlock()
	if alive {
		t.Fatal("在途窗口内的 legacy 条目未被删除（回归：升级后清理失效）")
	}
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen ownership store: %v", err)
	}
	left, err := store.Matching("dnspod", challengeZoneLit, challengeName)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("ownership left=%+v, want 删除成功后条目移除", left)
	}
}

// Given：Present 写入所有权条目。
// When：读取持久化文件。
// Then：条目带本实例凭据摘要（账户维度确实落盘，重启后仍可判定归属）。
func TestProvider_Present_persistsAccountDigest(t *testing.T) {
	// Given
	dataDir := t.TempDir()
	transport := &dnsPodRecordTransport{records: map[string]string{}}
	provider, err := NewPersistent("id,token", dataDir)
	if err != nil {
		t.Fatalf("create persistent provider: %v", err)
	}
	provider.client.Transport = transport

	// When
	if err := provider.Present(t.Context(), challengeZoneLit, challengeName, "alpha", 600); err != nil {
		t.Fatalf("present: %v", err)
	}

	// Then
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("reopen ownership store: %v", err)
	}
	records, err := store.Matching("dnspod", challengeZoneLit, challengeName)
	if err != nil {
		t.Fatalf("matching: %v", err)
	}
	want := ownership.AccountDigest("id,token")
	if len(records) != 1 || records[0].Account != want {
		t.Fatalf("records=%+v, want account=%q", records, want)
	}
	if want == "" {
		t.Fatal("account digest is empty")
	}
}
