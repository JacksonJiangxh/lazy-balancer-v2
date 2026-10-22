package ownership

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// 账本保留期：超过 OwnershipRetention 的已归属条目在下一次写入时退役，
// 避免历史域名/失败中断的条目永久滞留；无法证明年龄的 legacy 条目保留。
func TestStore_saveRetiresExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	store, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 用 Replace 预置「已落盘」的存量（Add 写入期也会剪枝，无法构造该前提）。
	snapshot := `{"version":1,"records":[
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"v1","record_id":"1","created_at":"` +
		time.Now().Add(-OwnershipRetention-time.Hour).UTC().Format(time.RFC3339) + `"},
		{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"v3","record_id":"3"}
	]}`
	if err := Replace(dir, []byte(snapshot)); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "v2", RecordID: "2"}); err != nil {
		t.Fatal(err)
	}
	matching, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, rec := range matching {
		seen[rec.Value] = true
	}
	if seen["v1"] {
		t.Fatal("超过保留期的存量条目应退役")
	}
	for _, want := range []string{"v2", "v3"} {
		if !seen[want] {
			t.Fatalf("条目 %s 不应被退役（seen=%v）", want, seen)
		}
	}
}

// 退役必须有日志：账本条目消失属于「数据被删」，运维需要可见（单行、含条数）。
func TestStore_saveLogsRetiredEntryCount(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	prev := logf
	SetLogf(func(level, format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, level+" "+fmt.Sprintf(format, args...))
	})
	t.Cleanup(func() { SetLogf(prev) })

	// 写入一个已超保留期的条目：写入期剪枝即触发退役日志。
	old := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "v1", RecordID: "1", CreatedAt: time.Now().Add(-OwnershipRetention - time.Hour)}
	if err := store.Add(old); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "退役 1 条") {
		t.Fatalf("退役日志缺失或条数不符: %q", joined)
	}
	if !strings.Contains(joined, "info") {
		t.Fatalf("退役日志级别应为 info: %q", joined)
	}
}
