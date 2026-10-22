package ownership

import (
	"testing"
	"time"
)

// 账本保留期：超过 OwnershipRetention 的已归属条目在下一次写入时退役，
// 避免历史域名/失败中断的条目永久滞留；无法证明年龄的 legacy 条目保留。
func TestStore_saveRetiresExpiredEntries(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "v1", RecordID: "1", CreatedAt: time.Now().Add(-OwnershipRetention - time.Hour)}
	fresh := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "v2", RecordID: "2", CreatedAt: time.Now().Add(-time.Hour)}
	legacy := Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "v3", RecordID: "3"}
	for _, rec := range []Record{old, fresh, legacy} {
		if err := store.Add(rec); err != nil {
			t.Fatal(err)
		}
	}
	// 再写一次触发退役
	if err := store.Add(Record{Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com", Value: "v4", RecordID: "4"}); err != nil {
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
		t.Fatal("超过保留期的条目应退役")
	}
	for _, want := range []string{"v2", "v3", "v4"} {
		if !seen[want] {
			t.Fatalf("条目 %s 不应被退役（seen=%v）", want, seen)
		}
	}
}
