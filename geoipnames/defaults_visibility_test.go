package geoipnames

import "testing"

// 默认勾选集不得外泄可变切片：消费方只取副本（就地排序/追加不污染全局默认，
// 否则向导默认值会被某次请求改写）。
func TestDefaultCrawlerEngines_returnsIndependentCopy(t *testing.T) {
	first := DefaultCrawlerEngines()
	if len(first) == 0 {
		t.Fatal("默认勾选集不得为空")
	}
	first[0] = "mutated"

	if got := DefaultCrawlerEngines()[0]; got == "mutated" {
		t.Fatal("DefaultCrawlerEngines 返回的切片与全局默认共享底层数组（可被消费方改写）")
	}
	for _, id := range DefaultCrawlerEngines() {
		if !ValidCrawlerEngineID(id) {
			t.Errorf("默认勾选集含非法 ID %q", id)
		}
	}
}
