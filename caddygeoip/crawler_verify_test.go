package caddygeoip

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeResolver 可编程 DNS 替身：PTR 与正向结果按表返回。
type fakeResolver struct {
	mu      sync.Mutex
	ptr     map[string][]string // ip → PTR names（含尾点模拟 LookupAddr）
	host    map[string][]string // name → addrs
	ptrErr  map[string]error
	hostErr map[string]error
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.ptrErr[addr]; ok {
		return nil, err
	}
	return f.ptr[addr], nil
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.hostErr[host]; ok {
		return nil, err
	}
	return f.host[host], nil
}

// Given/When/Then：真爬虫（双跳通过）、机房伪装、伪造 PTR、超时、缓存命中。
func TestVerifyCrawler_passFailMatrix(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptr: map[string][]string{
			"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
			"34.100.1.1":  {"vm-34-100-1-1.bc.googleusercontent.com."},
			"1.2.3.4":     {"fake.googlebot.com."},
		},
		host: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"},
			"fake.googlebot.com":              {"66.249.66.999"}, // 正向不含原 IP
		},
	})
	// 真 Googlebot：PTR 属域 + 正向回验含原 IP → 通过
	if !VerifyCrawler("66.249.66.1", "googlebot") {
		t.Error("真 Googlebot 应通过")
	}
	// GCP 机房伪装：PTR 后缀不属引擎域 → 拒
	if VerifyCrawler("34.100.1.1", "googlebot") {
		t.Error("GCP PTR 伪装应拒绝")
	}
	// 伪造 PTR 指向官方域：正向回验不含原 IP → 拒
	if VerifyCrawler("1.2.3.4", "googlebot") {
		t.Error("伪造 PTR（正向不含原 IP）应拒绝")
	}
	// 缓存：同 IP 二次询问不再触 DNS（通过结论已缓存）
	if !VerifyCrawler("66.249.66.1", "googlebot") {
		t.Error("缓存命中应直接通过")
	}
}

func TestVerifyCrawler_transientFailuresNotCached(t *testing.T) {
	t.Run("semaphore saturated", func(t *testing.T) {
		ResetCrawlerVerifyCacheForTest(&fakeResolver{})
		for len(crawlerVerifySem) > 0 {
			<-crawlerVerifySem
		}
		for range cap(crawlerVerifySem) {
			crawlerVerifySem <- struct{}{}
		}
		t.Cleanup(func() {
			for len(crawlerVerifySem) > 0 {
				<-crawlerVerifySem
			}
		})

		if VerifyCrawler("9.8.7.6", "googlebot") {
			t.Fatal("saturated verifier must fail closed for the current request")
		}
		crawlerCacheMu.Lock()
		_, cached := crawlerCache["9.8.7.6|googlebot"]
		crawlerCacheMu.Unlock()
		if cached {
			t.Fatal("semaphore saturation is transient and must not create a 10-minute negative entry")
		}
	})

	for _, tc := range []struct {
		name string
		ip   string
		err  error
	}{
		{name: "resolver error", ip: "5.6.7.8", err: errors.New("resolver down")},
		{name: "context timeout", ip: "5.6.7.9", err: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ResetCrawlerVerifyCacheForTest(&fakeResolver{ptrErr: map[string]error{tc.ip: tc.err}})
			if VerifyCrawler(tc.ip, "googlebot") {
				t.Fatal("DNS failure must fail closed")
			}
			crawlerCacheMu.Lock()
			_, cached := crawlerCache[tc.ip+"|googlebot"]
			crawlerCacheMu.Unlock()
			if cached {
				t.Fatal("transient DNS failure must not be cached")
			}
		})
	}

	t.Run("forward resolver error", func(t *testing.T) {
		const (
			ip   = "66.249.66.9"
			host = "crawl-66-249-66-9.googlebot.com"
		)
		ResetCrawlerVerifyCacheForTest(&fakeResolver{
			ptr:     map[string][]string{ip: {host + "."}},
			hostErr: map[string]error{host: errors.New("forward resolver down")},
		})
		if VerifyCrawler(ip, "googlebot") {
			t.Fatal("failed forward verification must fail closed")
		}
		crawlerCacheMu.Lock()
		_, cached := crawlerCache[ip+"|googlebot"]
		crawlerCacheMu.Unlock()
		if cached {
			t.Fatal("forward resolver failure is transient and must not be cached")
		}
	})

	t.Run("deterministic negative stays cached", func(t *testing.T) {
		const ip = "34.100.1.1"
		ResetCrawlerVerifyCacheForTest(&fakeResolver{ptr: map[string][]string{
			ip: {"vm-34-100-1-1.bc.googleusercontent.com."},
		}})
		if VerifyCrawler(ip, "googlebot") {
			t.Fatal("non-official PTR must not verify")
		}
		crawlerCacheMu.Lock()
		entry, cached := crawlerCache[ip+"|googlebot"]
		crawlerCacheMu.Unlock()
		if !cached || entry.ok {
			t.Fatalf("deterministic negative must retain its negative cache entry: %+v cached=%v", entry, cached)
		}
	})
}

func TestVerifyCrawler_cacheCapacityPreservesLiveEntries(t *testing.T) {
	const newIP = "34.100.1.1"
	newResolver := func() *fakeResolver {
		return &fakeResolver{ptr: map[string][]string{
			newIP: {"vm-34-100-1-1.bc.googleusercontent.com."},
		}}
	}

	t.Run("prunes only expired entries", func(t *testing.T) {
		ResetCrawlerVerifyCacheForTest(newResolver())
		oldMax := crawlerCacheMax
		crawlerCacheMax = 2
		t.Cleanup(func() { crawlerCacheMax = oldMax })
		now := time.Now()
		crawlerCacheMu.Lock()
		crawlerCache["keep|googlebot"] = crawlerVerifyCache{ok: true, expires: now.Add(time.Hour)}
		crawlerCache["expired|googlebot"] = crawlerVerifyCache{ok: true, expires: now.Add(-time.Minute)}
		crawlerCacheMu.Unlock()

		if VerifyCrawler(newIP, "googlebot") {
			t.Fatal("test input must produce a deterministic negative")
		}
		crawlerCacheMu.Lock()
		keep, keepExists := crawlerCache["keep|googlebot"]
		_, expiredExists := crawlerCache["expired|googlebot"]
		_, newExists := crawlerCache[newIP+"|googlebot"]
		size := len(crawlerCache)
		crawlerCacheMu.Unlock()
		if !keepExists || !keep.ok {
			t.Fatal("capacity cleanup must not evict a live positive verification")
		}
		if expiredExists {
			t.Fatal("expired entry must be pruned at capacity")
		}
		if !newExists || size != 2 {
			t.Fatalf("after pruning size=%d newCached=%v, want size=2 and new result cached", size, newExists)
		}
	})

	t.Run("full live cache rejects new key without eviction", func(t *testing.T) {
		ResetCrawlerVerifyCacheForTest(newResolver())
		oldMax := crawlerCacheMax
		crawlerCacheMax = 2
		t.Cleanup(func() { crawlerCacheMax = oldMax })
		now := time.Now()
		crawlerCacheMu.Lock()
		crawlerCache["keep-a|googlebot"] = crawlerVerifyCache{ok: true, expires: now.Add(time.Hour)}
		crawlerCache["keep-b|googlebot"] = crawlerVerifyCache{ok: true, expires: now.Add(time.Hour)}
		crawlerCacheMu.Unlock()

		if VerifyCrawler(newIP, "googlebot") {
			t.Fatal("test input must produce a deterministic negative")
		}
		crawlerCacheMu.Lock()
		_, keepA := crawlerCache["keep-a|googlebot"]
		_, keepB := crawlerCache["keep-b|googlebot"]
		_, newExists := crawlerCache[newIP+"|googlebot"]
		size := len(crawlerCache)
		crawlerCacheMu.Unlock()
		if !keepA || !keepB || size != 2 {
			t.Fatalf("live entries must survive a full cache: keepA=%v keepB=%v size=%d", keepA, keepB, size)
		}
		if newExists {
			t.Fatal("a full live cache must skip the new key rather than evict verified crawlers")
		}
	})
}

func TestVerifyCrawlerIPRangeFromList_jsonPerEngine(t *testing.T) {
	// Given：按引擎隔离的快照 JSON（与 root 服务 writeCrawlerIPListSnapshotAll 同形）
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	defer func() { crawlerIPListFile = oldFile }()
	if err := os.WriteFile(crawlerIPListFile, []byte(`{"so360spider":["42.236.8.0/21"],"googlebot":["66.249.66.0/24"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ResetCrawlerVerifyCacheForTest(nil)

	// When / Then：360 命中只认 360 源，不得混用 Google 段
	if !verifyCrawlerIPRangeFromList("42.236.8.1", "so360spider") {
		t.Fatal("360 官方段应命中 iprange")
	}
	if verifyCrawlerIPRangeFromList("42.236.8.1", "googlebot") {
		t.Fatal("360 段不得串入 Googlebot 命中")
	}
}

func TestVerifyCrawler_dnsFailureFailClosed(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptrErr: map[string]error{"5.6.7.8": errors.New("resolver down")},
	})
	if VerifyCrawler("5.6.7.8", "googlebot") {
		t.Error("DNS 失败必须 fail-closed 拒绝")
	}
}

// ---- 历史 历史问题 / 历史问题 ----

func resetCrawlerIPRangeCacheForTest() {
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap = nil
	crawlerFileCacheMu.Unlock()
}

func TestCrawlerIPRangeList_precompiledAndFailureThrottled(t *testing.T) {
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	resetCrawlerIPRangeCacheForTest()

	// 缺失快照：fail-closed，且失败也写节流时间戳。
	if verifyCrawlerIPRangeFromList("66.249.66.1", "googlebot") {
		t.Fatal("missing snapshot must fail closed")
	}
	if err := os.WriteFile(crawlerIPListFile, []byte(`{"googlebot":["66.249.66.0/24"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// 10 分钟内不重读：失败节流生效（旧实现在失败路径不写时间戳，会立即重读）。
	if verifyCrawlerIPRangeFromList("66.249.66.1", "googlebot") {
		t.Fatal("failure must be throttled for the reload interval")
	}
	// 过期后重读 → 命中；命中用预编译前缀（判定不再逐条 ParsePrefix）。
	crawlerFileCacheMu.Lock()
	crawlerFileCacheSnap.loadedAt = time.Now().Add(-11 * time.Minute)
	crawlerFileCacheMu.Unlock()
	if !verifyCrawlerIPRangeFromList("66.249.66.1", "googlebot") {
		t.Fatal("snapshot reload must match the configured prefix")
	}
	crawlerFileCacheMu.Lock()
	snap := crawlerFileCacheSnap
	crawlerFileCacheMu.Unlock()
	if snap == nil || len(snap.prefixes["googlebot"]) != 1 {
		t.Fatalf("prefixes must be precompiled at load, got %#v", snap)
	}
	// 回归形状：段外地址不命中。
	if verifyCrawlerIPRangeFromList("66.249.67.1", "googlebot") {
		t.Fatal("address outside the prefix must not match")
	}
}

func TestVerifyCrawlerIPRange_invalidAddrNoPanic(t *testing.T) {
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	if err := os.WriteFile(crawlerIPListFile, []byte(`{"so360spider":["140.0.0.0/24"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resetCrawlerIPRangeCacheForTest()
	for _, bad := range []string{"@", "not-an-addr", ""} {
		if verifyCrawlerIPRangeFromList(bad, "so360spider") {
			t.Fatalf("invalid address %q must not match", bad)
		}
	}
	if !verifyCrawlerIPRangeFromList("140.0.0.1", "so360spider") {
		t.Fatal("valid address regression: expected match")
	}
}

// ---- 历史 E-CM-05：地址归一化（Unmap/zone），方向 fail-closed ----

// Given: 客户端 IP 为 4in6 映射形态，PTR 属引擎官方域，正向回验返回 v4 规范串
// When: 双跳验证
// Then: 同地址不同文本形态须判等通过（Unmap 归一）；正向不含原 IP 仍拒绝。
func TestVerifyCrawlerDNS_v4MappedFormsUnified(t *testing.T) {
	ResetCrawlerVerifyCacheForTest(&fakeResolver{
		ptr: map[string][]string{
			"::ffff:66.249.66.1": {"crawl-66-249-66-1.googlebot.com."},
			"::ffff:66.249.66.2": {"crawl-66-249-66-2.googlebot.com."},
		},
		host: map[string][]string{
			"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}, // 正向返回 v4 规范串
			"crawl-66-249-66-2.googlebot.com": {"66.249.66.9"}, // 正向不含原 IP
		},
	})
	// 目标形状：4in6 客户端 + v4 规范正向应答 = 同地址，须通过
	// （旧字符串比较 "::ffff:66.249.66.1" == "66.249.66.1" 恒假 → 真爬虫误杀）。
	if !VerifyCrawler("::ffff:66.249.66.1", "googlebot") {
		t.Error("4in6 客户端与 v4 正向应答同地址应通过（Unmap 归一）")
	}
	// 回归形状：映射形态但正向回验不含原 IP → 仍 fail-closed。
	if VerifyCrawler("::ffff:66.249.66.2", "googlebot") {
		t.Error("4in6 客户端正向不含原 IP 仍须拒绝")
	}
	// 畸形形状：带 zone 地址不得命中（fail-closed）。
	if VerifyCrawler("2001:db8::1%eth0", "googlebot") {
		t.Error("带 zone 地址必须 fail-closed")
	}
}

// Given: 官方段名单含 v4 段与 v6 段
// When: 查询 4in6 映射形态/段外映射形态/原生 v6/带 zone 地址
// Then: 映射形态归一命中 v4 段；段外与 zone 形态 fail-closed；v6 不受影响。
func TestVerifyCrawlerIPRange_v4MappedAndZoneNormalized(t *testing.T) {
	oldFile := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldFile })
	if err := os.WriteFile(crawlerIPListFile, []byte(`{"so360spider":["42.236.8.0/21","2408:4000::/32"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resetCrawlerIPRangeCacheForTest()

	// 目标形状：4in6 映射形态命中 v4 段（Unmap 归一；旧实现 netip v4 前缀
	// 不含 4in6 地址，恒不命中 → 真爬虫被误判为伪装）。
	if !verifyCrawlerIPRangeFromList("::ffff:42.236.8.1", "so360spider") {
		t.Fatal("4in6 映射形态应命中 v4 官方段（Unmap 归一）")
	}
	// 回归形状 1：映射形态但段外 → fail-closed。
	if verifyCrawlerIPRangeFromList("::ffff:42.236.16.1", "so360spider") {
		t.Fatal("映射形态段外地址不得命中")
	}
	// 回归形状 2：原生 v6 命中 v6 段不受影响。
	if !verifyCrawlerIPRangeFromList("2408:4000::1", "so360spider") {
		t.Fatal("原生 v6 段内地址应命中")
	}
	// 畸形形状：带 zone 地址 fail-closed。
	if verifyCrawlerIPRangeFromList("2408:4000::1%eth0", "so360spider") {
		t.Fatal("带 zone 地址必须 fail-closed")
	}
}
