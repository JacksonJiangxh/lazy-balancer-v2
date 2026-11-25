package services

// 文件变更实时生效的退避/告警契约（子任务 3 验收钉）：
//   a) 文件变更的 reload 不被 sameConfig 短路——重载注入即
//      main.go 的 certReloader（WithCaddyOpLock + ReloadFromDB →
//      ApplyConfigForce，POST /load 带 must-revalidate）。本文件钉住看门狗
//      侧契约：检出变化必然调用 reload 注入（即强制重载），且基线只在
//      「重载成功/达限放弃」两个出口推进——失败路径下轮重检，不会被
//      「扫描即推基线」的形态静默吞掉（与 errSameConfig 短路同效的失效）。
//   b) 坏证书文件（配对无效/PEM 损坏）触发退避重试，达上限后告警并放弃。
//
// 失败重试契约的三个不动点：
//   - 校验失败（LoadReferencedCertificate 报错）与重载失败都是一次「尝试」，
//     各推进 referencedCertRetry 账面，退避 60s·2^n 封顶 30min；
//   - 文件再次变化（digest 变）即清零额度重开；
//   - 连续 referencedCertRetryLimit 次失败：TaskLogf 告警一次、基线推进、
//     停止重试（fail-safe 保持旧配置），文件下次变化重新开始。

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// resetReferencedCertRetryForTest 清空退避账面并复位测试时钟缝。
func resetReferencedCertRetryForTest(t *testing.T) {
	t.Helper()
	referencedCertWatchMu.Lock()
	referencedCertRetry = map[string]referencedCertRetryEntry{}
	referencedCertWatchMu.Unlock()
	oldClock := referencedCertClock
	t.Cleanup(func() {
		referencedCertWatchMu.Lock()
		referencedCertRetry = map[string]referencedCertRetryEntry{}
		referencedCertWatchMu.Unlock()
		referencedCertClock = oldClock
	})
}

// retryFixture 组装看门狗退避测试夹具：真实文件规则 + 可控重载注入。
func retryFixture(t *testing.T, ruleID, certPath, keyPath string) *reloadInjector {
	t.Helper()
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert_path, tls_key_path)
		VALUES (?,?,'http',?,19460,1,'file',?,?)`, ruleID, ruleID, ruleID+".test", certPath, keyPath); err != nil {
		t.Fatalf("seed file rule: %v", err)
	}
	ResetReferencedCertWatch()
	resetReferencedCertRetryForTest(t)
	inj := &reloadInjector{}
	SetReferencedCertReload(inj.reload)
	t.Cleanup(func() { SetReferencedCertReload(nil) })
	return inj
}

// reloadInjector 可控的重载注入：记录调用次数，failAfter 次后开始失败。
type reloadInjector struct {
	calls     int
	failAfter int // 0=恒成功；N=第 N 次起返回错误
	err       error
}

func (inj *reloadInjector) reload() error {
	inj.calls++
	if inj.failAfter > 0 && inj.calls > inj.failAfter {
		return inj.err
	}
	return nil
}

// 验收 a)：文件变更必触发重载注入（生产即强制重载链）；基线只在重载成功后
// 推进——注入失败时下一轮重新检出同一变化并重试，不被「扫描即推基线」静默吞掉。
// errSameConfig 短路发生在 Caddy applyConfigLockedOpt 的非 force 路径：看门狗
// 唯一重载注入是 ReloadFromDB→ApplyConfigForce（main.go certReloader），天然击穿。
func TestReferencedCertWatch_reloadNotShortCircuitedAndRetried(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "live1.crt", "live1.key")
	inj := retryFixture(t, "lb_live1", certPath, keyPath)

	checkReferencedCertFiles() // 首扫建基线
	if inj.calls != 0 {
		t.Fatalf("首扫不应重载, calls=%d", inj.calls)
	}

	// 外部更新为新合法配对：检出变化 → 调重载注入（生产=force reload）。
	newCert, newKey := matchingCertificatePair(t, "live1-updated.example.test")
	if err := os.WriteFile(certPath, []byte(newCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(newKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()
	if inj.calls != 1 {
		t.Fatalf("文件变化必须触发一次重载注入, calls=%d", inj.calls)
	}
	// 重载成功：下一轮同内容不再重载（基线已推进）。
	checkReferencedCertFiles()
	if inj.calls != 1 {
		t.Fatalf("重载成功后同内容不得重复重载, calls=%d", inj.calls)
	}

	// 注入失败变体：重载失败 → 基线未推进 → 下一轮重检出并再次调用重载。
	inj.failAfter = 1
	inj.err = errors.New("caddy down")
	newerCert, newerKey := matchingCertificatePair(t, "live1-second.example.test")
	if err := os.WriteFile(certPath, []byte(newerCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(newerKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()
	if inj.calls != 2 {
		t.Fatalf("重载失败后下一轮必须重检出并重试, calls=%d", inj.calls)
	}
}

// 验收 b)：坏证书文件（配对不匹配/PEM 损坏）触发退避重试；连续 5 次失败后
// 告警（运行日志 error + 任务日志）并放弃（基线推进、停止重试）。
func TestReferencedCertWatch_badCertRetriesWithBackoffThenAlerts(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "bad1.crt", "bad1.key")
	inj := retryFixture(t, "lb_bad1", certPath, keyPath)

	checkReferencedCertFiles() // 首扫建基线

	// 外部工具更新到一半：仅换私钥为新密钥对（与现存证书不配对）。
	_, badKey := matchingCertificatePair(t, "bad1-other.example.test")
	if err := os.WriteFile(keyPath, []byte(badKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}

	// 用可控时钟驱动 5 轮失败重试。
	start := time.Unix(1700000000, 0)
	now := start
	referencedCertClock = func() time.Time { return now }

	logs := captureServiceLog(t)
	for round := 1; round <= referencedCertRetryLimit; round++ {
		checkReferencedCertFiles()
		// 每轮都应推进失败账面（校验失败=一次尝试）；第 5 轮命中「放弃」出口，
		// 账面随之清空（由下方断言覆盖）。
		referencedCertWatchMu.Lock()
		failures := referencedCertRetry["lb_bad1"].failures
		referencedCertWatchMu.Unlock()
		if round < referencedCertRetryLimit && failures != round {
			t.Fatalf("第 %d 轮后失败账面=%d, want %d", round, failures, round)
		}
		now = now.Add(referencedCertRetryBackoff(failures) + time.Second)
	}
	if inj.calls != 0 {
		t.Fatalf("坏证书文件不得触发重载, calls=%d", inj.calls)
	}
	if got := logs.String(); !strings.Contains(got, "源文件校验失败") {
		t.Fatalf("校验失败必须留痕 warn: %q", got)
	}
	// 第 5 轮即命中「放弃」出口：告警一次（运行日志 error），账面清空、基线钉住。
	if got := logs.String(); !strings.Contains(got, "已停止自动重试") {
		t.Fatalf("达重试上限必须告警并放弃: %q", got)
	}
	referencedCertWatchMu.Lock()
	_, stillRetrying := referencedCertRetry["lb_bad1"]
	referencedCertWatchMu.Unlock()
	if stillRetrying {
		t.Fatal("达上限后失败账面必须清空（放弃）")
	}

	// 放弃后同内容再扫：不再重复告警/重试（基线已钉住磁盘当前内容）。
	logs3 := captureServiceLog(t)
	checkReferencedCertFiles()
	if got := logs3.String(); strings.Contains(got, "已停止自动重试") {
		t.Fatalf("放弃后同内容重扫不得重复告警: %q", got)
	}

	// 文件修复为合法配对：新变化 → 正常重载一次（重新开始）。
	fixedCert, fixedKey := matchingCertificatePair(t, "bad1-fixed.example.test")
	if err := os.WriteFile(certPath, []byte(fixedCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(fixedKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()
	if inj.calls != 1 {
		t.Fatalf("修复后文件变化应重新触发重载, calls=%d", inj.calls)
	}
}

// 验收 b) 补强：文件再次变化（新 digest）即清零失败额度重开——
// 不继承旧内容的失败额度。
func TestReferencedCertWatch_digestChangeResetsRetryBudget(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "bad2.crt", "bad2.key")
	inj := retryFixture(t, "lb_bad2", certPath, keyPath)

	checkReferencedCertFiles() // 首扫建基线

	// 两次不同的坏更新（digest 各异），各失败一次——第二次失败时账面应
	// 因 digest 变化而清零重开，最终 failures=1 而非 2。
	_, badKey1 := matchingCertificatePair(t, "bad2-a.example.test")
	if err := os.WriteFile(keyPath, []byte(badKey1), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()
	referencedCertWatchMu.Lock()
	f1 := referencedCertRetry["lb_bad2"].failures
	d1 := referencedCertRetry["lb_bad2"].digest
	referencedCertWatchMu.Unlock()
	if f1 != 1 {
		t.Fatalf("第一次失败账面=%d, want 1", f1)
	}

	_, badKey2 := matchingCertificatePair(t, "bad2-b.example.test")
	if err := os.WriteFile(keyPath, []byte(badKey2), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()
	referencedCertWatchMu.Lock()
	e := referencedCertRetry["lb_bad2"]
	referencedCertWatchMu.Unlock()
	if e.failures != 1 {
		t.Fatalf("内容再次变化应清零额度重开, failures=%d", e.failures)
	}
	if e.digest == d1 {
		t.Fatal("账面 digest 应推进到新内容")
	}
	if inj.calls != 0 {
		t.Fatalf("坏证书不得触发重载, calls=%d", inj.calls)
	}
}

// 退避函数契约：指数 60s·2^n，封顶 30min。
func TestReferencedCertWatch_backoffSchedule(t *testing.T) {
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{1, 60 * time.Second},
		{2, 120 * time.Second},
		{3, 240 * time.Second},
		{4, 480 * time.Second},
		{5, 960 * time.Second},
		{20, 30 * time.Minute},
	}
	for _, tc := range cases {
		if got := referencedCertRetryBackoff(tc.failures); got != tc.want {
			t.Fatalf("backoff(%d)=%v, want %v", tc.failures, got, tc.want)
		}
	}
}

