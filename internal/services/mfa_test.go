package services

import (
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// mfaTestEnv 建临时库并注入时间可控环境。
func mfaTestEnv(t *testing.T) {
	t.Helper()
	oldDB := db.DB
	oldCurrent := db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("init test db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB = oldDB
		// 后台循环句柄（db.GetDB）随 Close 置 nil，必须一并还原。
		db.SetDB(oldCurrent)
	})
	// Initialize 已种 global_config id=1（caddy_config '{}'）
}

func mfaSeedUser(t *testing.T, id int) {
	t.Helper()
	if _, err := db.DB.Exec(
		"INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (?,?,?,'admin',1)",
		id, "u"+string(rune('0'+id)), "x"); err != nil {
		t.Fatal(err)
	}
}

func mfaCurrentCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// —— RFC 6238 契约：真实 TOTP 码往返 ——

func TestMFAValidateTOTP_roundtrip(t *testing.T) {
	mfaTestEnv(t)
	secret, _, err := MFAGenerateSecret("tester")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := mfaCurrentCode(t, secret, now)
	if step, ok := mfaValidateTOTP(secret, code, now); !ok || step <= 0 {
		t.Fatalf("current-window code rejected (step=%d)", step)
	}
	// ±1 窗容差
	if _, ok := mfaValidateTOTP(secret, code, now.Add(25*time.Second)); !ok {
		t.Fatal("−1 window tolerance failed")
	}
	if _, ok := mfaValidateTOTP(secret, code, now.Add(-25*time.Second)); !ok {
		t.Fatal("+1 window tolerance failed")
	}
	// 超容差拒绝
	if _, ok := mfaValidateTOTP(secret, code, now.Add(95*time.Second)); ok {
		t.Fatal("code beyond ±1 window must be rejected")
	}
	// 错码拒绝
	if _, ok := mfaValidateTOTP(secret, "000000", now); ok {
		t.Fatal("wrong code accepted")
	}
}

// —— 重放防护 ——

func TestMFAVerifyCode_replayRejected(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 1)
	secret, _, _ := MFAGenerateSecret("tester")
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=? WHERE id=1", secret); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := mfaCurrentCode(t, secret, now)
	if ok, _ := MFAVerifyCode(1, code, now); !ok {
		t.Fatal("first use must succeed")
	}
	if ok, _ := MFAVerifyCode(1, code, now.Add(time.Second)); ok {
		t.Fatal("same-window replay must be rejected")
	}
	if ok, _ := MFAVerifyCode(1, code, now.Add(-time.Second)); ok {
		t.Fatal("earlier-window replay must be rejected")
	}
}

// —— 恢复码：单次消费 ——

func TestMFARecoveryCodes_singleUse(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 2)
	secret, _, _ := MFAGenerateSecret("tester")
	codes, hashes, err := mfaGenerateRecoveryCodes(mfaRecoveryCodeCount)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_recovery_codes=? WHERE id=2", secret, hashes); err != nil {
		t.Fatal(err)
	}
	if len(codes) != mfaRecoveryCodeCount {
		t.Fatalf("codes=%d want %d", len(codes), mfaRecoveryCodeCount)
	}
	now := time.Now()
	if ok, _ := MFAVerifyCode(2, codes[0], now); !ok {
		t.Fatal("recovery code must verify")
	}
	if ok, _ := MFAVerifyCode(2, codes[0], now); ok {
		t.Fatal("recovery code reuse must be rejected")
	}
	st, _ := MFAGetStatus(2)
	if st.RecoveryCodesRemaining != mfaRecoveryCodeCount-1 {
		t.Fatalf("remaining=%d want %d", st.RecoveryCodesRemaining, mfaRecoveryCodeCount-1)
	}
	// 第二个码仍可用
	if ok, _ := MFAVerifyCode(2, codes[1], now); !ok {
		t.Fatal("second recovery code must still work")
	}
}

// —— 绑定流程：pending → activate ——

func TestMFASetupActivateFlow(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 4)
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret='junk' WHERE id=4"); err != nil {
		t.Fatal(err)
	}
	// VerifyPending with a TOTP of the REAL secret we'll set next
	secret, _, _ := MFAGenerateSecret("tester")
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret=? WHERE id=4", secret); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := mfaCurrentCode(t, secret, now)
	if ok, _ := MFAVerifyPending(4, code, now); !ok {
		t.Fatal("pending verify failed for current code")
	}
	codes, err := MFAActivate(4)
	if err != nil || len(codes) != mfaRecoveryCodeCount {
		t.Fatalf("activate: %v codes=%d", err, len(codes))
	}
	st, _ := MFAGetStatus(4)
	if !st.Enabled {
		t.Fatal("activate must set mfa_enabled")
	}
	// activate 幂等保护：pending 已清，再 activate 报错
	if _, err := MFAActivate(4); err == nil {
		t.Fatal("second activate must fail (pending cleared)")
	}
}

// —— 挑战：单次 + 过期 ——

func TestMFAChallengeLifecycle(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 5)
	tok, err := MFAIssueChallenge(5)
	if err != nil || tok == "" {
		t.Fatal(err)
	}
	if ok, err := MFAConsumeChallenge(tok, 5); !ok || err != nil {
		t.Fatalf("first consume must succeed: ok=%v err=%v", ok, err)
	}
	if ok, err := MFAConsumeChallenge(tok, 5); ok || err != nil {
		t.Fatalf("replay consume must fail without service error: ok=%v err=%v", ok, err)
	}
	// 属主绑定必须在**未消费**挑战上观测：复用上面已消费的 token 时
	// consumed=1 已让 RowsAffected=0，删掉 user_id 谓词断言仍然通过。
	// （属主来自挑战行而非请求参数——MFAVerifyLogin 按 token 定位挑战后
	// 用行内 user_id 调用本函数，故观测点在服务层。）
	ownedTok, ownedErr := MFAIssueChallenge(5)
	if ownedErr != nil || ownedTok == "" {
		t.Fatalf("issue challenge for owner binding: tok=%q err=%v", ownedTok, ownedErr)
	}
	if ok, err := MFAConsumeChallenge(ownedTok, 999); ok || err != nil {
		t.Fatalf("wrong owner must fail without service error: ok=%v err=%v", ok, err)
	}
	// 错属主尝试不得改行：属主随后仍可消费同一挑战。
	if ok, err := MFAConsumeChallenge(ownedTok, 5); !ok || err != nil {
		t.Fatalf("owner must still consume challenge untouched by wrong-owner attempt: ok=%v err=%v", ok, err)
	}
	// 过期：手工回拨
	tok2, _ := MFAIssueChallenge(5)
	if _, err := db.DB.Exec("UPDATE mfa_challenges SET expires_at=datetime('now','-1 minute') WHERE token=?", tok2); err != nil {
		t.Fatal(err)
	}
	if ok, err := MFAConsumeChallenge(tok2, 5); ok || err != nil {
		t.Fatalf("expired challenge must fail without service error: ok=%v err=%v", ok, err)
	}
}

// 执行错误必须与「行未更新」分判，调用方才能区分 DB 故障 500
// 与正常挑战失效 401。
func TestMFAConsumeChallenge_returnsExecutionError(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 55)
	tok, err := MFAIssueChallenge(55)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`DROP TABLE mfa_challenges`); err != nil {
		t.Fatal(err)
	}
	if ok, err := MFAConsumeChallenge(tok, 55); ok || err == nil {
		t.Fatalf("consume after table loss: ok=%v err=%v, want false+error", ok, err)
	}
}

// —— 管理员重置 ——

func TestMFAResetForUser(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 6)
	secret, _, _ := MFAGenerateSecret("tester")
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_pending_fails=3 WHERE id=6", secret); err != nil {
		t.Fatal(err)
	}
	if err := MFAResetForUser(6); err != nil {
		t.Fatal(err)
	}
	st, _ := MFAGetStatus(6)
	if st.Enabled {
		t.Fatal("reset must disable mfa")
	}
	// pending 失败计数随重置一并清零（原死断言 if locked:= false 的
	// 替换——锁定本就归重置密码路径，此处钉住 reset 对 MFA 自有状态的覆盖）。
	var enabled, pendingFails int
	if err := db.DB.QueryRow("SELECT mfa_enabled, COALESCE(mfa_pending_fails,0) FROM users WHERE id=6").Scan(&enabled, &pendingFails); err != nil {
		t.Fatal(err)
	}
	if enabled != 0 {
		t.Fatal("db state mismatch")
	}
	if pendingFails != 0 {
		t.Fatalf("mfa_pending_fails=%d, want 0 (reset must clear pending fail counter)", pendingFails)
	}
}

// —— 全局开关读取 ——

func TestMFAWriteGuardEnabled(t *testing.T) {
	mfaTestEnv(t)
	enabled, err := MFAWriteGuardEnabled()
	if err != nil {
		t.Fatalf("default read: %v", err)
	}
	if enabled {
		t.Fatal("default must be off")
	}
	_, _ = db.DB.Exec("UPDATE global_config SET mfa_write_guard=1 WHERE id=1")
	if enabled, err = MFAWriteGuardEnabled(); err != nil || !enabled {
		t.Fatalf("toggle read: enabled=%v err=%v", enabled, err)
	}
	// 读取失败必须显式报错，不得静默降级为「开关关闭」（fail-open）。
	if _, err := db.DB.Exec("DELETE FROM global_config WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if enabled, err = MFAWriteGuardEnabled(); err == nil {
		t.Fatalf("read failure must surface, got enabled=%v err=nil", enabled)
	}
}

// 三个 TOTP 验证器输入容错须一致——MFAVerifyCode/
// MFAVerifyTOTPCode 均先 TrimSpace，MFAVerifyPending 缺失，绑定向导 activate
// 步粘贴带空格验证码恒失败。
func TestMFAVerifyPending_trimsWhitespace(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 9)
	secret, _, err := MFAGenerateSecret("tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret=? WHERE id=9", secret); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code := mfaCurrentCode(t, secret, now)

	ok, err := MFAVerifyPending(9, "  "+code+" \t", now)
	if err != nil {
		t.Fatalf("verify pending: %v", err)
	}
	if !ok {
		t.Fatal("padded code must verify（pending 验证须与另两个 TOTP 验证器同容错 TrimSpace）")
	}
}

// 挑战级失败计数硬闸——第 10 次失败即作废挑战（与全局锁定开关无关），
// 作废后 MFAConsumeChallenge 恒拒绝。
func TestMFARecordChallengeFailure_invalidatesAtThreshold(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 3)
	const token = "tok-challenge-threshold"
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token, user_id, expires_at, consumed, attempts)
		VALUES (?, 3, datetime('now','+10 minutes'), 0, 0)`, token); err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt < mfaChallengeFailThreshold; attempt++ {
		if invalidated := MFARecordChallengeFailure(token); invalidated {
			t.Fatalf("第 %d 次失败不应作废（阈值 %d）", attempt, mfaChallengeFailThreshold)
		}
	}
	if invalidated := MFARecordChallengeFailure(token); !invalidated {
		t.Fatalf("第 %d 次失败必须作废并返回 true", mfaChallengeFailThreshold)
	}
	var consumed bool
	var attempts int
	if err := db.DB.QueryRow(`SELECT COALESCE(consumed,0), COALESCE(attempts,0) FROM mfa_challenges WHERE token=?`, token).Scan(&consumed, &attempts); err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("达阈值后挑战必须置 consumed=1")
	}
	if attempts != mfaChallengeFailThreshold {
		t.Fatalf("attempts=%d, want %d", attempts, mfaChallengeFailThreshold)
	}
	if ok, err := MFAConsumeChallenge(token, 3); ok || err != nil {
		t.Fatalf("作废后的挑战不得再被消费: ok=%v err=%v", ok, err)
	}
}

// pending 验证失败第 5 次即作废 pending secret（重新 setup 才能再试）。
func TestMFARecordPendingFailure_invalidatesAtThreshold(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 4)
	secret, _, err := MFAGenerateSecret("tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret=?, mfa_pending_fails=0 WHERE id=4`, secret); err != nil {
		t.Fatal(err)
	}

	for attempt := 1; attempt < mfaPendingFailThreshold; attempt++ {
		invalidated, err := MFARecordPendingFailure(4)
		if err != nil {
			t.Fatalf("第 %d 次 pending 失败计数写失败: %v", attempt, err)
		}
		if invalidated {
			t.Fatalf("第 %d 次 pending 失败不应作废（阈值 %d）", attempt, mfaPendingFailThreshold)
		}
	}
	if invalidated, err := MFARecordPendingFailure(4); err != nil || !invalidated {
		t.Fatalf("第 %d 次 pending 失败必须作废并返回 true: invalidated=%v err=%v", mfaPendingFailThreshold, invalidated, err)
	}
	var pending string
	var fails int
	if err := db.DB.QueryRow(`SELECT COALESCE(mfa_pending_secret,''), COALESCE(mfa_pending_fails,0) FROM users WHERE id=4`).Scan(&pending, &fails); err != nil {
		t.Fatal(err)
	}
	if pending != "" {
		t.Fatalf("pending secret 未清空: %q", pending)
	}
	if fails != 0 {
		t.Fatalf("pending 失败计数未复位: %d", fails)
	}
	if _, err := MFAVerifyPending(4, "123456", time.Now()); err == nil {
		t.Fatal("作废后 MFAVerifyPending 必须报「没有待激活的 MFA 密钥」")
	}
}

// 计数未落库必须上抛（不得静默 false）：activate 无登录限流，5 次硬闸在
// DB 写故障期一旦静默失效，pending 码空间即无收敛手段。
func TestMFARecordPendingFailure_writeFailureReturnsError(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 6)
	oldDB := db.DB
	closed, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	db.DB = closed
	t.Cleanup(func() { db.DB = oldDB })

	invalidated, err := MFARecordPendingFailure(6)
	if err == nil {
		t.Fatalf("写失败必须上抛（invalidated=%v）；静默 false 会让硬闸失效且无痕", invalidated)
	}
	if invalidated {
		t.Fatalf("写失败不得报告已作废: %v", err)
	}
}

// restore 不复活已作废挑战——按 handler 真实顺序（consume→验码失败
// →restore→record failure）驱动 10 轮后，第 11 次登录在 consume 门即被拒绝
// （restore 只在 consume 成功后调用，作废行不经过恢复路径）。
func TestMFARestoreChallenge_invalidatedChallengeStaysDead(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 5)
	const token = "tok-restore-order"
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token, user_id, expires_at, consumed, attempts)
		VALUES (?, 5, datetime('now','+10 minutes'), 0, 0)`, token); err != nil {
		t.Fatal(err)
	}

	for round := 1; round <= mfaChallengeFailThreshold; round++ {
		if ok, err := MFAConsumeChallenge(token, 5); !ok || err != nil {
			t.Fatalf("第 %d 轮 consume 应成功（未达阈值）：ok=%v err=%v", round, ok, err)
		}
		MFARestoreChallenge(token, 5) // 错误码不烧挑战
		MFARecordChallengeFailure(token)
	}
	if ok, err := MFAConsumeChallenge(token, 5); ok || err != nil {
		t.Fatalf("达阈值后的挑战不得复活（consume 门必须拒绝，restore 不可达）：ok=%v err=%v", ok, err)
	}
	var consumed bool
	var attempts int
	if err := db.DB.QueryRow(`SELECT COALESCE(consumed,0), COALESCE(attempts,0) FROM mfa_challenges WHERE token=?`, token).Scan(&consumed, &attempts); err != nil {
		t.Fatal(err)
	}
	if !consumed || attempts != mfaChallengeFailThreshold {
		t.Fatalf("终态 consumed=%v attempts=%d, want consumed=true attempts=%d", consumed, attempts, mfaChallengeFailThreshold)
	}
}

// MFAGetStatus 对恢复码存储损坏必须显性报错，
// 不得以「剩余 0 个」掩盖（与 mfaConsumeRecoveryCode 的三态口径一致）。
func TestMFAGetStatus_reportsCorruptedRecoveryCodes(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 9)

	st, err := MFAGetStatus(9)
	if err != nil {
		t.Fatalf("默认空恢复码必须可读: %v", err)
	}
	if st.RecoveryCodesRemaining != 0 {
		t.Fatalf("默认恢复码数=%d, want 0", st.RecoveryCodesRemaining)
	}

	if _, err := db.DB.Exec("UPDATE users SET mfa_recovery_codes=? WHERE id=9", "not-json"); err != nil {
		t.Fatal(err)
	}
	if _, err := MFAGetStatus(9); err == nil {
		t.Fatal("恢复码存储损坏必须返回错误（此前被吞为 0 个）")
	}
}

// 未启用 MFA 的用户走任一验证入口都必须得到业务态哨兵（ErrMFANotEnabled），
// 与查询/写库故障的可识别错误分开——handler 据此映射 400 业务文案而非 500。
func TestMFAVerifyEntries_notEnabledSentinel(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 7)
	now := time.Now()

	if ok, err := MFAVerifyCode(7, "123456", now); ok || !errors.Is(err, ErrMFANotEnabled) {
		t.Fatalf("TOTP 通道: ok=%v err=%v, want (false, ErrMFANotEnabled)", ok, err)
	}
	// 恢复码通道（10-16 字符）同门：secret 为空时不得触及恢复码存储。
	if ok, err := MFAVerifyCode(7, "RECOVERYCODE1234", now); ok || !errors.Is(err, ErrMFANotEnabled) {
		t.Fatalf("恢复码通道: ok=%v err=%v, want (false, ErrMFANotEnabled)", ok, err)
	}
	if ok, err := MFAVerifyTOTPCode(7, "123456", now); ok || !errors.Is(err, ErrMFANotEnabled) {
		t.Fatalf("仅 TOTP 入口: ok=%v err=%v, want (false, ErrMFANotEnabled)", ok, err)
	}
}

// 并发交错的终局：失败计数已把挑战作废（consumed=1、attempts≥阈值），随后
// 到达的归还（同一 token 另一失败尝试的 consume→restore）不得把作废状态抹回
// 未消费——单挑战 10 次硬闸不得被并发抹平。
func TestMFARestoreChallenge_doesNotResurrectInvalidatedChallenge(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 8)
	const token = "tok-restore-interleaved"
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token, user_id, expires_at, consumed, attempts)
		VALUES (?, 8, datetime('now','+10 minutes'), 1, ?)`, token, mfaChallengeFailThreshold); err != nil {
		t.Fatal(err)
	}

	MFARestoreChallenge(token, 8)

	var consumed bool
	var attempts int
	if err := db.DB.QueryRow(`SELECT COALESCE(consumed,0), COALESCE(attempts,0) FROM mfa_challenges WHERE token=?`, token).Scan(&consumed, &attempts); err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatalf("达阈值的挑战被归还在 attempts=%d 下复活", attempts)
	}
	if ok, err := MFAConsumeChallenge(token, 8); ok || err != nil {
		t.Fatalf("作废挑战不得再被消费: ok=%v err=%v", ok, err)
	}
}

// 并发爆破下硬闸的原子性：计数自增与作废判定必须同语句（UPDATE…RETURNING）。
// 三语句形状（自增→读计数→置作废）在「读计数→置作废」窗口内，并发调用可
// 越过阈值继续自增（attempts > 阈值）且多个调用方同报 invalidated=true。
func TestMFARecordChallengeFailure_concurrentInvalidationIsAtomic(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 11)
	const token = "tok-challenge-atomic"
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token, user_id, expires_at, consumed, attempts)
		VALUES (?, 11, datetime('now','+10 minutes'), 0, 0)`, token); err != nil {
		t.Fatal(err)
	}

	const total = 4 * mfaChallengeFailThreshold
	var wg sync.WaitGroup
	var invalidatedCount atomic.Int64
	start := make(chan struct{})
	for range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if MFARecordChallengeFailure(token) {
				invalidatedCount.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := invalidatedCount.Load(); got != 1 {
		t.Fatalf("invalidated=true 的调用方数=%d, want 恰 1（作废判定必须原子）", got)
	}
	var consumed bool
	var attempts int
	if err := db.DB.QueryRow(`SELECT COALESCE(consumed,0), COALESCE(attempts,0) FROM mfa_challenges WHERE token=?`, token).Scan(&consumed, &attempts); err != nil {
		t.Fatal(err)
	}
	if !consumed {
		t.Fatal("达阈值后挑战必须置 consumed=1")
	}
	if attempts != mfaChallengeFailThreshold {
		t.Fatalf("attempts=%d, want 恒等于阈值 %d（作废后不得继续自增）", attempts, mfaChallengeFailThreshold)
	}
}

// 阈值以下仍须可归还：错误验证码不烧挑战的既有契约保持。
func TestMFARestoreChallenge_belowThresholdRestores(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 10)
	const token = "tok-restore-below"
	if _, err := db.DB.Exec(`INSERT INTO mfa_challenges (token, user_id, expires_at, consumed, attempts)
		VALUES (?, 10, datetime('now','+10 minutes'), 1, ?)`, token, mfaChallengeFailThreshold-1); err != nil {
		t.Fatal(err)
	}

	MFARestoreChallenge(token, 10)

	if ok, err := MFAConsumeChallenge(token, 10); !ok || err != nil {
		t.Fatalf("阈值以下的归还必须生效: ok=%v err=%v", ok, err)
	}
}

// 登录后验码限流的条目不得随一次性/已删除用户永驻：条目数超过阈值时整表
// 裁剪窗口外条目（每用户裁剪只在被访问时发生，删除用户不会再有访问）。
func TestMFARecordVerifyAttemptFailure_sweepsExpiredEntries(t *testing.T) {
	MFAResetVerifyAttemptsForTest()
	t.Cleanup(MFAResetVerifyAttemptsForTest)
	now := time.Now()

	mfaVerifyAttempts.Lock()
	for i := 1; i <= mfaVerifyAttemptsSweepThreshold; i++ {
		mfaVerifyAttempts.failures[i] = []time.Time{now.Add(-2 * mfaVerifyAttemptWindow)}
	}
	mfaVerifyAttempts.Unlock()

	MFARecordVerifyAttemptFailure(9999, now)

	mfaVerifyAttempts.Lock()
	defer mfaVerifyAttempts.Unlock()
	if len(mfaVerifyAttempts.failures) != 1 {
		t.Fatalf("清扫后条目数=%d, want 1（窗口外条目必须移除）", len(mfaVerifyAttempts.failures))
	}
	if _, ok := mfaVerifyAttempts.failures[9999]; !ok {
		t.Fatal("当前用户的最新失败记录必须保留")
	}
}
