package services

//   U04c-02 MFAIssueChallenge 落签发时 password_version（挑战与密码版本绑定）；
//   U04c-04 锁定开关读取失败必须显式报错（fail-closed 由调用方落实）；
//   U04c-05 恢复码消费的存储错误不得降级为「未命中」。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestMFAIssueChallenge_bindsPasswordVersion(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 1)
	if _, err := db.DB.Exec("UPDATE users SET password_version=7 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	token, err := MFAIssueChallenge(1)
	if err != nil || token == "" {
		t.Fatalf("issue challenge: token=%q err=%v", token, err)
	}
	var version int64
	if err := db.DB.QueryRow("SELECT password_version FROM mfa_challenges WHERE token=?", token).Scan(&version); err != nil {
		t.Fatalf("challenge must carry password_version: %v", err)
	}
	if version != 7 {
		t.Fatalf("challenge password_version=%d, want 7", version)
	}
}

func TestMFALockoutEnabled_reportsReadFailure(t *testing.T) {
	mfaTestEnv(t)
	if _, err := db.DB.Exec("DROP TABLE global_config"); err != nil {
		t.Fatal(err)
	}
	enabled, err := MFALockoutEnabled()
	if err == nil {
		t.Fatal("config read failure must be surfaced, not silently reported as disabled")
	}
	if enabled {
		t.Fatalf("enabled=%v on read failure", enabled)
	}
}

func TestMFAVerifyCode_recoveryStorageErrorSurfaces(t *testing.T) {
	mfaTestEnv(t)
	mfaSeedUser(t, 1)
	secret, _, err := MFAGenerateSecret("tester")
	if err != nil {
		t.Fatal(err)
	}
	// 损坏的恢复码 JSON = 存储错误（不是「码未命中」）。
	if _, err := db.DB.Exec("UPDATE users SET mfa_enabled=1, mfa_secret=?, mfa_recovery_codes='not-json' WHERE id=1", secret); err != nil {
		t.Fatal(err)
	}
	ok, verifyErr := MFAVerifyCode(1, "ABCDEFGHIJKLMNOP", time.Now())
	if ok {
		t.Fatal("corrupted recovery storage must not verify")
	}
	if verifyErr == nil {
		t.Fatal("storage error must not be reported as a wrong code")
	}
}
