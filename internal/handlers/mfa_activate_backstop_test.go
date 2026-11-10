package handlers

import (
	"net/http"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// pending 绑定校验的收敛不得只依赖 DB 失败计数硬闸：DB 写不可用（只读挂载/
// 磁盘满/WAL 长占）时计数落不了库，5 次作废不生效，10^6 码空间在 pending
// 存在期间可被持续枚举。内存 per-user 滑动窗（与登录后验码同一实现）不依赖
// DB，故障期仍限制尝试速率；DB 硬闸保留为跨进程/重启的二次防线。
func TestMFAActivate_memoryBackstopWhenPendingGateWriteFails(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedMfaSetupUser(t) // 内含内存窗口复位与用例结束清理
	if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret='junk',mfa_pending_fails=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	router := mfaSetupTestRouter(h)
	router.POST("/auth/mfa/activate", func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "operator")
		c.Set("auth_type", "jwt")
		h.MFAActivate(c)
	})

	// 写故障形态：pending secret 仍可读（校验照常进行），失败计数列不可写。
	if _, err := db.DB.Exec(`ALTER TABLE users DROP COLUMN mfa_pending_fails`); err != nil {
		t.Fatalf("break failure counter write: %v", err)
	}

	// When：连续提交错误码，DB 硬闸每轮都写失败。
	attempts := 0
	for !services.MFAVerifyAttemptLimited(1, time.Now()) {
		rec := postRaw(router, "/auth/mfa/activate", `{"code":"000000"}`)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("第 %d 次尝试 status=%d body=%s, want 500（计数写失败必须 fail-closed）",
				attempts+1, rec.Code, rec.Body.String())
		}
		attempts++
		if attempts > 10 {
			t.Fatal("内存滑动窗未生效：DB 写故障期错误码尝试不受限")
		}
	}

	// Then：达到窗口上限后，下一次请求在进入校验前即被拒——DB 故障不缩短预算。
	blocked := postRaw(router, "/auth/mfa/activate", `{"code":"000000"}`)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("窗口耗尽后 status=%d body=%s, want 429（内存硬闸必须在 DB 故障期生效）",
			blocked.Code, blocked.Body.String())
	}
}
