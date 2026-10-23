package handlers

// 失败横幅不得对运行配置做与事实相反的确定断言：
//   - 恢复失败 ⇒ 「状态未知」，不得与「旧配置已保留」并列；
//   - 退化提交（DB 已提交、/load 传输失败）⇒ 「可能未生效」，不得宣称「未生效」
//     （请求超时/响应丢失可能发生在 Caddy 已 provision 之后）。

import (
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func bannerText(t *testing.T) string {
	t.Helper()
	var text string
	if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&text); err != nil {
		t.Fatalf("read caddy_apply_error: %v", err)
	}
	return text
}

func TestCaddyApplyFailureBanner_twoStateWording(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	handler := &Handlers{}

	// 恢复成功：断言「旧配置已保留」是事实。
	handler.recordCaddyApplyFailure(errors.New("admin 4xx"), nil)
	if got := bannerText(t); !strings.Contains(got, caddyApplyOldConfigKeptLabel) || strings.Contains(got, "状态未知") {
		t.Fatalf("恢复成功横幅=%q, want 含「旧配置已保留」且不含「状态未知」", got)
	}

	// 恢复失败：双失败形态，运行配置可能停留候选态。
	handler.recordCaddyApplyFailure(errors.New("admin 4xx"), errors.New("恢复 /load 失败"))
	if got := bannerText(t); !strings.Contains(got, caddyApplyRestoreFailedLabel) || strings.Contains(got, caddyApplyOldConfigKeptLabel) {
		t.Fatalf("恢复失败横幅=%q, want 含「状态未知」且不含「旧配置已保留」", got)
	}

	// 退化提交：不确定口径。
	handler.recordCaddyApplySavedNotLive(errors.New("请求超时"))
	if got := bannerText(t); !strings.Contains(got, "可能未生效") || !strings.Contains(got, "请核对后重试") {
		t.Fatalf("退化提交横幅=%q, want 「可能未生效，请核对后重试」", got)
	}
	if got := bannerText(t); strings.Contains(got, "运行配置未生效）：") {
		t.Fatalf("退化提交横幅=%q, want 不得断言「运行配置未生效」", got)
	}

	// 默认失败写点（无恢复上下文）同样走两态函数，值为「旧配置已保留」。
	handler.recordCaddyApplyResult(errors.New("保存前校验失败"))
	if got := bannerText(t); !strings.Contains(got, caddyApplyOldConfigKeptLabel) {
		t.Fatalf("默认失败横幅=%q, want 含「旧配置已保留」", got)
	}
}

func TestCaddyApplyFailureLabel_shapes(t *testing.T) {
	if got := caddyApplyFailureLabel(nil); got != caddyApplyOldConfigKeptLabel {
		t.Fatalf("label(nil)=%q", got)
	}
	if got := caddyApplyFailureLabel(errors.New("x")); got != caddyApplyRestoreFailedLabel {
		t.Fatalf("label(err)=%q", got)
	}
}
