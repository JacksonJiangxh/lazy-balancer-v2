package handlers

// 批量设置阶段拦截页必须推进规则版本列（updated_at/updated_by）：阶段页是
// 渲染输入，其它四个规则写端点（更新/启用/禁用/复制）都显式 bump——批量端点
// 漏 bump 时，并发打开的编辑向导版本门恒通过，PUT 静默覆盖他人的批量结果，
// 且列表「更新时间/更新者」仍显示本次批量前的值与操作者。

import (
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// withBatchOperator 注入操作者身份（contextUserID 的读取面）。中间件必须在
// 路由注册之前 Use——gin 的 Use 只影响其后注册的路由。
func withBatchOperator(router *gin.Engine, userID float64) *gin.Engine {
	router.Use(func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Next()
	})
	return router
}

// operatorRouter 组装「操作者中间件 + 指定路由」的测试路由器。
func operatorRouter(userID float64, register func(*gin.Engine)) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := withBatchOperator(gin.New(), userID)
	register(router)
	return router
}

func readRuleVersionRow(t *testing.T, caddyID string) (string, int64) {
	t.Helper()
	var updatedAt string
	var updatedBy int64
	if err := db.DB.QueryRow(`SELECT COALESCE(updated_at,''), COALESCE(updated_by,0) FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&updatedAt, &updatedBy); err != nil {
		t.Fatalf("read version columns for %s: %v", caddyID, err)
	}
	return updatedAt, updatedBy
}

func TestBatchRuleBlockPages_bumpsRuleVersionColumns(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	seedStageBatchRules(t)
	router := operatorRouter(42, func(router *gin.Engine) {
		router.POST("/rules/batch-block-pages", handler.BatchRuleBlockPages)
	})

	const baseline = "2020-01-01 00:00:00"
	if _, err := db.DB.Exec(`UPDATE lb_rules SET updated_at=?, updated_by=7 WHERE caddy_id IN ('lb_b1','lb_b2','lb_b3')`, baseline); err != nil {
		t.Fatalf("seed baseline version: %v", err)
	}

	// When：异值批量（阶段页从未设置变为 7/403 + 7/503）
	first := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1","lb_b2","lb_b3"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)
	if first.Code != http.StatusOK {
		t.Fatalf("batch status=%d body=%s", first.Code, first.Body.String())
	}

	// Then 1：真实变更的行版本列前移且归属本次操作者。
	for _, id := range []string{"lb_b1", "lb_b2", "lb_b3"} {
		updatedAt, updatedBy := readRuleVersionRow(t, id)
		if updatedBy != 42 {
			t.Fatalf("%s updated_by=%d, want 42（批量端点必须写操作者）", id, updatedBy)
		}
		if updatedAt == baseline || updatedAt == "" {
			t.Fatalf("%s updated_at=%q 未推进，want 晚于基线 %q", id, updatedAt, baseline)
		}
	}

	// 同值批量：零写入 ⇒ 版本列保持不动（不得凭端点触发无条件 bump）。
	beforeVersions := make(map[string]string, 3)
	for _, id := range []string{"lb_b1", "lb_b2", "lb_b3"} {
		updatedAt, _ := readRuleVersionRow(t, id)
		beforeVersions[id] = updatedAt
	}
	second := postStageJSON(t, router, "/rules/batch-block-pages",
		`{"rule_ids":["lb_b1","lb_b2","lb_b3"],"block_page_stage1_id":7,"block_page_stage1_status":403,"block_page_stage3_id":7,"block_page_stage3_status":503}`)
	if second.Code != http.StatusOK {
		t.Fatalf("same-value batch status=%d body=%s", second.Code, second.Body.String())
	}
	for id, want := range beforeVersions {
		if got, _ := readRuleVersionRow(t, id); got != want {
			t.Fatalf("%s updated_at %q → %q：同值批量必须零写入", id, want, got)
		}
	}

	// 并发向导语义：批量写后，打开时拿到的旧基线必须被版本门判为冲突
	// （UpdateRule 的 409 分支即 ruleVersionConflicts(库内值, 提交基线)）。
	staleBaseline, err := time.Parse("2006-01-02 15:04:05", baseline)
	if err != nil {
		t.Fatalf("parse baseline: %v", err)
	}
	bumped, _ := readRuleVersionRow(t, "lb_b1")
	if !ruleVersionConflicts(bumped, staleBaseline) {
		t.Fatalf("批量后 updated_at=%q 与旧基线 %q 判为不冲突：并发向导仍会静默覆盖", bumped, baseline)
	}
	// 回归形状：与当前值一致的基线不得误判冲突（版本门不得恒真）。
	currentVersion, ok := parseRuleVersionValue(bumped)
	if !ok {
		t.Fatalf("parse current version %q failed", bumped)
	}
	if ruleVersionConflicts(bumped, currentVersion) {
		t.Fatalf("同值基线 %q 被误判为冲突（版本门不得恒真）", bumped)
	}
}
