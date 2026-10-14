package handlers

// 自动封禁（F73-A）端面：配置读写（六项+校验）、立即执行（任务引擎触发）、
// 运行状态（状态卡数据源：运行态/今日封禁/名单条数/引用状态/观察建议）。
// 预置名单的条目管理例外（删 400/条目可改/解封抑制）在 securityiplists.go。

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// GetAutobanConfig GET /security/autoban：六项配置（全员可读，business 组）。
func (h *Handlers) GetAutobanConfig(c *gin.Context) {
	c.JSON(http.StatusOK, services.GetAutobanConfig())
}

// UpdateAutobanConfig PUT /security/autoban：六项配置写侧（校验：阈值 1-10000、
// 窗口 1-60 分钟、时长/口径枚举）。窗口/口径变更由 services 层重置计数器
// （口径语义变化后旧计数不可混算）。配置只影响本节点调度与计数——主节点门
// （从节点写会被快照覆盖，与 UpdateThreatAutoUpdate 同口径）。
func (h *Handlers) UpdateAutobanConfig(c *gin.Context) {
	if !guardConfiguredJSONBody(c) {
		return
	}
	var req services.AutobanConfig
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if !requireMasterNode(c) {
		return
	}
	if err := services.SetAutobanConfig(req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	recordAudit(c, "更新", "自动封禁", fmt.Sprintf("启用：%s；阈值：%d 次/%d 分钟；时长：%s；口径：%s；模式：%s",
		boolOnOff(req.Enabled), req.Threshold, req.WindowMinutes,
		services.AutobanDurationLabel(req.Duration), autobanScopeText(req.Scope),
		map[bool]string{true: "观察", false: "正式"}[req.DryRun]))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "自动封禁配置已更新", Data: services.GetAutobanConfig()})
}

func boolOnOff(b bool) string {
	if b {
		return "开"
	}
	return "关"
}

func autobanScopeText(scope string) string {
	switch scope {
	case "blocked":
		return "仅拦截"
	case "logged":
		return "仅检测"
	default:
		return "全部"
	}
}

// RunAutobanNow POST /security/autoban/run：立即执行一轮（=te.Trigger，手动
// 触发不受 EnabledFn 业务开关门拦——域 E Ruling）。镜像 TriggerSystemTask
// 的单飞预检/审计/operator 归人形态。
func (h *Handlers) RunAutobanNow(c *gin.Context) {
	if !requireMasterNode(c) {
		return
	}
	te := services.TaskEngine()
	if te == nil {
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎未初始化"})
		return
	}
	if _, ok := te.Lookup(services.AutobanTaskID); !ok {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "自动封禁任务未注册"})
		return
	}
	if te.IsTaskInFlight(services.AutobanTaskID) {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "自动封禁任务运行中，请稍后重试"})
		return
	}
	recordAudit(c, "触发", "自动封禁", "手动执行自动封禁任务")
	op := auditOperator(c)
	go func() {
		// F-U1-1/F-U3-01 同款补偿：并发双击 CAS 落败（ErrAlreadyRunning）与
		// skipped 终态不复记失败；其余失败补「触发失败」审计+日志。
		if err := te.Trigger(services.AutobanTaskID, "manual", op); err != nil {
			if errors.Is(err, taskengine.ErrAlreadyRunning) || errors.Is(err, taskengine.ErrTaskSkipped) {
				return
			}
			services.Logf("error", "手动触发自动封禁失败: %v", err)
			services.RecordAuditLog(op, "触发失败", "自动封禁", fmt.Sprintf("手动执行自动封禁任务失败: %v", err), "")
		}
	}()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

// GetAutobanStatus GET /security/autoban/status：状态卡数据源（business 组全员
// 可读）。running/last_run 取任务引擎实态；list_referenced=启用中的安全策略
// （ip_acl_list_refs ∪ ip_whitelist_refs，JSON 精确解析）是否引用预置名单——
// 未引用时前端黄条提示「名单未生效」；suggestions=上一轮观察建议（dry-run）。
func (h *Handlers) GetAutobanStatus(c *gin.Context) {
	cfg := services.GetAutobanConfig()
	entries, _, err := services.AutobanListEntries()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自动封禁名单失败: " + err.Error()})
		return
	}
	resp := gin.H{
		"enabled":         cfg.Enabled,
		"dry_run":         cfg.DryRun,
		"threshold":       cfg.Threshold,
		"window_minutes":  cfg.WindowMinutes,
		"duration":        cfg.Duration,
		"scope":           cfg.Scope,
		"banned_today":    services.AutobanBannedToday(),
		"list_entries":    len(entries),
		"list_referenced": h.autobanListReferenced(),
		"tracked_ips":     services.AutobanTrackedIPs(),
		"suggestions":     services.AutobanSuggestions(),
		"running":         false,
		"last_run":        "",
		"last_status":     "",
	}
	if te := services.TaskEngine(); te != nil {
		if m, ok := te.Lookup(services.AutobanTaskID); ok {
			resp["running"] = m.Running
			resp["loop_on"] = m.LoopOn
			resp["enabled_gate"] = m.Enabled
		}
		if last := te.LatestRun(services.AutobanTaskID); last != nil {
			resp["last_run"] = last.StartedAt
			resp["last_status"] = last.Status
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: resp})
}

// autobanListReferenced 启用中的策略是否引用预置名单（黄条判据）。查询失败
// fail-closed（按已引用处理——不弹黄条，避免误报「未生效」）。
func (h *Handlers) autobanListReferenced() bool {
	var listID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, services.AutobanPresetListName).Scan(&listID); err != nil {
		return true
	}
	rows, err := db.DB.Query(`SELECT COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_refs,'[]') FROM security_policies WHERE enabled=1`)
	if err != nil {
		return true
	}
	defer rows.Close()
	for rows.Next() {
		var aclRefs, wlRefs string
		if rows.Scan(&aclRefs, &wlRefs) != nil {
			return true
		}
		for _, raw := range []string{aclRefs, wlRefs} {
			for _, refID := range parseIPListRefsIDs(raw) {
				if refID == listID {
					return true
				}
			}
		}
	}
	return false
}
