package handlers

// 任务监控 handlers（v2.3.4）：GET /system/tasks 全员可见（从节点只读视图）；
// trigger/toggle/cancel 为管理员操作（adminOnly+readOnlyGuard 路由组）。
// 操作映射到各任务族既有入口（manager StartUpdate/SetAutoUpdate/CancelRunning），
// 本层零新状态。

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"bytes"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
	"os"
)

// ListSystemTasks 聚合全部任务族状态（全员可见）。
func (h *Handlers) ListSystemTasks(c *gin.Context) {
	tasks := services.CollectSystemTasks()
	if tasks == nil {
		tasks = []services.TaskInfo{}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"tasks": tasks}})
}

// requireMasterNode 主节点门（写操作镜像 StartCRSUpdate 口径）。
func requireMasterNode(c *gin.Context) bool {
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", err)
		return false
	}
	return true
}

// TriggerSystemTask 手动触发（admin；仅排程/队列类任务族）。
func (h *Handlers) TriggerSystemTask(c *gin.Context) {
	id := c.Param("id")
	if !requireMasterNode(c) {
		return
	}
	// 终态：触发全经任务引擎（CanTrigger 语义族——单飞/主节点门/历史统一）
	if te := services.TaskEngine(); te != nil {
		for _, m := range te.DescribeAll() {
			if m.ID == id {
				if !m.CanTrigger {
					c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持手动触发（探测型/专属端点/镜像族）"})
					return
				}
				// R63-P2-7：单飞预检——已在跑立即 409（Trigger 异步 goroutine 曾吞此错）
				if te.IsRunning(id) {
					c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务运行中，请稍后重试"})
					return
				}
				go func(tid, operator string) {
					_ = te.Trigger(tid, "manual", operator) // 异步——耗时由 task_runs 记录；operator 审计归人
				}(id, auditOperator(c))
				// 审计由任务体自记（手动/自动同一审计——2026-09-29 用户裁定）；
				// 清理/证书循环族的执行记录在任务运行历史与任务日志。
				c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
				return
			}
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持手动触发"})
		return
	}
	// R63：无引擎时统一 503（回退 switch 删除）。
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎未初始化"})
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

func respondTaskStartErr(c *gin.Context, err error) {
	if errors.Is(err, services.ErrThreatUpdateRunning) || errors.Is(err, services.ErrCRSUpdateRunning) ||
		errors.Is(err, services.ErrIP2RegionUpdateRunning) {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: err.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
}

// ToggleSystemTask 暂停/恢复自动调度（admin；body {"enabled": bool}）。
// U1-P4-2：经 DescribeAll 元数据路由（Toggleable=描述符 ToggleFn 声明），
// 不再硬编码三族清单——注册即接入。
func (h *Handlers) ToggleSystemTask(c *gin.Context) {
	id := c.Param("id")
	if !requireMasterNode(c) {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Enabled == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效（需 enabled 布尔值）"})
		return
	}
	if te := services.TaskEngine(); te != nil {
		for _, m := range te.DescribeAll() {
			if m.ID != id {
				continue
			}
			if !m.Toggleable {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持暂停/恢复"})
				return
			}
			if err := te.Toggle(id, *req.Enabled); err != nil {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
				return
			}
			if *req.Enabled {
				recordAudit(c, "恢复", "任务监控", m.ToggleName)
				c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已恢复" + m.ToggleName})
			} else {
				recordAudit(c, "暂停", "任务监控", m.ToggleName)
				c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已暂停" + m.ToggleName})
			}
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持暂停/恢复"})
		return
	}
	// R63：无引擎时统一 503（回退 switch 删除）。
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎未初始化"})
}

// CancelSystemTask 取消运行中任务（admin；仅 Cancelable 声明族）。
// U1-P4-2：引擎路径经 te.Cancel（Cancelable+CancelHook 元数据路由），
// 不再硬编码三族清单；无引擎回退（测试环境）直调 manager。
func (h *Handlers) CancelSystemTask(c *gin.Context) {
	id := c.Param("id")
	// 取消不需要主节点门：从节点只读模式下任务本来不跑；万一在跑（demote 竞态
	// 窗口内）也应能取消。manager 自身有 running 判定（路由组 readOnlyGuard
	// 会先行拦截从节点写——此处语义为纵深注释，见 U3-P4-3 修正）。
	if te := services.TaskEngine(); te != nil {
		if !te.Cancel(id) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务未在运行中或不支持取消"})
			return
		}
		recordAudit(c, "取消", "任务监控", "手动取消任务 "+id+"（下载阶段中断，已完成部分保留）")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已发出取消信号，任务将在当前下载阶段中断"})
		return
	}
	// R63：无引擎时统一 503（回退 switch 删除）。
	c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "任务引擎未初始化"})
}

// ControlSystemTask 常驻循环启停（admin；body {"action":"start|stop|restart"}）。
// P2-②：经 DescribeAll 的 Controllable 元数据路由——cert-waiting-ca 等
// Continuous 族真正可控（曾硬编码三 ID map + TaskRuntime 死回退恒 400）；
// TaskRuntime 注册表已随 M2 退役删除。
func (h *Handlers) ControlSystemTask(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Action string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || (req.Action != "start" && req.Action != "stop" && req.Action != "restart") {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效（action=start|stop|restart）"})
		return
	}
	te := services.TaskEngine()
	if te == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "任务引擎未初始化"})
		return
	}
	controllable := false
	for _, m := range te.DescribeAll() {
		if m.ID == id {
			controllable = m.Controllable
			break
		}
	}
	if !controllable {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持启停（角色驱动或纯被动循环）"})
		return
	}
	switch req.Action {
	case "start":
		te.StartLoop(id)
	case "stop":
		te.StopLoop(id)
	case "restart":
		te.StopLoop(id)
		te.StartLoop(id)
	}
	switch req.Action {
	case "start":
		recordAudit(c, "启动", "任务监控", "常驻任务 "+id+" 启动")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已启动任务 " + id})
	case "stop":
		recordAudit(c, "停止", "任务监控", "常驻任务 "+id+" 停止")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已停止任务 " + id})
	default:
		recordAudit(c, "重启", "任务监控", "常驻任务 "+id+" 重启")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已重启任务 " + id})
	}
}

// GetSystemTaskHistory 任务运行历史（task_runs，时间倒序）。
func (h *Handlers) GetSystemTaskHistory(c *gin.Context) {
	id := c.Param("id")
	limit := 50
	if te := services.TaskEngine(); te != nil {
		runs := te.History(id, limit)
		if runs == nil {
			runs = []taskengine.RunRecord{}
		}
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"runs": runs}})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"runs": []struct{}{}}})
}

// GetSystemTaskLogs 任务文本日志（统一任务引擎管理——tasks/{id}.log；
// 更新族含分阶段流水 tee）。
func (h *Handlers) GetSystemTaskLogs(c *gin.Context) {
	id := c.Param("id")
	path := taskengine.TaskLogPath(id)
	if path == "" {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": ""}})
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		// U3-P4-4：文件不存在=空内容（任务尚未产生日志）；读失败=500（曾一律 200
		// 空内容，与不存在不可区分）。
		if errors.Is(err, os.ErrNotExist) {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": ""}})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务日志读取失败: " + err.Error()})
		return
	}
	// 尾部 256KB（日志弹框消费口径，防超长载荷）
	const tail = 256 << 10
	if len(data) > tail {
		data = data[len(data)-tail:]
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": string(data)}})
}
