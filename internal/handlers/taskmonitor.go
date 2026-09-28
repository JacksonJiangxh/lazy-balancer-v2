package handlers

// 任务监控 handlers（v2.3.4）：GET /system/tasks 全员可见（从节点只读视图）；
// trigger/toggle/cancel 为管理员操作（adminOnly+readOnlyGuard 路由组）。
// 操作映射到各任务族既有入口（manager StartUpdate/SetAutoUpdate/CancelRunning），
// 本层零新状态。

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
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
	switch id {
	case "threat":
		mgr := services.GetThreatUpdateManager()
		if mgr == nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "威胁情报库更新服务未初始化"})
			return
		}
		if err := mgr.RunUpdate("manual"); err != nil {
			respondTaskStartErr(c, err)
			return
		}
		recordAudit(c, "更新", "任务监控", "手动触发 威胁情报库更新")
	case "crs":
		mgr := services.GetCRSUpdateManager()
		if _, err := mgr.StartUpdate("manual"); err != nil {
			respondTaskStartErr(c, err)
			return
		}
		recordAudit(c, "更新", "任务监控", "手动触发 CRS 规则库更新")
	case "ip2region":
		mgr := services.GetIP2RegionUpdateManager()
		if _, err := mgr.StartUpdate("manual"); err != nil {
			respondTaskStartErr(c, err)
			return
		}
		recordAudit(c, "更新", "任务监控", "手动触发 IP2Region 更新")
	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持手动触发"})
		return
	}
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
	var setFn func(bool) error
	var taskName string
	switch id {
	case "threat":
		setFn, taskName = services.SetThreatAutoUpdate, "威胁情报库自动更新"
	case "crs":
		setFn, taskName = services.SetCRSAutoUpdate, "CRS 自动更新"
	case "ip2region":
		setFn, taskName = services.SetIP2RegionAutoUpdate, "IP2Region 自动更新"
	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持暂停/恢复"})
		return
	}
	if err := setFn(*req.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if *req.Enabled {
		recordAudit(c, "恢复", "任务监控", taskName)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已恢复" + taskName})
	} else {
		recordAudit(c, "暂停", "任务监控", taskName)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已暂停" + taskName})
	}
}

// CancelSystemTask 取消运行中任务（admin；仅下载类三族）。
func (h *Handlers) CancelSystemTask(c *gin.Context) {
	id := c.Param("id")
	// 取消不需要主节点门：从节点只读模式下任务本来不跑；万一在跑（demote 竞态
	// 窗口内）也应能取消。manager 自身有 running 判定。
	var cancelFn func() bool
	var taskName string
	switch id {
	case "threat":
		if m := services.GetThreatUpdateManager(); m != nil {
			cancelFn, taskName = m.CancelRunning, "威胁情报库更新"
		}
	case "crs":
		cancelFn, taskName = services.GetCRSUpdateManager().CancelRunning, "CRS 更新"
	case "ip2region":
		if m := services.GetIP2RegionUpdateManager(); m != nil {
			cancelFn, taskName = m.CancelRunning, "IP2Region 更新"
		}
	default:
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "该任务不支持手动取消（仅下载类任务可取消）"})
		return
	}
	if cancelFn == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务服务未初始化"})
		return
	}
	if !cancelFn() {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务未在运行中，无可取消"})
		return
	}
	recordAudit(c, "取消", "任务监控", "手动取消 "+taskName+"（下载阶段中断，已完成部分保留）")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已发出取消信号，任务将在当前下载阶段中断"})
}
