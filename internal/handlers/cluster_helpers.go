package handlers

import (
	"lazy-balancer-v2/internal/services"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) requireMaster(c *gin.Context) bool {
	isMaster, err := h.clusterService.IsMaster(c.Request.Context())
	if err != nil {
		clusterError(c, http.StatusInternalServerError, "读取节点模式失败", err)
		return false
	}
	if !isMaster {
		// 机器可读码：从端不得靠中文文案判断「目标已降级」（历史 历史问题-1）。
		c.Header("X-LB-Error-Code", "master_required")
		clusterError(c, http.StatusForbidden, "该操作仅允许在主节点执行", nil)
		return false
	}
	return true
}

func clusterError(c *gin.Context, status int, message string, err error) {
	if err != nil {
		services.Logf("error", "cluster request failed: %v", err)
	}
	c.JSON(status, models.APIResponse{Code: status, Message: message})
}
