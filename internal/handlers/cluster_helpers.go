package handlers

import (
	"lazy-balancer-v2/internal/services"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

type masterGateOptions struct {
	queryFailure string
	forbidden    string
	errorCode    string
}

const masterRequiredErrorCode = "master_required"

// requireMasterResult 统一三种入口的角色门结果：查询错误恒 500，确认从节点
// 恒 403，主节点放行。角色读取仍复用 services.RoleOf（ClusterService.IsMaster
// 是其薄包装）；端点仅保留自己的文案与机器错误码。
func requireMasterResult(c *gin.Context, isMaster bool, err error, options masterGateOptions) bool {
	if err != nil {
		clusterError(c, http.StatusInternalServerError, options.queryFailure, err)
		return false
	}
	if !isMaster {
		errorCode := options.errorCode
		if errorCode == "" {
			errorCode = masterRequiredErrorCode
		}
		c.Header("X-LB-Error-Code", errorCode)
		clusterError(c, http.StatusForbidden, options.forbidden, nil)
		return false
	}
	return true
}

func (h *Handlers) requireMaster(c *gin.Context) bool {
	isMaster, err := h.clusterService.IsMaster(c.Request.Context())
	return requireMasterResult(c, isMaster, err, masterGateOptions{
		queryFailure: "读取节点模式失败",
		forbidden:    "该操作仅允许在主节点执行",
		errorCode:    masterRequiredErrorCode,
	})
}

func clusterError(c *gin.Context, status int, message string, err error) {
	if err != nil {
		services.Logf("error", "cluster request failed: %v", err)
	}
	c.JSON(status, models.APIResponse{Code: status, Message: message})
}

// clusterMasterForbidden 统一服务层 ErrNotMasterNode → 403 的输出形状
// （历史问题）：与 requireMasterResult 同源携带 X-LB-Error-Code——从端
// Pull 的错误分类（cluster_sync.go）依赖该头，服务层降级竞态 403 不得裸发。
func clusterMasterForbidden(c *gin.Context, err error) {
	c.Header("X-LB-Error-Code", masterRequiredErrorCode)
	clusterError(c, http.StatusForbidden, err.Error(), err)
}
