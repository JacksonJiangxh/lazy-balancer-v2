package handlers

import (
	"database/sql"
	"errors"
	"lazy-balancer-v2/internal/services"
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

func dbQueryNotFound(c *gin.Context, err error, notFoundMessage, operation string) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: notFoundMessage})
		return true
	}
	services.Logf("error", "%s: %v", operation, err)
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
	return true
}

// writeInternalError 5xx 响应的唯一写点：响应只回固定文案，底层错误
// （SQL 文本/表列名、文件路径与 errno、Caddy admin 地址）只进运行日志。
// business 组任意登录用户可读——与 crawler-lib 域同政策（error_body_leak_test）。
// cause 为 nil 表示调用方已就地记录过该错误详情（避免重复日志）。
// 4xx 配置拒绝类不得走本函数：cli_validation_gate 等门禁依赖 400 内的
// CLI/字段细节，二者边界不得「顺手统一文案」。
func writeInternalError(c *gin.Context, status int, message string, cause error) {
	if cause != nil {
		services.Logf("error", "%s: %v", message, cause)
	}
	c.JSON(status, models.APIResponse{Code: status, Message: message})
}

// internalError 是「固定文案 + 服务端留痕」5xx 响应的唯一装配实现：日志标签
// （域）+ 公开文案 + 底层错误。system.go/crawlerlib.go/security.go 三个同语义
// 装配器一律委托本函数——文案策略（trace id/日志级别/统一脱敏）只改一处。
// err==nil 表示调用方已就地留痕，不再重复日志。
func internalError(tag, publicMsg string, err error) models.APIResponse {
	if err != nil {
		if tag != "" {
			services.Logf("error", "%s: %s: %v", tag, publicMsg, err)
		} else {
			services.Logf("error", "%s: %v", publicMsg, err)
		}
	}
	return models.APIResponse{Code: http.StatusInternalServerError, Message: publicMsg}
}
