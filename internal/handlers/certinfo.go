package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// GetRuleCertInfo returns parsed certificate information for a single rule.
// 服务层读取故障必须回 500（fail-visible）；规则不存在/未启用 TLS
// 保持 200 + data:null（既有契约，前端据此显示「无证书信息」）。
func (h *Handlers) GetRuleCertInfo(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	info, err := services.GetRuleCertInfo(caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则证书信息失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

// GetRulesCertInfo returns parsed certificate information for multiple rules in one call.
func (h *Handlers) GetRulesCertInfo(c *gin.Context) {
	var req models.CertInfoBatchRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request: " + err.Error()})
		return
	}

	if len(req.CaddyIDs) == 0 {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]*models.RuleCertInfo{}})
		return
	}

	// Limit batch size to prevent abuse
	if len(req.CaddyIDs) > 200 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "invalid_request：caddy_ids 数量不能超过 200"})
		return
	}

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(req.CaddyIDs)), ",")
	args := make([]any, len(req.CaddyIDs))
	for index, id := range req.CaddyIDs {
		args[index] = id
	}
	// 阈值经 GetCertExpiryThreshold 单源读取（services/certinfo.go
	// 基准口径：global_config 缺行/读故障 error 留痕后降级治理默认），替换原子
	// 查询里以字面量 30 兜底 cert_expiry_days 的 COALESCE 标量子查询——该形态
	// 对「缺行」无效（标量子查询零行恒 NULL，Scan 进 int 失败→整批 500），与
	// 单规则端点（同一基准函数降级成功）口径分叉。阈值对本请求恒定，作首参
	// 绑定；独立切片（不得前插共享 args——下方 cert_jobs 候选查询按 IN 占位
	// 复用 args，错位会让候选集恒空）。
	queryArgs := append([]any{services.GetCertExpiryThreshold()}, args...)
	rows, err := db.DB.QueryContext(c.Request.Context(), fmt.Sprintf(`
		SELECT caddy_id, COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(domain,''), COALESCE(tls_cert,''),
			?
		FROM lb_rules WHERE caddy_id IN (%s)`, placeholders), queryArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取规则证书配置失败"})
		return
	}
	defer rows.Close()
	type ruleCertificate struct {
		id, source, domains, certPEM string
		enabled                      bool
		expiryDays                   int
	}
	rules := make(map[string]ruleCertificate, len(req.CaddyIDs))
	for rows.Next() {
		var rule ruleCertificate
		if err := rows.Scan(&rule.id, &rule.enabled, &rule.source, &rule.domains, &rule.certPEM, &rule.expiryDays); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取规则证书配置失败"})
			return
		}
		rules[rule.id] = rule
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取规则证书配置失败"})
		return
	}

	jobRows, err := db.DB.QueryContext(c.Request.Context(), fmt.Sprintf(`
		SELECT rule_id, id, status, COALESCE(cert_pem,''), COALESCE(key_pem,''),
		       COALESCE(julianday(COALESCE(updated_at, created_at)), 0), COALESCE(domain,'')
		FROM cert_jobs
		WHERE rule_id IN (%s) AND %s
		ORDER BY rule_id, updated_at DESC, id DESC`, placeholders, services.CertJobMaterialPredicateSQL("")), args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取签发证书失败"})
		return
	}
	defer jobRows.Close()
	candidates := make(map[string][]services.CertificateCandidate, len(rules))
	now := time.Now()
	for jobRows.Next() {
		var id string
		var candidate services.CertificateCandidate
		if err := jobRows.Scan(&id, &candidate.ID, &candidate.Status, &candidate.CertPEM, &candidate.KeyPEM, &candidate.UpdatedAt, &candidate.Domain); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取签发证书失败"})
			return
		}
		// 装载阶段预解析一次，选择与过期回退共用同一 Leaf。
		if candidate.Status != "disabled" {
			candidate.Leaf = services.ParseCertificateLeaf(candidate.CertPEM, candidate.KeyPEM)
		}
		candidates[id] = append(candidates[id], candidate)
	}
	if err := jobRows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "批量读取签发证书失败"})
		return
	}

	result := make(map[string]*models.RuleCertInfo, len(req.CaddyIDs))
	for _, id := range req.CaddyIDs {
		rule, exists := rules[id]
		if !exists || !rule.enabled {
			result[id] = nil
			continue
		}
		certPEM := rule.certPEM
		if rule.source == "acme_dns" {
			var selected bool
			certPEM, selected = services.SelectRuleCertificate(candidates[id], rule.domains, now)
			// 同型回退——候选全过期时按 expired 呈现,
			// 与单规则端点同口径(此前批量恒报「尚未签发或不存在」)。
			if !selected {
				if info := services.ExpiredACMECertInfoFallback(candidates[id], id, rule.domains, rule.expiryDays, now); info != nil {
					result[id] = info
					continue
				}
			}
		}
		result[id] = services.FormatRuleCertInfo(certPEM, rule.source, rule.domains, id, rule.expiryDays, now)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}
