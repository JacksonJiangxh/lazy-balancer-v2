package services

import "fmt"

// auditResultTextMap 是审计结果码 → 中文渲染的唯一事实源
// 由 switch 改为 map，供 audit_result_text_test.go 以 AST/字面量互检钉住
// 「AuditResultPart 字面量实参集合 ⊆ 映射键集」——新增结果码漏映射即测试红）。
// 未收录码在 AuditResultText 中原样返回（保留英文兜底），但落库前应补映射。
var auditResultTextMap = map[string]string{
	"success":              "成功",
	"failed":               "失败",
	"failure":              "失败",
	"partial":              "部分成功",
	"max_attempts":         "达到最大重试次数",
	"missing_material":     "证书数据缺失",
	"queued":               "已重新排队",
	"deployment_retry":     "等待恢复部署",
	"slow_retry":           "慢速重试中",
	"requested":            "已触发",
	"skipped":              "已跳过",
	"invalid_request":      "请求格式错误",
	"invalid_ticket":       "登录票据无效或已过期",
	"invalid_signature":    "登录票据签名错误",
	"expired":              "登录票据已过期",
	"replay":               "登录票据已使用",
	"user_unavailable":     "登录票据用户不存在或已禁用",
	"database_error":       "数据库错误",
	"invalid_credentials":  "用户名或密码错误",
	"credentials_invalid":  "凭证无效",
	"internal_error":       "系统内部错误",
	"enabled":              "已启用",
	"disabled":             "已禁用",
	"approved":             "已通过",
	"rejected":             "已拒绝",
	"created":              "已创建",
	"reregistered":         "已重新注册",
	"not_found":            "对象不存在",
	"missing_domain":       "缺少测试域名",
	"unknown_provider":     "未知提供商",
	"provider_error":       "提供商错误",
	"missing_acme_email":   "缺少 ACME 邮箱",
	"invalid_config":       "配置无效",
	"register_failed":      "注册失败",
	"storage_corrupted":    "存储数据损坏",
	"applied_or_no_change": "同步完成或无变更",
	"sync_failed":          "同步失败",
	"io_error":             "文件写入失败",
	"query_failed":         "查询失败",
	"warning":              "警告",
	// 部署失败的状态回写本身失败（瞬时 DB 故障/CAS 冲突）：任务转入簿记
	// 补写 + 重试登记，审计必须能读懂这个结果码。
	"status_writeback_failed": "状态回写失败",
	// 证书任务「重试被阻止」终态（certificates.go 经局部
	// auditFailure 闭包以动态实参传入，字面量扫描钉测覆盖不到——本码曾因此
	// 渲染成英文 blocked）。
	"blocked":            "重试被阻止",
	"deleted_unverified": "已删除（结果未确认）",
}

func AuditResultText(result string) string {
	if text, ok := auditResultTextMap[result]; ok {
		return text
	}
	return result
}

func FormatAuditDetail(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return joinChineseParts(filtered)
}

func joinChineseParts(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, part := range parts[1:] {
		result += "；" + part
	}
	return result
}

// AuditUserPart 用户标识段(2026-09-11 裁定):用户相关审计详情显示完整标识
// 「用户 12（zhang）」;用户名空回退「用户 12」(不可解析场景)。
func AuditUserPart(id int, username string) string {
	if username == "" {
		return fmt.Sprintf("用户 %d", id)
	}
	return fmt.Sprintf("用户 %d（%s）", id, username)
}

func AuditJobPart(jobID int) string {
	return fmt.Sprintf("任务 %d", jobID)
}

func AuditRulePart(ruleID string) string {
	return fmt.Sprintf("规则 %s", ruleID)
}

func AuditResultPart(result string) string {
	return fmt.Sprintf("结果：%s", AuditResultText(result))
}

// auditSourceTextMap 是审计来源码 → 中文渲染的唯一事实源（历史
// 由 switch 改为 map，供 audit_result_text_test.go 以 AST 字面量互检钉住「来源码
// 字面量集合 ⊆ 映射键集」）。此前 switch 形态没有任何覆盖钉，生产者传入的
// runtime_reconcile/runtime_sweep/promote_or_startup 三个来源长期落 default，
// 操作审计详情直接渲染英文内部标识。
// 未收录码在 AuditSourcePart 中原样返回（保留英文兜底，便于定位漏映射）。
var auditSourceTextMap = map[string]string{
	"certificate_issued":      "来源：证书签发",
	"startup_materialization": "来源：启动恢复",
	"ca_cooldown":             "来源：CA 冷却结束",
	"startup_recovery":        "来源：启动恢复",
	"renewal":                 "来源：自动续签",
	// "manual"：词汇表预留项——全仓当前无生产者（手动操作类来源码未落审计），
	// 保留键以便未来接入时不改渲染层。
	"manual":            "来源：手动操作",
	"rule_create":       "来源：创建规则",
	"rule_update":       "来源：更新规则",
	"rule_delete":       "来源：删除规则",
	"rule_enable":       "来源：启用规则",
	"rule_disable":      "来源：禁用规则",
	"ip2region_update":  "来源：IP 库更新",
	"crs_update":        "来源：CRS 规则库更新",
	"threat_update":     "来源：威胁情报库更新",
	"crawlerbot_update": "来源：爬虫地址库更新",
	"autoban":           "来源：自动封禁名单",
	// 运行时/升主补建来源：生产者一直在传，此前全落
	// default → 操作审计详情显示「来源：runtime_sweep」等英文内部标识。
	"runtime_reconcile":    "来源：运行时对账",
	"runtime_sweep":        "来源：运行时清扫",
	"promote_or_startup":   "来源：升主或启动补建",
	"first_issuance_retry": "来源：首次签发重试",
	// 部署生命周期行缺证书材料（ACME 下载完成后进程退出）：补扫重新排队签发。
	"deployment_material_lost": "来源：证书材料丢失",
}

func AuditSourcePart(source string) string {
	if text, ok := auditSourceTextMap[source]; ok {
		return text
	}
	return fmt.Sprintf("来源：%s", source)
}

// recordSystemReloadAudit 数据类更新（IP 库/CRS）触发的真实 Caddy 重载统一
// 留痕（system 归因，裁定 2026-09-07；对齐 certissuer/集群同步口径）。
func recordSystemReloadAudit(source string, err error) {
	if err != nil {
		RecordAuditLog("system", "重载失败", "Caddy服务", FormatAuditDetail(AuditSourcePart(source), err.Error()), "")
		return
	}
	RecordAuditLog("system", "重载", "Caddy服务", FormatAuditDetail(AuditSourcePart(source), AuditResultPart("success")), "")
}
