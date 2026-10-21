package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var (
	createOrRequeueCertJobVerified = services.CreateOrRequeueCertJobVerified
	cancelRuleJobs                 = func(ctx context.Context, manager *services.CAQueueManager, ruleID string) error {
		return manager.CancelJobsForRule(ctx, ruleID)
	}
	cancelRuleJobsTimeout = 2 * time.Minute
)

// enableCertJobResumePreUpdateHook 是测试专用钩子：在 EnableRule 的
// EnableCertJobResume 分支 UPDATE 之前触发，用于模拟 SELECT 与 UPDATE 之间
// 任务行被并发删除（历史修复 RowsAffected 校验的回归测试）。
var enableCertJobResumePreUpdateHook func(jobID int)

func (h *Handlers) ListRules(c *gin.Context) {
	// 历史问题：lb_rules.id 为可空遗留列（生产形态恒 NULL，cluster_apply 才显式
	// 带值），ORDER BY id 语义退化；rowid 显式化——行为与现状等价（NULL 排序
	// 实践上即 rowid 序）。
	rows, err := db.DB.Query(`SELECT ` + lbRuleListColumns + ` FROM lb_rules ORDER BY rowid`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	rules, err := scanLbRules(rows)
	// 历史问题: rows.Close 错误也要记录，与 services 层 errors.Join 风格一致。
	if closeErr := rows.Close(); closeErr != nil {
		services.Logf("error", "ListRules rows close error: %v", closeErr)
	}
	if err != nil {
		services.Logf("error", "ListRules scan error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if err := hydrateRuleRelations(c.Request.Context(), rules); err != nil {
		services.Logf("error", "ListRules relations error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则关联数据失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rules})
}

func (h *Handlers) GetRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	rows, err := db.DB.Query(`SELECT `+lbRuleColumns+` FROM lb_rules WHERE caddy_id = ?`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	rules, err := scanLbRules(rows)
	// 历史问题: 同 ListRules。
	if closeErr := rows.Close(); closeErr != nil {
		services.Logf("error", "GetRule rows close error for caddy_id=%s: %v", caddyID, closeErr)
	}
	if err != nil {
		services.Logf("error", "GetRule scan error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if len(rules) == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	if err := hydrateRuleRelations(c.Request.Context(), rules); err != nil {
		services.Logf("error", "GetRule relations error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则关联数据失败"})
		return
	}
	rule := rules[0]
	// 历史问题（历史）：手动证书私钥与导出备份同敏感级——仅管理员 JWT
	// 与管理员读写 Key 可回读；只读 Key/非管理员掩码为空串并置 TLSKeySet，
	// 供编辑表单区分「未配置」与「已隐藏」（UpdateRule 空值=保留原私钥）。
	if rule.TLSKey != "" && !canReadRuleTLSPrivateKey(c) {
		rule.TLSKey = ""
		rule.TLSKeySet = true
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rule})
}

// canReadRuleTLSPrivateKey 报告当前请求身份是否可回读规则私钥字段：仅管理员
// JWT 与管理员读写 API Key；只读 Key/非管理员恒掩码。GetRule 与
// GetRuleCaddyConfig 共用本判据（同一敏感级的单一事实源）。
func canReadRuleTLSPrivateKey(c *gin.Context) bool {
	if c.GetString("role") != "admin" {
		return false
	}
	return !(c.GetString("auth_type") == "api_key" && c.GetBool("api_key_read_only"))
}

// maskRuleCaddyPrivateKeys 递归掩码证书条目中的私钥字段：证书条目
// （load_files 的私钥文件路径 / load_pem 的 PEM 正文）携带 certificate 与
// key，非管理员/只读 Key 看到的 key 置空并标记 key_redacted——配置查看框
// 只需证书与策略，无需私钥；与 GetRule 的 TLSKeySet 掩码口径一致。
func maskRuleCaddyPrivateKeys(value interface{}) {
	switch typed := value.(type) {
	case map[string]interface{}:
		if _, hasCertificate := typed["certificate"]; hasCertificate {
			if key, ok := typed["key"].(string); ok && key != "" {
				typed["key"] = ""
				typed["key_redacted"] = true
			}
		}
		for _, child := range typed {
			maskRuleCaddyPrivateKeys(child)
		}
	case []interface{}:
		for _, child := range typed {
			maskRuleCaddyPrivateKeys(child)
		}
	case []map[string]interface{}:
		for _, child := range typed {
			maskRuleCaddyPrivateKeys(child)
		}
	}
}

func (h *Handlers) GetRuleCaddyConfig(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var r struct {
		CaddyID    string
		ListenPort int
		Enabled    bool
		Domain     string
		Protocol   string
	}

	services.Logf("debug", "GetRuleCaddyConfig: querying rule caddy_id=%s", caddyID)

	err := db.DB.QueryRow(`
		SELECT COALESCE(caddy_id,''), listen_port, IIF(enabled IN ('1',1),1,0), COALESCE(domain,''), COALESCE(protocol,'http')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.CaddyID, &r.ListenPort, &r.Enabled, &r.Domain, &r.Protocol)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}

	if err != nil {
		services.Logf("error", "GetRuleCaddyConfig: query/scan error for rule caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "规则 Caddy 配置查询失败"})
		return
	}

	// 历史修复 同族（历史）：该 enabled 上游 COUNT 仅用于 debug 日志，
	// 每次请求额外执行一次查询——删除（排障价值不抵每请求成本）。
	services.Logf("debug", "GetRuleCaddyConfig: caddyID=%s, port=%d, enabled=%v",
		r.CaddyID, r.ListenPort, r.Enabled)

	responseData := map[string]interface{}{
		"caddy_id": r.CaddyID,
		"enabled":  r.Enabled,
	}

	if r.CaddyID == "" || !r.Enabled {
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	// 一次读取运行配置，按 @id 归属收集本规则的全部路由——主路由
	// （@id == caddyID，与原 GetConfigByID 同源）与兄弟路由（caddyID_ 前缀：
	// 自定义路由渲染的 caddyID_path_N、GeoIP pass 的 caddyID_geoip、
	// HTTP→HTTPS 跳转的 caddyID_redirect）。启用自定义路由的规则此前只返回
	// 主路由对象，配置查看对话框拿到的 JSON 缺路径路由。
	runtimeConfig, err := h.caddyService.GetConfig()
	if err != nil {
		// 历史问题：admin 不可达/超时 ≠「规则未应用」——此前两者都归一为
		// config_not_exists，排障被误导。返回 502，让 UI 的失败分支如实展示
		// 「获取配置失败」（后者只表示该规则无运行路由）。
		services.Logf("error", "GetRuleCaddyConfig: failed to get config from Caddy for caddy_id=%s: %v", r.CaddyID, err)
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: http.StatusBadGateway, Message: "读取 Caddy 运行配置失败: " + err.Error()})
		return
	}
	mainRoute, allRuleRoutes := ruleCaddyRoutes(runtimeConfig, r.CaddyID)
	if mainRoute == nil {
		services.Logf("info", "GetRuleCaddyConfig: route %s not found in running config", r.CaddyID)
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	// Build the surrounding server/TLS context so the dialog shows certificates
	// and policies. 历史问题: 定向构建仅含本规则端口 server 的上下文，
	// 不再为单条规则触发整库查询+证书快照读取的全量重渲染。
	fullConfig := services.GenerateRuleServerContext(r.CaddyID, r.ListenPort, r.Protocol, r.Domain)
	if previewErr, exists := fullConfig["error"]; exists && previewErr != nil {
		services.Logf("error", "GetRuleCaddyConfig: build server context for %s failed: %v", r.CaddyID, previewErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("生成规则 Caddy 配置失败: %v", previewErr)})
		return
	}
	ruleContext := buildRuleCaddyContext(fullConfig, r.CaddyID, r.Domain)

	responseData["config"] = map[string]interface{}{
		"route":                   mainRoute,
		"routes":                  allRuleRoutes,
		"server_context":          ruleContext["server"],
		"tls_certificates":        ruleContext["tls_certificates"],
		"tls_connection_policies": ruleContext["tls_connection_policies"],
	}
	responseData["config_not_exists"] = false
	// 规则私钥字段与 GetRule 同敏感级：非管理员/只读 Key 不下发私钥（PEM
	// 正文或私钥文件路径），只保留证书与策略上下文。
	if !canReadRuleTLSPrivateKey(c) {
		maskRuleCaddyPrivateKeys(responseData)
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
}

// sortedInterfaceKeys 按字典序返回 map 的键（多处「同一对象出现在
// 多个命名容器」的读取路径需要确定性遍历，避免 map 序导致的展示漂移）。
func sortedInterfaceKeys(values map[string]interface{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// buildRuleCaddyContext extracts the server and TLS context relevant to a rule from the full Caddy config.
func buildRuleCaddyContext(fullConfig map[string]interface{}, caddyID string, domain string) map[string]interface{} {
	result := map[string]interface{}{
		"server":                  nil,
		"tls_certificates":        []interface{}{},
		"tls_connection_policies": []interface{}{},
	}

	apps, _ := fullConfig["apps"].(map[string]interface{})
	if apps == nil {
		return result
	}

	// 历史修复（历史）：同一 @id 若出现在多个 server（外部写入/历史漂移，
	// 本仓另有漂移检测守卫但仍属可能形态），旧实现只在 routes 循环内 break，
	// 外层继续遍历并用后遍历者覆盖 result["server"]——map 序遍历不确定，
	// 配置查看框的 server_context 随机漂移，误导排障。改为按 server 名排序
	// 遍历 + 命中即跳出外层循环：同一份配置恒得同一结果（确定性=排序首个）。
	if httpApp, ok := apps["http"].(map[string]interface{}); ok {
		if servers, ok := httpApp["servers"].(map[string]interface{}); ok {
			for _, serverName := range sortedInterfaceKeys(servers) {
				server, _ := servers[serverName].(map[string]interface{})
				if server == nil {
					continue
				}
				routes, _ := server["routes"].([]interface{})
				matched := false
				for _, routeVal := range routes {
					route, _ := routeVal.(map[string]interface{})
					if route == nil {
						continue
					}
					if route["@id"] == caddyID {
						matched = true
						break
					}
				}
				if !matched {
					continue
				}
				scopedPolicies := scopedTLSConnectionPolicies(server["tls_connection_policies"], caddyID, domain)
				result["server"] = map[string]interface{}{
					"server_name":             serverName,
					"listen":                  server["listen"],
					"tls_connection_policies": scopedPolicies,
				}
				result["tls_connection_policies"] = scopedPolicies
				break
			}
		}
	}

	// If not found in HTTP app, search the layer4 app for TCP rules
	if result["server"] == nil {
		if layer4App, ok := apps["layer4"].(map[string]interface{}); ok {
			if servers, ok := layer4App["servers"].(map[string]interface{}); ok {
				for _, serverName := range sortedInterfaceKeys(servers) {
					server, _ := servers[serverName].(map[string]interface{})
					if server == nil {
						continue
					}
					routes, _ := server["routes"].([]interface{})
					matched := false
					for _, routeVal := range routes {
						route, _ := routeVal.(map[string]interface{})
						if route == nil {
							continue
						}
						if route["@id"] == caddyID {
							matched = true
							break
						}
					}
					if !matched {
						continue
					}
					result["server"] = map[string]interface{}{
						"server_name": serverName,
						"listen":      server["listen"],
					}
					break
				}
			}
		}
	}

	tlsApp, _ := apps["tls"].(map[string]interface{})
	if tlsApp == nil {
		return result
	}

	if certs, ok := tlsApp["certificates"].(map[string]interface{}); ok {
		var certList []interface{}
		switch v := certs["load_files"].(type) {
		case []interface{}:
			certList = v
		case []map[string]interface{}:
			for _, c := range v {
				certList = append(certList, c)
			}
		}
		if certList == nil {
			switch v := certs["load_pem"].(type) {
			case []interface{}:
				certList = v
			case []map[string]interface{}:
				for _, c := range v {
					certList = append(certList, c)
				}
			}
		}
		for _, certVal := range certList {
			cert, _ := certVal.(map[string]interface{})
			if cert == nil {
				continue
			}
			matched := false
			switch tags := cert["tags"].(type) {
			case []interface{}:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			case []string:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			}
			if matched {
				result["tls_certificates"] = append(result["tls_certificates"].([]interface{}), cert)
			}
		}
	}

	// 历史问题：此处曾有 tls.automation.policies 的域名作用域扫描——生产
	// 渲染（GenerateRuleServerContext / 全量生成）从不产出 tls.automation
	// （注释明确「no Caddy ACME automation」，证书由应用层任务管理），该字段
	// 恒为 []，测试为自造输入假绿。删除死代码，配置查看框不再展示不存在的
	// automation policies。
	return result
}

// ruleCaddyRoutes 从运行配置收集归属该规则的全部路由：遍历 http 与
// layer4 两个 app 的全部 server，按 services.RouteIDBelongsToRule（与
// DeleteRule 系列的路由清理同口径）识别主路由（@id == caddyID）与兄弟路由
// （caddyID_path_N / caddyID_geoip / caddyID_redirect）。同一 server 内保持
// 运行顺序；跨 server（如 80 端口跳转路由）顺序不保证。
func ruleCaddyRoutes(full map[string]interface{}, caddyID string) (main map[string]interface{}, all []interface{}) {
	apps, _ := full["apps"].(map[string]interface{})
	if apps == nil {
		return nil, nil
	}
	collect := func(routesRaw interface{}) {
		routes, _ := routesRaw.([]interface{})
		for _, routeVal := range routes {
			route, _ := routeVal.(map[string]interface{})
			if route == nil {
				continue
			}
			routeID, _ := route["@id"].(string)
			if routeID == "" || !services.RouteIDBelongsToRule(routeID, caddyID) {
				continue
			}
			if routeID == caddyID {
				main = route
			}
			all = append(all, route)
		}
	}
	for _, appName := range []string{"http", "layer4"} {
		app, _ := apps[appName].(map[string]interface{})
		if app == nil {
			continue
		}
		servers, _ := app["servers"].(map[string]interface{})
		for _, serverVal := range servers {
			server, _ := serverVal.(map[string]interface{})
			if server == nil {
				continue
			}
			collect(server["routes"])
		}
	}
	return main, all
}

// scopedTLSConnectionPolicies 只保留属于当前规则的连接策略：
// certificate_selection.any_tag 携带本规则 caddyID，或 match.sni 与规则规范域名相交。
func scopedTLSConnectionPolicies(raw interface{}, caddyID string, domain string) []interface{} {
	policies, ok := raw.([]interface{})
	if !ok {
		return []interface{}{}
	}
	wanted := make(map[string]struct{})
	for _, ruleDomain := range normalizedRuleDomains(domain) {
		wanted[ruleDomain] = struct{}{}
	}
	scoped := make([]interface{}, 0, len(policies))
	for _, policyVal := range policies {
		policy, _ := policyVal.(map[string]interface{})
		if policy == nil {
			continue
		}
		matched := false
		if selection, ok := policy["certificate_selection"].(map[string]interface{}); ok {
			switch tags := selection["any_tag"].(type) {
			case []interface{}:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			case []string:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			}
		}
		if !matched && len(wanted) > 0 {
			if match, ok := policy["match"].(map[string]interface{}); ok {
				switch sni := match["sni"].(type) {
				case []interface{}:
					for _, name := range sni {
						sniDomain, ok := name.(string)
						if !ok {
							continue
						}
						if _, hit := wanted[sniDomain]; hit {
							matched = true
							break
						}
					}
				case []string:
					for _, sniDomain := range sni {
						if _, hit := wanted[sniDomain]; hit {
							matched = true
							break
						}
					}
				}
			}
		}
		if matched {
			scoped = append(scoped, policyVal)
		}
	}
	return scoped
}

// normalizedRuleDomains 将逗号分隔域名转为规范化集合（小写+punycode）。
// 历史问题: CanonicalDomains 失败（手造脏数据）时回退小写拆分保留，
// 与渲染侧 normalizedDomainSet（caddy.go）同口径——此前失败返回 nil 会把
// 域名整体丢弃，导致遮蔽检查静默通过（两侧不对称且是问题方向）。
func normalizedRuleDomains(value string) []string {
	canonical, err := db.CanonicalDomains(value)
	if err == nil {
		return strings.Split(canonical, ",")
	}
	var result []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, strings.ToLower(part))
		}
	}
	return result
}

// canonicalACMEDomainForJobLookup 返回 cert_jobs.domain 使用的排序规范形式，
// 使任务查询不受 lb_rules.domain 用户输入顺序影响；非合法 ACME 域名集时回退原值。
func canonicalACMEDomainForJobLookup(domain string) string {
	canonical, err := services.CanonicalACMEDomains(domain)
	if err != nil {
		return domain
	}
	return canonical
}

// reversedACMEDomainForm 返回双域名集合的逆序形式；cert_jobs.domain 按排序规范
// 形式存储，而导入备份可携带用户输入顺序的非规范行——与 certjobs.go 规则侧
// joined+reversed 双形式匹配同型。
// 历史修复（历史）：单源收敛至 services.ReversedCertJobDomain（与
// certjobs.reversedCertJobDomain 同实现，两侧委托）。
func reversedACMEDomainForm(domain string) string {
	return services.ReversedCertJobDomain(domain)
}

// retireCertJobsForDomain 将规则下旧域证书任务退役为 disabled 终态（保留 PEM 作
// 历史）。导入备份可携带非规范 domain 行（大小写/空白/顺序变体），按去空白小写
// 归一（lower+replace）与 canonical/reversed 双形式匹配，避免变体行逃逸退役
// （历史修复）；零行命中为无害无操作。
// 历史问题:stage 参数化失败阶段(事务开启/迁移 UPDATE/commit),退役 message
// 随实际失败阶段落库,运维可从任务行直接看出哪一步失败。
func retireCertJobsForDomain(database *sql.DB, ruleID, canonicalDomain, reversedDomain, stage string) error {
	_, err := database.Exec(
		`UPDATE cert_jobs SET status='disabled', message=?, updated_at=datetime('now') WHERE rule_id=? AND lower(replace(domain,' ','')) IN (?,?)`,
		stage+"，旧域任务退役", ruleID, canonicalDomain, reversedDomain)
	return err
}

func validateRuleListenPort(protocol string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("端口必须在 1-65535 之间")
	}
	if port == 8000 || port == 2019 {
		return fmt.Errorf("端口 %d 为管理端口，不可使用", port)
	}
	if protocol == "tcp" && (port == 80 || port == 443) {
		return fmt.Errorf("端口 %d 为 HTTP/HTTPS 保留端口", port)
	}
	return nil
}

// validateRuleListenPortForSave 在包级 validateRuleListenPort（范围/默认管理口
// 8000/2019/TCP 80/443 保留）之上，叠加本进程实际管理端口校验：管理
// 面板 HTTP/HTTPS 监听口（cfg.Port——admin TLS 与面板同一监听口，见
// cmd/server/main.go）与 Caddy admin API 端口（cfg.CaddyAdminURL 解析）。此前
// 仅硬编码 8000/2019，部署自定义端口（config 文件 port / caddy_admin_url）时
// 规则可抢占面板端口导致管理面失联。导入链（config_backup/config_import_v1）
// 经 validateV2BackupRules/validateConvertedV1Rules 的可选 portGate 传入本函数，
// 与保存链同口径（历史问题）。
func (h *Handlers) validateRuleListenPortForSave(protocol string, port int) error {
	if err := validateRuleListenPort(protocol, port); err != nil {
		return err
	}
	if port == h.adminPanelListenPort() || port == h.caddyAdminListenPort() {
		return fmt.Errorf("端口 %d 为管理端口，不可使用", port)
	}
	return nil
}

func (h *Handlers) adminPanelListenPort() int {
	if h.cfg != nil && h.cfg.Port >= 1 && h.cfg.Port <= 65535 {
		return h.cfg.Port
	}
	return 8000
}

func (h *Handlers) caddyAdminListenPort() int {
	if h.cfg != nil && h.cfg.CaddyAdminURL != "" {
		if parsed, err := url.Parse(h.cfg.CaddyAdminURL); err == nil {
			if port, err := strconv.Atoi(parsed.Port()); err == nil && port >= 1 && port <= 65535 {
				return port
			}
		}
	}
	return 2019
}

// enabledRuleDomainConflict 同域名同端口冲突检查（历史修复，历史：删除
// 原 ruleDomainConflict 空包装，Create/Update/Enable 三处直用本函数）。
// 仅统计启用中的规则：禁用规则不占用域名，创建/更新时不应被其阻塞；启用时
// 由 EnableRule 侧同一函数二次把关，避免两条禁用规则同时启用产生冲突。
func enabledRuleDomainConflict(domain string, listenPort int, excludeCaddyID string) (bool, error) {
	return queryRuleDomainConflict(domain, listenPort, excludeCaddyID, " AND enabled = 1")
}

// queryRedirectShadowConflict 检查 80 端口跳转遮蔽：启用中的 TLS+HTTP 跳转规则会在
// 80 端口服务器头部生成 terminal 跳转路由（caddy.go redirectRoutes），同域名直接
// 监听 80 的规则会被遮蔽为死规则。两个方向同判：保存 80 端口规则时查跳转规则占用；
// 保存/启用 TLS+跳转规则时查 80 端口规则占用。返回冲突规则描述与冲突域名。
func queryRedirectShadowConflict(domain string, listenPort int, enableTLS, tlsHTTPRedirect bool, excludeCaddyID string) (string, string, error) {
	candidates := normalizedRuleDomains(domain)
	if len(candidates) == 0 {
		return "", "", nil
	}
	wanted := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		wanted[candidate] = struct{}{}
	}
	var rows *sql.Rows
	var err error
	switch {
	case listenPort == 80:
		// 历史问题: 排除对方 80 端口自环跳转规则（listen_port=80 + TLS + 跳转本身
		// 生成自环 Location、属非法存量，不应作为占用方拦截新建 80 规则）。
		// 历史问题(历史):镜像 2026-09 复审裁定 2(跳转分支同款 EXISTS)
		// ——全部上游被禁用的规则不产生 host 路由与跳转(caddy.go 历史修复),
		// 不作为占用方;此前裁定只落了单侧,该形态下 80 规则被纯误拦 400。
		rows, err = db.DB.Query(`SELECT caddy_id, name, COALESCE(domain,'') FROM lb_rules WHERE protocol='http' AND enabled=1 AND enable_tls=1 AND tls_http_redirect=1 AND listen_port != 80 AND caddy_id != ? AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id=lb_rules.caddy_id AND u.enabled=1)`, excludeCaddyID)
	case enableTLS && tlsHTTPRedirect:
		// 2026-09 复审裁定 2：与渲染面同口径——全部上游被禁用的 80 规则不产生
		// host 路由、不会遮蔽跳转，不再作为占用方（报错与真实渲染行为一致）。
		rows, err = db.DB.Query(`SELECT r.caddy_id, r.name, COALESCE(r.domain,'') FROM lb_rules r
			WHERE r.protocol='http' AND r.enabled=1 AND r.listen_port=80 AND r.caddy_id != ?
			AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id=r.caddy_id AND u.enabled=1)`, excludeCaddyID)
	default:
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	defer rows.Close()
	for rows.Next() {
		var otherID, otherName, otherDomain string
		if err := rows.Scan(&otherID, &otherName, &otherDomain); err != nil {
			return "", "", err
		}
		for _, existing := range normalizedRuleDomains(otherDomain) {
			if _, hit := wanted[existing]; hit {
				return otherName + "（" + otherID + "）", existing, nil
			}
		}
	}
	return "", "", rows.Err()
}

func queryRuleDomainConflict(domain string, listenPort int, excludeCaddyID, extraWhere string) (bool, error) {
	candidates := normalizedRuleDomains(domain)
	if len(candidates) == 0 {
		return false, nil
	}
	wanted := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		wanted[candidate] = struct{}{}
	}
	rows, err := db.DB.Query("SELECT COALESCE(domain,'') FROM lb_rules WHERE protocol='http' AND listen_port = ? AND caddy_id != ?"+extraWhere, listenPort, excludeCaddyID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var existing string
		if err := rows.Scan(&existing); err != nil {
			return false, err
		}
		for _, existingDomain := range normalizedRuleDomains(existing) {
			if _, conflict := wanted[existingDomain]; conflict {
				return true, nil
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

// respondRuleApplyError 规则×5 apply 错误统一映射（裁定 2026-09-07 历史修复）：
// 配置拒绝（CLI/admin 4xx/生成失败）→ 400「Caddy 配置应用失败，规则未<动词>: …」；
// ErrUnvalidatedApply/传输失败 → 500 同文案。恢复失败并入消息（不改状态码分类）。
// 历史修复（历史）：五个调用方的 applyErr 分支均伴随 tx 回滚——applyFromTxNote
// 的 CLI 预检/事务内应用两轮渲染已按未提交内容重写投影文件（规则×绑定策略的
// u-*/p<id> 投影），磁盘同步回退到已提交态（零 /load；单一收敛点=历史修复 同族
// 收敛，禁止单点补丁）。
func (h *Handlers) respondRuleApplyError(c *gin.Context, applyErr, restoreErr error, verb string) {
	h.caddyService.RollbackIPListProjectionsToCommittedInLock()
	if restoreErr != nil {
		applyErr = errors.Join(applyErr, restoreErr)
	}
	// 历史问题：规则五端点均为 Explicit 审计策略（中间件对 Explicit 整体
	// 跳过）——此前 apply 失败只写 HTTP 响应，操作审计完全缺席。与配置域
	// finishTxApply（拒绝/未校验分支）及安全域同口径：失败必须留痕。
	// 审计词条用字面量（词汇表门禁禁止动态 action；动词集合固定为五值）。
	failureDetail := services.FormatAuditDetail("Caddy 配置应用失败", applyErr.Error(), services.AuditResultPart("failure"))
	switch verb {
	case "创建":
		recordAudit(c, "创建失败", "负载规则", failureDetail)
	case "更新":
		recordAudit(c, "更新失败", "负载规则", failureDetail)
	case "删除":
		recordAudit(c, "删除失败", "负载规则", failureDetail)
	case "启用":
		recordAudit(c, "启用失败", "负载规则", failureDetail)
	case "禁用":
		recordAudit(c, "禁用失败", "负载规则", failureDetail)
	default:
		recordAudit(c, "应用失败", "负载规则", failureDetail)
	}
	if services.IsConfigRejected(applyErr) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置应用失败，规则未" + verb + ": " + applyErr.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置应用失败，规则未" + verb + ": " + applyErr.Error()})
}

// tcpDeadFields 是 TCP 写入侧「HTTP 专属字段」的指针视图：CreateRule（值
// 字段）/ UpdateRule（指针字段）/ DuplicateRule（存量行）共用同一张归一
// 清单。nil 目标 = 该入口有意不处置该字段（Create 的 NTLMCompatible/
// HealthCheckHost——显式携带由保存门 400 拒绝，不做静默弃置）。
type tcpDeadFields struct {
	EnableTLS                *bool
	TLSSource                *string
	TLSCert                  *string
	TLSKey                   *string
	ACMEConfigID             *int
	CAProviderID             *int
	Domain                   *string
	TLSHTTPRedirect          *bool
	HostHeader               *string
	HealthCheckPath          *string
	HealthCheckHost          *string
	EnableCompress           *bool
	CompressTypes            *string
	RequestBodyMaxSizeMB     *int
	UpstreamKeepaliveTimeout *int
	ServerTokensHidden       *int
	NTLMCompatible           *int
	UpstreamForceHTTP1       *int
	BlockPageStage1ID        *int
	BlockPageStage1Status    *int
	BlockPageStage3ID        *int
	BlockPageStage3Status    *int
	// 历史问题：访问日志渲染仅对 HTTP 生成 logger_names（caddy.go 按
	// r.Protocol=="http" 门控），TCP 行的 log_enabled 是死配置——UI 已对
	// TCP 隐藏开关，API/导入仍可写入，随导出/快照放大。
	LogEnabled *bool
	// TCP 自愈族（2026-10-22）：代理超时族与自定义上层/路径同属 HTTP
	// 语义（buildTCPServer/buildTCPProxyRoute 零消费，validateRuleFeatures
	// TCP 分支显式拒绝）——存量行携带这些死值会让任何无关编辑/复制命中
	// 保存门恒 400 死端（指针合并 nil=沿用存量）。save/update/duplicate
	// 三入口归一为 0，与导入/启动迁移 SQL 同族。
	ProxyDialTimeout           *int
	ProxyResponseHeaderTimeout *int
	ProxyReadTimeout           *int
	ProxyWriteTimeout          *int
	ProxyStreamTimeout         *int
	ProxyFlushInterval         *int
	ProxyStreamCloseDelay      *int
	CustomRoutesEnabled        *bool
	DynamicDNS                 *bool
	// Strategy：TCP 策略白名单外唯一 HTTP-only 值是 cookie
	//（validateStrategyForProtocol）——归一为 DDL 默认策略而非清空。
	Strategy *string
}

// tcpDeadFieldReset 是 TCP 规则归一的单一事实源（历史问题，2026-10-18）：
// TCP 渲染不消费下列 HTTP 专属字段（buildTCPServer/buildTCPProxyRoute
// 实证），携带即弃置——与协议切换归零同格，防止死配置随快照/导出/复制
// 放大。三入口各自用适配器把字段接进本清单，新增字段只改这一处。
func tcpDeadFieldReset(protocol string, fields tcpDeadFields) {
	if protocol != "tcp" {
		return
	}
	deadFalse, deadZero, deadEmpty := false, 0, ""
	for _, target := range []*bool{fields.EnableTLS, fields.TLSHTTPRedirect, fields.EnableCompress, fields.LogEnabled, fields.CustomRoutesEnabled, fields.DynamicDNS} {
		if target != nil {
			*target = deadFalse
		}
	}
	if fields.TLSSource != nil {
		*fields.TLSSource = "manual"
	}
	// cookie 是 TCP 策略白名单外的唯一 HTTP-only 值——归一为 DDL 默认策略
	// （weighted_round_robin，与导入/启动迁移 SQL 的 CASE 同终态），不清空。
	if fields.Strategy != nil && *fields.Strategy == "cookie" {
		*fields.Strategy = "weighted_round_robin"
	}
	for _, target := range []*string{fields.TLSCert, fields.TLSKey, fields.Domain, fields.HostHeader, fields.HealthCheckPath, fields.HealthCheckHost, fields.CompressTypes} {
		if target != nil {
			*target = deadEmpty
		}
	}
	for _, target := range []*int{
		fields.ACMEConfigID, fields.CAProviderID, fields.RequestBodyMaxSizeMB,
		fields.UpstreamKeepaliveTimeout, fields.ServerTokensHidden,
		fields.NTLMCompatible, fields.UpstreamForceHTTP1,
		fields.BlockPageStage1ID, fields.BlockPageStage1Status,
		fields.BlockPageStage3ID, fields.BlockPageStage3Status,
		fields.ProxyDialTimeout, fields.ProxyResponseHeaderTimeout,
		fields.ProxyReadTimeout, fields.ProxyWriteTimeout,
		fields.ProxyStreamTimeout, fields.ProxyFlushInterval,
		fields.ProxyStreamCloseDelay,
	} {
		if target != nil {
			*target = deadZero
		}
	}
}

// createRuleTCPDeadFields 接 CreateRule 的值字段；NTLMCompatible 留空——
// TCP 创建携带 NTLM 必须经 validateRuleFeatures 显式 400（2026-10-12 定稿）。
// HealthCheckHost 亦留空（历史问题）：HTTP-only 字段由保存门
// validateRulePayloadBeforeSave 显式 400（既有行为，与 NTLM 同格的「显式
// 携带即拒」），仅存量/复制/传输路径沉默归一。
// TCP 自愈族：代理超时族/自定义路由/动态上游/策略(cookie) 同样留空——
// Create 的请求值全部显式、无存量可愈，显式携带继续由 validateRuleFeatures
// TCP 分支 400 点名；同协议编辑/复制路径（update/stored 适配器）才需自愈。
func createRuleTCPDeadFields(req *models.CreateRuleRequest) tcpDeadFields {
	return tcpDeadFields{
		EnableTLS:                &req.EnableTLS,
		TLSSource:                &req.TLSSource,
		TLSCert:                  &req.TLSCert,
		TLSKey:                   &req.TLSKey,
		ACMEConfigID:             &req.ACMEConfigID,
		CAProviderID:             &req.CAProviderID,
		Domain:                   &req.Domain,
		TLSHTTPRedirect:          &req.TLSHTTPRedirect,
		HostHeader:               &req.HostHeader,
		HealthCheckPath:          &req.HealthCheckPath,
		EnableCompress:           &req.EnableCompress,
		CompressTypes:            &req.CompressTypes,
		RequestBodyMaxSizeMB:     &req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout: &req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:       &req.ServerTokensHidden,
		UpstreamForceHTTP1:       &req.UpstreamForceHTTP1,
		BlockPageStage1ID:        &req.BlockPageStage1ID,
		BlockPageStage1Status:    &req.BlockPageStage1Status,
		BlockPageStage3ID:        &req.BlockPageStage3ID,
		BlockPageStage3Status:    &req.BlockPageStage3Status,
		LogEnabled:               &req.LogEnabled,
	}
}

// updateRuleTCPDeadFields 接 UpdateRule 合并后的指针字段（调用点已保证非 nil）。
func updateRuleTCPDeadFields(req *models.UpdateRuleRequest) tcpDeadFields {
	return tcpDeadFields{
		EnableTLS:                req.EnableTLS,
		TLSSource:                &req.TLSSource,
		TLSCert:                  &req.TLSCert,
		TLSKey:                   &req.TLSKey,
		ACMEConfigID:             &req.ACMEConfigID,
		CAProviderID:             req.CAProviderID,
		Domain:                   &req.Domain,
		TLSHTTPRedirect:          req.TLSHTTPRedirect,
		HostHeader:               req.HostHeader,
		HealthCheckPath:          req.HealthCheckPath,
		HealthCheckHost:          req.HealthCheckHost,
		EnableCompress:           req.EnableCompress,
		CompressTypes:            &req.CompressTypes,
		RequestBodyMaxSizeMB:     req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout: req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:       req.ServerTokensHidden,
		NTLMCompatible:           req.NTLMCompatible,
		UpstreamForceHTTP1:       req.UpstreamForceHTTP1,
		BlockPageStage1ID:        req.BlockPageStage1ID,
		BlockPageStage1Status:    req.BlockPageStage1Status,
		BlockPageStage3ID:        req.BlockPageStage3ID,
		BlockPageStage3Status:    req.BlockPageStage3Status,
		LogEnabled:               req.LogEnabled,
		// TCP 自愈族：同协议编辑自愈族（调用点已保证非 nil）——
		// 存量死值不再让无关编辑恒 400 死端。
		ProxyDialTimeout:           req.ProxyDialTimeout,
		ProxyResponseHeaderTimeout: req.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:           req.ProxyReadTimeout,
		ProxyWriteTimeout:          req.ProxyWriteTimeout,
		ProxyStreamTimeout:         req.ProxyStreamTimeout,
		ProxyFlushInterval:         req.ProxyFlushInterval,
		ProxyStreamCloseDelay:      req.ProxyStreamCloseDelay,
		CustomRoutesEnabled:        req.CustomRoutesEnabled,
		DynamicDNS:                 req.DynamicDNS,
		Strategy:                   &req.Strategy,
	}
}

// storedRuleTCPDeadFields 接 DuplicateRule 的存量源行。
func storedRuleTCPDeadFields(rule *models.LbRule) tcpDeadFields {
	return tcpDeadFields{
		EnableTLS:                &rule.EnableTLS,
		TLSSource:                &rule.TLSSource,
		TLSCert:                  &rule.TLSCert,
		TLSKey:                   &rule.TLSKey,
		ACMEConfigID:             &rule.ACMEConfigID,
		CAProviderID:             &rule.CAProviderID,
		Domain:                   &rule.Domain,
		TLSHTTPRedirect:          &rule.TLSHTTPRedirect,
		HostHeader:               &rule.HostHeader,
		HealthCheckPath:          &rule.HealthCheckPath,
		HealthCheckHost:          &rule.HealthCheckHost,
		EnableCompress:           &rule.EnableCompress,
		CompressTypes:            &rule.CompressTypes,
		RequestBodyMaxSizeMB:     &rule.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout: &rule.UpstreamKeepaliveTimeout,
		ServerTokensHidden:       &rule.ServerTokensHidden,
		NTLMCompatible:           &rule.NTLMCompatible,
		UpstreamForceHTTP1:       &rule.UpstreamForceHTTP1,
		BlockPageStage1ID:        &rule.BlockPageStage1ID,
		BlockPageStage1Status:    &rule.BlockPageStage1Status,
		BlockPageStage3ID:        &rule.BlockPageStage3ID,
		BlockPageStage3Status:    &rule.BlockPageStage3Status,
		LogEnabled:               &rule.LogEnabled,
		// TCP 自愈族：TCP 源行携带的 HTTP 专属代理/路由/策略死值不得
		// 原样放大到副本（复制路径此前让 tcp+cookie、tcp+proxy 超时、
		// tcp+自定义路径的存量行复制即 400 死端）。
		ProxyDialTimeout:           &rule.ProxyDialTimeout,
		ProxyResponseHeaderTimeout: &rule.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:           &rule.ProxyReadTimeout,
		ProxyWriteTimeout:          &rule.ProxyWriteTimeout,
		ProxyStreamTimeout:         &rule.ProxyStreamTimeout,
		ProxyFlushInterval:         &rule.ProxyFlushInterval,
		ProxyStreamCloseDelay:      &rule.ProxyStreamCloseDelay,
		CustomRoutesEnabled:        &rule.CustomRoutesEnabled,
		DynamicDNS:                 &rule.DynamicDNS,
		Strategy:                   &rule.Strategy,
	}
}

// validateRuleRequestBodyMaxSizeMB 是 request_body_max_size_mb 的单一值域门
// （0-4096；0=不限制/跟随全局），Create/Update/Duplicate 三入口共用。
func validateRuleRequestBodyMaxSizeMB(value int) error {
	if value < 0 || value > 4096 {
		return fmt.Errorf("请求体大小限制必须在 0-4096 MB 之间")
	}
	return nil
}

// 规则文本列长度上限（规则文本长度上限，Ruling：取 DDL 声明值）：lb_rules.name
// VARCHAR(100)、description VARCHAR(300)（db.go 建表/重建 DDL 两处同值）。
// SQLite 不强制 VARCHAR 长度，无本门时超长文本可经 API 落库并随导出/快照/
// 备份放大。按 rune 计数（与前端 maxlength 的字符语义一致）。
const (
	maxRuleNameRunes        = 100
	maxRuleDescriptionRunes = 300
)

// validateRuleTextLengths 是 name/description 长度门的单一事实源
// （Create/Update/Duplicate 三入口共用）。
func validateRuleTextLengths(name, description string) error {
	if n := utf8.RuneCountInString(name); n > maxRuleNameRunes {
		return fmt.Errorf("规则名称过长（最多 %d 个字符，当前 %d 个）", maxRuleNameRunes, n)
	}
	if n := utf8.RuneCountInString(description); n > maxRuleDescriptionRunes {
		return fmt.Errorf("规则描述过长（最多 %d 个字符，当前 %d 个）", maxRuleDescriptionRunes, n)
	}
	return nil
}

// ruleDuplicateName 生成副本名「源名（副本）」并保证累积后缀不突破长度
// 上限（规则文本长度上限）：反复复制时源名本身已含「（副本）」后缀——截断基名而不是
// 后缀，否则后缀会被截掉导致副本名无法辨识。
func ruleDuplicateName(sourceName string) string {
	const suffix = "（副本）"
	base := []rune(sourceName)
	if limit := maxRuleNameRunes - utf8.RuneCountInString(suffix); len(base) > limit {
		base = base[:limit]
	}
	return string(base) + suffix
}

// duplicateRulePayloadRequest 把存量源行投影为共享保存输入，供
// validateRulePayloadBeforeSave 复用字段层校验（上游 host/端口/权重/查重/
// 健康检查/ACME 引用）。复制语义放宽 Create 表单门：零上游、零启用上游的
// 存量行合法（副本默认禁用，可事后补配），以一条探针启用上游满足「至少
// 一个上游 + 至少一个启用上游」两门后，其余字段仍逐项校验。
func duplicateRulePayloadRequest(rule models.LbRule) models.CreateRuleRequest {
	req := models.CreateRuleRequest{
		Name:                          rule.Name,
		Description:                   rule.Description,
		Protocol:                      rule.Protocol,
		Domain:                        rule.Domain,
		ListenPort:                    rule.ListenPort,
		Strategy:                      rule.Strategy,
		DynamicDNS:                    rule.DynamicDNS,
		EnableDnsServer:               rule.EnableDnsServer,
		DnsServer:                     rule.DnsServer,
		DnsFamily:                     rule.DnsFamily,
		HealthCheckPath:               rule.HealthCheckPath,
		HealthCheckInterval:           rule.HealthCheckInterval,
		HealthCheckTimeout:            rule.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold: rule.HealthCheckUnhealthyThreshold,
		HealthCheckHealthyThreshold:   rule.HealthCheckHealthyThreshold,
		EnableActiveHealthCheck:       rule.EnableActiveHealthCheck,
		TCPHealthCheckPort:            rule.TCPHealthCheckPort,
		TCPProxyProtocol:              rule.TCPProxyProtocol,
		TCPTryDuration:                rule.TCPTryDuration,
		TCPTryInterval:                rule.TCPTryInterval,
		RequestBodyMaxSizeMB:          rule.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout:      rule.UpstreamKeepaliveTimeout,
		ServerTokensHidden:            rule.ServerTokensHidden,
		NTLMCompatible:                rule.NTLMCompatible,
		UpstreamForceHTTP1:            rule.UpstreamForceHTTP1,
		CustomRoutesEnabled:           rule.CustomRoutesEnabled,
		ProxyDialTimeout:              rule.ProxyDialTimeout,
		ProxyResponseHeaderTimeout:    rule.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:              rule.ProxyReadTimeout,
		ProxyWriteTimeout:             rule.ProxyWriteTimeout,
		ProxyStreamTimeout:            rule.ProxyStreamTimeout,
		ProxyFlushInterval:            rule.ProxyFlushInterval,
		ProxyStreamCloseDelay:         rule.ProxyStreamCloseDelay,
		PathRules:                     rule.PathRules,
		HostHeader:                    rule.HostHeader,
		HealthCheckHost:               rule.HealthCheckHost,
		EnableTLS:                     rule.EnableTLS,
		TLSSource:                     rule.TLSSource,
		ACMEConfigID:                  rule.ACMEConfigID,
		CAProviderID:                  rule.CAProviderID,
		TLSCert:                       rule.TLSCert,
		TLSKey:                        rule.TLSKey,
		TLSHTTPRedirect:               rule.TLSHTTPRedirect,
		EnableCompress:                rule.EnableCompress,
		CompressTypes:                 rule.CompressTypes,
		LogEnabled:                    rule.LogEnabled,
		// 阶段页引用是「存量保留值」：与 UpdateRule 的 nil=保留现值口径
		// 一致（页面存在性由页删除侧引用检查与渲染侧「已失效」回落承担），
		// 复制路径不把存量行重新送进存在性门（否则存量坏引用使复制恒 400，
		// 而副本本就默认禁用、页面修复后可再启用）。
	}
	req.Upstreams = append(req.Upstreams, rule.Upstreams...)
	hasEnabled := false
	for _, upstream := range req.Upstreams {
		if upstream.Enabled {
			hasEnabled = true
			break
		}
	}
	if !hasEnabled {
		req.Upstreams = append(req.Upstreams, models.Upstream{
			Host: "duplicate-probe.invalid", Port: 1, Weight: 1, Enabled: true, Protocol: rule.Protocol,
		})
	}
	return req
}

// validateDuplicateRulePayload 是复制路径的字段层校验（历史问题）：源行的
// 上游 host/端口/权重/查重/健康检查与请求体大小等坏形态必须 400 点名源
// 规则，不得原样放大到副本。
func (h *Handlers) validateDuplicateRulePayload(rule models.LbRule) error {
	return h.validateRulePayloadBeforeSave(duplicateRulePayloadRequest(rule))
}

// 数据库即唯一事实源契约（CreateRule/UpdateRule 保存路径，2026-09-06 裁定 ④'）：
//  1. 三层校验：后端字段校验（validateRuleFeatures/validateRulePayloadBeforeSave）先于
//     任何写库；Caddy 层由 applyFromTxNote 内的 CLI 校验（真 validate-only）+ 事务内
//     ApplyConfigFromTx（最终门控）承担，校验与应用的输入同为事务视图最终渲染——
//     校验不过不落库；
//  2. 写库失败以「写入数据库失败（…）: <原因>」明确回报给保存方；
//  3. Caddy 配置只能从事务内渲染（ApplyConfigFromTx），应用失败即回滚事务并返回 400 +
//     具体原因，数据库与运行配置不会因保存路径产生不一致。
func (h *Handlers) CreateRule(c *gin.Context) {

	// 历史 问题: 限制请求体大小防止 OOM（与 config_backup.go limitConfigImportBody 一致策略）。
	const maxCreateRuleBodyBytes int64 = 1 << 20 // 1MB
	if c.Request.ContentLength > maxCreateRuleBodyBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxCreateRuleBodyBytes)
	// 历史修复: io.ReadAll(c.Request.Body) 在 ShouldBindJSON 之后调用永远读到空。
	// 改为先读原始 body 再放回，确保错误日志能记录到导致解析失败的实际请求内容。
	rawBody, readErr := io.ReadAll(c.Request.Body)
	c.Request.Body = io.NopCloser(bytes.NewReader(rawBody))
	// 历史问题(历史):MaxBytesReader 截断(chunked/未知 ContentLength 时快路径
	// 不触发)映射 413,与 PutCaddyConfig/导入路径同口径——预读会吞掉
	// MaxBytesError 让 bind 落在「unexpected EOF」的 400 上,须在预读处判。
	if isRequestBodyTooLarge(readErr) {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	var req models.CreateRuleRequest
	// ShouldBindBodyWith（缓存请求体）供 历史修复 的 weight 省略探针二次解码。
	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		// 历史 问题 / ：畸形 JSON 的请求体可能含
		// tls_key/tls_cert/password，运行日志对所有登录用户可读——原实现
		// 只截 512B 仍把密钥前缀写入日志。改为只记录结构性元信息，正文
		// 一律不落日志。
		services.Logf("error", "CreateRule bind error: %v, body_length: %d, content_type: %s（请求体正文不记录，避免证书/密钥泄漏）",
			err, len(rawBody), c.GetHeader("Content-Type"))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("Invalid request: %v", err)})
		return
	}

	// 历史修复 省略 weight 的上游行落默认 1（显式 0 由写侧校验 400）。
	applyOmittedUpstreamWeightDefaults(c, req.Upstreams)

	// 与 UpdateRule/DeleteRule 同一锁序：先 caddyOpMu 后 DB，冲突检查与写入串行化
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	services.Logf("info", "CreateRule bind success: name=%s, protocol=%s, port=%d, upstreams=%d", req.Name, req.Protocol, req.ListenPort, len(req.Upstreams))

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称不能为空"})
		return
	}
	// 规则文本长度上限：name/description 长度门（DDL 声明值，SQLite 不强制）。
	if err := validateRuleTextLengths(req.Name, req.Description); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if req.Protocol == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "协议不能为空"})
		return
	}
	// When TLS is enabled for HTTP, default the listen port to 443 unless the user explicitly set another port.
	if req.Protocol == "http" && req.EnableTLS && req.ListenPort == 0 {
		req.ListenPort = 443
	}

	if req.ListenPort <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "监听端口必须大于 0"})
		return
	}

	if len(req.Upstreams) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "至少需要一个上游服务器"})
		return
	}

	// 历史问题 CreateRule 补 历史修复 归一（历史问题 五层入口漏掉的第 5 个）——
	// TCP 规则不终结入站 TLS，保留 enable_tls=1 落库成死形态行（tcp+acme 组合
	// 还会产生永不消费证书的僵尸续签任务）。与 UpdateRule 归一分支同语义。
	// 历史修复（历史）：归一前移至全部 TLS 相关校验（来源白名单/手动证书
	// 材料/ACME 域名形状）之前——归一后 EnableTLS=false，校验自然跳过；此前
	// TCP+enable_tls:true+空/bogus tls_source 创建恒 400 而同形态更新放行 200。
	// 历史修复（历史）+ 历史问题（历史）：HTTP 专属死配置字段（含
	// tls_http_redirect/domain/upstream_force_http1）经同一 tcpDeadFieldReset
	// 清单弃置——TCP 渲染零消费（buildTCPServer/buildTCPProxyRoute grep 实证），
	// 携带即归一 0，不随快照/导出/复制放大。NTLM 兼容是清单的唯一例外：
	// TCP 创建携带 ntlm_compatible=1 由保存门（validateRuleFeatures）显式 400
	// 拒绝，不做静默弃置（2026-10-12 定稿），故 create 适配器不提供该字段。
	if req.Protocol == "tcp" {
		tcpDeadFieldReset(req.Protocol, createRuleTCPDeadFields(&req))
	} else if req.Protocol == "http" {
		// 历史问题：HTTP 渲染不消费 TCP-only 字段，创建时显式弃置。
		req.TCPProxyProtocol = false
		req.TCPHealthCheckPort = 0
	}

	if req.Protocol == "http" && strings.TrimSpace(req.Domain) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "HTTP/HTTPS 规则的域名不能为空"})
		return
	}
	if req.Protocol == "http" && req.Domain != "" {
		canonicalDomain, err := db.CanonicalDomains(req.Domain)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名格式无效"})
			return
		}
		req.Domain = canonicalDomain
	}
	if req.EnableTLS && req.TLSSource == "acme_dns" && req.Domain != "" {
		if err := services.ValidateACMEDomains(req.Domain); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// TCP 渲染零消费 DnsFamily；协议切换路径会清空该列。仅 HTTP 新规则补
	// 默认，避免同一 TCP 终态出现 ipv4/'' 两种形态（历史）。
	if req.Protocol == "http" && req.DnsFamily == "" {
		req.DnsFamily = "ipv4"
	}

	// 历史修复：创建即禁用（enabled 显式 false）跳过冲突门——禁用规则不渲染、
	// 零冲突（UI 复制向导按预览「禁用」态创建副本，旧码被下方域名/端口门恒
	// 400）；启用方向由 EnableRule 既有二次门把守（与 DuplicateRule 无门、
	// UpdateRule 启用方向检查同构）。enabled=true/缺省的创建行为完全不变。
	creatingDisabled := req.Enabled != nil && !*req.Enabled

	if err := h.validateRuleListenPortForSave(req.Protocol, req.ListenPort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if !creatingDisabled {
		if err := h.validatePortFromDB(req.Protocol, req.ListenPort, ""); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// Domain uniqueness: HTTP/HTTPS rules cannot share the same domain.
	if req.Protocol == "http" && req.Domain != "" && !creatingDisabled {
		existing, err := enabledRuleDomainConflict(req.Domain, req.ListenPort, "")
		if err != nil {
			services.Logf("error", "CreateRule domain conflict query failed for domain=%s: %v", req.Domain, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if existing {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名已被其他 HTTP/HTTPS 规则使用"})
			return
		}
		shadowRule, shadowDomain, err := queryRedirectShadowConflict(req.Domain, req.ListenPort, req.EnableTLS, req.TLSHTTPRedirect, "")
		if err != nil {
			services.Logf("error", "CreateRule redirect shadow query failed for domain=%s: %v", req.Domain, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if shadowRule != "" {
			if req.ListenPort == 80 {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被规则 %s 的 HTTPS 跳转占用（跳转在 80 端口优先生效，保存后本规则将不可达）", shadowDomain, shadowRule)})
			} else {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已有规则 %s 直接监听 80 端口，开启 HTTP 转 HTTPS 跳转会使其不可达，请先调整该规则", shadowDomain, shadowRule)})
			}
			return
		}
	}
	if req.Strategy == "" {
		req.Strategy = "weighted_round_robin"
	}
	// 库值唯一真相（批 1+2）：健康检查 interval/timeout 为类型①值型列——
	// 0→10/2 的写侧静默归一废除（0 由 validateRulePayloadBeforeSave 的 <1
	// 边界 400；前端表单初值=默认，清空提交被拦）。
	// 历史问题：手动证书模式不消费 acme_config_id（签发/渲染均按 tls_source
	// 分流）——清理跨模式死引用，避免随导出/快照放大不可达配置。
	if req.TLSSource == "manual" {
		req.ACMEConfigID = 0
	}
	// 历史修复（历史）：生效来源非 manual 时一律弃置证书材料——API/MCP/导入
	// 给 acme 行携带 tls_cert/tls_key 时私钥正文会随导出/备份/快照放大（渲染
	// 按 tls_source 分流零消费）。与 UpdateRule 的对称清理同口径。
	if req.TLSSource != "manual" {
		req.TLSCert, req.TLSKey = "", ""
	}
	// Validate TLS certificate if provided (manual source only)
	var certWarnings []string
	if req.EnableTLS && req.TLSSource == "manual" {
		if strings.TrimSpace(req.TLSCert) == "" || strings.TrimSpace(req.TLSKey) == "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "手动证书模式下必须提供 TLS 证书和私钥"})
			return
		}
		if err := validateTLSCertificate(req.TLSCert, req.TLSKey); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS 证书校验失败: " + err.Error()})
			return
		}
		// 链完整性/域名覆盖质量警告(不阻断)——配对合法性仍由上方
		// validateTLSCertificate 硬校验;警告随成功审计留痕(与导入侧同格)。
		certWarnings = tlsCertificateWarnings(req.TLSCert, req.TLSKey, req.Domain)
		for _, warning := range certWarnings {
			services.Logf("warn", "CreateRule manual TLS certificate warning (rule %s, domain %s): %s", req.Name, req.Domain, warning)
		}
	}

	// gzip 默认仅 http 注入——TCP 归一（创建头部）已清零
	// CompressTypes，此处不重建死配置（压缩是 HTTP 渲染语义）。
	if req.Protocol != "tcp" && req.CompressTypes == "" {
		req.CompressTypes = "gzip"
	}

	if req.UpstreamKeepaliveTimeout < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "上游 keepalive 超时不能为负数"})
		return
	}
	if req.ServerTokensHidden < 0 || req.ServerTokensHidden > 2 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "server_tokens_hidden 必须为 0、1 或 2"})
		return
	}
	features := createRuleFeatures(req)
	if err := validateRuleFeatures(features); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 后端字段层校验（三层校验第 2 层；Caddy 层由 applyFromTxNote 的 CLI 预检
	// + 事务内应用承担，裁定 2026-09-06 ④'）。历史修复（历史）：本门同时
	// 承担 tls_source 白名单与请求体上限——Create/Update 入口的同款本地检查
	// 已删除（单源，杜绝两处文案/边界漂移）。
	if err := h.validateRulePayloadBeforeSave(req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 历史问题:同端口 TLS/明文混布拦截(创建方向)。历史修复：创建即禁用
	// 同样跳过——禁用规则不进入监听器渲染，启用方向由 EnableRule 同函数把守。
	if req.Protocol == "http" && !creatingDisabled {
		if err := checkPortTLSMix("", req.ListenPort, req.EnableTLS); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	userIDInt := contextUserID(c)

	// Generate caddy_id for @id-based management
	caddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则 ID 失败"})
		return
	}

	// 运行配置快照：仅用于事务内应用失败的恢复（裁定 ④'：保存路径无预校验
	// 探针，快照摄取时点不再受副作用约束；Caddy 级校验由 applyFromTxNote 内
	// 的 CLI 层承担）。
	runtimeSnapshot, snapErr := h.snapshotImportRuntime([]string{caddyID})
	if snapErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败"})
		return
	}
	if req.Protocol == "http" && req.EnableTLS && req.TLSSource == "acme_dns" {
		resolvedCAProviderID, resolveErr := services.ResolveCAProviderID(req.CAProviderID)
		if resolveErr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析 CA 提供商失败: " + resolveErr.Error()})
			return
		}
		req.CAProviderID = resolvedCAProviderID
	} else {
		req.CAProviderID = 0
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败: " + err.Error()})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "CreateRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()

	// enabled 指针化落库——缺省=创建即启用（历史行为），显式 false=禁用
	//（UI 复制向导按预览「禁用」态创建副本）。
	enabledVal := 1
	if req.Enabled != nil && !*req.Enabled {
		enabledVal = 0
	}

	// 历史问题：INSERT 列清单与值投影走唯一事实源（services.LbRuleInsertSQL/
	// LbRuleInsertArgs）——新建排除 id/created_at/updated_by（主键自增分配、
	// created_at 走 schema 默认、updated_by 留 NULL 待首次更新），列形态与
	// 复制/集群镜像/快照导出同源自此结构性保证。
	rule := models.LbRule{
		CaddyID: caddyID, Name: req.Name, Description: req.Description, Protocol: req.Protocol,
		Domain: req.Domain, ListenPort: req.ListenPort, Strategy: req.Strategy,
		DynamicDNS: req.DynamicDNS, EnableDnsServer: req.EnableDnsServer, DnsServer: req.DnsServer, DnsFamily: req.DnsFamily,
		HealthCheckPath: req.HealthCheckPath, HealthCheckInterval: req.HealthCheckInterval, HealthCheckTimeout: req.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold: req.HealthCheckUnhealthyThreshold, HealthCheckHealthyThreshold: req.HealthCheckHealthyThreshold,
		EnableActiveHealthCheck: req.EnableActiveHealthCheck, TCPHealthCheckPort: req.TCPHealthCheckPort,
		TCPProxyProtocol: req.TCPProxyProtocol, TCPTryDuration: req.TCPTryDuration, TCPTryInterval: req.TCPTryInterval,
		RequestBodyMaxSizeMB: req.RequestBodyMaxSizeMB, UpstreamKeepaliveTimeout: req.UpstreamKeepaliveTimeout,
		ServerTokensHidden: req.ServerTokensHidden, NTLMCompatible: req.NTLMCompatible, UpstreamForceHTTP1: req.UpstreamForceHTTP1,
		CustomRoutesEnabled: features.CustomRoutesEnabled,
		ProxyDialTimeout:    features.ProxyDialTimeout, ProxyResponseHeaderTimeout: features.ProxyResponseHeaderTimeout,
		ProxyReadTimeout: features.ProxyReadTimeout, ProxyWriteTimeout: features.ProxyWriteTimeout,
		ProxyStreamTimeout: features.ProxyStreamTimeout, ProxyFlushInterval: features.ProxyFlushInterval,
		ProxyStreamCloseDelay: features.ProxyStreamCloseDelay,
		HostHeader:            req.HostHeader, HealthCheckHost: req.HealthCheckHost,
		EnableTLS: req.EnableTLS, TLSSource: req.TLSSource, ACMEConfigID: req.ACMEConfigID, CAProviderID: req.CAProviderID,
		TLSCert: req.TLSCert, TLSKey: req.TLSKey, TLSHTTPRedirect: req.TLSHTTPRedirect,
		EnableCompress: req.EnableCompress, CompressTypes: req.CompressTypes,
		Enabled: enabledVal == 1, LogEnabled: req.LogEnabled, CreatedBy: int(userIDInt),
		UpdatedAt:         models.JSONNullTime{NullTime: sql.NullTime{Time: time.Now().UTC(), Valid: true}},
		BlockPageStage1ID: req.BlockPageStage1ID, BlockPageStage1Status: req.BlockPageStage1Status,
		BlockPageStage3ID: req.BlockPageStage3ID, BlockPageStage3Status: req.BlockPageStage3Status,
	}
	insertColumns := services.LbRuleInsertColumns("id", "created_at", "updated_by")
	_, err = tx.Exec(services.LbRuleInsertSQL(insertColumns), services.LbRuleInsertArgs(&rule, insertColumns)...)

	if err != nil {
		tx.Rollback()
		services.Logf("error", "CreateRule database error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（创建规则）: " + err.Error()})
		return
	}

	for _, u := range req.Upstreams {
		// 历史修复 weight<1 已由 validateRulePayloadBeforeSave 响亮拒绝
		//（0→1 静默归一废除），此处不再兜底归一。
		if u.Protocol == "" {
			if req.Protocol == "tcp" {
				u.Protocol = "tcp"
			} else {
				u.Protocol = "http"
			}
		}
		// 历史问题：非协议族的上游 protocol（如 HTTP 规则携带 tls，此前
		// 静默当 http 处理，与 TCP 行为不对称）已在 validateRulePayloadBeforeSave
		// 显式 400 拒绝——此处 INSERT 只写归一后的合法值。
		_, err = tx.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections, origin_domain)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, false /* dynamic_dns 废弃列：写侧恒 0，渲染只读规则级 */, u.Enabled, u.Protocol, u.MaxConnections, u.OriginDomain)
		if err != nil {
			tx.Rollback()
			services.Logf("error", "CreateRule upstream insert error: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（创建上游服务器）: " + err.Error()})
			return
		}
	}
	if err := replacePathRulesTx(c.Request.Context(), tx, caddyID, features.PathRules); err != nil {
		tx.Rollback()
		services.Logf("error", "CreateRule path_rules replace error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（创建自定义路径规则）: " + err.Error()})
		return
	}

	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_create", caddyID))
	if applyErr != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		h.respondRuleApplyError(c, applyErr, restoreErr, "创建")
		return
	}
	if err := tx.Commit(); err != nil {
		//  + 历史问题：commit 失败与 finishTxApply/UpdateConfig
		// 同收口——统一恢复回滚事务、按已提交视图重渲染并 /load，双失败时
		// 仍把已提交字节写回 LKG（restoreImportRuntime 只用运行时快照，恢复
		// /load 失败会让 LKG 滞留未提交内容）。
		restoreErr := h.recoverCommittedViewAfterCommitFailure(tx)
		// 新规则证书文件可能已在事务内渲染时物化——已提交视图不引用该规则，
		// 不回退即为惰性孤儿（历史问题）。
		if certErr := services.RemoveCertFiles(caddyID); certErr != nil {
			restoreErr = errors.Join(restoreErr, certErr)
		}
		services.Logf("error", "CreateRule transaction commit error: %v", err)
		// 提交后失败审计：Explicit 审计策略下提交后失败必须留痕（与
		// respondRuleApplyError / EnableRule failEnableWithStatus 同口径）。
		recordAudit(c, "创建失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), "提交已创建规则事务失败: "+errors.Join(err, restoreErr).Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则失败: " + errors.Join(err, restoreErr).Error()})
		return
	}
	committed = true

	removeCreatedRule := func() error {
		cleanupCtx, cancelCleanup := compensationContext(c.Request.Context())
		defer cancelCleanup()
		cleanupTx, beginErr := db.DB.BeginTx(cleanupCtx, nil)
		if beginErr != nil {
			return fmt.Errorf("开启创建补偿事务: %w", beginErr)
		}
		cleanupCommitted := false
		defer func() {
			if !cleanupCommitted {
				// 历史修复 附带（历史）：ErrTxDone 判定统一 errors.Is（与
				// 本文件其余五处回滚守卫同格，裸 != 不穿透包装）。
				if rollbackErr := cleanupTx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
					services.Logf("error", "CreateRule compensation rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
				}
			}
		}()
		for _, statement := range []string{
			"DELETE FROM cert_jobs WHERE rule_id = ?",
			"DELETE FROM security_policy_bindings WHERE rule_caddy_id = ?",
			"DELETE FROM upstreams WHERE rule_id = ?",
			"DELETE FROM path_rules WHERE rule_id = ?",
			"DELETE FROM lb_rules WHERE caddy_id = ?",
		} {
			if _, cleanupErr := cleanupTx.ExecContext(cleanupCtx, statement, caddyID); cleanupErr != nil {
				return fmt.Errorf("补偿删除已创建规则: %w", cleanupErr)
			}
		}
		if commitErr := cleanupTx.Commit(); commitErr != nil {
			return fmt.Errorf("提交创建补偿事务: %w", commitErr)
		}
		cleanupCommitted = true
		services.RemoveCertFiles(caddyID)
		return nil
	}
	restoreCreatedRule := func() error {
		return errors.Join(h.restoreImportRuntime(runtimeSnapshot), removeCreatedRule())
	}
	if enabledVal == 1 && req.EnableTLS && req.TLSSource == "acme_dns" && req.Protocol == "http" && req.Domain != "" {
		qm := services.GetCAQueueManager()
		if qm == nil {
			restoreErr := restoreCreatedRule()
			if restoreErr != nil {
				services.Logf("error", "问题: CreateRule ACME compensation failed for caddy_id=%s: %v", caddyID, restoreErr)
			}
			// 提交后失败审计：提交后失败（含补偿）必须落操作审计。
			detail := "证书任务入队失败：CA 队列未初始化，已回滚创建"
			if restoreErr != nil {
				detail = "证书任务入队失败（CA 队列未初始化），补偿恢复失败: " + restoreErr.Error()
			}
			recordAudit(c, "创建失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化"})
			return
		}
		if _, err := services.CreateOrRequeueCertJob(caddyID, req.Domain, req.CAProviderID, qm); err != nil {
			restoreErr := restoreCreatedRule()
			if restoreErr != nil {
				services.Logf("error", "问题: CreateRule ACME compensation failed for caddy_id=%s: %v", caddyID, restoreErr)
			}
			// 提交后失败审计：入队失败 + 补偿结果一并留痕（补偿失败时点名）。
			detail := "证书任务入队失败，已回滚创建: " + err.Error()
			if restoreErr != nil {
				detail = "证书任务入队失败，补偿恢复失败: " + errors.Join(err, restoreErr).Error()
			}
			recordAudit(c, "创建失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
			// 历史问题-05：证书签发任务未运行（队列 paused/inactive）与手工签发
			// 同口径 409，不再折成 500 误报内部故障。
			status, message := certEnqueueErrorResponse("创建证书任务失败", err)
			c.JSON(status, models.APIResponse{Code: status, Message: message})
			return
		}
	}

	services.Logf("info", "Rule created with caddy_id=%s", caddyID)
	createAuditParts := []string{services.AuditRulePart(caddyID), req.Name, fmt.Sprintf("协议：%s", req.Protocol), fmt.Sprintf("端口：%d", req.ListenPort), req.Domain}
	if len(certWarnings) > 0 {
		// 证书链/域名警告随成功审计留痕(不阻断)。
		createAuditParts = append(createAuditParts, "证书警告："+strings.Join(certWarnings, "；"))
	}
	recordAudit(c, "创建", "负载规则", services.FormatAuditDetail(createAuditParts...))
	reloadNote()
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "规则已创建", Data: gin.H{"caddy_id": caddyID}})
}

// certEnqueueErrorResponse 证书任务入队失败的状态/文案单源（历史问题-05）：
// 证书签发任务未运行（队列 paused/inactive）→ 409 点名可操作原因，与手工
// 签发端点同口径；历史修复（历史）：规则当前态守卫拒绝（服务层
// ErrCertRuleStateConflict——并发禁用/改域/删除，services/certificates.go
// 明确要求 handler 409、不得折成 500）同样映射 409；其余内部失败维持 500。
func certEnqueueErrorResponse(prefix string, err error) (int, string) {
	if errors.Is(err, services.ErrCertificateQueueInactive) {
		return http.StatusConflict, prefix + "：证书签发任务已停止，请先在任务监控中恢复后再试（" + err.Error() + "）"
	}
	if errors.Is(err, services.ErrCertRuleStateConflict) {
		return http.StatusConflict, prefix + "：规则状态已变更，请刷新后重试（" + err.Error() + "）"
	}
	return http.StatusInternalServerError, prefix + ": " + err.Error()
}

// retireOldDomainCertJobOrAudit 历史修复（历史）：UpdateRule 域名迁移
// 三失败分支（事务开启/UPDATE/commit 失败）的「退役旧域任务 + 退役失败补
// 审计」块逐字三份——收敛为单一 helper，三处只差退役原因/日志相位/审计
// 前缀文案，行为零变化。历史问题：退役失败即旧域任务保持原状（'issued'+PEM
// 行永驻，与 pre-v2 行为等效，fail-safe 但静默），补审计让运维可见。
func retireOldDomainCertJobOrAudit(c *gin.Context, caddyID string, existingRule models.LbRule, reason, logPhase, auditPrefix string) {
	oldCanonical := canonicalACMEDomainForJobLookup(existingRule.Domain)
	if retireErr := retireCertJobsForDomain(db.DB, caddyID, oldCanonical, reversedACMEDomainForm(oldCanonical), reason); retireErr != nil {
		services.Logf("error", "问题: UpdateRule: failed to retire old-domain cert job after %s for caddy_id=%s: %v", logPhase, caddyID, retireErr)
		recordAudit(c, "写入失败", "证书任务", services.FormatAuditDetail(
			services.AuditRulePart(caddyID),
			fmt.Sprintf("%s：%v。旧域任务保持原状，请人工检查", auditPrefix, retireErr),
		))
	}
}

func (h *Handlers) UpdateRule(c *gin.Context) {

	caddyID := c.Param("caddy_id")

	// 历史问题: 与 CreateRule（历史 问题）同口径的请求体上限——UpdateRule
	// 同样携带 tls_cert/tls_key 与 upstreams 数组，缺此门时认证客户端可用超大 body
	// OOM 单进程服务（gin + Caddy 编排 + 证书队列同进程）。
	const maxUpdateRuleBodyBytes int64 = 1 << 20 // 1MB
	if c.Request.ContentLength > maxUpdateRuleBodyBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUpdateRuleBodyBytes)
	var req models.UpdateRuleRequest
	// ShouldBindBodyWith（缓存请求体）供 历史修复 的 weight 省略探针二次解码。
	if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
		// 历史问题(历史):MaxBytesReader 超限(chunked/未知长度)映射 413,
		// 与 CreateRule/PutCaddyConfig/导入路径口径一致。
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		services.Logf("error", "UpdateRule bind error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的请求: " + err.Error()})
		return
	}
	// 历史修复 省略 weight 的上游行落默认 1（显式 0 由写侧校验 400）；
	// upstreams 整体省略时 len=0 探针 no-op，合并区保留存量。
	applyOmittedUpstreamWeightDefaults(c, req.Upstreams)
	requestedProtocol := req.Protocol

	// caddyOpMu 必须覆盖 读取→合并→验证→快照→提交→应用→恢复 全程：锁外读取合并时，
	// 并发的成功请求会用旧快照合并值覆盖彼此已提交的字段（丢失更新）。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	services.Logf("debug", "UpdateRule request for caddy_id=%s: enable_tls=%v, tls_source=%s, ca_provider_id=%v, cert_len=%d, key_len=%d",
		caddyID, derefBool(req.EnableTLS), req.TLSSource, func() interface{} {
			if req.CAProviderID == nil {
				return "<nil>"
			}
			return *req.CAProviderID
		}(), len(req.TLSCert), len(req.TLSKey))

	// 443 默认只属于「新建」。此处若在读到存量之前就
	// 把省略的 listen_port 填成 443，下方 `req.ListenPort == 0` 的存量合并在
	// 结构上永不生效——API/MCP 的部分更新（update_rule 明确允许省略字段）
	// 会把 8443/8080 的规则静默迁到 443，且旧端口的占用/混布校验被整体跳过。
	// 默认改到合并之后：存量端口优先，仅在合并后仍为 0（理论上不可达）时兜底。

	// Fill in missing fields from database so validation and the update use complete data.
	var existingRule models.LbRule
	err := db.DB.QueryRow(`
		SELECT COALESCE(protocol,''), COALESCE(domain,''), listen_port, COALESCE(strategy,'weighted_round_robin'),
			COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0),
			COALESCE(ca_provider_id,0),
			COALESCE(enable_tls,0), COALESCE(tls_http_redirect,0),
			COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
			COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,2),
			COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
			COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
	COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0), COALESCE(ntlm_compatible,0), COALESCE(upstream_force_http1,0),
		COALESCE(custom_routes_enabled,0),
		COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
		COALESCE(host_header,''), COALESCE(health_check_host,''), COALESCE(enable_compress,0), COALESCE(compress_types,'gzip'),
		IIF(enabled IN ('1',1),1,0), COALESCE(log_enabled,0), name, description
	FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(
		&existingRule.Protocol, &existingRule.Domain, &existingRule.ListenPort, &existingRule.Strategy,
		&existingRule.TLSCert, &existingRule.TLSKey, &existingRule.TLSSource, &existingRule.ACMEConfigID,
		&existingRule.CAProviderID,
		&existingRule.EnableTLS, &existingRule.TLSHTTPRedirect,
		&existingRule.DynamicDNS, &existingRule.EnableDnsServer, &existingRule.DnsServer, &existingRule.DnsFamily,
		&existingRule.HealthCheckPath, &existingRule.HealthCheckInterval, &existingRule.HealthCheckTimeout,
		&existingRule.HealthCheckUnhealthyThreshold, &existingRule.HealthCheckHealthyThreshold,
		&existingRule.EnableActiveHealthCheck, &existingRule.TCPHealthCheckPort, &existingRule.TCPProxyProtocol, &existingRule.TCPTryDuration, &existingRule.TCPTryInterval,
		&existingRule.RequestBodyMaxSizeMB, &existingRule.UpstreamKeepaliveTimeout, &existingRule.ServerTokensHidden, &existingRule.NTLMCompatible, &existingRule.UpstreamForceHTTP1,
		&existingRule.CustomRoutesEnabled,
		&existingRule.ProxyDialTimeout, &existingRule.ProxyResponseHeaderTimeout, &existingRule.ProxyReadTimeout, &existingRule.ProxyWriteTimeout, &existingRule.ProxyStreamTimeout, &existingRule.ProxyFlushInterval, &existingRule.ProxyStreamCloseDelay,
		&existingRule.HostHeader, &existingRule.HealthCheckHost, &existingRule.EnableCompress, &existingRule.CompressTypes,
		&existingRule.Enabled, &existingRule.LogEnabled, &existingRule.Name, &existingRule.Description)
	if err != nil {
		// 历史问题:分判 ErrNoRows 与真实 DB 故障(同 EnableRule 口径)——
		// 此前任意 DB 错误误报 404「规则不存在」误导排障。
		if dbQueryNotFound(c, err, "规则不存在", "读取规则") {
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	existingRule.PathRules, err = db.LoadPathRules(c.Request.Context(), db.DB, caddyID)
	if err != nil {
		services.Logf("error", "UpdateRule failed to load path_rules for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自定义路径规则失败"})
		return
	}

	// Capture old upstreams for potential DB rollback.
	// 历史问题: 存量 upstreams.enabled 无 NOT NULL，NULL 行裸 scan 进 bool 会 500；
	// IIF 与生成侧（services/caddy.go）同口径：NULL 视同禁用，回写/回滚保持同一有效状态。
	var oldUpstreams []models.Upstream
	oldUpstreamRows, err := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0), IIF(enabled IN ('1',1),1,0), COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(origin_domain,'') FROM upstreams WHERE rule_id = ?", caddyID)
	if err != nil {
		services.Logf("error", "UpdateRule failed to read existing upstreams for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
		return
	}
	for oldUpstreamRows.Next() {
		var u models.Upstream
		if err := oldUpstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.OriginDomain); err != nil {
			if closeErr := oldUpstreamRows.Close(); closeErr != nil {
				services.Logf("error", "UpdateRule failed to close existing upstream cursor for caddy_id=%s: %v", caddyID, closeErr)
			}
			services.Logf("error", "UpdateRule failed to scan existing upstream for caddy_id=%s: %v", caddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
			return
		}
		oldUpstreams = append(oldUpstreams, u)
	}
	if err := oldUpstreamRows.Err(); err != nil {
		if closeErr := oldUpstreamRows.Close(); closeErr != nil {
			services.Logf("error", "UpdateRule failed to close existing upstream cursor for caddy_id=%s: %v", caddyID, closeErr)
		}
		services.Logf("error", "UpdateRule existing upstream cursor failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
		return
	}
	if err := oldUpstreamRows.Close(); err != nil {
		services.Logf("error", "UpdateRule failed to close existing upstream cursor for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取现有上游服务器失败"})
		return
	}

	// Use existing values for fields not provided in request
	if req.Protocol == "" {
		req.Protocol = existingRule.Protocol
	}
	if req.Domain == "" {
		req.Domain = existingRule.Domain
	}
	if req.ListenPort == 0 {
		req.ListenPort = existingRule.ListenPort
	}
	// F10：删除「合并后仍为 0 再填 443」的兜底——existingRule.listen_port 为
	// NOT NULL，合并后为 0 不可达（死代码）；合并后仍为 0 走下方
	// 「监听端口必须大于 0」显性拒绝，不再静默改端口。
	if req.Strategy == "" {
		req.Strategy = existingRule.Strategy
	}
	if req.TLSSource == "" {
		req.TLSSource = existingRule.TLSSource
	}
	if req.ACMEConfigID == 0 {
		req.ACMEConfigID = existingRule.ACMEConfigID
	}
	// 历史问题：手动证书模式同格清理残留 ACME 配置引用（存量导入/旧版本
	// 行可携带 acme_config_id 而 tls_source=manual；渲染/签发零消费）。必须在
	// validateRulePayloadBeforeSave 之前——否则残留引用指向已删除配置时，
	// 编辑会被不存在的 ACME 引用门 400 卡死，清理永远不可达。
	if req.TLSSource == "manual" {
		req.ACMEConfigID = 0
	}
	// 历史问题（写侧）：nil=保留现值先合并，validateRulePayloadBeforeSave
	// 才能对合并后的生效值做存在性校验（与上方 acme_config_id 同口径）。
	if req.CAProviderID == nil {
		req.CAProviderID = &existingRule.CAProviderID
	}
	if req.HealthCheckPath == nil {
		req.HealthCheckPath = &existingRule.HealthCheckPath
	}
	// 非 nil=沿用存量（0=未提供的 API 编码，非显式零值）先合并——合并后的
	// 生效值经 validateRulePayloadBeforeSave 的 <1 边界校验（库值唯一真相批 1+2：
	// 类型①值型列落库恒有效，渲染零兜底）。指针阈值列 nil=沿用存量、显式 0
	// 直达 <1 门 400。
	if req.HealthCheckInterval == 0 {
		req.HealthCheckInterval = existingRule.HealthCheckInterval
	}
	if req.HealthCheckTimeout == 0 {
		req.HealthCheckTimeout = existingRule.HealthCheckTimeout
	}
	if req.HealthCheckUnhealthyThreshold == nil {
		req.HealthCheckUnhealthyThreshold = &existingRule.HealthCheckUnhealthyThreshold
	}
	if req.HealthCheckHealthyThreshold == nil {
		req.HealthCheckHealthyThreshold = &existingRule.HealthCheckHealthyThreshold
	}
	// 历史修复（历史修复 口径）：nil=沿用存量，显式 0=真实零值（0=不重试/默认间隔/
	// 跟随上游端口均有消费语义，此前非指针合并使显式清零永不可达）。
	// 历史问题（历史）：合并前先记录请求是否显式提供——显式越界必须 400
	// （交 validateRuleFeatures 上界门，错误点名字段），只有存量/导入/直改
	// DB 的越界值允许随编辑自愈。
	tcpTryDurationProvided := req.TCPTryDuration != nil
	tcpTryIntervalProvided := req.TCPTryInterval != nil
	if req.TCPHealthCheckPort == nil {
		req.TCPHealthCheckPort = &existingRule.TCPHealthCheckPort
	}
	if req.TCPTryDuration == nil {
		req.TCPTryDuration = &existingRule.TCPTryDuration
	}
	if req.TCPTryInterval == nil {
		req.TCPTryInterval = &existingRule.TCPTryInterval
	}
	// 历史修复（历史）：重试窗口上界自愈——仅存量/导入/直改 DB 行携带
	// >60000 的越界值随任意编辑归零（0=默认窗口），避免命中新增上界门 400
	// 死端（与 历史修复 负值自愈同格；http 侧 td=-1 是 NTLM 接管态合法哨兵，
	// 不在本门，TCP 侧负值由下方 TCP 块按 历史修复 归零）。
	if !tcpTryDurationProvided && *req.TCPTryDuration > 60000 {
		upperZero := 0
		req.TCPTryDuration = &upperZero
	}
	if !tcpTryIntervalProvided && *req.TCPTryInterval > 60000 {
		upperZero := 0
		req.TCPTryInterval = &upperZero
		// 历史问题：interval 是 duration>0 时的渲染必填值（caddy.go 两处
		// 渲染门：td>0 && ti<=0 直接生成失败）——interval 越界归零后
		// duration 不得残留正值，否则保存成功但配置生成必败（自相矛盾）。
		if *req.TCPTryDuration > 0 {
			req.TCPTryDuration = &upperZero
		}
	}
	if req.RequestBodyMaxSizeMB == nil {
		req.RequestBodyMaxSizeMB = &existingRule.RequestBodyMaxSizeMB
	}
	if req.UpstreamKeepaliveTimeout == nil {
		req.UpstreamKeepaliveTimeout = &existingRule.UpstreamKeepaliveTimeout
	}
	if req.ServerTokensHidden == nil {
		req.ServerTokensHidden = &existingRule.ServerTokensHidden
	}
	if req.NTLMCompatible == nil {
		req.NTLMCompatible = &existingRule.NTLMCompatible
	}
	if req.UpstreamForceHTTP1 == nil {
		req.UpstreamForceHTTP1 = &existingRule.UpstreamForceHTTP1
	}
	if req.DynamicDNS == nil {
		req.DynamicDNS = &existingRule.DynamicDNS
	}
	if req.EnableDnsServer == nil {
		req.EnableDnsServer = &existingRule.EnableDnsServer
	}
	if req.EnableActiveHealthCheck == nil {
		req.EnableActiveHealthCheck = &existingRule.EnableActiveHealthCheck
	}
	if req.TCPProxyProtocol == nil {
		req.TCPProxyProtocol = &existingRule.TCPProxyProtocol
	}
	if req.EnableTLS == nil {
		req.EnableTLS = &existingRule.EnableTLS
	}
	if req.TLSHTTPRedirect == nil {
		req.TLSHTTPRedirect = &existingRule.TLSHTTPRedirect
	}
	if req.EnableCompress == nil {
		req.EnableCompress = &existingRule.EnableCompress
	}
	if req.Enabled == nil {
		req.Enabled = &existingRule.Enabled
	}
	if req.LogEnabled == nil {
		req.LogEnabled = &existingRule.LogEnabled
	}
	if req.CompressTypes == "" {
		req.CompressTypes = existingRule.CompressTypes
	}
	if req.DnsServer == nil {
		req.DnsServer = &existingRule.DnsServer
	}
	if req.DnsFamily == "" {
		req.DnsFamily = existingRule.DnsFamily
	}
	if req.HostHeader == nil {
		req.HostHeader = &existingRule.HostHeader
	}
	if req.HealthCheckHost == nil {
		req.HealthCheckHost = &existingRule.HealthCheckHost
	}
	if req.Name == "" {
		req.Name = existingRule.Name
	}
	if req.Description == nil {
		req.Description = &existingRule.Description
	}
	// 规则文本长度上限：合并后的 name/description 长度门（DDL 声明值）。
	if err := validateRuleTextLengths(req.Name, *req.Description); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	protocolChanged := requestedProtocol != "" && requestedProtocol != existingRule.Protocol

	if protocolChanged {
		zero, disabled, empty := 0, false, ""
		switch req.Protocol {
		case "tcp":
			if req.Strategy == "cookie" {
				req.Strategy = "weighted_round_robin"
			}
			// 历史问题：HTTP 专属死配置字段统一由下方最终协议 tcp 块的
			// tcpDeadFieldReset 清单处置（这里只保留协议形态切换自身需要的
			// 归一：路径规则/代理超时/DNS——它们由 validateRuleFeatures 对
			// tcp 显式拒绝，不属静默弃置清单）。
			req.CustomRoutesEnabled = &disabled
			emptyPathRules := []models.PathRule{}
			req.PathRules = &emptyPathRules
			req.ProxyDialTimeout = &zero
			req.ProxyResponseHeaderTimeout = &zero
			req.ProxyReadTimeout = &zero
			req.ProxyWriteTimeout = &zero
			req.ProxyStreamTimeout = &zero
			req.ProxyFlushInterval = &zero
			req.ProxyStreamCloseDelay = &zero
			// 历史问题:DNS 动态上游是 HTTP 语义,切换即清零(dynamic_dns 残留
			// 会让 validateRuleFeatures 恒拒协议切换,且永不消费的脏配置随
			// 快照/导出放大)。
			req.DynamicDNS = &disabled
			req.EnableDnsServer = &disabled
			req.DnsServer = &empty
			req.DnsFamily = ""
			req.HealthCheckHost = &empty
		case "http":
			// TCP 三字段已指针化，切回 http 时以显式零指针清理。
			req.TCPHealthCheckPort = &zero
			req.TCPProxyProtocol = &disabled
			req.TCPTryDuration = &zero
			req.TCPTryInterval = &zero
			// 历史问题(历史):回切 http 恢复 dns_family 默认(与 CreateRule
			// :758-760 同口径)——切 TCP 已清零(:1337),存量 '' 直接落库会让
			// DB 终态与创建态分叉(读路径 COALESCE 兜底,快照/导出携带脏空值)。
			if req.DnsFamily == "" {
				req.DnsFamily = "ipv4"
			}
		}
	}
	// 历史问题: 最终协议为 tcp 时一律归一 TLS 字段（与上方切换到 TCP 的分支同
	// 语义）——存量 v1 导入可能携带 enable_tls=1 + 空 manual 证书的死形态（渲染
	// 忽略，但下方非协议门控的手动证书检查会让该规则任何编辑恒 400，UI 又对 TCP
	// 隐藏 TLS 开关而无自救路径）；协议未变的 tcp 编辑在此顺带自愈。
	// 历史问题（历史）：HTTP 专属死配置字段族（host_header/health_check_path/
	// enable_compress/compress_types/request_body_max_size_mb/
	// upstream_keepalive_timeout/server_tokens_hidden/ntlm_compatible/
	// upstream_force_http1/tls_http_redirect/domain/TLS 族/阶段页）统一经
	// tcpDeadFieldReset 清单弃置——与 CreateRule/DuplicateRule 共用同一清单。
	if req.Protocol == "tcp" {
		tcpZero := 0
		// 阶段页四列在 UpdateRule 是「仅非 nil 才写库」的指针语义——TCP 归一
		// 必须显式提供零值指针，否则协议切换/同协议编辑不会把存量非零值落库
		// 归零（tcpDeadFieldReset 对 nil 目标跳过）。
		if req.BlockPageStage1ID == nil {
			req.BlockPageStage1ID = &tcpZero
		}
		if req.BlockPageStage1Status == nil {
			req.BlockPageStage1Status = &tcpZero
		}
		if req.BlockPageStage3ID == nil {
			req.BlockPageStage3ID = &tcpZero
		}
		if req.BlockPageStage3Status == nil {
			req.BlockPageStage3Status = &tcpZero
		}
		// 历史问题：log_enabled 仅 HTTP 渲染消费（logger_names 按协议门控）——
		// 指针合并会把存量 1 带进 TCP 终态，显式补 false 指针使同协议编辑也自愈。
		if req.LogEnabled == nil {
			tcpLogOff := false
			req.LogEnabled = &tcpLogOff
		}
		// TCP 自愈族：代理超时族/自定义路径同协议编辑自愈——这些字段
		// 在 UpdateRule 是「仅非 nil 才写库」的指针语义，nil 合并会沿用存量
		// 死值并喂进 validateRuleFeatures TCP 分支，使任何无关编辑恒 400
		// 死端（存量 v1 导入/直改 DB 行携带）。显式补零指针：与协议切换块
		// 同口径（TCP 终态不携带这些 HTTP 专属配置）；path_rules 由指针填充
		// 为空集后经 replacePathRulesTx 删除存量行。
		for _, target := range []**int{
			&req.ProxyDialTimeout, &req.ProxyResponseHeaderTimeout,
			&req.ProxyReadTimeout, &req.ProxyWriteTimeout,
			&req.ProxyStreamTimeout, &req.ProxyFlushInterval,
			&req.ProxyStreamCloseDelay,
		} {
			if *target == nil {
				*target = &tcpZero
			}
		}
		if req.CustomRoutesEnabled == nil {
			tcpRoutesOff := false
			req.CustomRoutesEnabled = &tcpRoutesOff
		}
		if req.PathRules == nil {
			emptyPathRules := []models.PathRule{}
			req.PathRules = &emptyPathRules
		}
		tcpDeadFieldReset(req.Protocol, updateRuleTCPDeadFields(&req))
		// 历史修复（历史）：重试窗口是 http/tcp 共用字段（方案 C），http 侧
		// -1=NTLM 接管态合法；指针合并（nil=沿用存量）会把存量 -1 带进 TCP
		// 值域门（rule_features.go TCP 分支拒负值）——切换与同协议编辑双路径
		// 均命中 400 死端，错误指向用户从未提交的字段。负值一律自愈归零
		// （TCP 语义：0 与 -1 均为零窗口=不重试；5s 默认窗口仅属 HTTP）；
		// 非负值尊重 历史修复 指针合并契约（nil=沿用存量/
		// 显式值=尊重输入，rules_lb_fixes_test 钉测）——不可无条件归零。
		if req.TCPTryDuration != nil && *req.TCPTryDuration < 0 {
			req.TCPTryDuration = &tcpZero
		}
		if req.TCPTryInterval != nil && *req.TCPTryInterval < 0 {
			req.TCPTryInterval = &tcpZero
		}
	} else if req.Protocol == "http" {
		// 历史问题：HTTP 渲染不消费 TCP-only 字段；同协议编辑也显式清零，
		// 防止历史 TCP→HTTP 残留随快照/导出放大。
		zero, disabled := 0, false
		req.TCPHealthCheckPort = &zero
		req.TCPProxyProtocol = &disabled
	}

	if req.Protocol == "http" && strings.TrimSpace(req.Domain) == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "HTTP/HTTPS 规则的域名不能为空"})
		return
	}
	if req.Protocol == "http" && req.Domain != "" {
		canonicalDomain, err := db.CanonicalDomains(req.Domain)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名格式无效"})
			return
		}
		req.Domain = canonicalDomain
		if req.EnableTLS != nil && *req.EnableTLS && req.TLSSource == "acme_dns" {
			if err := services.ValidateACMEDomains(req.Domain); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
				return
			}
		}
		// 历史问题: existingRule.Domain 可能为导入态非规范化值
		//（"Example.COM"），与规范化后的 req.Domain 比较会误判变更，比较前先做同样规范化。
		existingDomain := existingRule.Domain
		if existingDomain != "" {
			if canonical, err := db.CanonicalDomains(existingDomain); err == nil {
				existingDomain = canonical
			}
		}
		// 历史问题: 域名冲突检查同样加变更门控——仅当域名/监听端口/启用态相对存量
		// 变化时才执行（enabledRuleDomainConflict 只统计 enabled=1 的规则）。导入遗留的
		// 「一启用一禁用同域名」组合中，禁用方仅改名等无关更新不再被 400 卡死；
		// 启用态变化仍走检查（启用时二次把关，与 enabledRuleDomainConflict 口径一致）。
		// 历史问题: 启用态门控收敛为仅启用方向（*req.Enabled && !existingRule.Enabled）——
		// 禁用方向不渲染、无冲突可言，存量冲突组合（同域名同端口双启用）的禁用操作
		// 不应被 400 误拦（DisableRule 端点本就不查，口径对齐）。
		if req.Domain != existingDomain || req.ListenPort != existingRule.ListenPort || (*req.Enabled && !existingRule.Enabled) {
			existing, err := enabledRuleDomainConflict(req.Domain, req.ListenPort, caddyID)
			if err != nil {
				services.Logf("error", "UpdateRule domain conflict query failed for caddy_id=%s domain=%s: %v", caddyID, req.Domain, err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
				return
			}
			if existing {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名已被其他 HTTP/HTTPS 规则使用"})
				return
			}
		}
		// 历史问题: 仅当域名/监听端口/EnableTLS/TLSHTTPRedirect/Enabled 任一相对存量变化时
		// 执行遮蔽检查（fallback 已把 req 字段填成现值，直接与 existingRule 比较）——
		// 存量冲突组合（导入态 80 规则 + 跳转规则并存）下仅改名称/健康检查不应被 400 阻塞。
		// 历史问题: Enabled 变化也触发——与 EnableRule 端点同口径，禁用规则经 UpdateRule
		// 启用时同样拦截会遮蔽 80 直听规则的跳转组合（shadowRelevantChanged 不含 enabled
		// 时仅提交 {"enabled":true} 会绕过遮蔽检查）。
		// 历史问题: 启用态门控收敛为仅启用方向——禁用方不渲染，遮蔽检查无意义；
		// 存量冲突组合（80 直听启用 + 443 TLS+跳转启用同域名）的禁用操作不应被 400 误拦。
		// 历史问题: 门控再加启用状态前置——仅当「新状态启用 或 原状态启用」时才可能产生
		// 运行时影响。禁用中规则（双方均 disabled）不会被渲染，此时改 TLS/跳转/端口/域名
		// 仍被 400 拦截会阻塞「先改好禁用方配置再启用」的正常流程（启用方向仍会二次把关）。
		// 历史问题: 注意放宽的仅是下方遮蔽检查；上方同域名+同端口冲突门控对禁用规则
		// 仍然 400——该组合永远无法启用（EnableRule 端点同样拦截），编辑期拦截只是
		// 提前报错，属有意保守，勿误读为「禁用规则可随意改域名」。
		shadowRelevantChanged := req.Domain != existingDomain ||
			req.ListenPort != existingRule.ListenPort ||
			*req.EnableTLS != existingRule.EnableTLS ||
			*req.TLSHTTPRedirect != existingRule.TLSHTTPRedirect ||
			(*req.Enabled && !existingRule.Enabled)
		if shadowRelevantChanged && (*req.Enabled || existingRule.Enabled) {
			shadowRule, shadowDomain, err := queryRedirectShadowConflict(req.Domain, req.ListenPort, *req.EnableTLS, *req.TLSHTTPRedirect, caddyID)
			if err != nil {
				services.Logf("error", "UpdateRule redirect shadow query failed for caddy_id=%s domain=%s: %v", caddyID, req.Domain, err)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
				return
			}
			if shadowRule != "" {
				if req.ListenPort == 80 {
					c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被规则 %s 的 HTTPS 跳转占用（跳转在 80 端口优先生效，保存后本规则将不可达）", shadowDomain, shadowRule)})
				} else {
					c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已有规则 %s 直接监听 80 端口，开启 HTTP 转 HTTPS 跳转会使其不可达，请先调整该规则", shadowDomain, shadowRule)})
				}
				return
			}
		}
	}

	// Load existing upstreams if not provided in request
	// 历史问题(历史):nil 判定区分「省略」与「显式空数组」——len==0 会把显式
	// [] 归并进保留存量。显式 []=非合法形态:下游 validateRulePayloadBeforeSave
	// 「至少需要一个上游服务器」(handlers.go)400 拒绝、存量不变(历史问题 注释纠正:
	// 此处曾误称「显式 []=清空,零上游为合法形态」——实际清空路径被 400 拒绝,
	// 历史问题 裁定)。updateRuleFeatures 按调用契约直接消费合并后的 req.Upstreams
	// （历史修复，历史删死分支后不再按 nil 判空）。
	if req.Upstreams == nil {
		req.Upstreams = oldUpstreams
	}
	// 历史问题：同协议 TCP 编辑也必须弃置上游回源域名（HTTP-only
	// 语义）——此前只在 protocolChanged 分支清理，存量残留会在下方
	// validateRulePayloadBeforeSave 命中「回源域名仅 HTTP」400，UI 对 TCP
	// 隐藏该字段，用户无自救路径。协议切换分支的同类清理保留（幂等）。
	if req.Protocol == "tcp" {
		for index := range req.Upstreams {
			req.Upstreams[index].OriginDomain = ""
		}
	}
	if protocolChanged {
		for index := range req.Upstreams {
			switch req.Protocol {
			case "tcp":
				// 历史修复（历史）：回源域名是 HTTP-only 语义——切换即弃置
				//（与 host_header/health_check_host 归零同格），否则隐藏残留字段
				// 被「回源域名仅 HTTP 规则支持」门恒拒，卡死保存。
				req.Upstreams[index].OriginDomain = ""
				switch req.Upstreams[index].Protocol {
				case "", "http":
					req.Upstreams[index].Protocol = "tcp"
				case "https":
					req.Upstreams[index].Protocol = "tls"
				}
			case "http":
				switch req.Upstreams[index].Protocol {
				case "", "tcp":
					req.Upstreams[index].Protocol = "http"
				case "tls":
					req.Upstreams[index].Protocol = "https"
				}
			}
		}
	}

	if req.UpstreamKeepaliveTimeout != nil && *req.UpstreamKeepaliveTimeout < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "上游 keepalive 超时不能为负数"})
		return
	}
	if req.ServerTokensHidden != nil && (*req.ServerTokensHidden < 0 || *req.ServerTokensHidden > 2) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "server_tokens_hidden 必须为 0、1 或 2"})
		return
	}
	features := updateRuleFeatures(req, existingRule)
	features.Protocol = req.Protocol
	if err := validateRuleFeatures(features); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 后端字段层校验（三层校验第 2 层，同 CreateRule，裁定 2026-09-06 ④'）。
	if err := h.validateRulePayloadBeforeSave(req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 历史问题:同端口 TLS/明文混布拦截(更新方向)——nil=保留现值,合并后判定。
	if req.Protocol == "http" {
		effTLS := existingRule.EnableTLS
		if req.EnableTLS != nil {
			effTLS = *req.EnableTLS
		}
		if err := checkPortTLSMix(caddyID, req.ListenPort, effTLS); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// Validate TLS certificate if provided (manual source only)
	var certWarnings []string
	if (*req.EnableTLS || req.TLSCert != "" || req.TLSKey != "") && req.TLSSource == "manual" {
		tlsCert := req.TLSCert
		tlsKey := req.TLSKey
		// 历史问题-1（用户裁定）:从 acme_dns 切换到 manual 时必须提供新的证书
		// 和私钥——不允许静默沿用 ACME 签发的旧证书（用户以为换了新证书，
		// 实际在用旧证书）；仅同为 manual 且未修改证书时允许 DB 回退。
		if existingRule.TLSSource == "acme_dns" {
			if strings.TrimSpace(req.TLSCert) == "" || strings.TrimSpace(req.TLSKey) == "" {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "从自动签发切换到手动模式必须上传或填写新的证书和私钥，不能沿用自动签发的旧证书"})
				return
			}
		} else {
			// If cert/key not provided in request, get from DB (same-mode fallback)
			if tlsCert == "" {
				tlsCert = existingRule.TLSCert
			}
			if tlsKey == "" {
				tlsKey = existingRule.TLSKey
			}
		}
		if *req.EnableTLS && (strings.TrimSpace(tlsCert) == "" || strings.TrimSpace(tlsKey) == "") {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "手动证书模式下必须提供 TLS 证书和私钥"})
			return
		}
		if tlsCert != "" && tlsKey != "" {
			if err := validateTLSCertificate(tlsCert, tlsKey); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS 证书校验失败: " + err.Error()})
				return
			}
			// 链完整性/域名覆盖质量警告(不阻断)——与 CreateRule/导入侧同格,
			// 按生效证书材料与合并后域名评估,警告随成功审计留痕。
			certWarnings = tlsCertificateWarnings(tlsCert, tlsKey, req.Domain)
			for _, warning := range certWarnings {
				services.Logf("warn", "UpdateRule manual TLS certificate warning for caddy_id=%s (domain %s): %s", caddyID, req.Domain, warning)
			}
		}
	}

	// 历史问题：端口类 400 前移至快照/validate 之前（与 CreateRule 的
	// validateRuleListenPortForSave/validatePortFromDB 前置顺序对齐）
	// ——TCP 候选 server 名含端口，validate 经 /load 真实加载会把同端口启用中规则 B
	// 的 server 替换为候选（跨规则流量顶替），此前端口冲突在 validate 之后才拒绝且
	// 无运行配置恢复。前移后该场景在副作用发生前拦截。
	if err := h.validateRuleListenPortForSave(req.Protocol, req.ListenPort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	if err := h.validatePortFromDB(req.Protocol, req.ListenPort, caddyID); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// 历史修复（历史）：PUT enabled=false 与 /disable 同语义，同样在副作用
	// 之前做「执行中签发」快路径 409——此前 UpdateRule 直接进入有界取消等待
	// （最长数分钟）并返回 200，/disable 同场景秒回 409，任务史与行为分叉。
	// 仅拦「执行中」（HasRunningJobForRule）；queued/pending 维持既有语义。
	// 单源判据：updatingToDisabled 同时供事务内 disableCertJobsForRuleTx 使用。
	updatingToDisabled := existingRule.Enabled && !derefBool(req.Enabled) &&
		derefBool(req.EnableTLS) && req.TLSSource == "acme_dns"
	if updatingToDisabled {
		if qm := services.GetCAQueueManager(); qm != nil && qm.HasRunningJobForRule(caddyID) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "该规则有正在进行的证书签发任务（约需几分钟），请任务完成后再禁用或稍后重试"})
			return
		}
	}

	// 运行配置快照：仅用于事务内应用失败的恢复（同 CreateRule，裁定 ④'）。
	runtimeSnapshot, snapErr := h.snapshotImportRuntime([]string{caddyID})
	if snapErr != nil {
		services.Logf("error", "UpdateRule runtime snapshot failed for caddy_id=%s: %v", caddyID, snapErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败"})
		return
	}

	// 历史问题-1: acme→manual 切换时清理 ACME 关联——acme_config_id 清零(渲染层
	// 不再引用 ACME 配置)。在途/排队任务的收敛分两步(历史问题-01，镜像 DisableRule
	// 正确序):事务内先把非终态 cert_jobs 翻转为终态(见下方 tx 内翻转——否则主
	// UPDATE 的 NOT EXISTS 守卫恒 409、queued/waiting_ca 行被 30s 补扫复活重签)，
	// 事务提交后再取消队列在途签发(见 committed 之后的 cancelRuleJobs——提交前
	// 取消会在回滚/重试窗口留下「队列已摘、行仍非终态」的复活态)。
	switchingFromACME := existingRule.TLSSource == "acme_dns" && req.TLSSource == "manual"
	if switchingFromACME {
		req.ACMEConfigID = 0
	}
	// 历史修复（历史）：生效证书来源非 manual 时不保留任何证书材料——
	// manual→acme_dns 此前保留 tls_cert/tls_key（渲染按 tls_source 分流零消费，
	// 但私钥正文长期留在 lb_rules 并随导出/备份/集群快照放大）。与 历史问题-1
	// 「acme→manual 必须重新上传」对称清理。
	clearingTLSMaterial := req.TLSSource != "manual"
	if clearingTLSMaterial {
		req.TLSCert, req.TLSKey = "", ""
	}
	// 历史修复（历史）：生效来源非 acme_dns 时 ca_provider_id 归零（与
	// CreateRule 非 ACME 分支同口径）。此前仅 switchingFromACME / tcp 归零，
	// manual→manual 编辑把存量残留值原样写回；而 ResolveCAProviderID 对非 0
	// 直接返回（不校验存在性），残留死引用会随导出放大并在签发期才暴露。
	if req.TLSSource != "acme_dns" {
		zeroCA := 0
		req.CAProviderID = &zeroCA
	}

	// Build dynamic update for lb_rules table
	query := "UPDATE lb_rules SET "
	var args []interface{}

	query += "name = ?, "
	args = append(args, req.Name)
	query += "description = ?, "
	args = append(args, derefStr(req.Description))
	query += "protocol = ?, "
	args = append(args, req.Protocol)
	query += "domain = ?, "
	args = append(args, req.Domain)
	query += "listen_port = ?, "
	args = append(args, req.ListenPort)
	query += "strategy = ?, "
	args = append(args, req.Strategy)
	query += "dynamic_dns = ?, "
	args = append(args, *req.DynamicDNS)
	query += "enable_dns_server = ?, "
	args = append(args, *req.EnableDnsServer)
	query += "dns_server = ?, "
	args = append(args, derefStr(req.DnsServer))
	query += "dns_family = ?, "
	args = append(args, req.DnsFamily)
	query += "health_check_path = ?, "
	args = append(args, derefStr(req.HealthCheckPath))
	query += "health_check_interval = ?, "
	args = append(args, req.HealthCheckInterval)
	query += "health_check_timeout = ?, "
	args = append(args, req.HealthCheckTimeout)
	query += "health_check_unhealthy_threshold = ?, "
	args = append(args, *req.HealthCheckUnhealthyThreshold)
	query += "health_check_healthy_threshold = ?, "
	args = append(args, *req.HealthCheckHealthyThreshold)
	query += "enable_active_health_check = ?, "
	args = append(args, *req.EnableActiveHealthCheck)
	query += "tcp_health_check_port = ?, "
	args = append(args, *req.TCPHealthCheckPort)
	query += "tcp_proxy_protocol = ?, "
	args = append(args, *req.TCPProxyProtocol)
	query += "tcp_try_duration = ?, "
	args = append(args, *req.TCPTryDuration)
	query += "tcp_try_interval = ?, "
	args = append(args, *req.TCPTryInterval)
	query += "request_body_max_size_mb = ?, "
	args = append(args, *req.RequestBodyMaxSizeMB)
	query += "upstream_keepalive_timeout = ?, "
	args = append(args, *req.UpstreamKeepaliveTimeout)
	query += "server_tokens_hidden = ?, "
	args = append(args, *req.ServerTokensHidden)
	query += "ntlm_compatible = ?, "
	args = append(args, *req.NTLMCompatible)
	query += "upstream_force_http1 = ?, "
	args = append(args, *req.UpstreamForceHTTP1)
	query += "custom_routes_enabled = ?, "
	args = append(args, features.CustomRoutesEnabled)
	query += "proxy_dial_timeout = ?, "
	args = append(args, features.ProxyDialTimeout)
	query += "proxy_response_header_timeout = ?, "
	args = append(args, features.ProxyResponseHeaderTimeout)
	query += "proxy_read_timeout = ?, "
	args = append(args, features.ProxyReadTimeout)
	query += "proxy_write_timeout = ?, "
	args = append(args, features.ProxyWriteTimeout)
	query += "proxy_stream_timeout = ?, "
	args = append(args, features.ProxyStreamTimeout)
	query += "proxy_flush_interval = ?, "
	args = append(args, features.ProxyFlushInterval)
	query += "proxy_stream_close_delay = ?, "
	args = append(args, features.ProxyStreamCloseDelay)
	query += "host_header = ?, "
	args = append(args, derefStr(req.HostHeader))
	query += "health_check_host = ?, "
	args = append(args, derefStr(req.HealthCheckHost))
	query += "enable_tls = ?, "
	args = append(args, *req.EnableTLS)
	query += "tls_source = ?, "
	args = append(args, req.TLSSource)
	query += "acme_config_id = ?, "
	args = append(args, req.ACMEConfigID)
	// 历史修复（历史）：ca_provider_id 恒随更新写入——前方合并区已保证
	// req.CAProviderID 非 nil（nil=沿用存量），原 if 条件恒真。
	query += "ca_provider_id = ?, "
	args = append(args, *req.CAProviderID)
	if req.BlockPageStage1ID != nil {
		query += "block_page_stage1_id = ?, "
		args = append(args, *req.BlockPageStage1ID)
	}
	if req.BlockPageStage1Status != nil {
		query += "block_page_stage1_status = ?, "
		args = append(args, *req.BlockPageStage1Status)
	}
	if req.BlockPageStage3ID != nil {
		query += "block_page_stage3_id = ?, "
		args = append(args, *req.BlockPageStage3ID)
	}
	if req.BlockPageStage3Status != nil {
		query += "block_page_stage3_status = ?, "
		args = append(args, *req.BlockPageStage3Status)
	}
	// 历史问题：空值=保留存量的语义只适用于 HTTP（手动证书留空=沿用）；
	// TCP 行经上方 tcpDeadFieldReset 已把 TLSCert/TLSKey 置空，但同协议编辑
	// 时两条件此前皆假 → DELETE 列不写，死证书/私钥材料永久滞留并随导出/
	// 快照放大。TCP 恒写（值为归一后的空串）。
	if req.TLSCert != "" || protocolChanged || req.Protocol == "tcp" || clearingTLSMaterial {
		query += "tls_cert = ?, "
		args = append(args, req.TLSCert)
	}
	if req.TLSKey != "" || protocolChanged || req.Protocol == "tcp" || clearingTLSMaterial {
		query += "tls_key = ?, "
		args = append(args, req.TLSKey)
	}
	query += "tls_http_redirect = ?, "
	args = append(args, *req.TLSHTTPRedirect)
	query += "enable_compress = ?, "
	args = append(args, *req.EnableCompress)
	query += "compress_types = ?, "
	args = append(args, req.CompressTypes)
	query += "enabled = ?, "
	args = append(args, *req.Enabled)
	query += "log_enabled = ?, "
	args = append(args, *req.LogEnabled)

	// 历史修复：原此处的 SingleRuleConfig 死构造（建成后无任何消费）已删。
	// domain 保留：下方 ACME 任务域名迁移/查找以其为键。
	domain := req.Domain

	// Caddy 应用失败时需要用这些快照把已提交的 DB 更新恢复回去
	oldRuleRow, oldRuleRowErr := dumpRowByKey(c.Request.Context(), "lb_rules", "caddy_id", caddyID)
	if oldRuleRowErr != nil {
		services.Logf("error", "UpdateRule failed to snapshot lb_rules row for caddy_id=%s: %v", caddyID, oldRuleRowErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份规则数据失败"})
		return
	}
	oldUpstreamRowsMap, oldUpstreamRowsErr := dumpRowsByKey(c.Request.Context(), "upstreams", "rule_id", caddyID)
	if oldUpstreamRowsErr != nil {
		services.Logf("error", "UpdateRule failed to snapshot upstreams for caddy_id=%s: %v", caddyID, oldUpstreamRowsErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份上游数据失败"})
		return
	}
	restoreRuleDBSnapshot := func() error {
		restoreCtx, cancelRestore := compensationContext(c.Request.Context())
		defer cancelRestore()
		if err := restoreRuleSnapshot(restoreCtx, caddyID, oldRuleRow, oldUpstreamRowsMap, existingRule.PathRules); err != nil {
			services.Logf("error", "问题: UpdateRule DB restore failed for caddy_id=%s: %v", caddyID, err)
			return err
		}
		return nil
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败: " + err.Error()})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "UpdateRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()

	// 孤儿自愈（历史用户裁定，取代 历史问题-01 的转换事件判定）：规则保存后
	// 终态不使用 ACME 自动签发（证书源手动 / 禁用 TLS）即删除其全部 cert_jobs
	//（含 failed/issued 历史残留）——v2.3.5 时代 acme→manual 翻转语义遗留的
	// 失败行，用户重存规则（manual→manual，无转换事件）也一并收敛，幂等。
	// 30s 补扫不再有非终态行可复活；事务回滚（应用失败）时删除一并撤销。
	// req.TLSSource/req.EnableTLS 在合并区已按 existingRule 兜底（缺省提交
	// =维持原状），直接判终态即可。删除在 tx 内（应用失败随事务回滚），提交
	// 后仍取消队列在途签发（下方 cancelRuleJobs——行已删仍需防 worker 僵尸执行）。
	orphanACME := !derefBool(req.EnableTLS) || req.TLSSource != "acme_dns"
	var switchedCertJobs int64
	delReason := ""
	if orphanACME {
		// 历史问题（收窄裁定 2026-10-19，不反转历史修复）：409 在途守卫
		// 前置到删除之前——此前先 DELETE 致下方 UPDATE 的 NOT EXISTS 守卫在
		// 本路径恒失效，CA 往返在途的规则可被改成 manual/关 TLS（队列取消是
		// 提交后 best-effort）。仅拦「执行中」状态集（executingACMEJobStatuses
		// =非终态减 queued/pending 未起动行）；queued/pending 维持 历史修复
		// 「删除+提交后取消+200」语义，保留持续失败域名的切换逃生口。
		executingStatuses := executingACMEJobStatuses()
		if len(executingStatuses) > 0 {
			countArgs := make([]any, 0, len(executingStatuses)+1)
			countArgs = append(countArgs, caddyID)
			placeholders := ""
			for i, status := range executingStatuses {
				if i > 0 {
					placeholders += ","
				}
				placeholders += "?"
				countArgs = append(countArgs, status)
			}
			var executingJobs int
			if scanErr := tx.QueryRow("SELECT COUNT(*) FROM cert_jobs WHERE rule_id=? AND status IN ("+placeholders+")", countArgs...).Scan(&executingJobs); scanErr != nil {
				services.Logf("error", "UpdateRule executing cert job check error for caddy_id=%s: %v", caddyID, scanErr)
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查证书任务状态失败: " + scanErr.Error()})
				return
			}
			if executingJobs > 0 {
				tx.Rollback()
				c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "证书申请中，请等待完成或失败后再修改规则"})
				return
			}
		}
		delReason = "规则已不使用 ACME 自动签发，证书任务已删除"
		delResult, delErr := tx.Exec("DELETE FROM cert_jobs WHERE rule_id=?", caddyID)
		if delErr != nil {
			services.Logf("error", "UpdateRule cert job delete error for caddy_id=%s: %v", caddyID, delErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除证书任务失败: " + delErr.Error()})
			return
		}
		switchedCertJobs, delErr = delResult.RowsAffected()
		if delErr != nil {
			services.Logf("error", "UpdateRule cert job delete RowsAffected error for caddy_id=%s: %v", caddyID, delErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "确认证书任务删除结果失败: " + delErr.Error()})
			return
		}
	}

	// PUT enabled=false 与 /disable 同语义：ACME 任务置 disabled 并取消在途，
	// 否则任务视图仍显示 issued（历史问题-01）。谓词经
	// disableCertJobsForRuleTx 单源（历史问题，failed 终态行保留失败史实）。
	// 单源判据：上方 updatingToDisabled 已含 !orphanACME 的全部条件（启用中 +
	// 请求禁用 + 终态仍为 acme_dns + TLS 开启），此处复用避免两处谓词漂移。
	disabledByUpdate := updatingToDisabled
	var disabledJobs int64
	if disabledByUpdate {
		var derr error
		disabledJobs, derr = disableCertJobsForRuleTx(tx, caddyID)
		if derr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "暂停证书任务失败: " + derr.Error()})
			return
		}
	}

	userIDInt := contextUserID(c)
	query += "updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ? AND NOT EXISTS (SELECT 1 FROM cert_jobs WHERE rule_id = ? AND status NOT IN ('issued','failed','disabled'))"
	args = append(args, userIDInt, caddyID, caddyID)

	res, err := tx.Exec(query, args...)
	if err != nil {
		tx.Rollback()
		services.Logf("error", "UpdateRule database error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（更新规则）: " + err.Error()})
		return
	}
	rowsAffected, err := res.RowsAffected()
	if err != nil {
		tx.Rollback()
		services.Logf("error", "UpdateRule RowsAffected error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（确认规则更新结果）: " + err.Error()})
		return
	}
	services.Logf("debug", "UpdateRule executed for caddy_id=%s: rows_affected=%d", caddyID, rowsAffected)
	if rowsAffected == 0 {
		tx.Rollback()
		// 历史问题：409 早退（非终态证书任务在途）。裁定 ④' 后保存路径无预校验
		// 探针，此处早退零运行时扰动，无需恢复。
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "证书申请中，请等待完成或失败后再修改规则"})
		return
	}
	// 历史修复（历史）：此处曾有 protocolChanged&&tcp 的二次
	// `DELETE FROM cert_jobs WHERE rule_id=?`——恒 0 行 协议切到 tcp 时
	// req.EnableTLS 已置 false，上方 orphanACME（!EnableTLS||TLSSource!="acme_dns"）
	// 的删除已先行命中同一 rule_id（cert_jobs 按 rule_id 唯一），且 409 早退
	// 保证无在途非终态行。文件清理段（下方 RemoveCertFiles）保留。

	// 历史问题：HTTP→TCP 协议切换同事务解除安全策略绑定——TCP 渲染链
	// （buildTCPProxyRoute）不加载策略，绑定残留会在策略页 rule_count/绑定视图
	// 中显示为生效而运行态零防护；绑定写接口又拒绝 TCP，用户无法在面板内自救。
	// 同协议编辑保留绑定（对照行为由 audit85_l7_test 钉住）。
	var droppedBindings int64
	if protocolChanged && req.Protocol == "tcp" {
		result, err := tx.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id = ?", caddyID)
		if err != nil {
			tx.Rollback()
			services.Logf("error", "UpdateRule security_policy_bindings cleanup error for caddy_id=%s: %v", caddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（清理安全策略绑定）: " + err.Error()})
			return
		}
		droppedBindings, _ = result.RowsAffected()
	}

	// 历史问题：归一（weight/protocol/tls 校验）前置后走增量收敛——同内容编辑
	// 不再 DELETE+INSERT 重建全部上游行（id 保留、不触发上游表行级同步触发器）。
	for i := range req.Upstreams {
		u := &req.Upstreams[i]
		// 历史修复 weight<1 已由 validateRulePayloadBeforeSave 响亮拒绝
		//（0→1 静默归一废除），此处不再兜底归一。
		if u.Protocol == "" {
			if req.Protocol == "tcp" {
				u.Protocol = "tcp"
			} else {
				u.Protocol = "http"
			}
		}
	}
	if err := replaceUpstreamsTx(c.Request.Context(), tx, caddyID, req.Upstreams); err != nil {
		tx.Rollback()
		services.Logf("error", "UpdateRule upstreams replace error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（更新上游服务器）: " + err.Error()})
		return
	}
	if err := replacePathRulesTx(c.Request.Context(), tx, caddyID, features.PathRules); err != nil {
		tx.Rollback()
		services.Logf("error", "UpdateRule path_rules replace error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "写入数据库失败（更新自定义路径规则）: " + err.Error()})
		return
	}
	// 离开 ACME（禁用 TLS / 切换手动 / 切到 TCP）后，旧 ACME 私钥不再被
	// 规则引用，与任务行同事务语义清理；manual 替换会由下方渲染重新物化
	// 新证书，应用失败则由 runtimeSnapshot 恢复旧文件。
	if (protocolChanged && req.Protocol == "tcp") || (existingRule.TLSSource == "acme_dns" && orphanACME) {
		if err := services.RemoveCertFiles(caddyID); err != nil {
			restoreErr := services.RestoreCertFiles(runtimeSnapshot.certFiles)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理旧证书文件失败: " + errors.Join(err, restoreErr).Error()})
			return
		}
	}

	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_update", caddyID))
	if applyErr != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		h.respondRuleApplyError(c, applyErr, restoreErr, "更新")
		return
	}
	if err := tx.Commit(); err != nil {
		//  + 历史问题：commit 失败统一走已提交视图恢复
		//（回滚事务 + 重渲染 /load + 回退 LKG/投影/证书物化）。
		restoreErr := h.recoverCommittedViewAfterCommitFailure(tx)
		services.Logf("error", "UpdateRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		// 提交后失败审计：提交后失败留痕（Explicit 审计策略，中间件不兜底）。
		recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), "提交规则更新事务失败: "+errors.Join(err, restoreErr).Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则更新失败: " + errors.Join(err, restoreErr).Error()})
		return
	}
	committed = true

	// 并发修改复核：并发修改基线——本请求提交后的规则形态（lb_rules 行 +
	// upstreams + path_rules）。下方放锁窗口内他人 UpdateRule 可完整提交；
	// 基线用于窗口后判定「补偿是否仍只回退本请求」，指纹读取失败时降级为
	// 不判定（仍走既有 delete 复核与恢复链）。
	postCommitFingerprint, fingerprintErr := ruleMutationFingerprint(caddyID)
	if fingerprintErr != nil {
		services.Logf("error", "UpdateRule: 记录规则并发基线失败 for caddy_id=%s: %v", caddyID, fingerprintErr)
	}

	if droppedBindings > 0 {
		recordAudit(c, "更新", "安全策略", fmt.Sprintf("规则 %s 切换为 TCP，已解除 %d 条安全策略绑定（TCP 不参与策略渲染）", caddyID, droppedBindings))
	}

	// 历史问题-01/规则脱离 ACME（改手动/禁用 TLS）第二步——提交成功后留痕
	// 并取消队列在途签发（DisableRule 同序：先收敛任务行后取消）。有界等待；
	// 失败仅告警继续——规则切换本身已提交，任务行已删除，队列残留由取消的
	// best-effort 收敛。
	if orphanACME || disabledByUpdate {
		if switchedCertJobs > 0 {
			services.WriteCertJobLogByRule(caddyID, "WARN", "cancelled", delReason)
			recordAudit(c, "更新", "证书任务", fmt.Sprintf("规则 %s %s（%d 个）", caddyID, delReason, switchedCertJobs))
		}
		if disabledByUpdate && disabledJobs > 0 {
			services.WriteCertJobLogByRule(caddyID, "WARN", "cancelled", "规则已禁用，证书任务已暂停")
			recordAudit(c, "更新", "证书任务", fmt.Sprintf("规则 %s 已禁用，暂停证书任务（%d 个）", caddyID, disabledJobs))
		}
		if qm := services.GetCAQueueManager(); qm != nil {
			// 有界取消等待不得占住全局 Caddy 操作锁；队列屏障阻止
			// 等待期间的新任务入队，panic 时 defer 先恢复锁再走补偿链。
			blockToken := qm.BlockJobsForRule(caddyID)
			h.caddyOpMu.Unlock()
			func() {
				defer h.caddyOpMu.Lock()
				if updateRuleLockWindowHook != nil {
					updateRuleLockWindowHook(caddyID, 1)
				}
				cancelCtx, cancel := context.WithTimeout(c.Request.Context(), cancelRuleJobsTimeout)
				defer cancel()
				if err := cancelRuleJobs(cancelCtx, qm, caddyID); err != nil {
					services.Logf("warn", "UpdateRule cert job cancel for %s failed: %v (continuing)", caddyID, err)
				}
			}()
			qm.UnblockJobsForRule(caddyID, blockToken)
			// 放锁窗口内可能已并发删除本规则；继续后续迁移/补偿会把它复活。
			if abortIfRuleDeleted(c, caddyID) {
				return
			}
			// 并发修改复核：窗口内他人提交的更新不得被本请求的失败补偿回退。
			if fingerprintErr == nil && abortIfRuleConcurrentlyModified(c, caddyID, postCommitFingerprint) {
				return
			}
		}
	}

	// 历史问题-2(历史):门控放宽到「ACME+http+domain 变化」——迁移
	// 逻辑与启用态无关;此前 *req.Enabled 门控使禁用态改域绕过迁移,旧域
	// disabled 任务行永驻,再启用时按新域查不到任务另建新行,破坏「一规则
	// 一任务」不变量(块内 needJob 判定仍按启用语义执行)。
	if *req.EnableTLS && req.TLSSource == "acme_dns" && req.Protocol == "http" && domain != "" {
		// 历史修复 同族（历史）：合并区已保证 req.CAProviderID 非 nil，
		// 原 if 判空恒真，直接解引用。
		caProviderID := *req.CAProviderID
		resolvedCAProviderID, resolveErr := services.ResolveCAProviderID(caProviderID)
		resolvedExistingCAProviderID, resolveExistingErr := services.ResolveCAProviderID(existingRule.CAProviderID)
		if resolveErr != nil || resolveExistingErr != nil {
			restoreErr := errors.Join(h.restoreImportRuntime(runtimeSnapshot), restoreRuleDBSnapshot())
			// 审计项：提交后失败的更早补偿分支同样必须留痕（此前只有应用日志）。
			detail := "解析 CA 提供商失败，已回滚更新: " + errors.Join(resolveErr, resolveExistingErr).Error()
			if restoreErr != nil {
				detail = "解析 CA 提供商失败且恢复失败: " + errors.Join(resolveErr, resolveExistingErr, restoreErr).Error()
			}
			recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析 CA 提供商失败: " + errors.Join(resolveErr, resolveExistingErr, restoreErr).Error()})
			return
		}
		caProviderID = resolvedCAProviderID
		domainChanged := canonicalACMEDomainForJobLookup(domain) != canonicalACMEDomainForJobLookup(existingRule.Domain)
		// 历史问题 不变量：补偿快照必须先于任何它可能需要撤销的变更。
		// 下面的域名迁移会就地抹除已签发任务的 PEM；快照若在其后执行，
		// restoreACMEState 恢复出的任务将永久丢失 PEM（TLS 静默中断且
		// 无自动恢复路径）。快照失败时迁移尚未执行，只需回滚规则与运行时。
		certJobsSnapshot, err := services.SnapshotCertJobsForRule(caddyID)
		if err != nil {
			restoreErr := errors.Join(h.restoreImportRuntime(runtimeSnapshot), restoreRuleDBSnapshot())
			// 审计项：同族更早补偿分支补审计（失败/回滚结果一并留痕）。
			detail := "备份证书任务失败，已回滚更新: " + err.Error()
			if restoreErr != nil {
				detail = "备份证书任务失败且恢复失败: " + errors.Join(err, restoreErr).Error()
			}
			recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
			if restoreErr != nil {
				services.Logf("error", "问题: UpdateRule cert job snapshot failed and restore failed for caddy_id=%s: snapshot=%v restore=%v", caddyID, err, restoreErr)
			}
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份证书任务失败: " + errors.Join(err, restoreErr).Error()})
			return
		}
		// When domain changes, update the existing cert job's domain instead of
		// creating a new job and disabling the old one. This preserves the job ID
		// and maintains the "one rule = one cert job" invariant.
		if domainChanged {
			newCanonical := canonicalACMEDomainForJobLookup(domain)
			// 历史问题 迁移前取消在途旧域签发。否则 worker 可能在迁移把行改写为新域
			// 之后仍完成签发，confirmCertificateDeployment 见到 job.domain==rule.domain
			// （同为新域）便放行，把旧域证书部署到新域（瞬时 TLS 名称不匹配，重签后
			// 自愈）。CancelJob 等待在途执行退出（30s 上限）；被取消的 worker 走
			// handleExecutionCancellation 的静默分支（q.ctx 未取消、非执行超时），
			// 不写任务状态，requeueCanceledJob 不会复活迁移后置为 'failed' 的行。
			var inFlightJobID int
			if scanErr := db.DB.QueryRow(`SELECT id FROM cert_jobs WHERE rule_id=? ORDER BY id DESC LIMIT 1`, caddyID).Scan(&inFlightJobID); scanErr == nil && inFlightJobID > 0 {
				// 取消等待在途签发退出；worker 部署尾段需要同一 CaddyOpLock。
				// 持锁等待会形成 30–60s 等待环并阻塞全部配置写（历史
				// 历史问题-1，与 DeleteRule/DisableRule/DeleteCertJob 同构）：
				// 先释放全局锁，有界取消后再取回，迁移事务仍在锁内。
				h.caddyOpMu.Unlock()
				cancelCertJob(inFlightJobID)
				h.caddyOpMu.Lock()
				if updateRuleLockWindowHook != nil {
					updateRuleLockWindowHook(caddyID, 2)
				}
				// 取消等待期间并发 DeleteRule 可完整提交；此时继续
				// createOrRequeueCertJobVerified 会命中「规则已删除」并走
				// restoreACMEState → 按快照复活规则。改为在窗口后直接复核。
				if abortIfRuleDeleted(c, caddyID) {
					return
				}
				// 并发修改复核：同一窗口内的并发更新同样中止（后续恢复按请求前
				// 快照回滚会覆盖他人已提交内容）。
				if fingerprintErr == nil && abortIfRuleConcurrentlyModified(c, caddyID, postCommitFingerprint) {
					return
				}
			}
			certTx, txErr := db.DB.Begin()
			if txErr != nil {
				// 历史问题：迁移事务开启失败不能静默吞掉——任务仍持旧域，后续会为
				// 新域另建任务，破坏「一规则一任务」。规则主更新已提交且用户请求
				// 本身有效，此时回滚规则是错误语义；记录错误并继续：新任务按
				// 既有 needJob 路径创建。
				// 历史问题：旧域残留任务不会被孤儿清扫收敛（sweepOrphanedCertJobs
				// 跳过终态，'issued'+PEM 行将永驻），须在此显式退役旧域任务。
				// 退役与迁移成功路径同为终态（disabled/failed 均使 sweep 不再触碰），
				// 但语义不同：成功路径把行改写为新域、抹除 PEM、置 'failed' 等待重签；
				// 此处域名未实际迁移，故保留 PEM 作历史、置 'disabled'——旧证留在
				// 旧域行上无副作用（部署/续期均按新域匹配，不读此行）。
				services.Logf("error", "UpdateRule: cert job domain migration begin failed for caddy_id=%s: %v", caddyID, txErr)
				retireOldDomainCertJobOrAudit(c, caddyID, existingRule, "域名迁移事务开启失败", "migration begin failure", "域名迁移事务开启失败后旧域任务退役失败")
			} else {
				var existingJobID int
				queryErr := certTx.QueryRow(
					`SELECT id FROM cert_jobs WHERE rule_id=? ORDER BY id DESC LIMIT 1`,
					caddyID).Scan(&existingJobID)
				migrationRolledBack := false
				// 历史修复（历史）：真实查询错误（busy/IO，非 ErrNoRows）不得当作
				// 「无任务」继续空提交——迁移未生效，旧域 issued+PEM 行永驻（sweep
				// 跳过终态），needJob 又为新域另建行，破坏「一规则一任务」且无留痕。
				// 与下方 UPDATE 失败/commit 失败分支同语义：回滚 + 退役旧域任务。
				if queryErr != nil && !errors.Is(queryErr, sql.ErrNoRows) {
					if rbErr := certTx.Rollback(); rbErr != nil {
						services.Logf("error", "UpdateRule: cert job domain migration lookup rollback failed for caddy_id=%s: %v", caddyID, rbErr)
					}
					services.Logf("error", "UpdateRule: failed to read cert job during domain migration for caddy_id=%s: %v", caddyID, queryErr)
					retireOldDomainCertJobOrAudit(c, caddyID, existingRule, "域名迁移查询任务失败", "migration lookup failure", "域名迁移查询失败后旧域任务退役失败")
					migrationRolledBack = true
				}
				if queryErr == nil && existingJobID > 0 {
					if _, err := certTx.Exec(
						`UPDATE cert_jobs SET domain=?, status='failed', message='域名已更新，等待重新签发', cert_pem='', key_pem='', expires_at=NULL, renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?`,
						newCanonical, existingJobID); err != nil {
						// 历史问题 迁移 UPDATE 失败与事务开启失败（历史问题 分支）
						// 同后果——旧域任务未迁移，稍后 needJob 路径会为新域另建任务，
						// 旧域 'issued'+PEM 行永驻且「一规则一任务」被破坏。回滚本事务
						// （其内无其他有效写），并与开启失败分支同语义退役旧域任务。
						if rbErr := certTx.Rollback(); rbErr != nil {
							services.Logf("error", "UpdateRule: cert job domain migration rollback failed for caddy_id=%s: %v", caddyID, rbErr)
						}
						services.Logf("error", "UpdateRule: failed to update cert job %d domain for caddy_id=%s: %v", existingJobID, caddyID, err)
						retireOldDomainCertJobOrAudit(c, caddyID, existingRule, "域名迁移 UPDATE 失败", "migration update failure", "域名迁移更新失败后旧域任务退役失败")
						migrationRolledBack = true
					} else {
						services.Logf("info", "UpdateRule: migrated cert job %d domain to %s for caddy_id=%s", existingJobID, newCanonical, caddyID)
					}
					if !migrationRolledBack {
						if _, err := certTx.Exec(
							`DELETE FROM cert_jobs WHERE rule_id=? AND id!=?`,
							caddyID, existingJobID); err != nil {
							services.Logf("error", "UpdateRule: failed to clean up extra cert jobs for caddy_id=%s: %v", caddyID, err)
						}
					}
				}
				if !migrationRolledBack {
					if err := certTx.Commit(); err != nil {
						// 审计 历史问题：commit 失败与开启/更新失败同后果——迁移未生效，
						// 旧域任务持原域永驻（sweep 跳过终态），稍后 needJob 为新域
						// 另建任务破坏「一规则一任务」。与 历史问题 分支同语义退役。
						services.Logf("error", "UpdateRule: cert job domain migration commit failed for caddy_id=%s: %v", caddyID, err)
						retireOldDomainCertJobOrAudit(c, caddyID, existingRule, "域名迁移 commit 失败", "migration commit failure", "域名迁移提交失败后旧域任务退役失败")
					}
				}
			}
		}
		caProviderChanged := resolvedCAProviderID != resolvedExistingCAProviderID
		wasReEnabled := !existingRule.Enabled && *req.Enabled
		tlsSourceChangedToACME := existingRule.TLSSource != "acme_dns"
		var enqueuedJobID int
		var queueManager *services.CAQueueManager
		restoreACMEState := func() error {
			if enqueuedJobID > 0 && queueManager != nil {
				cancelCertJob(enqueuedJobID)
			}
			return errors.Join(h.restoreImportRuntime(runtimeSnapshot), restoreRuleDBSnapshot(), services.RestoreCertJobsForRule(certJobsSnapshot))
		}
		var jobID, jobProviderID int
		var jobStatus string
		var jobExpiresAt sql.NullTime
		jobErr := db.DB.QueryRow("SELECT id,status,expires_at,COALESCE(ca_provider_id,0) FROM cert_jobs WHERE rule_id=? AND domain=? ORDER BY id DESC LIMIT 1", caddyID, canonicalACMEDomainForJobLookup(domain)).Scan(&jobID, &jobStatus, &jobExpiresAt, &jobProviderID)
		if jobErr != nil && !errors.Is(jobErr, sql.ErrNoRows) {
			restoreErr := restoreACMEState()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + errors.Join(jobErr, restoreErr).Error()})
			return
		}
		if jobErr == nil {
			resolvedJobProviderID, resolveJobErr := services.ResolveCAProviderID(jobProviderID)
			if resolveJobErr != nil {
				restoreErr := restoreACMEState()
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析证书任务 CA 提供商失败: " + errors.Join(resolveJobErr, restoreErr).Error()})
				return
			}
			caProviderChanged = caProviderChanged || resolvedJobProviderID != caProviderID
		}
		resumedValidJob := false
		if wasReEnabled && jobErr == nil {
			// 历史问题（历史）：续期天数读取单源（services.GetCertRenewalDays）——
			// 原内联 COALESCE(cert_renewal_days,30) 与读侧零兜底口径分裂。
			renewalDays := services.GetCertRenewalDays()
			var expiryPtr *time.Time
			if jobExpiresAt.Valid {
				expiry := jobExpiresAt.Time
				expiryPtr = &expiry
			}
			if !domainChanged && !caProviderChanged && ResolveEnableCertJobAction(true, jobStatus, expiryPtr, time.Now(), renewalDays) == EnableCertJobResume {
				// 审计 历史修复（历史修复 同型守卫）：行被并发删除时 UPDATE 命中 0 行
				// 不报错——必须校验 RowsAffected，否则幻影 resume 抑制 needJob，
				// 续签链静默断裂且被 200 掩盖（与 EnableRule 出口同口径）。
				resumeResult, err := db.DB.Exec("UPDATE cert_jobs SET status='issued',message='证书有效，已恢复使用',renewal_attempts=0,ca_available_after=NULL,last_error_code=NULL,updated_at=datetime('now') WHERE id=?", jobID)
				if err == nil {
					resumed, raErr := resumeResult.RowsAffected()
					if raErr != nil || resumed != 1 {
						err = fmt.Errorf("任务行不存在或已被并发变更（rows=%d, err=%v）", resumed, raErr)
					}
				}
				if err != nil {
					restoreErr := restoreACMEState()
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "恢复证书任务失败: " + errors.Join(err, restoreErr).Error()})
					return
				}
				// 历史修复（第二出口）：Resume 后已应用配置同样缺 TLS——补一次重渲染
				// 重应用；失败走既有 restoreACMEState 补偿。历史问题 改走
				// 强制变体（证书文件已在事务外落盘，JSON 相同会被短路）并接线
				// recordCaddyApplyResult（失败必须进 caddy_apply_error，UI 可见）；
				// 本函数已持有 caddyOpMu，不可改用 applyCaddyConfigE（重入死锁）。
				reapplyErr := h.caddyService.GenerateAndApplyConfigForceInLock() // 已持锁——InLock 变体防重入死锁
				h.recordCaddyApplyResult(reapplyErr)
				if reapplyErr != nil {
					restoreErr := restoreACMEState()
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "恢复证书任务后重载 Caddy 配置失败: " + errors.Join(reapplyErr, restoreErr).Error()})
					return
				}
				resumedValidJob = true
			}
		}
		needJob := domainChanged || caProviderChanged || !services.IsACMECertIssued(caddyID, domain) ||
			((wasReEnabled || tlsSourceChangedToACME) && !services.HasCertJob(caddyID, domain))
		needJob = needJob && !resumedValidJob
		// 历史问题-2:外层门放宽后,块内恢复「禁用不签发」语义——
		// 禁用态改域仅做任务迁移,不排队新签发。
		needJob = needJob && *req.Enabled
		if needJob {
			queueManager = services.GetCAQueueManager()
			if queueManager == nil {
				restoreErr := restoreACMEState()
				// 提交后失败审计：提交后失败留痕（补偿结果一并点名）。
				detail := "证书任务入队失败：CA 队列未初始化"
				if restoreErr != nil {
					detail = "证书任务入队失败且恢复失败: " + restoreErr.Error()
				}
				recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
					services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
				if restoreErr != nil {
					services.Logf("error", "问题: UpdateRule ACME enqueue failed and restore failed for caddy_id=%s: restore=%v", caddyID, restoreErr)
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("CA 队列未初始化且恢复失败: %v", restoreErr)})
					return
				}
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化"})
				return
			}
			services.Logf("info", "UpdateRule enqueueing cert job for caddy_id=%s domain=%s ca_provider_id=%d", caddyID, domain, caProviderID)
			jobID, changed, err := createOrRequeueCertJobVerified(caddyID, domain, caProviderID, queueManager)
			if changed {
				enqueuedJobID = jobID
			}
			if err != nil {
				restoreErr := restoreACMEState()
				// 提交后失败审计：入队失败 + 补偿结果留痕。
				detail := "创建证书任务失败，已回滚更新: " + err.Error()
				if restoreErr != nil {
					detail = "创建证书任务失败且恢复失败: " + errors.Join(err, restoreErr).Error()
				}
				recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
					services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
				if restoreErr != nil {
					services.Logf("error", "问题: UpdateRule ACME enqueue failed and restore failed for caddy_id=%s: enqueue=%v restore=%v", caddyID, err, restoreErr)
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("创建证书任务失败且恢复失败: %v; %v", err, restoreErr)})
					return
				}
				status, message := certEnqueueErrorResponse("创建证书任务失败", err)
				c.JSON(status, models.APIResponse{Code: status, Message: message})
				return
			}
		}
	}

	services.Logf("info", "Rule %s updated", caddyID)
	tlsPart := ""
	if req.Protocol == "http" {
		tlsPart = fmt.Sprintf("TLS：%s", boolText(*req.EnableTLS))
	}
	auditParts := []string{services.AuditRulePart(caddyID), req.Name, fmt.Sprintf("协议：%s", req.Protocol), domain, tlsPart}
	if len(certWarnings) > 0 {
		// 证书链/域名警告随成功审计留痕(不阻断)。
		auditParts = append(auditParts, "证书警告："+strings.Join(certWarnings, "；"))
	}
	recordAudit(c, "更新", "负载规则", services.FormatAuditDetail(auditParts...))
	reloadNote()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已更新"})
}

func (h *Handlers) DeleteRule(c *gin.Context) {

	caddyID := c.Param("caddy_id")

	// 与 UpdateRule 同一锁序：先 caddyOpMu 后 DB 事务，避免 AB-BA 循环等待
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var protocol string
	var listenPort int
	var domain string
	err := db.DB.QueryRow("SELECT COALESCE(caddy_id,''), COALESCE(protocol,''), listen_port, COALESCE(domain,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&caddyID, &protocol, &listenPort, &domain)
	if dbQueryNotFound(c, err, "规则不存在", "DeleteRule query rule") {
		return
	}

	// UX 快路径预检（用户裁决）：有 worker 正在执行签发时删除会进入有界取消
	// 等待（最长 2 分钟），秒回 409 让用户稍后重试优于请求悬挂。仅拦「执行中」
	// ——queued 取消瞬时、waiting_ca 冷却可达数小时均不拦；检查与操作间的
	// TOCTOU 窗口落入既有超时中止+快照回滚保护，正确性不变。
	if qm := services.GetCAQueueManager(); qm != nil && qm.HasRunningJobForRule(caddyID) {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "该规则有正在进行的证书签发任务（约需几分钟），请任务完成后再删除或稍后重试"})
		return
	}
	certJobsSnapshot, err := services.SnapshotCertJobsForRule(caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份证书任务失败: " + err.Error()})
		return
	}
	queueManager := services.GetCAQueueManager()
	jobsCanceled := false
	deleteCompleted := false
	compensationStarted := false
	var blockToken services.RuleBlockToken
	if queueManager != nil {
		// No DB transaction is held while waiting, so worker rollback/reload paths can exit.
		blockToken = queueManager.BlockJobsForRule(caddyID)
		// 历史问题 发现1：租约释放收口到登记于 drain 之前的唯一 defer——drain 前/中
		// panic（gin Recovery 只恢复 HTTP 栈、不清理 blockedRules）也能走到这里。
		// 补偿一旦启动成功即接管租约（完成时自行释放），abort 路径不得提前释放，
		// 否则补偿的 enqueueCompensation 见租约缺失而永久退避（历史问题 注释描述的
		// panic 窗口由此真正闭合）。UnblockJobsForRule 幂等：token 未注册均为无操作。
		defer func() {
			if compensationStarted || deleteCompleted {
				return
			}
			if !jobsCanceled {
				queueManager.UnblockJobsForRule(caddyID, blockToken)
				return
			}
			if err := queueManager.StartRuleDeletionCompensation(services.RuleDeletionCompensation{
				RuleID: caddyID, Token: blockToken, Snapshot: certJobsSnapshot,
			}); err != nil {
				services.Logf("error", "问题: DeleteRule failed to start certificate rollback compensation for caddy_id=%s: %v", caddyID, err)
				// 历史问题 同上——补偿未能接管租约时立即释放，不留孤儿屏障。
				queueManager.UnblockJobsForRule(caddyID, blockToken)
				return
			}
			compensationStarted = true
		}()
		drainRuleJobs := cancelRuleJobs
		h.caddyOpMu.Unlock()
		cancelErr := func() error {
			defer h.caddyOpMu.Lock()
			cancelCtx, cancel := context.WithTimeout(c.Request.Context(), cancelRuleJobsTimeout)
			defer cancel()
			return drainRuleJobs(cancelCtx, queueManager, caddyID)
		}()
		if cancelErr != nil {
			if err := queueManager.StartRuleDeletionCompensation(services.RuleDeletionCompensation{
				RuleID: caddyID, Token: blockToken, Snapshot: certJobsSnapshot,
				Drain: func(ctx context.Context) error { return drainRuleJobs(ctx, queueManager, caddyID) },
			}); err != nil {
				services.Logf("error", "问题: DeleteRule failed to start certificate compensation for caddy_id=%s: %v", caddyID, err)
				// 历史问题 补偿启动失败即无人持有该 token（典型为降级竞态：Stop 清空
				// blockedRules 后 block 才创建），必须当场释放租约，否则节点重新提升后
				// 该规则证书任务被屏障永久拦截、静默停发直到下一次 Stop。对运行中的
				// manager 同样幂等安全。
				queueManager.UnblockJobsForRule(caddyID, blockToken)
			} else {
				compensationStarted = true
			}
			// 提交后失败审计：提交前失败同样必须留痕（Explicit 审计策略）——
			// 规则与证书未变，原因点名取消超时。
			recordAudit(c, "删除失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), "取消证书任务超时，规则与证书保持不变: "+cancelErr.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "取消证书任务超时，规则与证书保持不变: " + cancelErr.Error()})
			return
		}
		jobsCanceled = true
	}

	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) { // LBH-A-U4 附带（历史）：统一 errors.Is
				services.Logf("error", "DeleteRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()

	if _, err := tx.Exec("DELETE FROM cert_jobs WHERE rule_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule cert_jobs delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除证书任务失败"})
		return
	}
	// 删除规则时一并清理安全策略绑定，避免遗留孤儿绑定导致该规则 caddy_id
	// 被新规则复用时错误继承旧策略（历史修复）。
	if _, err := tx.Exec("DELETE FROM security_policy_bindings WHERE rule_caddy_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule security_policy_bindings delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除安全策略绑定失败"})
		return
	}
	if _, err := tx.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule upstreams delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除上游服务器失败"})
		return
	}
	// 审计 FK 刻意 OFF（sqlite_pragmas.go），CASCADE 是死条款——path_rules
	// 必须显式删除，否则孤儿行随备份导出后导入侧引用校验 400（备份自毒）。
	if _, err := tx.Exec("DELETE FROM path_rules WHERE rule_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule path_rules delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除自定义路径失败"})
		return
	}
	if _, err := tx.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
		services.Logf("error", "DeleteRule lb_rules delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除规则失败"})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		services.Logf("error", "DeleteRule runtime snapshot failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败"})
		return
	}
	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_delete", caddyID))
	if applyErr != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		if restoreErr != nil {
			services.Logf("error", "问题: DeleteRule Caddy apply and runtime restore failed for caddy_id=%s: apply=%v restore=%v", caddyID, applyErr, restoreErr)
		}
		h.respondRuleApplyError(c, applyErr, restoreErr, "删除")
		return
	}
	if err := h.removeRuleCertFiles(caddyID); err != nil {
		certPath, keyPath := services.CertFilePaths(caddyID)
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		// 历史 问题: 证书文件可能被部分删除（cert 已删 / key 残留 或反之），
		// 即便 Caddy 配置和 DB 事务都恢复了，下次 reload 可能因找不到证书导致 TLS 静默失败。
		// 用户决策：保留现有顺序（先删文件再 commit），但加 问题 告警 + audit + 操作审计（当前实现无安全事件写入），
		// 让运维收到通知后人工恢复证书文件（从备份或其他节点同步）。
		services.Logf("error", "问题: DeleteRule 证书文件清理失败，可能存在 DB-文件状态不一致。caddy_id=%s cert_path=%s key_path=%s cleanup_error=%v restore_error=%v。请人工检查证书文件并在必要时从备份恢复",
			caddyID, certPath, keyPath, err, restoreErr)
		recordAudit(c, "清理失败", "证书文件", services.FormatAuditDetail(
			services.AuditRulePart(caddyID),
			fmt.Sprintf("残留路径：%s, %s。错误：%v。请人工检查证书文件，必要时从备份恢复", certPath, keyPath, err),
		))
		if restoreErr != nil {
			services.Logf("error", "问题: DeleteRule certificate cleanup and runtime restore failed for caddy_id=%s: cleanup=%v restore=%v", caddyID, err, restoreErr)
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "清理规则证书文件失败，删除已回滚。规则已恢复但证书文件可能不一致，请检查日志并人工恢复证书: " + errors.Join(err, restoreErr).Error()})
		return
	}
	if err := tx.Commit(); err != nil {
		//  + 历史问题：commit 失败统一走已提交视图恢复
		//（回滚事务 + 重渲染 /load + 回退 LKG/投影/证书物化）。
		restoreErr := h.recoverCommittedViewAfterCommitFailure(tx)
		services.Logf("error", "DeleteRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		if restoreErr != nil {
			services.Logf("error", "问题: DeleteRule commit and runtime restore failed for caddy_id=%s: commit=%v restore=%v", caddyID, err, restoreErr)
		}
		// 提交后失败审计：提交失败留痕（补偿结果一并点名）。
		detail := "提交规则删除事务失败: " + err.Error()
		if restoreErr != nil {
			detail = "提交规则删除事务失败且恢复失败: " + errors.Join(err, restoreErr).Error()
		}
		recordAudit(c, "删除失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), detail, services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则删除失败"})
		return
	}
	committed = true
	deleteCompleted = true
	if queueManager != nil {
		queueManager.UnblockJobsForRule(caddyID, blockToken)
	}

	if db.MetricsDB != nil {
		if _, err := db.MetricsDB.Exec("DELETE FROM metrics_history WHERE rule_id = ?", caddyID); err != nil {
			// 历史修复（历史裁定）：清理失败不阻断删除（规则已提交），
			// 但必须显性化——操作审计留痕 + 周期任务 metrics-orphan-cleanup
			// 按「已删除规则」谓词有界收敛重试（残留行 7 天保留期另兜底）。
			services.Logf("error", "DeleteRule metrics_history delete error for caddy_id=%s: %v", caddyID, err)
			recordAudit(c, "清理失败", "规则指标", services.FormatAuditDetail(
				services.AuditRulePart(caddyID),
				fmt.Sprintf("metrics_history 清理失败：%v（累计残留由孤儿指标清理任务有界重试收敛）", err),
			))
		}
	}

	services.RemoveRuleLogFiles(caddyID)
	if err := services.RemoveCertJobLogFiles(caddyID); err != nil {
		services.Logf("error", "DeleteRule cert-job log cleanup failed for caddy_id=%s: %v", caddyID, err)
		recordAudit(c, "清理失败", "证书日志", services.FormatAuditDetail(services.AuditRulePart(caddyID), fmt.Sprintf("路径：%s", services.CertJobLogPath(caddyID)), err.Error()))
	}

	recordAudit(c, "删除", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), fmt.Sprintf("协议：%s", protocol), fmt.Sprintf("端口：%d", listenPort), domain))
	reloadNote()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已删除"})
}

func (h *Handlers) DuplicateRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	rows, err := db.DB.Query(`SELECT `+lbRuleColumns+` FROM lb_rules WHERE caddy_id = ?`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	rules, err := scanLbRules(rows)
	// 历史问题: 同 ListRules。
	if closeErr := rows.Close(); closeErr != nil {
		services.Logf("error", "DuplicateRule rows close error for caddy_id=%s: %v", caddyID, closeErr)
	}
	if err != nil {
		services.Logf("error", "DuplicateRule scan error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if len(rules) == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	// 历史问题：复制前补挂载关联数据——scanLbRules 不带 Upstreams/PathRules，
	// EnabledUpstreamCount 恒 0 会让 validateRuleFeatures 的动态 DNS 多上游
	// 预检（DynamicDNS && count>1）在复制路径永不触发。
	// 历史问题：不再对 rule.Domain 规范化——落库域名已由 Create/Update 与启动迁移规范化。
	if err := hydrateRuleRelations(c.Request.Context(), rules); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则关联数据失败"})
		return
	}
	rule := rules[0]

	// 历史修复（历史）：重试窗口上界自愈——源行携带 >60000 越界值
	//（API/MCP/导入/直改 DB 落库的历史值）时，副本不得原样放大并命中新增
	// 上界门 400 死端（与 历史修复 负值自愈同格；http/tcp 上界同值）。负值
	// 由下方 TCP 块按协议处理（http td=-1 是 NTLM 接管态合法哨兵）。
	// 历史问题（历史）：interval 越界归零时 duration 同步归零——td>0+ti=0
	// 是渲染必填门的自相矛盾形态（保存成功但配置生成必败）。
	if rule.TCPTryInterval > 60000 {
		rule.TCPTryInterval = 0
		if rule.TCPTryDuration > 0 {
			rule.TCPTryDuration = 0
		}
	}
	if rule.TCPTryDuration > 60000 {
		rule.TCPTryDuration = 0
	}

	// 审计 历史问题 + 历史修复 + 历史问题：tcp-TLS / HTTP 专属死配置字段族归一
	// 与 CreateRule/UpdateRule 共用同一 tcpDeadFieldReset 清单——源行遗留
	// enable_tls=1/tls_source=acme_dns、tls_http_redirect、domain、
	// upstream_force_http1 等死形态时，副本会原样携带（tcp 不终结入站 TLS、
	// ACME 任务永不消费证书、HTTP 专属字段 TCP 渲染零消费）。
	if rule.Protocol == "tcp" {
		tcpDeadFieldReset(rule.Protocol, storedRuleTCPDeadFields(&rule))
		// TCP 自愈族：custom_routes_enabled 归零后源行残留 path_rules 不得
		// 进入保存门（TCP 分支对 len(PathRules)>0 显式 400）或复制到副本——
		// hydrateRuleRelations 不按开关过滤，须在此显式清空。
		rule.PathRules = []models.PathRule{}
		// 历史修复 同族（历史修复 收敛）：负值重试窗口不喂进复制校验（td/ti 原样
		// 传入会让直改 DB 残留的 tcp 源行复制即 400 死端），也不放大到副本——
		// 与 UpdateRule 最终协议 tcp 块负值自愈同格；非负窗口是合法 tcp 配置，
		// 原样复制（http 源行 td=-1 是 NTLM 接管态，协议原样复制、不受此门）。
		if rule.TCPTryDuration < 0 {
			rule.TCPTryDuration = 0
		}
		if rule.TCPTryInterval < 0 {
			rule.TCPTryInterval = 0
		}
	} else if rule.Protocol == "http" {
		// 历史问题：HTTP 方向反向归一——Create/Update 已清零 TCP-only
		// 字段（tcp_health_check_port/tcp_proxy_protocol），复制路径此前只处理
		// TCP 源行，HTTP 源行的残留值被原样放大到副本。tcp_try_* 是 http/tcp
		// 共用字段，不在此列。
		rule.TCPProxyProtocol = false
		rule.TCPHealthCheckPort = 0
	}
	// 历史问题：手动 TLS 源的残留 acme_config_id 不被消费——副本不放大该
	// 跨模式死引用（与 Create/Update/导入同口径；两协议同判）。
	if rule.TLSSource == "manual" {
		rule.ACMEConfigID = 0
	}
	// 历史修复（历史）：副本同样按生效来源清理跨模式残留——
	// 非 manual 不复制证书材料；非 acme_dns 不复制 CA 提供商引用。
	if rule.TLSSource != "manual" {
		rule.TLSCert, rule.TLSKey = "", ""
	}
	if rule.TLSSource != "acme_dns" {
		rule.CAProviderID = 0
	}

	// 历史问题（历史）：复制前把源行投影为共享保存输入并执行字段层校验
	// （host/端口/权重/查重/健康检查/请求体大小）——坏上游/坏值不得原样
	// 放大到副本，400 点名源规则。
	if err := h.validateDuplicateRulePayload(rule); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("源规则 %s（%s）：%s", rule.Name, caddyID, err.Error())})
		return
	}

	userIDInt := contextUserID(c)

	newCaddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则 ID 失败"})
		return
	}

	nowTime := time.Now().UTC()
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启复制事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			// 历史修复: 与 CreateRule/UpdateRule/DeleteRule 模式一致，回滚错误需记录。
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "DuplicateRule transaction rollback failed: %v", rollbackErr)
			}
		}
	}()

	// 历史 历史修复: DuplicateRule 必须经过与 CreateRule 一致的校验。
	enabledUpstreamCount := 0
	upstreamHosts := make([]string, 0, len(rule.Upstreams))
	for _, u := range rule.Upstreams {
		if u.Enabled {
			enabledUpstreamCount++
			upstreamHosts = append(upstreamHosts, u.Host)
		}
	}
	if err := validateRuleFeatures(ruleFeatureInput{
		Protocol: rule.Protocol, Strategy: rule.Strategy, DynamicDNS: rule.DynamicDNS,
		EnableDnsServer: rule.EnableDnsServer, DnsServer: rule.DnsServer,
		EnabledUpstreamCount: enabledUpstreamCount,
		// 历史修复(历史):补 5 字段——历史修复 80 自环门与 历史修复 地址族门在复制
		// 路径此前因零值恒不触发(注释自述「与 CreateRule 一致」未兑现)。
		ListenPort: rule.ListenPort, EnableTLS: rule.EnableTLS, TLSHTTPRedirect: rule.TLSHTTPRedirect,
		EnabledUpstreamHosts: upstreamHosts, DnsFamily: rule.DnsFamily,
		HealthCheckInterval: rule.HealthCheckInterval, HealthCheckTimeout: rule.HealthCheckTimeout,
		EnableCompress: rule.EnableCompress, CompressTypes: rule.CompressTypes,
		CustomRoutesEnabled: rule.CustomRoutesEnabled, PathRules: rule.PathRules,
		ProxyDialTimeout: rule.ProxyDialTimeout, ProxyResponseHeaderTimeout: rule.ProxyResponseHeaderTimeout,
		ProxyReadTimeout: rule.ProxyReadTimeout, ProxyWriteTimeout: rule.ProxyWriteTimeout,
		ProxyStreamTimeout: rule.ProxyStreamTimeout, ProxyFlushInterval: rule.ProxyFlushInterval,
		ProxyStreamCloseDelay:    rule.ProxyStreamCloseDelay,
		NTLMCompatible:           rule.NTLMCompatible,
		UpstreamForceHTTP1:       rule.UpstreamForceHTTP1,
		UpstreamKeepaliveTimeout: rule.UpstreamKeepaliveTimeout,
		// 历史问题:TCP 三字段随负值门接入——复制路径与 CreateRule/UpdateRule 同校验
		// (历史 历史修复 契约),不留绕行口。
		TCPHealthCheckPort: rule.TCPHealthCheckPort,
		TCPTryDuration:     rule.TCPTryDuration,
		TCPTryInterval:     rule.TCPTryInterval,
	}); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "源规则配置不合法：" + err.Error()})
		return
	}

	// 历史问题 发现5 的 ACME 引用校验已由上方 validateDuplicateRulePayload →
	// validateRulePayloadBeforeSave（共享 validateRuleACMEReferences）覆盖并
	// 点名源规则；：此处原有一次同条件/同文案的重复调用（永不
	// 产生新结果，且重复查库），删除。

	// 历史修复（历史）：源行启用上游池混布同检——保存门只拦新建/更新
	// 载荷，复制是对存量混布行（69 轮修复前落库/直改 DB）的旁路放大通道。
	if err := mixedUpstreamPoolError(rule); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "源规则配置不合法：" + err.Error()})
		return
	}

	// 历史问题：INSERT 列清单与值投影走唯一事实源（services.LbRuleInsertSQL/
	// LbRuleInsertArgs）——复制排除 id（AUTOINCREMENT 分配新主键），审计四列
	// 按复制语义覆写（created_by/updated_by=操作者，created_at/updated_at=现在）。
	duplicate := rule
	duplicate.ID = 0
	duplicate.CaddyID = newCaddyID
	// 规则文本长度上限：副本名累积后缀截断到上限内（源名可能已含后缀或接近上限）。
	duplicate.Name = ruleDuplicateName(rule.Name)
	if err := validateRuleTextLengths(duplicate.Name, rule.Description); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("源规则 %s（%s）：%s", rule.Name, caddyID, err.Error())})
		return
	}
	duplicate.Enabled = false
	duplicate.CreatedBy = int(userIDInt)
	duplicate.UpdatedBy = int(userIDInt)
	duplicate.CreatedAt = nowTime
	duplicate.UpdatedAt = models.JSONNullTime{NullTime: sql.NullTime{Time: nowTime, Valid: true}}
	duplicateColumns := services.LbRuleInsertColumns("id")
	if _, err := tx.Exec(services.LbRuleInsertSQL(duplicateColumns), services.LbRuleInsertArgs(&duplicate, duplicateColumns)...); err != nil {
		services.Logf("error", "Failed to duplicate rule %s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制规则失败，已回滚: " + err.Error()})
		return
	}

	// 历史问题: 同 UpdateRule——NULL enabled 行须 IIF 归一化（NULL 视同禁用），
	// 复制出的新行显式落 0，避免裸 scan 500 与复制后意外启用。
	// 历史问题（历史）：dynamic_dns 同列同病——legacy NULL 行裸 scan
	// NULL→bool 报错恒 500，按 0 归一（遗留死列，渲染只读规则级值）。
	upstreamRows, err := tx.Query(`
		SELECT host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0), IIF(enabled IN ('1',1),1,0), COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(origin_domain,'')
		FROM upstreams WHERE rule_id = ?
	`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取上游失败，已回滚: " + err.Error()})
		return
	}
	for upstreamRows.Next() {
		var u struct {
			Host           string
			Port           int
			Weight         int
			DynamicDNS     bool
			Enabled        bool
			Protocol       string
			MaxConnections int
			OriginDomain   string
		}
		if err := upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.OriginDomain); err != nil {
			upstreamRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "扫描上游失败，已回滚: " + err.Error()})
			return
		}
		if _, err := tx.Exec(`
			INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections, origin_domain)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, newCaddyID, u.Host, u.Port, u.Weight, false /* dynamic_dns 废弃列：复制时归 0 */, u.Enabled, u.Protocol, u.MaxConnections, u.OriginDomain); err != nil {
			upstreamRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制上游失败，已回滚: " + err.Error()})
			return
		}
	}
	if err := upstreamRows.Err(); err != nil {
		if closeErr := upstreamRows.Close(); closeErr != nil {
			services.Logf("error", "DuplicateRule failed to close upstream cursor for caddy_id=%s: %v", caddyID, closeErr)
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "遍历上游失败，已回滚: " + err.Error()})
		return
	}
	if err := upstreamRows.Close(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "关闭上游游标失败，已回滚: " + err.Error()})
		return
	}

	if rule.CustomRoutesEnabled {
		if _, err := tx.Exec(`
		INSERT INTO path_rules (rule_id, sort_order, match_type, path, upstream_path, upstreams_json, response_mode, response_status, response_body, response_content_type, redirect_to, created_at, updated_at)
		SELECT ?, sort_order, match_type, path, upstream_path, upstreams_json, response_mode, response_status, response_body, response_content_type, redirect_to, datetime('now'), datetime('now') FROM path_rules WHERE rule_id = ?
		`, newCaddyID, caddyID); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制路径规则失败，已回滚: " + err.Error()})
			return
		}
	}

	// 2026-09-20 用户裁定（样式批第 4 项）：副本携带安全策略绑定——不携带
	// 会在「启用副本」时形成零防护静默缺口。同事务 INSERT SELECT（与上游/
	// 路径规则复制同口径），成功消息明示携带数量。
	// 历史问题：TCP 副本不复制绑定——TCP 渲染链零消费策略，复制只会把
	// 存量惰性绑定放大到副本（复制路径与协议切换/导入同口径不自造惰性绑定）。
	if rule.Protocol != "tcp" {
		if _, err := tx.Exec(`
			INSERT INTO security_policy_bindings (rule_caddy_id, policy_id)
			SELECT ?, policy_id FROM security_policy_bindings WHERE rule_caddy_id = ?
		`, newCaddyID, caddyID); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制策略绑定失败，已回滚: " + err.Error()})
			return
		}
	}
	var copiedBindings int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id = ?`, newCaddyID).Scan(&copiedBindings); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取副本绑定失败，已回滚: " + err.Error()})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交复制事务失败: " + err.Error()})
		return
	}
	committed = true

	recordAudit(c, "复制", "负载规则", services.FormatAuditDetail(fmt.Sprintf("源规则：%s", caddyID), fmt.Sprintf("新规则：%s", newCaddyID), rule.Name))
	successMsg := "副本已创建（已禁用）：域名与源规则相同，启用前请修改域名或端口"
	if copiedBindings > 0 {
		successMsg += fmt.Sprintf("；已携带 %d 条策略绑定", copiedBindings)
	}
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: successMsg, Data: gin.H{"caddy_id": newCaddyID}})
}

// storedUpstream 是 upstreams 的现有行投影（仅收敛判定所需列；表无时间戳列，
// 身份保留 = id 不重建 ⇒ 不触发行级同步触发器）。needsNormalize：存量行在
// COALESCE/IIF 归一读覆盖的列上为 NULL（legacy 可空 schema 残留）——历史问题
// 契约要求保存后不再存在 NULL 行，此类行即使内容等价也必须原地 UPDATE 归一。
type storedUpstream struct {
	id             int
	host           string
	port           int
	weight         int
	dynamicDNS     bool
	enabled        bool
	protocol       string
	maxConnections int
	originDomain   string
	needsNormalize bool
}

// replaceUpstreamsTx 以「保留不变行」的方式收敛给定规则的上游集合（历史
// 历史问题，镜像 replacePathRulesTx 三入口语义）。修复前 UpdateRule 恒 DELETE
// 全删 + INSERT：任何规则编辑（含纯改名）都重建全部上游行（id 递增），且恒
// 触发行级同步触发器（upstreams 在集群版本矩阵内）→ 每次 UpdateRule 多一轮
// 从端同步。现语义：
//   - 内容完全一致的存量行 → 零写入，id 原样保留；
//   - 内容变更但身份一致（host+port+protocol）或显式回传真实 id 的行 →
//     原地 UPDATE 保 id；
//   - 消失的行 DELETE（按 id）、新增的行 INSERT。
//
// 身份判定的两个入口：前端编辑既有行回传真实 id；无 id 的调用方
// （MCP/导出导入/集群 apply）退化为按身份键配对。调用方须先完成归一
// （weight 0→1、protocol 默认、tls 校验），内容比较以终值为准。
func replaceUpstreamsTx(ctx context.Context, tx *sql.Tx, ruleID string, upstreams []models.Upstream) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0),
		IIF(enabled IN ('1',1),1,0), COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(origin_domain,''),
		(weight IS NULL OR dynamic_dns IS NULL OR enabled IS NULL OR protocol IS NULL OR max_connections IS NULL)
		FROM upstreams WHERE rule_id = ? ORDER BY id`, ruleID)
	if err != nil {
		return fmt.Errorf("读取规则 %s 的上游: %w", ruleID, err)
	}
	var existing []storedUpstream
	for rows.Next() {
		var row storedUpstream
		if err := rows.Scan(&row.id, &row.host, &row.port, &row.weight, &row.dynamicDNS, &row.enabled, &row.protocol, &row.maxConnections, &row.originDomain, &row.needsNormalize); err != nil {
			rows.Close()
			return fmt.Errorf("解析规则 %s 的上游: %w", ruleID, err)
		}
		existing = append(existing, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("遍历规则 %s 的上游: %w", ruleID, err)
	}

	indexByID := make(map[int]int, len(existing))
	for index, row := range existing {
		indexByID[row.id] = index
	}
	consumed := make([]bool, len(existing))
	inserts := make([]storedUpstream, 0, len(upstreams))
	for _, u := range upstreams {
		// 上游级 dynamic_dns 是废弃列（渲染只读规则级 DynamicDNS）：写侧恒 0，
		// 不再把请求里的伪语义落库；存量 1 行在内容比较时与 false 不等，故本轮
		// 保存会原地归零一次（语义无变化，列值收敛）。
		incoming := storedUpstream{
			host: u.Host, port: u.Port, weight: u.Weight,
			enabled: u.Enabled, protocol: u.Protocol, maxConnections: u.MaxConnections, originDomain: u.OriginDomain,
		}
		// ① 显式 id 命中（前端编辑既有行回传真实 id）
		if index, ok := indexByID[u.ID]; ok && !consumed[index] {
			consumed[index] = true
			if err := updateUpstreamTx(ctx, tx, existing[index], incoming); err != nil {
				return fmt.Errorf("更新规则 %s 的上游 %s:%d: %w", ruleID, u.Host, u.Port, err)
			}
			continue
		}
		// ② 内容完全一致且无 NULL 残留 → 原样保留（零写入 ⇒ 不触发同步触发器）；
		// needsNormalize 行落入 ③ 原地 UPDATE 归一（历史问题：保存后无 NULL 行）。
		if index := matchStoredUpstream(existing, consumed, incoming, true); index >= 0 {
			consumed[index] = true
			continue
		}
		// ③ 身份一致（host+port+protocol）→ 原地 UPDATE 保留 id
		if index := matchStoredUpstream(existing, consumed, incoming, false); index >= 0 {
			consumed[index] = true
			if err := updateUpstreamTx(ctx, tx, existing[index], incoming); err != nil {
				return fmt.Errorf("更新规则 %s 的上游 %s:%d: %w", ruleID, u.Host, u.Port, err)
			}
			continue
		}
		inserts = append(inserts, incoming)
	}
	for index, row := range existing {
		if consumed[index] {
			continue
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM upstreams WHERE id = ?", row.id); err != nil {
			return fmt.Errorf("删除规则 %s 的上游 %d: %w", ruleID, row.id, err)
		}
	}
	for _, insert := range inserts {
		if _, err := tx.ExecContext(ctx, `INSERT INTO upstreams (rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections, origin_domain)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ruleID, insert.host, insert.port, insert.weight, insert.dynamicDNS, insert.enabled, insert.protocol, insert.maxConnections, insert.originDomain); err != nil {
			return fmt.Errorf("写入规则 %s 的上游 %s:%d: %w", ruleID, insert.host, insert.port, err)
		}
	}
	return nil
}

// matchStoredUpstream 在未消费的存量行中定位与 incoming 配对的行：exactContent
// 为 true 时要求全部内容列一致（零写入），否则仅按身份键（host+port+protocol）
// 配对（原地 UPDATE 保 id）。
func matchStoredUpstream(existing []storedUpstream, consumed []bool, incoming storedUpstream, exactContent bool) int {
	for index, row := range existing {
		if consumed[index] {
			continue
		}
		if row.host != incoming.host || row.port != incoming.port || row.protocol != incoming.protocol {
			continue
		}
		if exactContent && (row.needsNormalize || row.weight != incoming.weight || row.dynamicDNS != incoming.dynamicDNS ||
			row.enabled != incoming.enabled || row.maxConnections != incoming.maxConnections || row.originDomain != incoming.originDomain) {
			continue
		}
		return index
	}
	return -1
}

// updateUpstreamTx 内容真有变化（或存量行含待归一 NULL 列）时才 UPDATE
// （保 id ⇒ 不触发同步触发器的 DELETE/INSERT 对）。
func updateUpstreamTx(ctx context.Context, tx *sql.Tx, row, incoming storedUpstream) error {
	if !row.needsNormalize && row.host == incoming.host && row.port == incoming.port && row.protocol == incoming.protocol &&
		row.weight == incoming.weight && row.dynamicDNS == incoming.dynamicDNS &&
		row.enabled == incoming.enabled && row.maxConnections == incoming.maxConnections && row.originDomain == incoming.originDomain {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE upstreams SET host=?, port=?, weight=?, dynamic_dns=?, enabled=?, protocol=?, max_connections=?, origin_domain=? WHERE id=?`,
		incoming.host, incoming.port, incoming.weight, incoming.dynamicDNS, incoming.enabled, incoming.protocol, incoming.maxConnections, incoming.originDomain, row.id); err != nil {
		return err
	}
	return nil
}

// BatchRuleBlockPages 批量设置阶段拦截页（规则列表多选浮动操作条）：
// {rule_ids:[], block_page_stage1_id, block_page_stage1_status,
// block_page_stage3_id, block_page_stage3_status}——同校验（页存在/状态码集，
// validateStageBlockPageRef 共享），单事务逐规则 UPDATE lb_rules 4 列 +
// 一次 finishTxApply（单渲染）。非 http（tcp）规则跳过不 UPDATE——阶段页
// 仅 http 渲染消费（与 batch-bind 同口径）。响应
// {bound:n, unchanged:n, skipped:[{rule_id,reason}]}——bound=RowsAffected>0
// 的真实变更数，unchanged=已在目标态的同值命中数（历史问题）。
func (h *Handlers) BatchRuleBlockPages(c *gin.Context) {
	var req struct {
		RuleIDs               []string `json:"rule_ids"`
		BlockPageStage1ID     int      `json:"block_page_stage1_id"`
		BlockPageStage1Status int      `json:"block_page_stage1_status"`
		BlockPageStage3ID     int      `json:"block_page_stage3_id"`
		BlockPageStage3Status int      `json:"block_page_stage3_status"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求参数无效"})
		return
	}
	if len(req.RuleIDs) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "rule_ids 不能为空"})
		return
	}
	// 历史问题（历史）：trim+去重保序——重复 id 只处理一次（修复前逐个
	// UPDATE 并放大计数）；全空白视为空清单。
	dedupedRuleIDs := make([]string, 0, len(req.RuleIDs))
	seenRuleIDs := make(map[string]struct{}, len(req.RuleIDs))
	for _, rawRuleID := range req.RuleIDs {
		ruleID := strings.TrimSpace(rawRuleID)
		if ruleID == "" {
			continue
		}
		if _, duplicate := seenRuleIDs[ruleID]; duplicate {
			continue
		}
		seenRuleIDs[ruleID] = struct{}{}
		dedupedRuleIDs = append(dedupedRuleIDs, ruleID)
	}
	if len(dedupedRuleIDs) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "rule_ids 不能为空"})
		return
	}
	req.RuleIDs = dedupedRuleIDs
	// 历史问题：规则条数上限——逐规则 UPDATE 在单事务/单锁内执行，
	// 请求体只受全局 128MB 上限约束，认证管理员可长时间占用 caddyOpMu。
	const maxBatchRuleBlockPages = 500
	if len(req.RuleIDs) > maxBatchRuleBlockPages {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("单次批量设置最多 %d 条规则（当前 %d 条）", maxBatchRuleBlockPages, len(req.RuleIDs))})
		return
	}
	// 请求体读取/绑定已完成后再取全局写锁：慢速上传不得阻塞全部配置写
	//（历史问题-03，与 handlers/caddy.go 的锁序契约一致）。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if err := validateStageBlockPageRef(req.BlockPageStage1ID, req.BlockPageStage1Status, "阶段 1（IP 访问控制/地域拦截）"); err != nil {
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: validationErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if err := validateStageBlockPageRef(req.BlockPageStage3ID, req.BlockPageStage3Status, "阶段 3（WAF）"); err != nil {
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: validationErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	defer tx.Rollback()
	type skippedRule struct {
		RuleID string `json:"rule_id"`
		Reason string `json:"reason"`
	}
	bound := 0
	unchanged := 0
	skipped := make([]skippedRule, 0)
	// 历史问题：一次 IN 预取协议，替代逐规则 SELECT（2N → N+1 次 SQL）。
	placeholders := make([]string, len(req.RuleIDs))
	prefetchArgs := make([]any, len(req.RuleIDs))
	for i, ruleID := range req.RuleIDs {
		placeholders[i] = "?"
		prefetchArgs[i] = ruleID
	}
	protocolByRule := make(map[string]string, len(req.RuleIDs))
	prefetchRows, err := tx.QueryContext(c.Request.Context(),
		"SELECT caddy_id, COALESCE(protocol,'') FROM lb_rules WHERE caddy_id IN ("+strings.Join(placeholders, ",")+")", prefetchArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	for prefetchRows.Next() {
		var caddyID, protocol string
		if err := prefetchRows.Scan(&caddyID, &protocol); err != nil {
			prefetchRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		protocolByRule[caddyID] = protocol
	}
	if err := prefetchRows.Close(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if err := prefetchRows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	for _, ruleCaddyID := range req.RuleIDs {
		// 历史问题:阶段页 4 列仅 http 渲染消费——非 http(tcp)先查后跳过不 UPDATE
		// (与 batch-bind 的 TCP 跳过同文案同口径),仅不存在记「规则不存在」。
		ruleProtocol, exists := protocolByRule[ruleCaddyID]
		if !exists {
			skipped = append(skipped, skippedRule{ruleCaddyID, "规则不存在"})
			continue
		}
		if ruleProtocol != "http" {
			skipped = append(skipped, skippedRule{ruleCaddyID, "TCP 规则不经过安全链"})
			continue
		}
		// 历史问题-13：同值守卫——四列已在目标态的行不匹配（IS NOT 空安全比较），
		// 同值批量零写入 ⇒ 不触发 lb_rules 行级同步触发器（阶段页四列在 OF 清单
		// 内）；历史问题：bound 按 RowsAffected>0 计（真实变更），affected=0 即
		// 「已在目标态」计入 unchanged（不再把零写入算作成功/误判「规则不存在」）。
		result, err := tx.ExecContext(c.Request.Context(), `UPDATE lb_rules SET block_page_stage1_id=?, block_page_stage1_status=?, block_page_stage3_id=?, block_page_stage3_status=?
			WHERE caddy_id=? AND (block_page_stage1_id IS NOT ? OR block_page_stage1_status IS NOT ? OR block_page_stage3_id IS NOT ? OR block_page_stage3_status IS NOT ?)`,
			req.BlockPageStage1ID, req.BlockPageStage1Status, req.BlockPageStage3ID, req.BlockPageStage3Status, ruleCaddyID,
			req.BlockPageStage1ID, req.BlockPageStage1Status, req.BlockPageStage3ID, req.BlockPageStage3Status)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		affected, err := result.RowsAffected()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
			return
		}
		if affected > 0 {
			bound++
		} else {
			unchanged++
		}
	}
	h.finishTxApply(c, tx, txApplyFinish{
		Resource: "负载规则", AuditAction: "更新",
		AuditDetail: fmt.Sprintf("批量设置阶段拦截页（阶段 1 页 %d/码 %d，阶段 3 页 %d/码 %d）：成功 %d 条，不变 %d 条，跳过 %d 条",
			req.BlockPageStage1ID, req.BlockPageStage1Status, req.BlockPageStage3ID, req.BlockPageStage3Status, bound, unchanged, len(skipped)),
		SuccessMsg: "批量设置阶段拦截页完成",
		Data:       gin.H{"bound": bound, "unchanged": unchanged, "skipped": skipped},
	})
}

func (h *Handlers) EnableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var originalEnabled, enableTLS, tlsHTTPRedirect bool
	var ruleProtocol, ruleDomain, tlsSource string
	var rulePort, caProviderID int
	var originalUpdatedBy sql.NullInt64
	var originalUpdatedAt sql.NullString
	err := db.DB.QueryRow(`SELECT IIF(enabled IN ('1',1),1,0), COALESCE(protocol,''), COALESCE(domain,''), listen_port,
		COALESCE(tls_source,''), COALESCE(enable_tls,0), COALESCE(tls_http_redirect,0), COALESCE(ca_provider_id,0), updated_by, updated_at
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&originalEnabled, &ruleProtocol, &ruleDomain, &rulePort, &tlsSource, &enableTLS, &tlsHTTPRedirect, &caProviderID, &originalUpdatedBy, &originalUpdatedAt)
	if dbQueryNotFound(c, err, "规则不存在", "读取规则") {
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	// 历史问题：补偿需要恢复启用 UPDATE 改写前的原始域名/操作者——
	// ruleDomain 随后被规范化，原值必须单独留存。
	originalDomain := ruleDomain
	if ruleProtocol == "http" && ruleDomain != "" {
		ruleDomain, err = db.CanonicalDomains(ruleDomain)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名格式无效"})
			return
		}
	}
	if originalEnabled {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已启用"})
		return
	}
	if err := validateStoredRuleConfig(c.Request.Context(), caddyID); err != nil {
		var validationErr *configValidationError
		if errors.As(err, &validationErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: validationErr.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "预校验规则配置失败: " + err.Error()})
		return
	}
	// 2026-09-07 裁定 历史修复：启用路径与保存路径同口径（叠加本进程真实管理口的
	// 历史修复 层——包级校验只覆盖默认口 8000/2019）。
	if err := h.validateRuleListenPortForSave(ruleProtocol, rulePort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口冲突，无法启用: " + err.Error()})
		return
	}
	// 历史问题:同端口 TLS/明文混布拦截(启用方向)。
	if ruleProtocol == "http" {
		if err := checkPortTLSMix(caddyID, rulePort, enableTLS); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口冲突，无法启用: " + err.Error()})
			return
		}
	}
	if err := h.validatePortFromDB(ruleProtocol, rulePort, caddyID); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口冲突，无法启用: " + err.Error()})
		return
	}
	if ruleProtocol == "http" && ruleDomain != "" {
		conflict, err := enabledRuleDomainConflict(ruleDomain, rulePort, caddyID)
		if err != nil {
			services.Logf("error", "EnableRule domain conflict query failed for caddy_id=%s domain=%s: %v", caddyID, ruleDomain, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if conflict {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被其他启用中的规则使用，无法启用", ruleDomain)})
			return
		}
		shadowRule, shadowDomain, err := queryRedirectShadowConflict(ruleDomain, rulePort, enableTLS, tlsHTTPRedirect, caddyID)
		if err != nil {
			services.Logf("error", "EnableRule redirect shadow query failed for caddy_id=%s domain=%s: %v", caddyID, ruleDomain, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "检查域名冲突失败"})
			return
		}
		if shadowRule != "" {
			if rulePort == 80 {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被规则 %s 的 HTTPS 跳转占用（跳转在 80 端口优先生效，启用后本规则将不可达），无法启用", shadowDomain, shadowRule)})
			} else {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已有规则 %s 直接监听 80 端口，启用 HTTP 转 HTTPS 跳转会使其不可达，请先调整该规则", shadowDomain, shadowRule)})
			}
			return
		}
	}
	// 历史问题 协议门控——tcp 规则不终结 TLS，证书任务对 tcp 规则只会产生
	// 永不消费的僵尸签发/续签（certJobRuleApplicable 仅查域名）。
	isACME := ruleProtocol == "http" && enableTLS && tlsSource == "acme_dns" && ruleDomain != ""
	var certJobsSnapshot services.CertJobsSnapshot
	if isACME {
		certJobsSnapshot, err = services.SnapshotCertJobsForRule(caddyID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份证书任务失败: " + err.Error()})
			return
		}
	}
	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败: " + err.Error()})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "EnableRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()
	userIDInt := contextUserID(c)
	if _, err := tx.Exec("UPDATE lb_rules SET enabled = 1, domain = ?, updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?", ruleDomain, userIDInt, caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "启用规则失败"})
		return
	}
	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_enable", caddyID))
	if applyErr != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		h.respondRuleApplyError(c, applyErr, restoreErr, "启用")
		return
	}
	if err := tx.Commit(); err != nil {
		//  + 历史问题：commit 失败统一走已提交视图恢复
		//（回滚事务 + 重渲染 /load + 回退 LKG/投影/证书物化）。
		restoreErr := h.recoverCommittedViewAfterCommitFailure(tx)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则启用失败: " + errors.Join(err, restoreErr).Error()})
		return
	}
	committed = true

	var enqueuedJobID int
	var queueManager *services.CAQueueManager
	restoreEnabledState := func() error {
		if enqueuedJobID > 0 && queueManager != nil {
			cancelCertJob(enqueuedJobID)
		}
		var caddyErr, dbErr, jobsErr error
		if isACME {
			caddyErr = h.restoreImportRuntime(runtimeSnapshot)
		}
		// 历史问题：补偿必须恢复启用 UPDATE 改写过的全部列——此前只恢复
		// enabled，updated_at/updated_by 指向未生效的启用尝试，规范化域名也
		// 被留在行上。
		if _, dbErr = db.DB.Exec("UPDATE lb_rules SET enabled = ?, domain = ?, updated_by = ?, updated_at = COALESCE(NULLIF(?, ''), datetime('now')) WHERE caddy_id = ?",
			originalEnabled, originalDomain, originalUpdatedBy, originalUpdatedAt.String, caddyID); dbErr != nil {
			dbErr = fmt.Errorf("恢复规则启用状态: %w", dbErr)
		}
		if isACME {
			jobsErr = services.RestoreCertJobsForRule(certJobsSnapshot)
		}
		return errors.Join(caddyErr, dbErr, jobsErr)
	}
	failEnableWithStatus := func(message string, status int) {
		// 历史问题：启用端点为 Explicit 审计策略，中间件不兜底；此前
		// 提交后的失败（CA 解析/任务读取/Resume 0 行等）只回滚无操作审计，
		// 运维无法追溯谁在何时启用了哪条规则以及失败原因。
		if restoreErr := restoreEnabledState(); restoreErr != nil {
			services.Logf("error", "问题: EnableRule compensation failed for caddy_id=%s: %v", caddyID, restoreErr)
			recordAudit(c, "启用失败", "负载规则", services.FormatAuditDetail(
				services.AuditRulePart(caddyID), message, "补偿恢复失败: "+restoreErr.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: message + "；规则与 Caddy 恢复失败: " + restoreErr.Error()})
			return
		}
		recordAudit(c, "启用失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), message, services.AuditResultPart("failure")))
		c.JSON(status, models.APIResponse{Code: status, Message: message})
	}
	failEnable := func(message string) { failEnableWithStatus(message, http.StatusInternalServerError) }
	// 历史问题-05：入队失败按错误种类定状态（证书签发任务未运行 → 409）。
	failCertEnqueue := func(prefix string, enqueueErr error) {
		status, message := certEnqueueErrorResponse(prefix, enqueueErr)
		failEnableWithStatus(message, status)
	}

	domain := ruleDomain
	services.Logf("info", "EnableRule TLS state for caddy_id=%s: enableTLS=%v tlsSource=%s domain=%s caProviderID=%d", caddyID, enableTLS, tlsSource, domain, caProviderID)
	if isACME {
		resolvedCAProviderID, resolveErr := services.ResolveCAProviderID(caProviderID)
		if resolveErr != nil {
			failEnable("解析 CA 提供商失败: " + resolveErr.Error())
			return
		}
		caProviderID = resolvedCAProviderID
		queueManager = services.GetCAQueueManager()
		enqueueCertJob := func() error {
			jobID, changed, enqueueErr := createOrRequeueCertJobVerified(caddyID, domain, caProviderID, queueManager)
			if changed {
				enqueuedJobID = jobID
			}
			return enqueueErr
		}

		var jobStatus, jobMsg string
		var jobExpiresAt sql.NullTime
		var jobID, jobProviderID int
		hasJob := false
		err := db.DB.QueryRow("SELECT id, status, COALESCE(message,''), expires_at, COALESCE(ca_provider_id,0) FROM cert_jobs WHERE rule_id=? AND domain=? ORDER BY id DESC LIMIT 1", caddyID, canonicalACMEDomainForJobLookup(domain)).Scan(&jobID, &jobStatus, &jobMsg, &jobExpiresAt, &jobProviderID)
		if err == nil {
			hasJob = true
		} else if err != sql.ErrNoRows {
			failEnable("读取证书任务失败")
			return
		}
		// 历史问题（历史）：续期天数读取单源（services.GetCertRenewalDays）——
		// 无效值降级与 error 级留痕统一由 helper 承担（历史修复 的 <=0 兜底语义
		// 保持：helper 对 <=0 返回默认 30 并留痕）。
		renewalDays := services.GetCertRenewalDays()
		var expiryPtr *time.Time
		if jobExpiresAt.Valid {
			expiry := jobExpiresAt.Time
			expiryPtr = &expiry
		}
		action := ResolveEnableCertJobAction(hasJob, jobStatus, expiryPtr, time.Now(), renewalDays)
		if hasJob {
			resolvedJobProviderID, resolveJobErr := services.ResolveCAProviderID(jobProviderID)
			if resolveJobErr != nil {
				failEnable("解析证书任务 CA 提供商失败: " + resolveJobErr.Error())
				return
			}
			if resolvedJobProviderID != caProviderID {
				action = EnableCertJobRetry
			}
		}

		switch action {
		case EnableCertJobCreate:
			if queueManager == nil {
				failEnable("CA 队列未初始化，无法创建证书任务")
				return
			}
			err = enqueueCertJob()
			if err != nil {
				failCertEnqueue("创建证书任务失败", err)
				return
			}
			recordAudit(c, "创建", "证书任务", fmt.Sprintf("启用规则 %s，创建证书任务 (%s)", caddyID, domain))
		case EnableCertJobKeep:
			recordAudit(c, "启用", "证书任务", fmt.Sprintf("启用规则 %s，证书有效（过期前%d天续签），保持现有证书", caddyID, renewalDays))
		case EnableCertJobResume:
			if enableCertJobResumePreUpdateHook != nil {
				enableCertJobResumePreUpdateHook(jobID)
			}
			// 历史问题 UPDATE 无状态 CAS，任何未来在上方 SELECT 与此处之间
			// 删除行的路径都会 0 行命中，「启用成功但任务行不存在、续签链断」
			// 被审计文案掩盖——核对 RowsAffected==1，否则按失败补偿。
			resumeResult, err := db.DB.Exec("UPDATE cert_jobs SET status='issued', message='证书有效，已恢复使用', renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?", jobID)
			if err != nil {
				failEnable("恢复证书任务失败: " + err.Error())
				return
			}
			resumed, err := resumeResult.RowsAffected()
			if err != nil || resumed != 1 {
				failEnable("恢复证书任务失败：任务行不存在或已被并发变更")
				return
			}
			// 历史问题 Resume 把 'disabled'→'issued' 发生在 ApplyConfigFromTx 之后——
			// 渲染时双层过滤（caddy.go SQL status!='disabled' + certselector 跳过 disabled）
			// 使已应用配置缺 TLS/301/证书文件，且 needJob 被 Resume 抑制不再触发任何
			// re-apply，看门狗只查路由存在性——静默失配无上界。此处已提交视图=规则启用
			// +job issued，立即重渲染重应用使 TLS 恢复；失败走既有 failEnable 补偿
			//（enabled=0 + certJobsSnapshot 恢复 + 运行时快照恢复）。历史问题
			// 强制变体 + recordCaddyApplyResult（已持 caddyOpMu，不可用
			// applyCaddyConfigE——重入死锁）。
			reapplyErr := h.caddyService.GenerateAndApplyConfigForceInLock() // 已持锁——InLock 变体防重入死锁
			h.recordCaddyApplyResult(reapplyErr)
			if reapplyErr != nil {
				failEnable("恢复证书任务后重载 Caddy 配置失败: " + reapplyErr.Error())
				return
			}
			recordAudit(c, "启用", "证书任务", fmt.Sprintf("启用规则 %s，证书仍有效，恢复使用现有证书", caddyID))
		case EnableCertJobRenew:
			if queueManager == nil {
				failEnable("CA 队列未初始化，无法续签证书")
				return
			}
			err = enqueueCertJob()
			if err != nil {
				failCertEnqueue("续签排队失败", err)
				return
			}
			recordAudit(c, "续签", "证书任务", fmt.Sprintf("启用规则 %s，证书即将过期，重新排队续签", caddyID))
		case EnableCertJobRetry:
			if queueManager == nil {
				failEnable("CA 队列未初始化，无法重试证书任务")
				return
			}
			err = enqueueCertJob()
			if err != nil {
				failCertEnqueue("重试排队失败", err)
				return
			}
			recordAudit(c, "重试", "证书任务", fmt.Sprintf("启用规则 %s，任务之前已暂停/失败，重新排队", caddyID))
		default:
			recordAudit(c, "启用", "证书任务", fmt.Sprintf("启用规则 %s，签发任务已在进行中 (状态: %s)", caddyID, jobStatus))
		}
	}

	recordAudit(c, "启用", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), "状态：已启用"))
	reloadNote()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已启用"})
}

// upstreamWeightPresenceProbe 区分「省略 weight」与「显式 0」（历史修复）：
// typed 绑定把省略解码为 0，与显式 0 不可分——省略须落默认 1（与导入侧
// 缺键→schema DEFAULT 1 同口径，config_backup.go 历史修复 门），显式 0/负值
// 留给 validateRuleUpstreams 响亮 400。
type upstreamWeightPresenceProbe struct {
	Upstreams []struct {
		Weight *int `json:"weight"`
	} `json:"upstreams"`
}

// applyOmittedUpstreamWeightDefaults 把省略 weight 的上游行置默认 1；显式值
// （含 0/负）原样保留给写侧校验判定。探针绑定失败或行数不齐时不做填充
// （主绑定已先行报错，或畸形形态由后续校验兜底）。
func applyOmittedUpstreamWeightDefaults(c *gin.Context, upstreams []models.Upstream) {
	if len(upstreams) == 0 {
		return
	}
	var probe upstreamWeightPresenceProbe
	if err := c.ShouldBindBodyWith(&probe, binding.JSON); err != nil {
		return
	}
	if len(probe.Upstreams) != len(upstreams) {
		return
	}
	for i := range upstreams {
		if probe.Upstreams[i].Weight == nil {
			upstreams[i].Weight = 1
		}
	}
}

// executingACMEJobStatuses 派生「执行中/CA 往返在途」cert_jobs 状态集
// （历史问题 收窄裁定 2026-10-19）：规范枚举（db.CertJobStatuses 单源）减去
// 终态（issued/failed/disabled）与未起动行（queued/pending）——未起动行
// 维持历史修复「删除+取消+200」语义，在途行才在 orphanACME 删除前 409。
// 逐调用计算：枚举极小（26 项），UpdateRule 非热路径，避免包级缓存漂移。
func executingACMEJobStatuses() []string {
	excluded := map[string]bool{"queued": true, "pending": true, "issued": true, "failed": true, "disabled": true}
	statuses := make([]string, 0, len(db.CertJobStatuses()))
	for _, status := range db.CertJobStatuses() {
		if !excluded[status] {
			statuses = append(statuses, status)
		}
	}
	return statuses
}

// disableCertJobsForRuleTx 是「规则禁用/停用」暂停证书任务的单源写点
// （历史问题）：UpdateRule（PUT enabled=false 同语义入口）与 DisableRule
// 原两份手写 UPDATE 谓词漂移——前者 status<>'disabled' 会把 failed 终态行
// 改写为 disabled 抹掉失败史实；统一为 NOT IN ('failed','disabled')，与
// config_backup.go pauseCertJobsForImportDisabledRule（历史问题 导入冲突
// 暂停）谓词逐字一致。返回受影响行数；审计/日志由调用方负责。
func disableCertJobsForRuleTx(tx *sql.Tx, caddyID string) (int64, error) {
	result, err := tx.Exec(`UPDATE cert_jobs SET status='disabled', message='规则已禁用，任务已暂停', updated_at=datetime('now') WHERE rule_id=? AND status NOT IN ('failed','disabled')`, caddyID)
	if err != nil {
		return 0, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return rowsAffected, nil
}

// ruleExistsByCaddyID 报告规则行是否仍存在（历史修复 的放锁窗口复核用）。
func ruleExistsByCaddyID(caddyID string) (bool, error) {
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(1) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// abortIfRuleDeleted 复核 UpdateRule 主动放锁窗口结束后规则是否仍存在。
// 域名迁移/证书任务取消路径会临时放开 caddyOpMu，
// 窗口内并发的 DeleteRule 可以完整提交；若本请求随后继续，任何失败分支的
// restoreRuleDBSnapshot/restoreImportRuntime 都会按更新前快照把已删除的规则
// （含上游、路径规则与运行路由）整体复活——删除结果被静默撤销，且
// security_policy_bindings 已随删除清空，复活出的是「零策略」规则。
// 返回 true 表示已写出错误响应，调用方必须立即 return。
func abortIfRuleDeleted(c *gin.Context, caddyID string) bool {
	exists, err := ruleExistsByCaddyID(caddyID)
	if err != nil {
		services.Logf("error", "UpdateRule: 复核规则存在性失败 for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return true
	}
	if !exists {
		services.Logf("warn", "UpdateRule: 规则 %s 已在放锁窗口内被删除，中止后续迁移/补偿（不复活规则）", caddyID)
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则已被删除，本次更新已中止"})
		return true
	}
	return false
}

// updateRuleLockWindowHook / disableRuleLockWindowHook 是测试专用钩子：在
// UpdateRule（window=1 证书取消窗口 / window=2 域名迁移取消窗口）与
// DisableRule 的放锁窗口内触发，用于模拟窗口内并发的规则删除/更新
// （并发修改复核 并发修改复核与 删除复核 删除复核的回归测试）。
var (
	updateRuleLockWindowHook  func(caddyID string, window int)
	disableRuleLockWindowHook func(caddyID string)
)

// ruleMutationFingerprint 计算规则形态指纹（并发修改复核）：lb_rules 行 +
// upstreams + path_rules 三面的完整投影。map 序列化由 encoding/json 按键名
// 排序；关系行按 id 排序。用于判定主动放锁窗口内是否有人提交了对同一规则的
// 修改（本请求提交后的指纹为基线）。
func ruleMutationFingerprint(caddyID string) (string, error) {
	ctx := context.Background()
	ruleRow, err := dumpRowByKey(ctx, "lb_rules", "caddy_id", caddyID)
	if err != nil {
		return "", err
	}
	ruleJSON, err := json.Marshal(ruleRow)
	if err != nil {
		return "", fmt.Errorf("序列化规则行指纹: %w", err)
	}
	upstreamRows, err := queryRowsAsMaps(ctx, db.DB, rowQuery{
		label: "上游指纹",
		query: "SELECT * FROM upstreams WHERE rule_id = ? ORDER BY id",
		args:  []any{caddyID},
	})
	if err != nil {
		return "", err
	}
	upstreamJSON, err := json.Marshal(upstreamRows)
	if err != nil {
		return "", fmt.Errorf("序列化上游指纹: %w", err)
	}
	pathRows, err := queryRowsAsMaps(ctx, db.DB, rowQuery{
		label: "路径规则指纹",
		query: "SELECT * FROM path_rules WHERE rule_id = ? ORDER BY id",
		args:  []any{caddyID},
	})
	if err != nil {
		return "", err
	}
	pathJSON, err := json.Marshal(pathRows)
	if err != nil {
		return "", fmt.Errorf("序列化路径规则指纹: %w", err)
	}
	return string(ruleJSON) + "\n" + string(upstreamJSON) + "\n" + string(pathJSON), nil
}

// abortIfRuleConcurrentlyModified 在放锁窗口结束后复核规则是否被并发修改
// （并发修改复核）：窗口内他人 UpdateRule 可完整提交；本请求若继续并随后失败，
// restoreRuleDBSnapshot/restoreImportRuntime 会按请求前快照把他人已提交内容
// 整体回退。检测到不一致即中止（409 + 审计「并发修改」），并跳过整份恢复
// ——中止时运行态与本请求提交后的 DB 视图一致，恢复反而会回退他人路由。
// 指纹读取失败时不判定（返回 false，维持既有恢复链语义）。
// 返回 true 表示已写出错误响应，调用方必须立即 return。
func abortIfRuleConcurrentlyModified(c *gin.Context, caddyID, baseline string) bool {
	current, err := ruleMutationFingerprint(caddyID)
	if err != nil {
		services.Logf("error", "UpdateRule: 复核规则并发修改失败 for caddy_id=%s: %v", caddyID, err)
		return false
	}
	if current == baseline {
		return false
	}
	services.Logf("warn", "UpdateRule: 规则 %s 已在放锁窗口内被并发修改，中止后续迁移/补偿（不回退他人已提交内容）", caddyID)
	recordAudit(c, "更新失败", "负载规则", services.FormatAuditDetail(
		services.AuditRulePart(caddyID), "放锁窗口内检测到并发修改，已中止后续迁移/补偿（不回退他人已提交内容）", services.AuditResultPart("failure")))
	c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "规则已被并发修改，本次更新已中止，请刷新后重试"})
	return true
}

func (h *Handlers) DisableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var originalEnabled, enableTLS bool
	var domain, tlsSource string
	err := db.DB.QueryRow("SELECT IIF(enabled IN ('1',1),1,0), COALESCE(domain,''), COALESCE(tls_source,''), COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&originalEnabled, &domain, &tlsSource, &enableTLS)
	if dbQueryNotFound(c, err, "规则不存在", "读取规则") {
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if !originalEnabled {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已禁用"})
		return
	}

	// UX 快路径预检（用户裁决）：与 DeleteRule 同款——有 worker 正在执行签发
	// 时禁用会进入有界取消等待（最长 2 分钟），秒回 409 优于请求悬挂。仅拦
	// 「执行中」；TOCTOU 窗口落入既有超时中止+回滚保护，正确性不变。
	if qm := services.GetCAQueueManager(); qm != nil && qm.HasRunningJobForRule(caddyID) {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "该规则有正在进行的证书签发任务（约需几分钟），请任务完成后再禁用或稍后重试"})
		return
	}

	runtimeSnapshot, err := h.snapshotImportRuntime([]string{caddyID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前运行配置失败: " + err.Error()})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "DisableRule transaction rollback failed for caddy_id=%s: %v", caddyID, rollbackErr)
			}
		}
	}()
	userIDInt := contextUserID(c)
	if _, err := tx.Exec("UPDATE lb_rules SET enabled = 0, updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?", userIDInt, caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "禁用规则失败"})
		return
	}
	var disabledJobs int64
	if enableTLS && tlsSource == "acme_dns" && domain != "" {
		// 谓词经 disableCertJobsForRuleTx 单源（历史问题）——与 UpdateRule
		// 禁用入口/config_backup 导入冲突暂停同口径，failed 终态行保留。
		var derr error
		disabledJobs, derr = disableCertJobsForRuleTx(tx, caddyID)
		if derr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新证书任务状态失败: " + derr.Error()})
			return
		}
	}
	reloadNote, applyErr := h.applyFromTxNote(c, tx, txReloadDetail("rule_disable", caddyID))
	if applyErr != nil {
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		h.respondRuleApplyError(c, applyErr, restoreErr, "禁用")
		return
	}
	if err := tx.Commit(); err != nil {
		//  + 历史问题：commit 失败统一走已提交视图恢复
		//（回滚事务 + 重渲染 /load + 回退 LKG/投影/证书物化）。
		restoreErr := h.recoverCommittedViewAfterCommitFailure(tx)
		// 提交后失败审计：提交失败留痕（Explicit 审计策略）。
		recordAudit(c, "禁用失败", "负载规则", services.FormatAuditDetail(
			services.AuditRulePart(caddyID), "提交规则禁用事务失败: "+errors.Join(err, restoreErr).Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则禁用失败: " + errors.Join(err, restoreErr).Error()})
		return
	}
	committed = true
	if disabledJobs > 0 {
		services.WriteCertJobLogByRule(caddyID, "WARN", "cancelled", "规则已禁用，证书任务已暂停")
		recordAudit(c, "禁用", "证书任务", fmt.Sprintf("规则 %s 已禁用，%d 个证书任务状态设为已禁用", caddyID, disabledJobs))
	}

	// 取消仍在排队或执行中的签发协程，避免已禁用规则继续占用 CA 配额
	if qm := services.GetCAQueueManager(); qm != nil {
		blockToken := qm.BlockJobsForRule(caddyID)
		h.caddyOpMu.Unlock()
		func() {
			defer h.caddyOpMu.Lock()
			if disableRuleLockWindowHook != nil {
				disableRuleLockWindowHook(caddyID)
			}
			cancelCtx, cancel := context.WithTimeout(c.Request.Context(), cancelRuleJobsTimeout)
			defer cancel()
			if err := cancelRuleJobs(cancelCtx, qm, caddyID); err != nil {
				services.Logf("error", "DisableRule certificate cancellation timed out for caddy_id=%s: %v", caddyID, err)
			}
		}()
		qm.UnblockJobsForRule(caddyID, blockToken)
		// 删除复核：放锁窗口内并发的 DeleteRule 可完整提交（含证书任务/绑定
		// 清理）——此时不得再写「禁用」成功审计（会留下指向已不存在规则的
		// 成功留痕），按冲突中止；与 UpdateRule 同用 abortIfRuleDeleted。
		if abortIfRuleDeleted(c, caddyID) {
			return
		}
	}

	recordAudit(c, "禁用", "负载规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), "状态：已禁用"))
	reloadNote()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已禁用"})
}

func (h *Handlers) GetRuleLogStream(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	offset, _ := strconv.ParseInt(c.Query("offset"), 10, 64)
	lines, next := services.ReadRuleLogFrom(caddyID, offset)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"offset": next, "lines": lines}})
}

func (h *Handlers) GetRuleLogs(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	content, offset := services.ReadRuleLogTail(caddyID, 1000)
	// offset must point just past the returned tail so a following stream
	// request continues without re-reading the same lines.
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": content, "offset": offset + int64(len(content))}})
}
