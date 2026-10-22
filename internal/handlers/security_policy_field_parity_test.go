package handlers

// 策略字段清单的编译期断言（反射比对）：models.SecurityPolicy 的每个对外列都必须
// 出现在详情 DTO 与列表摘要的对应位置——历史上两次「新增列漏改投影/摘要」事故
// 都是编译通过但运行期静默丢字段（爬虫豁免列表回写被关、详情 DTO 缺席）。
// 本文件把「新增列必须同步」变成测试红。

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// securityPolicyModelJSONFields 返回 SecurityPolicy 的对外 JSON 字段集合
// （json:"-" 的内部计算字段不计）。
func securityPolicyModelJSONFields() map[string]struct{} {
	fields := map[string]struct{}{}
	t := reflect.TypeOf(models.SecurityPolicy{})
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		fields[name] = struct{}{}
	}
	return fields
}

func jsonFieldSet(v any) map[string]struct{} {
	fields := map[string]struct{}{}
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			continue
		}
		fields[name] = struct{}{}
	}
	return fields
}

// 详情 DTO 必须覆盖模型全部对外列，唯一例外是 updated_by（列表摘要承载，
// 详情编辑不需要）——新增列若漏改则会命中本测试。
func TestSecurityPolicyDetailCoversEveryModelColumn(t *testing.T) {
	model := securityPolicyModelJSONFields()
	detail := jsonFieldSet(securityPolicyDetail{})
	const documentedDetailGap = "updated_by"

	var missing []string
	for name := range model {
		if name == documentedDetailGap {
			continue
		}
		if _, ok := detail[name]; !ok {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("详情 DTO 缺失列 %v——新增列必须同步 securityPolicyDetail/newSecurityPolicyDetail", missing)
	}
	for name := range detail {
		if _, ok := model[name]; !ok {
			t.Fatalf("详情 DTO 出现模型外字段 %q（列集漂移）", name)
		}
	}
}

// 列表摘要必须携带「编辑回写会静默改变行为」的字段族（历史两次事故：
// 爬虫豁免缺席 → 回写即关闭；refs 缺席 → 回写即解绑）。这些字段逐一钉死。
func TestSecurityPolicySummaryCarriesEditorRoundTripFields(t *testing.T) {
	summary := jsonFieldSet(models.SecurityPolicySummary{})
	required := []string{
		"ip_acl_list", "ip_acl_list_refs", "ip_whitelist", "ip_whitelist_refs",
		"ip_whitelist_enabled", "ip_acl_enabled", "ip_acl_mode", "ip_blacklist",
		"geoip_countries", "geoip_mode", "geoip_crawler_exempt", "geoip_crawler_engines",
		"crs_rule_groups", "crs_excluded_count", "custom_rules_count",
		"rate_limit_rps", "rate_limit_burst",
		"waf_check_response", "log_request_body", "policy_type", "trust_detection",
	}
	var missing []string
	for _, name := range required {
		if _, ok := summary[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		t.Fatalf("摘要缺失编辑回写必需字段 %v——前端按摘要回写会静默改变策略行为", missing)
	}
}
