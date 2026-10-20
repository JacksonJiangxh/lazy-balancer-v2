package handlers

import (
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 阶段外字段归零矩阵必须单源——Create 与 Update 两条写路径对同一阶段
// 归零同一组字段。此前双份逐字段 switch 已产生 SEC-B-F2 的
// IPWhitelistEnabled nil/false 形状漂移。本测试把两条 applier 的决策逐阶段对齐：
// 请求全字段填入非零哨兵值，归零后两边的「字段→零/非零」视图必须完全一致。
func TestStageZeroMatrix_createUpdateParity(t *testing.T) {
	stages := []string{
		models.PolicyTypeStage0, models.PolicyTypeStage1,
		models.PolicyTypeStage2, models.PolicyTypeStage3,
	}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			createReq := pollutedCreateRequest()
			applyStageZerosToCreate(&createReq, stage)
			updateReq := pollutedUpdateRequest()
			applyStageZerosToUpdate(&updateReq, stage)

			created := createShape(createReq)
			updated := updateShape(updateReq)
			for field, want := range created {
				if got := updated[field]; got != want {
					t.Fatalf("stage=%s field=%s: create zeroed=%v, update zeroed=%v（矩阵必须单源）", stage, field, want, got)
				}
			}
			// 阶段内字段不得被误清零：每阶段至少保留一项非零哨兵
			if !hasNonZero(created) {
				t.Fatalf("stage=%s: 所有字段被归零（矩阵过度清零）", stage)
			}
		})
	}
}

// 矩阵内容钉住（各阶段保留面）：防止「单源但改错」。
func TestStageZeroMatrix_keepsInStageFields(t *testing.T) {
	cases := []struct {
		stage  string
		field  string
		zeroed bool
	}{
		{models.PolicyTypeStage0, "trust_detection", false},
		{models.PolicyTypeStage0, "block_page_id", true},
		{models.PolicyTypeStage1, "ip_acl_list", false},
		{models.PolicyTypeStage1, "geoip_countries", false},
		{models.PolicyTypeStage1, "geoip_crawler_engines", false},
		{models.PolicyTypeStage1, "trust_detection", true},
		{models.PolicyTypeStage2, "rate_limit_rps", false},
		{models.PolicyTypeStage2, "block_page_id", false},
		{models.PolicyTypeStage2, "block_status_code", true},
		{models.PolicyTypeStage2, "geoip_crawler_engines", true},
		{models.PolicyTypeStage3, "crs_rule_groups", false},
		{models.PolicyTypeStage3, "rate_limit_rps", true},
		{models.PolicyTypeStage3, "ip_acl_enabled", true},
	}
	for _, tc := range cases {
		createReq := pollutedCreateRequest()
		applyStageZerosToCreate(&createReq, tc.stage)
		got := createShape(createReq)[tc.field]
		if got != tc.zeroed {
			t.Fatalf("stage=%s field=%s zeroed=%v, want %v", tc.stage, tc.field, got, tc.zeroed)
		}
	}
}

func pollutedCreateRequest() models.CreateSecurityPolicyRequest {
	yes := true
	return models.CreateSecurityPolicyRequest{
		Name:                "p",
		Mode:                "blocking",
		IPACLMode:           "deny",
		IPACLList:           `["10.0.0.0/8"]`,
		IPACLListRefs:       `[1]`,
		IPACLEnabled:        true,
		IPWhitelist:         `["192.168.1.1"]`,
		IPWhitelistRefs:     `[2]`,
		IPWhitelistEnabled:  &yes,
		IPBlacklist:         `["203.0.113.9"]`,
		RateLimitEnabled:    true,
		RateLimitRPS:        120,
		RateLimitBurst:      240,
		CRSRuleGroups:       `[942]`,
		CRSExcludedRules:    `[942100]`,
		CustomRules:         `[1]`,
		BlockPageID:         3,
		BlockStatusCode:     403,
		GeoIPCountries:      `["CN"]`,
		GeoIPMode:           "deny",
		GeoIPCrawlerExempt:  true,
		GeoIPCrawlerEngines: `["googlebot"]`,
		WAFCheckResponse:    true,
		LogRequestBody:      true,
		TrustDetection:      true,
	}
}

func pollutedUpdateRequest() models.UpdateSecurityPolicyRequest {
	c := pollutedCreateRequest()
	return models.UpdateSecurityPolicyRequest{
		Name:                &c.Name,
		Mode:                &c.Mode,
		IPACLMode:           &c.IPACLMode,
		IPACLList:           &c.IPACLList,
		IPACLListRefs:       &c.IPACLListRefs,
		IPACLEnabled:        &c.IPACLEnabled,
		IPWhitelist:         &c.IPWhitelist,
		IPWhitelistRefs:     &c.IPWhitelistRefs,
		IPWhitelistEnabled:  c.IPWhitelistEnabled,
		IPBlacklist:         &c.IPBlacklist,
		RateLimitEnabled:    &c.RateLimitEnabled,
		RateLimitRPS:        &c.RateLimitRPS,
		RateLimitBurst:      &c.RateLimitBurst,
		CRSRuleGroups:       &c.CRSRuleGroups,
		CRSExcludedRules:    &c.CRSExcludedRules,
		CustomRules:         &c.CustomRules,
		BlockPageID:         &c.BlockPageID,
		BlockStatusCode:     &c.BlockStatusCode,
		GeoIPCountries:      &c.GeoIPCountries,
		GeoIPMode:           &c.GeoIPMode,
		GeoIPCrawlerExempt:  &c.GeoIPCrawlerExempt,
		GeoIPCrawlerEngines: &c.GeoIPCrawlerEngines,
		WAFCheckResponse:    &c.WAFCheckResponse,
		LogRequestBody:      &c.LogRequestBody,
		TrustDetection:      &c.TrustDetection,
	}
}

func createShape(r models.CreateSecurityPolicyRequest) map[string]bool {
	wlEnabled := r.IPWhitelistEnabled == nil || !*r.IPWhitelistEnabled
	return map[string]bool{
		"mode":                  r.Mode == "" || r.Mode == "off",
		"crs_rule_groups":       r.CRSRuleGroups == "" || r.CRSRuleGroups == "[]",
		"rate_limit_rps":        r.RateLimitRPS == 0,
		"waf_check_response":    !r.WAFCheckResponse,
		"ip_acl_enabled":        !r.IPACLEnabled,
		"ip_acl_list":           r.IPACLList == "" || r.IPACLList == "[]",
		"ip_whitelist_enabled":  wlEnabled,
		"ip_whitelist":          r.IPWhitelist == "" || r.IPWhitelist == "[]",
		"ip_blacklist":          r.IPBlacklist == "" || r.IPBlacklist == "[]",
		"geoip_mode":            r.GeoIPMode == "" || r.GeoIPMode == "off",
		"geoip_countries":       r.GeoIPCountries == "" || r.GeoIPCountries == "[]",
		"geoip_crawler_engines": r.GeoIPCrawlerEngines == "" || r.GeoIPCrawlerEngines == "[]",
		"block_page_id":         r.BlockPageID == 0,
		"block_status_code":     r.BlockStatusCode == 0,
		"trust_detection":       !r.TrustDetection,
	}
}

func updateShape(r models.UpdateSecurityPolicyRequest) map[string]bool {
	strZero := func(p *string) bool { return p == nil || *p == "" || *p == "[]" }
	intZero := func(p *int) bool { return p == nil || *p == 0 }
	boolZero := func(p *bool) bool { return p == nil || !*p }
	return map[string]bool{
		"mode":                  r.Mode == nil || *r.Mode == "" || *r.Mode == "off",
		"crs_rule_groups":       strZero(r.CRSRuleGroups),
		"rate_limit_rps":        intZero(r.RateLimitRPS),
		"waf_check_response":    boolZero(r.WAFCheckResponse),
		"ip_acl_enabled":        boolZero(r.IPACLEnabled),
		"ip_acl_list":           strZero(r.IPACLList),
		"ip_whitelist_enabled":  boolZero(r.IPWhitelistEnabled),
		"ip_whitelist":          strZero(r.IPWhitelist),
		"ip_blacklist":          strZero(r.IPBlacklist),
		"geoip_mode":            r.GeoIPMode == nil || *r.GeoIPMode == "" || *r.GeoIPMode == "off",
		"geoip_countries":       strZero(r.GeoIPCountries),
		"geoip_crawler_engines": strZero(r.GeoIPCrawlerEngines),
		"block_page_id":         intZero(r.BlockPageID),
		"block_status_code":     intZero(r.BlockStatusCode),
		"trust_detection":       boolZero(r.TrustDetection),
	}
}

func hasNonZero(shape map[string]bool) bool {
	for _, zeroed := range shape {
		if !zeroed {
			return true
		}
	}
	return false
}
