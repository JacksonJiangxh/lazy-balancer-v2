package handlers

import "testing"

// 2026-10-04 用户裁定：dns_server 多地址逐地址守卫——splitDnsAddresses 拆分后
// 逐地址跑现有单地址校验（host[:port]/端口范围/非法字符），而非整串当单 host 放过。
// 当前 validateDnsServerShape 把 "a,b" 整串当 host 通过——RED。

func TestValidateDnsServerShape_multiAddressPerEntryValidation(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool // true=应通过
	}{
		{"垃圾地址无端口但非IP", "abc,def", false},
		{"合法多地址逗号分隔", "119.29.29.29,119.28.28.28", true},
		{"合法多地址中文逗号", "119.29.29.29，119.28.28.28", true},
		{"合法多地址带端口", "119.29.29.29:53,119.28.28.28:53", true},
		{"合法单地址", "8.8.8.8", true},
		{"空串", "", true},
		{"垃圾多地址非数字端口", "119.29.29.29:bad,119.28.28.28", false},
		{"垃圾多地址端口越界", "119.29.29.29:99999,119.28.28.28", false},
		{"垃圾多地址控制字符", "119.29.29.29\x01,119.28.28.28", false},
		{"单地址端口非法", "8.8.8.8:notaport", false},
		// 全数字点分但非合法 IP：netip 解析失败后被 isValidHost 的字母表校验
		// 放行，落库后渲染进 resolver.addresses → 动态上游解析静默失败（502）。
		{"全数字点分越界八位组", "999.1.1.1", false},
		{"全数字点分末段越界", "1.2.3.256", false},
		{"五段全数字点分", "1.2.3.4.5", false},
		{"全数字点分非法IP带端口", "999.1.1.1:53", false},
		// 防误伤：合法 IP 与含数字的域名不得被「全数字」判据波及。
		{"合法IP不误伤", "119.29.29.29", true},
		{"合法域名含数字标签", "dns1.example.com", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateDnsServerShape(c.raw)
			if c.want && err != nil {
				t.Errorf("validateDnsServerShape(%q) = %v, want nil", c.raw, err)
			}
			if !c.want && err == nil {
				t.Errorf("validateDnsServerShape(%q) = nil, want error", c.raw)
			}
		})
	}
}
