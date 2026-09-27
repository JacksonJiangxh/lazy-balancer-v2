package handlers

import "testing"

// F64 用户名策略（2026-09-28 用户裁定）：仅允许小写英文开头，
// 字符只允许小写字母或小写字母+数字。
func TestValidateUsernamePolicy(t *testing.T) {
	valid := []string{"admin", "root", "user123", "abc", "a1b2c3"}
	invalid := []string{
		"Admin",    // 大写开头
		"1abc",     // 数字开头
		"admin-",   // 连字符
		"admin_",   // 下划线
		"管理员",      // 汉字
		"admin@",   // 特殊字符
		"Admin123", // 大写字母
		"",         // 空串
		" admin",   // 前导空格
	}
	for _, u := range valid {
		if err := validateUsernamePolicy(u); err != nil {
			t.Errorf("validateUsernamePolicy(%q) = %v, want nil", u, err)
		}
	}
	for _, u := range invalid {
		if err := validateUsernamePolicy(u); err == nil {
			t.Errorf("validateUsernamePolicy(%q) = nil, want error", u)
		}
	}
}
