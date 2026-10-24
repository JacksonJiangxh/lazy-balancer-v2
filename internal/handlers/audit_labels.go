package handlers

// enabledStateLabel 是「开/关」审计文案的唯一出处。审计留痕必须记录**目标
// 状态**（旧实现只写「自动更新总开关」/「X 更新开关」，事后无法从操作日志
// 判断这次点击是开还是关）。同域两套口径分工：本函数（开启/关闭）用于调度/
// 开关类状态位；api_keys 与自动封禁的「启用：开/关」用 boolOnOff（单字段
// 布尔在变更差分里更易读）。新增状态位请按此分工取用，不再自造第三套词。
func enabledStateLabel(enabled bool) string {
	if enabled {
		return "开启"
	}
	return "关闭"
}
