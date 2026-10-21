package handlers

// enabledStateLabel 是「开/关」审计文案的唯一出处。审计留痕必须记录**目标
// 状态**（旧实现只写「自动更新总开关」/「X 更新开关」，事后无法从操作日志
// 判断这次点击是开还是关）；同域还存在三份内联副本，统一经本函数。
func enabledStateLabel(enabled bool) string {
	if enabled {
		return "开启"
	}
	return "关闭"
}
