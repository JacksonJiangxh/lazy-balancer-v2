package handlers

// 历史问题（历史）：生产文件不再承载「仅测试消费」的入口——原
// config_backup.go 的 validateV2BackupTLSShape（软入口的零参数硬包装，生产
// 零调用）与 config_backup_lbbak.go 的 buildLbbakPayload（threatSnapshot
// 缺省捷径，生产零调用）迁移到本文件。两者语义完全不变，仅为消除「生产文件
// 里看似第二条调用链」的维护误导；历史修复 既有用例与本包各夹具同包消费。
//
// 新增测试请优先使用正式入口（validateV2BackupTLSShapeSoft /
// buildLbbakPayloadWithThreatIplists）——本文件仅是历史用例的兼容壳。

import (
	"lazy-balancer-v2/internal/services"
)

// validateV2BackupTLSShape 硬包装：软入口 + 关闭 历史修复 软降级（live ACME
// 引用悬挂即硬错误）。生产导入/预览一律显式调用 validateV2BackupTLSShapeSoft
// 并按分类决定软降级方向。
func validateV2BackupTLSShape(tables map[string][]map[string]any) error {
	_, err := validateV2BackupTLSShapeSoft(tables, false)
	return err
}

// buildLbbakPayload 组包便捷入口：威胁名单在缺省快照时即时读取（仅测试/独立
// 调用形态）。生产导出必须经 buildLbbakPayloadWithThreatIplists 传入
// WafFileLock 内的内存快照（长持锁以外的稳定代）。
func buildLbbakPayload(backupJSON []byte, bundle *services.WafFileBundle) ([]byte, error) {
	return buildLbbakPayloadWithThreatIplists(backupJSON, bundle, nil)
}
