package handlers

// 生产文件不再承载「仅测试消费」的入口——原
// config_backup.go 的 validateV2BackupTLSShape（软入口的零参数硬包装，生产
// 零调用）与 config_backup_lbbak.go 的 buildLbbakPayload（threatSnapshot
// 缺省捷径，生产零调用）迁移到本文件。两者语义完全不变，仅为消除「生产文件
// 里看似第二条调用链」的维护误导；既有用例与本包各夹具同包消费。
//
// 新增测试请优先使用正式入口（validateV2BackupTLSShapeSoft /
// buildLbbakPayloadWithThreatIplists）——本文件仅是历史用例的兼容壳。

import (
	"lazy-balancer-v2/internal/services"
)

// validateV2BackupTLSShape 硬包装：软入口 + 关闭软降级（live ACME
// 引用悬挂即硬错误）。生产导入/预览一律显式调用 validateV2BackupTLSShapeSoft
// 并按分类决定软降级方向。
func validateV2BackupTLSShape(tables map[string][]map[string]any) error {
	_, err := validateV2BackupTLSShapeSoft(tables, false)
	return err
}

// buildLbbakPayload 组包便捷入口（历史用例兼容壳）：威胁名单原文按生产同款
// 快照函数从磁盘构造后传给正式入口——正式入口不再提供「锁外直读」回退，
// 缺件一律显式失败（与生产导出同一语义）。
func buildLbbakPayload(backupJSON []byte, bundle *services.WafFileBundle) ([]byte, error) {
	threatSnapshot, err := snapshotLbbakThreatIplists(bundle)
	if err != nil {
		return nil, err
	}
	return buildLbbakPayloadWithThreatIplists(backupJSON, bundle, threatSnapshot)
}
