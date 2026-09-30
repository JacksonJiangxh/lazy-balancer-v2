package services

import (
	"lazy-balancer-v2/internal/taskengine"
	"time"
)

// writeCRSUpdateLog 规则库变更流水唯一写口（R63-P2-2/P2-3：tee 单点在写口——
// Append* 包装层不再重复 tee；旧 crs-update.log 已退役——tasks/crs.log 为
// 唯一数据源，轮转/保留由 taskLogsHousekeeping 统一执行）。
func writeCRSUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("crs", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}

// AppendCRSUpdateLog 供非更新器路径(lbbak 导入/集群同步)记录规则库变更日志
// （2026-09-18 用户裁定：同步/导入有变动也要留痕；R63 单源裁定后留痕落
// tasks/crs.log——经 writeCRSUpdateLog 单点）。
func AppendCRSUpdateLog(level, stage, message string) {
	writeCRSUpdateLog(level, stage, message)
}
