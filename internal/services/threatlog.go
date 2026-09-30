package services

import (
	"lazy-balancer-v2/internal/taskengine"
	"time"
)

// 威胁情报库更新日志（v2.3.2 名单化重构；R63-P2-3 单源裁定后 tasks/threat.log
// 为唯一数据源——旧 threat-update.log 已退役，轮转/保留由 taskLogsHousekeeping
// 统一执行）。

// SetUpdateLogDirForTest 覆写测试目录 seam（历史形态保留——部分测试仍以
// 目录覆写驱动；写侧已不落盘该目录，仅维持兼容供逐步迁移）。
func SetUpdateLogDirForTest(dir string) (restore func()) {
	// no-op（R63-P2-3 后无目录状态可覆写；保留签名防测试编译断裂）。
	return func() {}
}

// AppendThreatUpdateLog 写一条威胁库更新日志（更新任务与同步/导入路径共用——
// tee 单点落 tasks/threat.log）。
func AppendThreatUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("threat", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}
