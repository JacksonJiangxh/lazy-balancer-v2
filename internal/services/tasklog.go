package services

import (
	"fmt"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// TaskLogf 业务摘要行（INFO 级，统一 tee 到 tasks/{id}.log）。
func TaskLogf(taskID, stage, format string, args ...any) {
	taskengine.TeeTaskLogTime(taskID, "INFO", stage, fmt.Sprintf(format, args...))
}

// TaskLogfWarn 业务告警行（WARN 级；状态变化/失败类信号使用）。
func TaskLogfWarn(taskID, stage, format string, args ...any) {
	taskengine.TeeTaskLogTime(taskID, "WARN", stage, fmt.Sprintf(format, args...))
}

// WriteCRSUpdateLog CRS 更新流水（单一日志入口，统一 tee 到 tasks/crs.log）。
func WriteCRSUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("crs", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}

// WriteIP2RegionUpdateLog IP2Region 更新流水（统一到 tasks/ip2region.log）。
func WriteIP2RegionUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("ip2region", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}

// AppendThreatUpdateLog 威胁库更新流水（统一到 tasks/threat.log）。
func AppendThreatUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("threat", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}

// 任务日志大小配置缓存（缓存机制单源 dbValueCache——此前与审计
// 侧各有一套实现，任务侧还把读库失败的回退值写进缓存）。TTL 5 分钟：设置保存
// 经 InvalidateTaskLogSizeCache 立刻生效，TTL 只覆盖带外改库。
var taskLogSizeCache = dbValueCache{ttl: 5 * time.Minute}

// InvalidateTaskLogSizeCache 使任务日志大小配置缓存失效。
// 设置保存成功后必须调用——否则改库后仍有最长 5 分钟（TTL）按旧阈值滚动。
func InvalidateTaskLogSizeCache() {
	taskLogSizeCache.invalidate()
}

func getTaskLogSizeBytes() int64 {
	// 未初始化库回退默认 10MB；与多数配置读取 helper 的 db.DB==nil 守卫一致。
	if db.DB == nil {
		return 10 * 1024 * 1024
	}
	return taskLogSizeCache.get(func() (int64, error) {
		var sizeMB int
		if err := db.DB.QueryRow("SELECT COALESCE(task_log_size_mb, 10) FROM global_config WHERE id = 1").Scan(&sizeMB); err != nil {
			Logf("warn", "读取任务日志大小配置失败,按 10MB 降级: %v", err)
			// 失败不缓存：回退值只对本轮生效，下一轮重试。
			return 0, err
		}
		if sizeMB <= 0 {
			sizeMB = 10
		}
		return int64(sizeMB) * 1024 * 1024, nil
	}, 10*1024*1024)
}
