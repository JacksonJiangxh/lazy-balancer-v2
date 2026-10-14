package services

import (
	"context"
	"fmt"

	"lazy-balancer-v2/internal/db"
)

// legacySecurityEnumBackfills 把 历史问题 之前落库的枚举空串行归一到 Create 侧
// 默认值（历史问题 发现1）：空串行在发射端零产出规则而 UI 宣称控制已启用，且
// Update 对空串 400 拒绝导致无法手动修复，集群快照又原样镜像到从节点。
var legacySecurityEnumBackfills = []string{
	"UPDATE security_policies SET ip_acl_mode='deny' WHERE COALESCE(TRIM(ip_acl_mode),'')=''",
	"UPDATE security_policies SET mode='off' WHERE COALESCE(TRIM(mode),'')=''",
	"UPDATE security_policies SET geoip_mode='deny' WHERE COALESCE(TRIM(geoip_mode),'')=''",
	// 历史问题 B-N5：历史问题 F3 之前落库的 threshold=0 行——UI 显示 0、发射端 >0 判断
	// 跳过阈值 SecAction 而 CRS 回落默认 5（「UI 宣称 0、实际 5」的展示/行为
	// 漂移，与空串枚举行同型）。归一到 Create 侧 max1(x,5) 的默认值 5。
	// 库值唯一真相（批 3）：口径从 `=0` 扩为 `<=0`——写侧 max1/枚举白名单恒
	// 产生正值，负值只能是带外直写；NULL 由 COALESCE(...,0) 归并同分支。
	// 渲染侧对回填后仍无效的值 fail-visible（BuildCorazaDirectives）。
	// G6（历史）：字面量 5 改绑定 db.DefaultAnomalyThreshold 单源。
	fmt.Sprintf("UPDATE security_policies SET anomaly_threshold=%d WHERE COALESCE(anomaly_threshold,0)<=0", db.DefaultAnomalyThreshold),
	// 历史问题（历史）：429 已剔除出拦截状态码白名单（限流专用语义，
	// overviewmetrics.go 限流卡片按 code=429 计数，WAF 拦截页 429 会混入
	// 限流指标口径）——存量 429 行归一为默认拦截状态码 403。
	// security_block_pages 无 status_code 列（db.go:492-502，遗留列口径见
	// db.go:1234-1236），429 仅可能存于 security_policies。
	// 库值唯一真相（批 3）：从 `=429` 扩为枚举外全集（写侧白名单 0/400/401/
	// 403/404/503，0=未设置跟随默认 403 为类型②省略型合法值）——旧备份/带外
	// 脏值（如 418）随启动归一，渲染层不再消费枚举外状态码。
	"UPDATE security_policies SET block_status_code=403 WHERE block_status_code IS NOT NULL AND block_status_code NOT IN (0,400,401,403,404,503)",
	// G2（历史，用户裁定方案①）：rate_limit_rps 历史脏行（enabled=1 &
	// rps<1，修复前 Update 缺陷可落库）绑定启用规则时整份配置生成失败
	// （渲染层 fail-visible）。启动归一关停业务开关——rps 库值保持原样
	//（不造假默认值），INFO 摘要行披露归一计数；写侧 validateRateLimitShape
	// 现行校验 rps>=1，本条仅兜历史形态。
	"UPDATE security_policies SET rate_limit_enabled=0 WHERE rate_limit_enabled=1 AND COALESCE(rate_limit_rps,0)<1",
}

// ValidBlockStatusCode 报告 v 是否为拦截状态码合法值：写侧
// validateSecurityPolicyEnums 白名单（400/401/403/404/503）+ 0=未设置跟随
// 默认 403（类型②省略型合法值，批 3 Ruling）。导入门（handlers）与集群
// apply 门共用本谓词。
func ValidBlockStatusCode(v int) bool {
	switch v {
	case 0, 400, 401, 403, 404, 503:
		return true
	}
	return false
}

// NormalizeLegacySecurityPolicyEnums 启动时一次性归一 security_policies 的
// 遗留枚举空串行。主节点：实际变更 >0 时在同一事务内递增集群版本，从节点随
// 下次同步收敛。从节点按 sync_security 分流（历史问题）：
//   - sync_security=1：完全跳过（历史问题-3）——主节点快照权威下发；若主节点为
//     无归一修复的旧版本，本地归一会与旧主快照互相覆盖（归一翻转 ACL 发射
//     行为 → 首次 Pull 漂移全量重拉 → 快照恢复遗留空串行），每重启一次行为
//     翻转一次；保留遗留空串行是旧主集群下的一致状态。
//   - sync_security=0：security 段被门控、没有快照流，本地归一是遗留空串行
//     唯一修复路径（Update 400 拒修、发射端零规则），执行归一但不 bump
//     集群版本（从节点无版本权威，bump 会与主节点版本流冲突）。
func NormalizeLegacySecurityPolicyEnums(ctx context.Context) {
	var isMaster, syncSecurity bool
	if err := db.DB.QueryRowContext(ctx, "SELECT COALESCE(is_master,1), COALESCE(sync_security,1) FROM global_config WHERE id=1").Scan(&isMaster, &syncSecurity); err != nil {
		Logf("warn", "security enum normalize: failed to read cluster role, skipping: %v", err)
		return
	}
	if !isMaster && syncSecurity {
		return
	}
	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		Logf("error", "security enum normalize: failed to begin transaction: %v", err)
		return
	}
	defer tx.Rollback()
	var versionBefore int64
	if isMaster {
		if err := tx.QueryRowContext(ctx, "SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&versionBefore); err != nil {
			Logf("error", "security enum normalize: failed to read cluster version: %v", err)
			return
		}
	}
	var changed int64
	for _, stmt := range legacySecurityEnumBackfills {
		res, err := tx.ExecContext(ctx, stmt)
		if err != nil {
			Logf("error", "security enum normalize: backfill failed: %v", err)
			return
		}
		n, err := res.RowsAffected()
		if err != nil {
			Logf("error", "security enum normalize: failed to read affected rows: %v", err)
			return
		}
		changed += n
	}
	if changed == 0 {
		return
	}
	if isMaster {
		// 二次启动起行级版本触发器已持久化于库，上方每条 UPDATE 已按命中行数
		// bump 过；显式递增会叠加成多次（历史问题-F1）。落「启动前值+1」的确定性
		// 值：无论触发器是否已安装/触发，一次启动归一只净增 1，测试（无触发
		// 器）与生产口径一致。版本语义只需单调递增，多次 bump 折叠为一次不
		// 影响从节点收敛。
		if _, err := tx.ExecContext(ctx, "UPDATE global_config SET cluster_version=? WHERE id=1", versionBefore+1); err != nil {
			Logf("error", "security enum normalize: failed to bump cluster version: %v", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		Logf("error", "security enum normalize: failed to commit: %v", err)
		return
	}
	if isMaster {
		Logf("info", "security enum normalize: normalized %d legacy rows (empty-enum/threshold/status-code/rate-limit dirty rows), cluster version bumped", changed)
	} else {
		Logf("info", "security enum normalize: normalized %d legacy rows (empty-enum/threshold/status-code/rate-limit dirty rows; slave, sync_security off, no version authority)", changed)
	}
}
