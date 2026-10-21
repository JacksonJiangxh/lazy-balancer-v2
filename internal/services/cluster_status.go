package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"lazy-balancer-v2/internal/models"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// nodeHealthWarn 是节点列表 health_json 解析失败的限频状态（历史问题-08）：
// Nodes() 每次节点列表请求都会碰到同一坏行，前端轮询（秒级/十秒级）下同一条
// warn 会持续刷屏。与同包 snapshotRowIsolation / throttled*Logf 家族同口径：
// 同一 nodeID 在窗口内只告警一次，插入时顺带回收过期键（节点 ID 有界）。
var (
	nodeHealthWarnMu     sync.Mutex
	nodeHealthWarnSeen   = map[int]time.Time{}
	nodeHealthWarnWindow = 60 * time.Second
)

// warnNodeHealthParseThrottled 按 nodeID 限频输出 health_json 解析失败告警。
func warnNodeHealthParseThrottled(nodeID int, cause error, now time.Time) {
	nodeHealthWarnMu.Lock()
	last, seen := nodeHealthWarnSeen[nodeID]
	if seen && now.Sub(last) < nodeHealthWarnWindow {
		nodeHealthWarnMu.Unlock()
		return
	}
	nodeHealthWarnSeen[nodeID] = now
	for id, seenAt := range nodeHealthWarnSeen {
		if now.Sub(seenAt) >= nodeHealthWarnWindow {
			delete(nodeHealthWarnSeen, id)
		}
	}
	nodeHealthWarnMu.Unlock()
	Logf("warn", "解析节点 %d 健康状态失败: %v", nodeID, cause)
}

// RoleOf 读取节点角色（主节点=true）的单源实现（历史问题-07）。COALESCE(is_master,1)
// 与 readonly 写闸（readonly.go）及 cluster_version 触发器口径一致：历史库 NULL
// 视为主节点。历史问题 迁移（db.go）已回填存量 NULL，稳态不可达，
// 此处为纵深防御一致性（2026-09-06 集群审计 历史问题 / 历史修复 复核结论）——此前裸
// SELECT 对 NULL Scan 失败会使 requireMaster/Promote 走 500，
// 同一脏数据在两守卫处语义相反。
//
// 读失败语义由调用方决定（fail-open 主节点 / 500 / 跳过本轮）：本函数只做
// 单源读取，不做策略；新调用点禁止再内联 SQL（历史：25 处重复实现已
// 出现失败语义分叉，本批先收敛 cluster 相关点，residual 见修复报告）。
func RoleOf(ctx context.Context, database *sql.DB) (bool, error) {
	if database == nil {
		return false, errors.New("读取节点模式: 数据库未初始化")
	}
	var isMaster bool
	if err := database.QueryRowContext(ctx, "SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		return false, fmt.Errorf("读取节点模式: %w", err)
	}
	return isMaster, nil
}

// IsMaster 读取节点角色（ClusterService 便捷包装，语义见 RoleOf）。
func (s *ClusterService) IsMaster(ctx context.Context) (bool, error) {
	return RoleOf(ctx, s.db)
}

func (s *ClusterService) BecomeSlave(ctx context.Context, masterURL string, registration models.ClusterRegistration) error {
	s.roleMu.Lock()
	defer s.roleMu.Unlock()
	var previousMasterURL, previousToken string
	if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(master_url,''),COALESCE(cluster_token,'') FROM global_config WHERE id=1`).Scan(&previousMasterURL, &previousToken); err != nil {
		return fmt.Errorf("读取当前集群拓扑: %w", err)
	}
	// 换主与升主同样需要排干旧拓扑已准入的拉取：否则旧主快照的提交后
	// 阶段可能越过新凭据落库点，继续物化旧配置/触发旧 Caddy 重载。
	// 历史问题-06：同库全部实例逐个排干（只处理最后注册的一个会漏掉在途 apply）。
	drainers := syncDrainersFor(s.db)
	if len(drainers) > 0 {
		for _, drainer := range drainers {
			// 历史问题-01：排干成功后所有返回路径都必须恢复拉取准入。原实现只在
			// 成功尾部重开——下方 UPDATE 失败（SQLITE_BUSY/磁盘满）时准入永久
			// 关闭；而「已是从节点换主」不触发引擎换代（SetRole(false) flipped=
			// false），旧 daemon 不会重新 Start，后续每轮 Pull 在 beginPull 即
			// 返回 errSyncPullStopped 且该哨兵刻意不落库 → 静默脱同步、状态面
			// 全绿、无自愈。defer 覆盖失败路径，成功路径另行提前重开。
			defer drainer.reopenPullAdmission()
		}
		for _, drainer := range drainers {
			if err := drainer.DrainPulls(ctx); err != nil {
				return fmt.Errorf("等待在途同步拉取结束: %w", err)
			}
		}
	}
	// 历史问题：last_sync 与 applied_version 同语义
	// ——旧集群的同步时间对新集群无意义，同一 UPDATE 里置 NULL，状态卡不残留
	// 旧集群时间（Status() 仅对 Valid 值格式化）。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始从节点拓扑事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE global_config SET is_master=0, master_url=?, cluster_token='', registration_id=?, registration_secret=?, applied_version=0, sync_fingerprint='', last_sync_error='', registration_confirm_failures=0, last_sync=NULL, applied_waf_ref_hash='', applied_waf_ref_version=0 WHERE id=1`, masterURL, registration.RegistrationID, registration.RegistrationSecret)
	if err != nil {
		return fmt.Errorf("保存从节点注册状态: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取从节点注册状态保存结果: %w", err)
	}
	if updated != 1 {
		return fmt.Errorf("保存从节点注册状态: 影响 %d 行", updated)
	}
	// 与 Promote 对称：旧拓扑的节哈希/WAF 文件态不得成为新主节点的
	// 跳过或漂移判定依据；清理与角色落库必须同成同败。
	if _, err := tx.ExecContext(ctx, `DELETE FROM cluster_applied_sections`); err != nil {
		return fmt.Errorf("清理从节点已应用节记账: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交从节点拓扑事务: %w", err)
	}
	// 拓扑已提交：先恢复拉取准入，再让新 daemon 起步——若等到函数尾部才重开，
	// 新循环的首次 Pull 可能撞上仍关闭的准入并以 errSyncPullStopped 静默失败
	//（该哨兵不落库），延迟 = 一个 sync_interval。
	if len(drainers) > 0 {
		for _, drainer := range drainers {
			drainer.reopenPullAdmission()
		}
	}
	// 历史问题-06：角色翻转显式失效快照缓存。缓存键只有 version/ownership/开关，
	// 降级瞬间在途的 master-only Run 可越过角色检查写库且 is_master=0 不 bump
	// 版本——若此后未发生任何 apply 就再次升主，旧缓存会被当作权威下发。
	clusterSnapshotCaches.Delete(s.db)
	// 历史问题-05：角色翻转后主节点期间的分区上报缓存不再有权威来源。
	s.clearAllSectionReports()
	// 角色翻转由引擎 SetRole 唯一驱动：master-only 任务统一停调，cluster-sync
	// 经 RestartOnRoleFlip 换代为从节点分支；无管理器/旧调度器旁路。
	// LINK-4：看门狗漂移状态必须先于 SetRole 复位——放末尾会在 SetRole(false)
	// 与复位之间打开窗口，在途看门狗轮次按从节点角色对旧主节点的漂移状态
	// 误报一次「配置漂移」。升主路径（cluster.go Promote）已是先复位后换角色。
	ResetConfigDrift()
	if te := TaskEngine(); te != nil {
		te.SetRole(false)
		// 历史问题：SetRole 只按角色启停 daemon，
		// 不会覆盖主节点期间被用户停止的 loopEnabled——切从是本机拓扑变更
		// （等价基线的 StartSync 直调），不同步即为静默脱管，必须显式恢复调度。
		te.StartLoop("cluster-sync")
		// 历史问题：偏好表若仍保留主节点期间的 cluster-sync=0，下次重启会再次
		// 停同步。切从是显式拓扑变更——持久偏好同步恢复（写失败仅告警，
		// 当前进程已启动）。
		if err := RecordTaskLoopPref("cluster-sync", true); err != nil {
			Logf("warn", "切成从节点后持久化 cluster-sync 调度偏好失败（当前进程已恢复）: %v", err)
		}
	}
	// 拉取准入已在上方拓扑提交后重开（defer 兜底失败路径）；此处不再重复。
	if len(drainers) > 0 {
		// 历史问题-05(b)：换主后内存 TOFU pin 缓存与磁盘生命周期对齐——磁盘侧由
		// detachFromMaster 删除旧主 pin，内存 verifiedPins 若不清空会残留旧主
		// 指纹（与 Promote handler 的 ForgetClusterPins 收尾对称）。同主重注册
		// 也一并清空：下次请求按 pin 文件重钉，行为等价且无落盘副作用。
		for _, drainer := range drainers {
			drainer.ForgetClusterPins()
		}
	}
	// 仅在主节点地址实际变化时通知旧主。相同主节点重新注册可能刚复用
	// 节点行， detached 会误删本次新注册。
	if previousToken != "" && strings.TrimRight(previousMasterURL, "/") != strings.TrimRight(masterURL, "/") {
		s.detachFromMaster(ctx, previousMasterURL, previousToken)
	}
	ResetConfigDrift()
	return nil
}

func (s *ClusterService) UpdateSettings(ctx context.Context, req models.ClusterSettingsRequest) error {
	isMaster, err := s.IsMaster(ctx)
	if err != nil {
		return err
	}
	if !isMaster {
		return ErrSlaveReadOnly
	}
	// sync_interval 无下限校验会让从节点 run 循环 waitDelay(0) 进入零间隔
	// Pull 风暴（主节点被持续高压请求打满）；上限 86400 防误填（历史问题 发现1）。
	if req.SyncInterval != nil && (*req.SyncInterval < minSyncIntervalSeconds || *req.SyncInterval > maxSyncIntervalSeconds) {
		return ErrInvalidSyncInterval
	}
	if s.beforeUpdateSettings != nil {
		s.beforeUpdateSettings()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始集群设置事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if req.SyncInterval != nil {
		result, err := tx.ExecContext(ctx, "UPDATE global_config SET sync_interval=? WHERE id=1 AND COALESCE(is_master,1)=1", *req.SyncInterval)
		if err != nil {
			return fmt.Errorf("更新同步间隔: %w", err)
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("读取同步间隔更新结果: %w", err)
		}
		if updated != 1 {
			return ErrSlaveReadOnly
		}
	}
	// 系统数据恒同步(2026-09-11 裁定):users/api_keys/ACME 等确保系统基本
	// 运行的数据不可禁用同步(证书任务行与文件随负载规则开关,历史修复)。
	// 历史问题:哨兵错误使 handler 映射 400(客户端错误,与间隔校验同型)。
	if req.SyncUsers != nil && !*req.SyncUsers {
		return ErrSyncUsersLocked
	}
	switchUpdates := []struct {
		name string
		val  *bool
	}{
		{"sync_users", req.SyncUsers},
		{"sync_rules", req.SyncRules},
		{"sync_security", req.SyncSecurity},
	}
	for _, sw := range switchUpdates {
		if sw.val == nil {
			continue
		}
		result, err := tx.ExecContext(ctx, "UPDATE global_config SET "+sw.name+"=? WHERE id=1 AND COALESCE(is_master,1)=1", *sw.val)
		if err != nil {
			return fmt.Errorf("更新 %s: %w", sw.name, err)
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("读取 %s 更新结果: %w", sw.name, err)
		}
		if updated != 1 {
			return ErrSlaveReadOnly
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交集群设置: %w", err)
	}
	return nil
}

func (s *ClusterService) Status(ctx context.Context) (models.ClusterStatus, error) {
	var status models.ClusterStatus
	var isMaster bool
	var clusterToken string
	var lastSync sql.NullTime
	var storedSyncError string
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(is_master,1), COALESCE(cluster_version,0), COALESCE(master_url,''), COALESCE(sync_interval,60), COALESCE(sync_users,1), COALESCE(sync_rules,1), COALESCE(sync_security,1), COALESCE(cluster_token,''), COALESCE(applied_version,0), last_sync, COALESCE(last_sync_error,'') FROM global_config WHERE id=1`).Scan(
		&isMaster, &status.ClusterVersion, &status.MasterURL, &status.SyncInterval, &status.SyncUsers, &status.SyncRules, &status.SyncSecurity, &clusterToken, &status.AppliedVersion, &lastSync, &storedSyncError)
	if err != nil {
		return models.ClusterStatus{}, fmt.Errorf("读取集群状态: %w", err)
	}
	// 历史问题-1(历史)/历史问题-1(历史幻影修复修正——clamp 曾被误插
	// 在上方 return 之后不可达,go vet unreachable 实证):展示口径与运行时 clamp
	// 对齐(cluster_sync.go 的 run 循环 interval clamp,<10 → 60)——存量脏值
	// (0/负/1-9s)不再原样展示与运行时分叉。(历史问题:原注释的固定行号已漂移,
	// 改为符号化定位。)
	status.SyncInterval = normalizeSyncInterval(status.SyncInterval)
	status.LastSyncError, status.SyncErrorCode = decodeSyncError(storedSyncError)
	status.NodeMode = "slave"
	status.ClusterActive = clusterToken != ""
	// 历史问题-09：链路明文常驻标志——注册时刻只告警一次，之后面板无从得知当前
	// 上行为明文（快照承载证书私钥/CA 与 DNS 凭据、服务控制票据为 Bearer，且
	// HTTP 下 TOFU 指纹防护完全不生效）。前端据 transport_insecure 常驻提示。
	if !isMaster && status.MasterURL != "" {
		if parsed, parseErr := url.Parse(status.MasterURL); parseErr == nil && parsed.Scheme == "http" {
			status.TransportInsecure = true
		}
	}
	if isMaster {
		status.NodeMode = "master"
		status.ClusterActive = true
		if err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(CASE WHEN is_approved=0 THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN is_approved=1 THEN 1 ELSE 0 END),0) FROM nodes`).Scan(&status.PendingCount, &status.ApprovedCount); err != nil {
			return models.ClusterStatus{}, fmt.Errorf("统计集群节点: %w", err)
		}
	}
	if lastSync.Valid {
		status.LastSyncAt = lastSync.Time.UTC().Format(time.RFC3339)
	}
	return status, nil
}

func (s *ClusterService) Nodes(ctx context.Context, now time.Time) ([]models.ClusterNodeView, error) {
	var currentVersion, syncInterval int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(cluster_version,0), COALESCE(sync_interval,60) FROM global_config WHERE id=1").Scan(&currentVersion, &syncInterval); err != nil {
		return nil, fmt.Errorf("读取集群版本: %w", err)
	}
	var masterSiteLat, masterSiteLon float64
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(server_map_lat,0), COALESCE(server_map_lon,0) FROM global_config WHERE id=1").Scan(&masterSiteLat, &masterSiteLon); err != nil {
		return nil, fmt.Errorf("读取主节点默认站点坐标: %w", err)
	}
	masterSiteConfigured := masterSiteLat != 0 || masterSiteLon != 0
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,''),is_approved,COALESCE(reported_version,0),COALESCE(health_json,''),last_seen,created_at,COALESCE(server_map_lat,0),COALESCE(server_map_lon,0) FROM nodes ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取节点列表: %w", err)
	}
	defer rows.Close()
	nodes := make([]models.ClusterNodeView, 0)
	for rows.Next() {
		var node models.ClusterNodeView
		var lastSeen, createdAt sql.NullTime
		var healthJSON string
		if err := rows.Scan(&node.ID, &node.Name, &node.IPAddress, &node.Port, &node.Protocol, &node.AccessURL, &node.IsApproved, &node.ReportedVersion, &healthJSON, &lastSeen, &createdAt, &node.ServerMapLat, &node.ServerMapLon); err != nil {
			return nil, fmt.Errorf("扫描节点列表: %w", err)
		}
		node.CurrentVersion = currentVersion
		if node.ServerMapLat == 0 && node.ServerMapLon == 0 && masterSiteConfigured {
			node.ServerMapLat = masterSiteLat
			node.ServerMapLon = masterSiteLon
			node.SiteInherited = true
		}
		node.Status = ComputeNodeStatus(node.IsApproved, lastSeen.Time, syncInterval, now)
		// 单节点 health_json 损坏只降级该节点（Health=nil），不拖垮整个节点列表
		health, decodeErr := DecodeClusterHealth(healthJSON)
		if decodeErr != nil {
			// 历史问题-08：同一坏行按 nodeID 限频告警（节点页轮询不再刷屏）。
			warnNodeHealthParseThrottled(node.ID, decodeErr, now)
		} else {
			node.Health = health
		}
		if lastSeen.Valid {
			node.LastSeen = lastSeen.Time.UTC().Format(time.RFC3339)
		}
		if createdAt.Valid {
			node.CreatedAt = createdAt.Time.UTC().Format(time.RFC3339)
		}
		nodes = append(nodes, node)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	attachSectionSync(ctx, s, nodes, currentVersion)
	return nodes, nil
}

// clusterSectionHashCache 主节点三节哈希的进程内缓存：键=(库句柄,
// cluster_version)。与快照缓存同一失效维度——任一配置写（含登录锁/密钥
// 使用等任意 bump）都会推进版本并让本缓存失效；同版本内的节点列表轮询
// （默认 60s 或更高频）零重算（driftGuardSectionHashes 要跑只读事务装载
// 三节全部输入 + 三次 JSON 序列化 + SHA-256）。
type clusterSectionHashCacheEntry struct {
	version int
	hashes  map[string]string
}

var (
	clusterSectionHashCacheMu sync.Mutex
	clusterSectionHashCache   = map[*sql.DB]clusterSectionHashCacheEntry{}
	// clusterSectionHashBuilds 实际重建次数（测试观测同版本零重算）。
	clusterSectionHashBuilds atomic.Int64
)

// resetClusterSectionHashCacheForTest 测试缝：清空版本缓存（生产不调用）。
func resetClusterSectionHashCacheForTest() {
	clusterSectionHashCacheMu.Lock()
	clusterSectionHashCache = map[*sql.DB]clusterSectionHashCacheEntry{}
	clusterSectionHashCacheMu.Unlock()
}

// masterSectionHashes 返回主节点三节哈希（version=当前 cluster_version）。
// 命中返回缓存（只读，调用方不得修改）；失败不缓存、错误上抛由调用方降级。
func (s *ClusterService) masterSectionHashes(ctx context.Context, version int) (map[string]string, error) {
	clusterSectionHashCacheMu.Lock()
	entry, ok := clusterSectionHashCache[s.db]
	clusterSectionHashCacheMu.Unlock()
	if ok && entry.version == version {
		return entry.hashes, nil
	}
	hashes, err := s.driftGuardSectionHashes(ctx)
	if err != nil {
		return nil, err
	}
	clusterSectionHashBuilds.Add(1)
	clusterSectionHashCacheMu.Lock()
	// 多库进程（测试/多实例）下按句柄各留一条；条目数等于库句柄数，量级极小。
	if len(clusterSectionHashCache) > 16 {
		clusterSectionHashCache = map[*sql.DB]clusterSectionHashCacheEntry{}
	}
	clusterSectionHashCache[s.db] = clusterSectionHashCacheEntry{version: version, hashes: hashes}
	clusterSectionHashCacheMu.Unlock()
	return hashes, nil
}

// attachSectionSync 为已上报分区哈希的节点聚合 per-section 同步状态：主节点
// 自身节哈希与同步开关过滤每次请求只计算一次；任一依赖读取失败时整体降级
// （所有节点 SectionSync 保持 nil，等同旧版本从节点占位），绝不把错误上抛
// 拖垮节点列表，也绝不展示可能失真的「全部滞后」。
// clusterVersion 由调用方（Nodes）在同一请求内读取，作为主节点哈希缓存的
// 失效键——与快照缓存同一版本口径。
func attachSectionSync(ctx context.Context, s *ClusterService, nodes []models.ClusterNodeView, clusterVersion int) {
	reports := s.snapshotSectionReports()
	hasReport := false
	for i := range nodes {
		if nodes[i].IsApproved && reports[nodes[i].ID] != nil {
			hasReport = true
			break
		}
	}
	if !hasReport {
		return
	}
	switches, err := readSyncSwitches(ctx, s.db)
	if err != nil {
		Logf("warn", "读取同步开关失败（分区同步状态降级省略）: %v", err)
		return
	}
	// 本函数只消费 users/rules/security 三节哈希，不得走全量快照
	// 构建路径——那条路径会做 WAF 全树 tar.gz 哈希与全部 ACME 证书 X.509
	// 解析，并在 cache.mu 内阻塞从节点快照拉取、在 wafFileMu 内阻塞 CRS
	// 更新/导入；而任意一次 cluster_version 递增（例如一次登录锁变更）都会
	// 让下一次节点列表轮询触发重建。driftGuardSectionHashes 与
	// ComputeSnapshotSectionHashes 共用同一 sectionPayloadFor 口径（有奇偶
	// 不变式钉测），只装载三节输入——并按 cluster_version 缓存，同版本轮询
	// 零重算。
	masterHashes, err := s.masterSectionHashes(ctx, clusterVersion)
	if err != nil {
		Logf("warn", "计算主节点分区哈希失败（分区同步状态降级省略）: %v", err)
		return
	}
	for i := range nodes {
		if !nodes[i].IsApproved {
			continue
		}
		if reported := reports[nodes[i].ID]; reported != nil {
			nodes[i].SectionSync = buildSectionSyncStatuses(reported, masterHashes, switches)
		}
	}
}

// buildSectionSyncStatuses 按主节点开关过滤节，逐节比对从节点上报哈希与主节点
// 自身哈希；从节点缺该节记录（从未同步/开关曾关闭）按滞后处理。
func buildSectionSyncStatuses(reported, masterHashes map[string]string, switches SyncSwitches) []models.ClusterSectionSyncStatus {
	statuses := make([]models.ClusterSectionSyncStatus, 0, len(syncSections))
	for _, sec := range syncSections {
		if !switches.sectionEnabled(sec.Key) {
			continue
		}
		hash := reported[sec.Key]
		masterHash := masterHashes[sec.Key]
		statuses = append(statuses, models.ClusterSectionSyncStatus{
			Section:    sec.Key,
			Label:      sec.NewLabel,
			Hash:       hash,
			MasterHash: masterHash,
			Synced:     hash != "" && hash == masterHash,
		})
	}
	if len(statuses) == 0 {
		return nil
	}
	return statuses
}

// storeSectionReport 记录节点最近一次上报的分区哈希（防御性拷贝，调用方后续
// 改动上报载荷不影响已存状态）；空哈希视为旧版本从节点上报，清除既有记录。
func (s *ClusterService) storeSectionReport(nodeID int, hashes map[string]string) {
	s.sectionMu.Lock()
	defer s.sectionMu.Unlock()
	if s.sectionReports == nil {
		s.sectionReports = make(map[int]map[string]string)
	}
	if len(hashes) == 0 {
		delete(s.sectionReports, nodeID)
		return
	}
	stored := make(map[string]string, len(hashes))
	for key, hash := range hashes {
		stored[key] = hash
	}
	s.sectionReports[nodeID] = stored
}

func (s *ClusterService) snapshotSectionReports() map[int]map[string]string {
	s.sectionMu.Lock()
	defer s.sectionMu.Unlock()
	reports := make(map[int]map[string]string, len(s.sectionReports))
	for nodeID, hashes := range s.sectionReports {
		copied := make(map[string]string, len(hashes))
		for key, hash := range hashes {
			copied[key] = hash
		}
		reports[nodeID] = copied
	}
	return reports
}

func (s *ClusterService) clearSectionReport(nodeID int) {
	s.sectionMu.Lock()
	defer s.sectionMu.Unlock()
	delete(s.sectionReports, nodeID)
}

func (s *ClusterService) clearAllSectionReports() {
	s.sectionMu.Lock()
	defer s.sectionMu.Unlock()
	clear(s.sectionReports)
}

// ClearNodeSectionReports（历史问题/历史修复，历史修复主审授权扩展）：
// 拓扑整体恢复（备份导入）删除节点时，按库遍历登记的全部 ClusterService
// 实例清除该节点的分区上报缓存（与 clusterServicesFor 同模式——缓存是实例
// 本地状态，需逐实例清理）。仅用于「节点已被删除」的清理；仍存在的节点
// 不得调用（其上报记录保持有效，历史修复 裁定）。缓存本为内存态：进程重启或
// 节点下次上报（≤60s）可自愈，本函数消除的是「备份行复用已删节点 id 时
// 旧上报错挂到新节点」的窗口。
func ClearNodeSectionReports(database *sql.DB, nodeID int) {
	for _, service := range clusterServicesFor(database) {
		service.clearSectionReport(nodeID)
	}
}

func (s *ClusterService) ReportNode(ctx context.Context, nodeID int, report models.ClusterReport, now time.Time) error {
	health := report.Health
	// 历史问题-2:last_sync_error 落库前与从端写侧同口径截断(512B + UTF-8
	// 边界回退)——64KB 错误串不再撑大 nodes 行与 health_json。
	if len(report.LastSyncError) > 512 {
		report.LastSyncError = string(truncateValidUTF8Tail([]byte(report.LastSyncError[:512])))
	}
	health.LastSyncAt = report.LastSyncAt
	health.LastSyncError = report.LastSyncError
	health.SyncErrorCode = report.SyncErrorCode
	encoded, err := json.Marshal(health)
	if err != nil {
		return fmt.Errorf("编码节点健康状态: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `UPDATE nodes SET status='online',last_seen=?,reported_version=?,health_json=?,last_sync_at=?,last_sync_error=? WHERE id=? AND is_approved=1 AND `+masterRoleConditionSQL, now.UTC(), report.AppliedVersion, string(encoded), nullableString(report.LastSyncAt), report.LastSyncError, nodeID)
	if err != nil {
		return fmt.Errorf("更新节点上报: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取节点上报结果: %w", err)
	}
	if rows != 1 {
		// 历史问题：降级窗口内的上报按 403 语义拒绝，而不是误报 404。
		return s.nodeWriteMissError(ctx)
	}
	s.storeSectionReport(nodeID, report.SectionHashes)
	return nil
}

// resolveNodeAccessURL 推导节点访问地址的单源实现（历史问题）：显式
// access_url 优先，否则 protocol://ip:port；protocol 非 https 一律归一为 http
// （原四处逐字重复，口径漂移风险）。
func resolveNodeAccessURL(ipAddress string, port int, protocol, accessURL string) string {
	if protocol != "https" {
		protocol = "http"
	}
	if accessURL == "" {
		accessURL = protocol + "://" + net.JoinHostPort(ipAddress, strconv.Itoa(port))
	}
	return accessURL
}

// nodePinPathFromAccessURL 由节点访问地址定位其 TOFU pin 文件（单源：
// ForgetNodePin/DeleteNode 原各自重复「解析 URL → clusterPinPathForDatabase」）。
func nodePinPathFromAccessURL(database *sql.DB, accessURL string) (pinPath, host string, err error) {
	parsed, err := url.Parse(accessURL)
	if err != nil || parsed.Host == "" {
		return "", "", fmt.Errorf("节点访问地址无效: %q", accessURL)
	}
	pinPath, err = clusterPinPathForDatabase(database, parsed.Host)
	if err != nil {
		return "", "", err
	}
	return pinPath, parsed.Host, nil
}

func (s *ClusterService) DeleteNode(ctx context.Context, nodeID int) error {
	// 历史问题-05（历史）：nodes 不在 cluster_version 触发器清单——拓扑
	// 变更（注册/改坐标）历来在同事务显式 BumpClusterVersion，删除节点此前漏
	// bump：快照缓存（键含 cluster_version）会继续携带被删节点的站点项，直到
	// 下一次无关 bump（消费方仅该节点自身，功能影响≈0，但同族约定不得不对称
	// ——后续给 nodes 增加同步字段会漏传播）。此处把删行与 bump 并入同一事务。
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开启删除节点事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// 历史问题(历史):删行前取访问地址——删行后 pin 成孤儿且无 API
	// 清除通道,同 host:port 复用时服务控制 fail-closed PinMismatch 只能手工
	// 删盘。地址解析与 ForgetNodePin 同口径(access_url 优先)。
	var ipAddress, protocol, accessURL string
	var port int
	addrErr := tx.QueryRowContext(ctx, `SELECT ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,'') FROM nodes WHERE id=?`, nodeID).
		Scan(&ipAddress, &port, &protocol, &accessURL)
	result, err := tx.ExecContext(ctx, "DELETE FROM nodes WHERE id=? AND "+masterRoleConditionSQL, nodeID)
	if err != nil {
		return fmt.Errorf("删除节点: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		// 历史问题：降级窗口内的删除按 403 语义拒绝（节点仍在），而非 404。
		// 复核角色用独立连接（nodeWriteMissError），必须先退出写事务。
		_ = tx.Rollback()
		return s.nodeWriteMissError(ctx)
	}
	if err := BumpClusterVersion(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交删除节点: %w", err)
	}
	s.clearSectionReport(nodeID)
	// 行已删:清 pin(读址失败/无 pin/地址无效均不影响删除结果,仅留痕)。
	if addrErr != nil {
		Logf("warn", "DeleteNode %d: 读取访问地址失败，pin 清理已跳过: %v", nodeID, addrErr)
	}
	if addrErr == nil {
		accessURL = resolveNodeAccessURL(ipAddress, port, protocol, accessURL)
		if pinPath, host, perr := nodePinPathFromAccessURL(s.db, accessURL); perr == nil {
			if rerr := os.Remove(pinPath); rerr == nil {
				RecordAuditLog("system", "清除", "证书指纹", FormatAuditDetail(fmt.Sprintf("节点删除伴随清除 pin：%s", host), AuditResultPart("success")), "")
			} else if !errors.Is(rerr, os.ErrNotExist) {
				Logf("warn", "节点删除后清除 pin 失败(%s): %v", host, rerr)
			}
		}
	}
	return nil
}
