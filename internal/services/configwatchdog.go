package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

// ConfigDriftStatus 配置一致性看门狗的当前状态：数据库（唯一事实源）中应渲染的
// 规则与 Caddy 实际运行配置的比对结果。
type ConfigDriftStatus struct {
	Consistent bool     `json:"consistent"`
	Missing    []string `json:"missing"` // 应渲染但运行配置缺失的规则（名称（caddy_id））
	Extra      []string `json:"extra"`   // 运行配置中存在但 DB 已不存在的规则路由
	Since      string   `json:"since"`   // 首次确认不一致的时间（UTC）
	CheckedAt  string   `json:"checked_at"`
}

var (
	configDriftMu          sync.RWMutex
	configDriftStatus      = ConfigDriftStatus{Consistent: true}
	configDriftStreak      int
	configDriftCleanRounds int  // R66 心跳窗口：连续一致轮计数（60s 节拍 × 60 轮 ≈ 1h 一条心跳）
	configDriftQueryWarned bool // 规则数据读取失败首报留痕
	configDriftReadWarned  bool // 运行配置读取失败首报留痕
	configWatchdogMu       sync.Mutex
	configWatchdogCancel   context.CancelFunc
	configWatchdogDone     chan struct{}
)

// ResetConfigDrift 角色切换时重置看门狗状态——曾漂移的主节点降级为从节点后，
// 内存中的陈旧漂移态必须清除（从节点不再运行检查，状态不会自行过期）。
func ResetConfigDrift() {
	configDriftMu.Lock()
	defer configDriftMu.Unlock()
	configDriftStatus = ConfigDriftStatus{Consistent: true}
	configDriftStreak = 0
	configDriftCleanRounds = 0
	configDriftQueryWarned = false
	configDriftReadWarned = false
	// 引用型证书指纹快照同源重置：从→主切换后下一轮 scan 重新建基线，避免用
	// 旧快照误判「证书已更新」而触发一次多余重载。
	ResetReferencedCertWatch()
}

// 引用型证书（tls_source="file"）外部更新自动重载（2026-10-09）：用户直接维护
// /app/certs 内的成品证书文件（多项目公用），更新后看门狗在下一轮（60s 节拍）
// 检出文件内容指纹变化并强制重载 Caddy。因引用模式只传路径、配置 JSON 与路径
// 均未变，Caddy changeConfig 会按「同字节」短路——必须走 force 变体绕过，否则
// Caddy 内存仍停留旧证书（重载静默不生效）。
var (
	referencedCertWatchMu    sync.Mutex
	referencedCertWatchState = map[string]string{}
	referencedCertWatchReady bool
	referencedCertReloadFn   func() error
)

// SetReferencedCertReload 注入引用型证书变化后的强制重载实现（main: caddyReloader）。
func SetReferencedCertReload(fn func() error) { referencedCertReloadFn = fn }

// ResetReferencedCertWatch 清空引用型证书指纹快照——角色切换/测试隔离复用；
// 清空后下一轮 scan 只重建基线、不触发重载（首扫语义）。
func ResetReferencedCertWatch() {
	referencedCertWatchMu.Lock()
	defer referencedCertWatchMu.Unlock()
	referencedCertWatchState = map[string]string{}
	referencedCertWatchReady = false
}

// checkReferencedCertFiles 扫描引用型证书规则，逐条比对证书/私钥文件对的内容
// 指纹；检出变化（含新出现与内容变更）即触发强制重载并留痕。首扫仅建基线不
// 重载——避免启动/升主即产生一次多余 /load。
func checkReferencedCertFiles() {
	if db.DB == nil {
		return
	}
	rows, err := db.DB.Query(`SELECT caddy_id, COALESCE(tls_cert_path,''), COALESCE(tls_key_path,'')
		FROM lb_rules WHERE enable_tls=1 AND tls_source='file'
		AND COALESCE(tls_cert_path,'')<>'' AND COALESCE(tls_key_path,'')<>''`)
	if err != nil {
		Logf("warn", "引用证书看门狗: 读取规则失败: %v", err)
		return
	}
	defer rows.Close()
	current := make(map[string]string)
	for rows.Next() {
		var caddyID, certPath, keyPath string
		if err := rows.Scan(&caddyID, &certPath, &keyPath); err != nil {
			Logf("warn", "引用证书看门狗: 扫描规则失败: %v", err)
			return
		}
		current[caddyID] = ReferencedCertFileDigest(certPath, keyPath)
	}
	if err := rows.Err(); err != nil {
		Logf("warn", "引用证书看门狗: 遍历规则失败: %v", err)
		return
	}

	referencedCertWatchMu.Lock()
	prev := referencedCertWatchState
	ready := referencedCertWatchReady
	var changed []string
	if ready {
		for id, digest := range current {
			if old, ok := prev[id]; !ok || old != digest {
				changed = append(changed, id)
			}
		}
	}
	referencedCertWatchState = current
	referencedCertWatchReady = true
	referencedCertWatchMu.Unlock()

	if !ready || len(changed) == 0 {
		return
	}
	sort.Strings(changed)
	if referencedCertReloadFn == nil {
		Logf("warn", "引用证书看门狗: 检出证书文件变化但重载未接线，跳过（规则: %s）", strings.Join(changed, "、"))
		return
	}
	if err := referencedCertReloadFn(); err != nil {
		Logf("error", "引用证书看门狗: 证书文件变化后重载失败: %v", err)
		TaskLogf("config-watchdog", "cert-file", "引用证书文件已更新，自动重载失败：%v", err)
		return
	}
	Logf("info", "引用证书看门狗: 检出证书文件变化，已自动重载（规则: %s）", strings.Join(changed, "、"))
	TaskLogf("config-watchdog", "cert-file", "引用证书文件已更新，已自动重载 %d 条规则", len(changed))
}

// CurrentConfigDrift 返回看门狗当前状态（GetCaddyStatus 等展示路径消费）。
func CurrentConfigDrift() ConfigDriftStatus {
	configDriftMu.RLock()
	defer configDriftMu.RUnlock()
	status := configDriftStatus
	status.Missing = append([]string(nil), configDriftStatus.Missing...)
	status.Extra = append([]string(nil), configDriftStatus.Extra...)
	return status
}

// StartConfigWatchdog 主节点每 60s 比对「应渲染规则」与 Caddy 运行配置：不一致时
// 经系统日志 + 操作日志 + GetCaddyStatus（前端全局横幅）三通道告知，连续两轮不一致
// 才置状态（防配置应用窗口的瞬时误报）。从节点不运行——同步链路已有 drift 检测与
// 重载失败标记自愈覆盖。恢复由用户手动重启完成（横幅入口），不做自动重应用。
// 重复调用幂等（已运行时不重启）；停止路径为 StopConfigWatchdog（main.go 优雅退出）。
// watchdogAdminURLOnce 引擎驱动单轮检查的 admin 地址（首次启动钉定）。
var watchdogAdminURLValue string

// WatchdogCheckOnce 单轮一致性检查（panic 留痕——看门狗是唯一消费者，
// goroutine 静默死亡是最坏形态；引擎 60s 节拍调用）。
// L1-P4-2（第 67 轮审计）：主节点专属检测——从节点整轮短路（循环保持存活，
// 升主后自动生效；COALESCE(is_master,1) 口径与全仓一致）。此前从节点每轮
// 空跑簿记：心跳计数累积并逐小时发「配置一致」假心跳（从未真实检查）。
func WatchdogCheckOnce() {
	if db.DB == nil {
		return
	}
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		if err != nil {
			// 查询失败与「非主节点」同为跳过，失败留痕（对齐 checkConfigConsistency
			// 内层门第 55 轮 P5 标准——静默吞错会掩盖 DB 异常）。
			Logf("warn", "配置看门狗: 读取集群角色失败，本轮跳过: %v", err)
		}
		return
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				Logf("error", "配置一致性看门狗：检查 panic: %v", r)
				TaskLogf("config-watchdog", "check", "检查异常（panic 已拦，明细见运行日志）")
			}
		}()
		checkConfigConsistency(watchdogAdminURLValue)
		// 引用型证书文件变化检测（外部更新 /app/certs 内成品证书后自动重载）：
		// 与一致性检查同节拍、同主节点门（从节点 Caddy 无需本地证书热更）。
		checkReferencedCertFiles()
		// R66 日志收敛（2026-10-03 裁定，R65「日志只记真实执行」延伸）：一致轮
		// 零逐轮行，每 configWatchdogHeartbeatRounds 轮（60s×60≈1h）一条心跳；
		// 漂移期逐轮漂移行与恢复事件照旧（task_runs 维持失败留痕不膨胀）。
		d := CurrentConfigDrift()
		configDriftMu.Lock()
		if d.Consistent {
			configDriftCleanRounds++
		} else {
			configDriftCleanRounds = 0
		}
		rounds := configDriftCleanRounds
		configDriftMu.Unlock()
		if d.Consistent {
			if rounds%configWatchdogHeartbeatRounds == 0 {
				TaskLogf("config-watchdog", "check", "配置一致（心跳，近 60 轮无漂移）")
			}
			return
		}
		TaskLogf("config-watchdog", "check", "配置漂移：缺失 %d 条 / 多余 %d 条（自 %s）", len(d.Missing), len(d.Extra), d.Since)
	}()
}

func checkConfigConsistency(adminURL string) {
	if db.DB == nil {
		return
	}
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || !isMaster {
		if err != nil {
			// 查询失败与「非主节点」同为跳过，但失败应留痕（第 55 轮 P5，
			// 对齐同文件 first-warn 标准——静默吞错会掩盖 DB 异常）。
			Logf("warn", "配置看门狗: 读取集群角色失败，本轮跳过: %v", err)
		}
		return
	}
	expected, err := expectedRenderedRules()
	if err != nil {
		configDriftMu.Lock()
		if !configDriftQueryWarned {
			configDriftQueryWarned = true
			Logf("warn", "配置一致性看门狗：读取规则失败（本轮起跳过检查）: %v", err)
		}
		configDriftMu.Unlock()
		return
	}
	running, err := runningRuleRouteIDs(adminURL)
	if err != nil {
		// Caddy 不可达由 GetCaddyStatus 的 status 通道报告；但「配置超解析上限/
		// 解析失败」会让看门狗永久静默——须留痕（首次失败告警，恢复后复位）。
		configDriftMu.Lock()
		if !configDriftReadWarned {
			configDriftReadWarned = true
			Logf("warn", "配置一致性看门狗：读取运行配置失败（本轮起跳过检查）: %v", err)
		}
		configDriftMu.Unlock()
		return
	}
	configDriftMu.Lock()
	configDriftQueryWarned = false
	configDriftReadWarned = false
	configDriftMu.Unlock()
	updateConfigDrift(diffExpectedMissing(expected, running), diffRunningExtra(expected, running))
}

// expectedRenderedRules 计算应出现在运行配置中的规则：启用中且至少有一个启用上游，
// 并排除渲染侧有意跳过的两类（与 caddy.go:1949-1974 同口径——TCP+动态 DNS 逐规则
// 跳过、同端口多 TCP 整组拒绝），否则这两类规则会被误报为「缺失」（R37 F-1）。
// 返回 caddy_id → 规则名称。
func expectedRenderedRules() (map[string]string, error) {
	rows, err := db.DB.Query(`SELECT caddy_id, name, protocol, COALESCE(dynamic_dns,0), listen_port FROM lb_rules WHERE enabled=1
		AND EXISTS (SELECT 1 FROM upstreams u WHERE u.rule_id=lb_rules.caddy_id AND IIF(u.enabled IN ('1',1),1,0)=1)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type ruleRow struct {
		caddyID    string
		name       string
		protocol   string
		dynamicDNS bool
		listenPort int
	}
	var all []ruleRow
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.caddyID, &r.name, &r.protocol, &r.dynamicDNS, &r.listenPort); err != nil {
			return nil, err
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 渲染侧的同端口多 TCP 判定作用于动态 DNS 过滤之后的集合——统计口径保持一致。
	tcpPorts := make(map[int]int)
	for _, r := range all {
		if r.protocol == "tcp" && !r.dynamicDNS {
			tcpPorts[r.listenPort]++
		}
	}
	expected := make(map[string]string)
	for _, r := range all {
		if r.protocol == "tcp" && (r.dynamicDNS || tcpPorts[r.listenPort] > 1) {
			continue
		}
		expected[r.caddyID] = r.name
	}
	return expected, nil
}

// configWatchdogHeartbeatRounds 一致轮心跳间隔：60s 节拍 × 60 轮 = 每小时一条
// 「配置一致」心跳（R66 收敛——一致轮不再逐轮记录）。
const configWatchdogHeartbeatRounds = 60

// maxAdminConfigBytes 看门狗读取 Caddy 运行配置的解码上限——LB44-4 家族口径
// 32MB（与 caddy.go:210/565/780 同源；U8-P4-2 对齐，原先 4MB 上限使 >4MB 配置
// 漂移检测永久静默而 apply 仍工作至 32MB）。
const maxAdminConfigBytes = 32 << 20

// runningRuleRouteIDs 从 Caddy 运行配置收集规则路由 @id（lb_ 前缀），
// 覆盖 http 与 layer4 两类服务器。
func runningRuleRouteIDs(adminURL string) (map[string]bool, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(strings.TrimRight(adminURL, "/") + "/config/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("caddy admin status %d", resp.StatusCode)
	}
	var config map[string]interface{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAdminConfigBytes)).Decode(&config); err != nil {
		return nil, err
	}
	ids := make(map[string]bool)
	apps, _ := config["apps"].(map[string]interface{})
	for _, appName := range []string{"http", "layer4"} {
		app, _ := apps[appName].(map[string]interface{})
		servers, _ := app["servers"].(map[string]interface{})
		for _, srv := range servers {
			routes, _ := srv.(map[string]interface{})["routes"].([]interface{})
			for _, route := range routes {
				if id, ok := route.(map[string]interface{})["@id"].(string); ok && strings.HasPrefix(id, "lb_") {
					ids[id] = true
				}
			}
		}
	}
	return ids, nil
}

// RunningConfigHasRuleRoutes 报告 Caddy 运行配置是否仍含规则路由（lb_ 前缀
// @id）——启动「0 规则应用」守卫的探测面（F49-15）：空库实例启动时若运行
// 配置仍带规则路由，极可能是数据目录/Admin 地址误配，不得把空配置 /load
// 进去。admin 不可达返回错误，调用方按「无正向证据」放行（保持既有行为）。
func RunningConfigHasRuleRoutes(adminURL string) (bool, error) {
	ids, err := runningRuleRouteIDs(adminURL)
	if err != nil {
		return false, err
	}
	return len(ids) > 0, nil
}

// ForeignRunningRuleRoutes 返回运行配置中不被本库规则认领的规则路由 @id
// （2026-09-25 漂移根因 C 加固）：host 网络下默认 admin 地址（localhost:2019）
// 无鉴权共享，外来实例（dev/e2e 误指）会把自身配置 /load 进本实例 Caddy——
// 启动应用前以此检出「非本库规则路由」并响亮留痕（09-18 多余路由、09-24
// 清空路由两次实证事故）。子路由（lb_x_path_0 等）归主规则认领，不计外来。
// admin 不可达返回错误，调用方按「无正向证据」跳过告警（与看门狗同口径）。
func ForeignRunningRuleRoutes(adminURL string, ownIDs map[string]bool) ([]string, error) {
	running, err := runningRuleRouteIDs(adminURL)
	if err != nil {
		return nil, err
	}
	own := make(map[string]string, len(ownIDs))
	for id := range ownIDs {
		own[id] = id
	}
	var foreign []string
	for routeID := range running {
		if !routeClaimedByAny(routeID, own) {
			foreign = append(foreign, routeID)
		}
	}
	return foreign, nil
}

func diffExpectedMissing(expected map[string]string, running map[string]bool) []string {
	var missing []string
	for caddyID, name := range expected {
		if !running[caddyID] {
			missing = append(missing, fmt.Sprintf("%s（%s）", name, caddyID))
		}
	}
	return missing
}

func diffRunningExtra(expected map[string]string, running map[string]bool) []string {
	var extra []string
	for routeID := range running {
		// 子路由（lb_x_redirect / lb_x_path_0 等，caddy.go tagRuleRoute 系）属于其
		// 主规则——仅当没有任何期望规则认领该 @id 时才计为多余（R36 WD-1：
		// 精确匹配会把每条 HTTPS 跳转/路径规则的子路由误报为多余）。
		if !routeClaimedByAny(routeID, expected) {
			extra = append(extra, routeID)
		}
	}
	return extra
}

func routeClaimedByAny(routeID string, expected map[string]string) bool {
	for caddyID := range expected {
		if routeID == caddyID || strings.HasPrefix(routeID, caddyID+"_") {
			return true
		}
	}
	return false
}

func updateConfigDrift(missing, extra []string) {
	drifted := len(missing) > 0 || len(extra) > 0
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	configDriftMu.Lock()
	defer configDriftMu.Unlock()
	if !drifted {
		if !configDriftStatus.Consistent {
			Logf("info", "配置一致性看门狗：运行配置与规则数据已恢复一致")
			RecordAuditLog("system", "配置恢复", "Caddy配置", "运行配置与规则数据已恢复一致", "")
		}
		configDriftStreak = 0
		configDriftStatus = ConfigDriftStatus{Consistent: true, CheckedAt: now}
		return
	}
	configDriftStreak++
	if configDriftStatus.Consistent && configDriftStreak < 2 {
		configDriftStatus.CheckedAt = now
		return
	}
	if configDriftStatus.Consistent {
		detail := formatDriftDetail(missing, extra)
		Logf("error", "配置一致性看门狗：%s", detail)
		RecordAuditLog("system", "配置漂移", "Caddy配置", detail, "")
		configDriftStatus = ConfigDriftStatus{Consistent: false, Since: now}
	}
	configDriftStatus.Missing = missing
	configDriftStatus.Extra = extra
	configDriftStatus.CheckedAt = now
}

func formatDriftDetail(missing, extra []string) string {
	parts := make([]string, 0, 2)
	if len(missing) > 0 {
		parts = append(parts, "缺失规则路由: "+strings.Join(missing, "、"))
	}
	if len(extra) > 0 {
		parts = append(parts, "多余规则路由: "+strings.Join(extra, "、"))
	}
	return "运行配置与规则数据不一致（" + strings.Join(parts, "；") + "），请重启服务恢复"
}
