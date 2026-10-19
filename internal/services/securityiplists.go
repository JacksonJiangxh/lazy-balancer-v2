package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"lazy-balancer-v2/wafiplist"
	"os"
	"path/filepath"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// ipListChunkSize bounds each IN (...) placeholder batch (SQLite 上限 32766 绑定
// 变量，与 policyCustomRuleChunkSize 同型防线)：超大会让整个查询失败，引用条目
// 静默丢失（IP 控制削弱）。
var ipListChunkSize = 500

// policyIPRefExpansion 是 expandPolicyIPRefs 的输出：inline ∪ 引用条目的合并集
// （去重、inline 优先）。listByID 为 nil/缺失 id/畸形 refs 时退化为 inline-only。
type policyIPRefExpansion struct {
	ACLList   []string
	Whitelist []string
}

// parseIPListRefs 解析 refs JSON（[]int64 形态）：nil/空串/空白 → nil；畸形 → nil
// （跳过引用，仅保留 inline，发射不因此失败——与 resolvePolicyCustomRules 的
// 悬空引用仅留痕口径一致）。条目去重，保持出现顺序。
// parseIPListRefs 与 handlers.parseIPListRefsIDs 为镜像实现（历史 历史问题
// 裁定保留双份并声明）：本侧投影路径去重保序，handlers 侧校验路径不去重
// ——语义有意分叉，勿单方面合并。
// SSA-87-01（历史）：本函数为零日志形态（判定/兼容调用）；渲染路径
// 必须走 parseIPListRefsLogged——畸形 refs 静默按空集处理会让 deny ACL 仅引用
// 列表的策略合并集为空、id:2 永不命中（静默 fail-open），此前零告警。
func parseIPListRefs(raw string) []int64 {
	ids, _ := parseIPListRefsChecked(raw)
	return ids
}

// parseIPListRefsChecked 与 parseIPListRefs 同解析语义，另把「非空但畸形」暴露
// 为错误（空/空白=未配置引用，不算畸形）。
func parseIPListRefsChecked(raw string) ([]int64, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var ids []int64
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		return nil, err
	}
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

// parseIPListRefsLogged 渲染路径解析入口（SSA-87-01）：非空畸形 refs 留痕后按
// 空集处理——行为与旧实现一致（仅保留 inline，不升级 IPRefMissing：该标记会
// 让整条策略含 WAF/限流一并跳过渲染，缺失面反而放大）。
func parseIPListRefsLogged(policyID int, field, raw string) []int64 {
	ids, err := parseIPListRefsChecked(raw)
	if err != nil {
		logMalformedIPListRefs(policyID, field, err)
	}
	return ids
}

// logMalformedIPListRefs 渲染期引用 IP 名单 JSON 畸形留痕（SSA-87-01，限流）：
// 与 logMalformedInlineIPList 同口径。写侧（handlers parseIPListRefsPayload）/
// 导入校验已拒畸形，仅带外改库/集群快照继承/旧备份可达。
func logMalformedIPListRefs(policyID int, field string, err error) {
	msg := fmt.Sprintf("渲染: 策略 #%d 引用 IP 名单 %s 解析失败（该列按空集处理，仅保留 inline 条目）: %v", policyID, field, err)
	if auditFailureShouldLog(msg) {
		Logf("warn", "%s", msg)
	}
}

// ipListRefsNonEmpty 报告 refs JSON 是否解析出至少一个条目（畸形视为空）。
// SecurityPolicyHasIPControl 用它在无需加载数据库的情况下判定「仅引用」策略。
func ipListRefsNonEmpty(raw string) bool {
	return len(parseIPListRefs(raw)) > 0
}

// logMalformedInlineIPList 渲染期内联 IP 名单 JSON 畸形留痕（历史问题-03 第 83
// 轮审计，限流）。写侧/导入侧已拒非 JSON，仅带外改库/旧库残留可达；旧实现
// 静默按空集处理——deny ACL / 黑名单方向即 fail-open 且零告警。
func logMalformedInlineIPList(policyID int, field string, err error) {
	msg := fmt.Sprintf("渲染: 策略 #%d 内联 IP 名单 %s 解析失败（该列按空集处理）: %v", policyID, field, err)
	if auditFailureShouldLog(msg) {
		Logf("warn", "%s", msg)
	}
}

// logMalformedInlineIPLists 按策略留痕两个内联 IP 列（SSA-87-06：合并集缓存
// 命中时不再走 expandPolicyIPRefs，需在此补齐该策略自身的畸形留痕）。
func logMalformedInlineIPLists(p *models.SecurityPolicy) {
	if p == nil {
		return
	}
	var list []string
	if err := json.Unmarshal([]byte(p.IPACLList), &list); err != nil {
		logMalformedInlineIPList(p.ID, "ip_acl_list", err)
	}
	list = nil
	if err := json.Unmarshal([]byte(string(p.IPWhitelist)), &list); err != nil {
		logMalformedInlineIPList(p.ID, "ip_whitelist", err)
	}
}

// expandPolicyIPRefs 把策略的 inline IP 条目与引用的 IP 列表条目合并为生效集：
// inline 条目优先，其后按 refs 出现顺序追加各列表条目；跨来源逐值去重；
// listsByID 缺失的 id 与内嵌 null 值跳过。纯函数，不触碰数据库。
func expandPolicyIPRefs(p *models.SecurityPolicy, listsByID map[int64][]string) policyIPRefExpansion {
	var exp policyIPRefExpansion
	if p == nil {
		return exp
	}
	merge := func(field, refsField, inlineRaw string, refsRaw string) []string {
		var merged []string
		seen := make(map[string]struct{})
		addAll := func(entries []string) {
			for _, entry := range entries {
				if entry == "" {
					continue
				}
				if _, dup := seen[entry]; dup {
					continue
				}
				seen[entry] = struct{}{}
				merged = append(merged, entry)
			}
		}
		var inline []string
		if err := json.Unmarshal([]byte(inlineRaw), &inline); err != nil {
			logMalformedInlineIPList(p.ID, field, err)
		}
		addAll(inline)
		// SSA-87-01：非法 refs 与非 inline 同口径留痕（同一消息限流，不重复刷屏）。
		for _, id := range parseIPListRefsLogged(p.ID, refsField, refsRaw) {
			addAll(listsByID[id])
		}
		return merged
	}
	// 合并即聚合（历史 历史问题 修复，用户上报「规则越多保存越慢」根因）：
	// 发射端 mergedACLList/mergedWhitelist 按规则×策略逐次调用，若在此处不
	// 聚合，万条级合并集（如 USTC 11415 条）会被每次调用全量重聚合——保存
	// 耗时随绑定规则数线性放大。聚合幂等，此处一次完成后发射端直接返回。
	exp.ACLList = aggregateIPEntries(merge("ip_acl_list", "ip_acl_list_refs", p.IPACLList, p.IPACLListRefs))
	exp.Whitelist = aggregateIPEntries(merge("ip_whitelist", "ip_whitelist_refs", string(p.IPWhitelist), p.IPWhitelistRefs))
	return exp
}

// LoadIPListEntriesByID 以一次查询批量加载 IP 地址列表条目值（仅 value）。
// ids 为空或数据库未初始化时返回空映射；缺失的 id 不出现在结果中。
// loadIPListEntriesVia：唯一装载实现（历史问题 曾声明与 loadIPListEntries 双实现，
// 后者零调用已删——历史 SEC-A-1；渲染与严格校验统一走 Via 错误通道）。
// store 感知装载（审计 历史问题）——store 非-nil（v2 导入事务视图）经其查询，
// nil 回退 db.DB。镜像 resolvePolicyIPListRefs 的回退逻辑。
func loadIPListEntriesVia(store caddyConfigStore, ids []int64) (map[int64][]string, map[int64]bool, error) {
	if store == nil {
		m, err := LoadIPListEntriesByID(ids)
		return m, nil, err
	}
	// RDB 文件化：system=1（威胁库）条目读 .iplist 文件，system=0（自定义）
	// 读 DB entries——查询加 system+source 列路由。
	entries := make(map[int64][]string, len(ids))
	failed := make(map[int64]bool) // RDB 严格模式：文件读取失败的列表 id
	if len(ids) == 0 {
		return entries, failed, nil
	}
	var firstErr error
	for start := 0; start < len(ids); start += ipListChunkSize {
		end := start + ipListChunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		placeholders := strings.Repeat("?,", len(chunk))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]interface{}, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := store.Query("SELECT id, COALESCE(entries,'[]'), COALESCE(system,0), COALESCE(name,'') FROM security_ip_lists WHERE id IN ("+placeholders+")", args...)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("store 查询 security_ip_lists: %w", err)
			}
			for _, id := range chunk {
				failed[id] = true
			}
			continue
		}
		for rows.Next() {
			var id int64
			var raw string
			var system int
			var name string
			if err := rows.Scan(&id, &raw, &system, &name); err != nil {
				// SEC-A-F1（历史）：Scan 失败不再静默——行丢弃须留痕（该列表
				// 若被引用，缺失表现为合并集静默缺条目）。
				Logf("warn", "渲染: security_ip_lists 行扫描失败（该行丢弃）: %v", err)
				// 严格模式必须把该 id 记为失败；仅 continue 会按 inline-only
				// 继续渲染，deny 集合静默收窄（历史 历史问题-2）。
				failed[id] = true
				if firstErr == nil {
					firstErr = fmt.Errorf("scan security_ip_lists id %d: %w", id, err)
				}
				continue
			}
			if system == 1 && threatSourceByListName(name) != "" {
				// 威胁库（RDB 文件化名单）：读 .iplist 文件（源文件）。历史问题：
				// 以「名字映射到威胁源」路由而非 system=1——自动封禁预置名单
				// 同为 system=1 但条目在 DB entries，走文件分支会恒失败并触发
				// 严格模式跳过引用策略的渲染。
				vals, ferr := readThreatIplistEntries(name)
				if ferr != nil {
					Logf("error", "渲染: 威胁库 %q 文件读取失败: %v（严格模式：引用该列表的策略将被跳过渲染）", name, ferr)
					failed[id] = true
					if firstErr == nil {
						firstErr = ferr
					}
					continue
				}
				entries[id] = vals
			} else {
				// 自定义列表：读 DB entries JSON
				var list []models.IPListEntry
				if err := json.Unmarshal([]byte(raw), &list); err != nil {
					// 畸形自定义名单必须进入 failedIDs：引用策略走严格跳过，
					// 不得以缺内容的合并集静默收窄防护；不向全局 firstErr 上抛，
					// 避免未引用该名单的渲染被无关脏行整体阻断。
					Logf("error", "渲染: 自定义 IP 列表(id=%d) entries 解析失败（引用策略将跳过渲染）: %v", id, err)
					failed[id] = true
					continue
				}
				// 历史问题：过期条目（expires_at 可解析且 <= now）不再下发——到期即
				// 自动解封的唯一发射面。解析失败的 expires_at 保留条目（fail-open
				// 不误删）；判断以 UTC 墙钟串（autobanTimeLayout 同形态），
				// 时钟走 autobanNow 缝（与自动封禁同源，测试可注入时间轴）。
				// AB-4（历史）：判据单源化 autobanEntryExpired——/status 计数
				// 与渲染生效面共用同一谓词，永不漂移。
				now := autobanNow()
				vals := make([]string, 0, len(list))
				for _, e := range list {
					v := strings.TrimSpace(e.Value)
					if v == "" {
						continue
					}
					if autobanEntryExpired(e, now) {
						continue
					}
					vals = append(vals, v)
				}
				entries[id] = vals
			}
		}
		// SEC-A-F1（历史 历史问题）：迭代错误必须显式捕获——rows.Next() 因错误
		// （而非 EOF）返回 false 时静默走掉会让装载集合缺行而 failedIDs 不置位，
		// 引用策略拿到「静默缺内容的合并集」绕过 IPRefMissing 严格模式
		// （ACL/信任面静默收窄零留痕）。与查询失败分支同口径：warn+整块
		// fail-closed（全入 failedIDs）+首错上抛。
		if err := rows.Err(); err != nil {
			Logf("error", "渲染: security_ip_lists 迭代失败（本块 %d 个列表全部按装载失败处理）: %v", len(chunk), err)
			for _, id := range chunk {
				failed[id] = true
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("store 迭代 security_ip_lists: %w", err)
			}
		}
		rows.Close()
	}
	if firstErr != nil {
		return entries, failed, firstErr
	}
	return entries, failed, nil
}

// readThreatIplistPath 按代际读取威胁名单文件（历史 历史问题）：文本与
// .fast 同时存在时以 mtime 较新者为准——从节点只同步 .fast（零编译裁定），
// 降级前遗留的文本可能是旧代；旧「文本优先」会让集群新同步的 .fast 被陈旧
// 文本静默遮蔽（新威胁漏拦/已移除误拦）。同代（mtime 相等）保持文本优先
// （主节点写入相位先落文本后落 fast，内容等价）。
// 两个文件都缺失返回文本侧错误（os.ErrNotExist 语义由调用方判定）。
// A86 历史问题（历史）：.fast 较新但损坏/不可读时回退文本（在场时）
// 并告警——旧实现直接失败，引用名单的 ACL/信任策略被渲染层整体跳过
// （安全面静默缺失），且更新器哈希快路径按 stat 判定永不修复。
func readThreatIplistPath(iplistPath string) ([]string, error) {
	textInfo, textErr := os.Stat(iplistPath)
	fastPath := wafiplist.FastPath(iplistPath)
	fastInfo, fastErr := os.Stat(fastPath)
	readText := func() ([]string, error) {
		raw, err := os.ReadFile(iplistPath)
		if err != nil {
			return nil, err
		}
		// 三处行过滤契约（渲染/UI/编译）同口径：空行与 #/; 注释跳过。
		vals := make([]string, 0, 1024)
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			vals = append(vals, line)
		}
		return vals, nil
	}
	useText := textErr == nil && (fastErr != nil || !fastInfo.ModTime().After(textInfo.ModTime()))
	if useText {
		return readText()
	}
	if fastErr == nil {
		vals, err := expandThreatFastEntries(fastPath)
		if err == nil {
			return vals, nil
		}
		// .fast 较新但损坏：文本在场时回退文本（告警留痕）；无文本才报错。
		if textErr == nil {
			Logf("warn", "威胁名单 %s 的 .fast 读取失败（回退 .iplist 文本）: %v", fastPath, err)
			return readText()
		}
		return nil, err
	}
	if textErr != nil {
		return nil, textErr
	}
	return nil, fastErr
}

// expandThreatFastEntries 展开 .fast 前缀集（已聚合排序，match-set 等价）。
func expandThreatFastEntries(fastPath string) ([]string, error) {
	set, err := wafiplist.ReadFastFile(fastPath)
	if err != nil {
		return nil, err
	}
	vals := make([]string, 0, len(set.V4)+len(set.V6))
	for _, p := range set.V4 {
		vals = append(vals, p.String())
	}
	for _, p := range set.V6 {
		vals = append(vals, p.String())
	}
	return vals, nil
}

// readThreatIplistEntries 按列表名读威胁名单条目（渲染层消费）。
// 文件路径: /app/waf/threat-{source_name}.iplist
func readThreatIplistEntries(listName string) ([]string, error) {
	source := threatSourceByListName(listName)
	if source == "" {
		return nil, fmt.Errorf("列表 %q 不映射到任何威胁源", listName)
	}
	iplistPath := filepath.Join(wafDir, fmt.Sprintf("threat-%s.iplist", source))
	vals, err := readThreatIplistPath(iplistPath)
	if err != nil {
		// 严格模式由调用方跳过策略：两个文件都不可用时才报错。
		return nil, fmt.Errorf("读取 %s 与其 .fast 均失败: %w", iplistPath, err)
	}
	return vals, nil
}

// threatSourceByListName 列表名 → 威胁源名（反向映射 ThreatListNameBySource）。
func threatSourceByListName(listName string) string {
	for _, sl := range db.ThreatSystemLists() {
		if sl.Name == listName {
			return sl.Source
		}
	}
	return ""
}

// IsThreatSystemListName 报告列表名是否登记为威胁情报系统名单。
func IsThreatSystemListName(listName string) bool {
	return threatSourceByListName(listName) != ""
}

func LoadIPListEntriesByID(ids []int64) (map[int64][]string, error) {
	if len(ids) == 0 || db.DB == nil {
		return map[int64][]string{}, nil
	}
	// S历史问题-6(历史):db 分支错误上抛(对齐 store 分支 V3-S1 契约)
	// ——委托 loadIPListEntriesVia(分块+错误通道),不再吞错返回恒 nil error。
	entries, _, err := loadIPListEntriesVia(db.DB, ids)
	return entries, err
}

// danglingIPListRefs 返回既未装载成功也未标记失败的引用 id（列表已删除或导入残留）。
func danglingIPListRefs(p *models.SecurityPolicy, listsByID map[int64][]string, failedIDs map[int64]bool) []int64 {
	if p == nil {
		return nil
	}
	seen := make(map[int64]struct{})
	var dangling []int64
	for _, raw := range []string{p.IPACLListRefs, p.IPWhitelistRefs} {
		for _, id := range parseIPListRefs(raw) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			if _, loaded := listsByID[id]; !loaded && !failedIDs[id] {
				dangling = append(dangling, id)
			}
		}
	}
	return dangling
}

// ResolvePolicyIPListRefsForSummary 供摘要/列表路径批量解析引用 IP 名单
// （历史问题：SecurityPolicyHasIPControl 需要与发射面一致的合并集内容判定）。
// 与渲染加载路径同一实现（store=nil → db.DB）；批次内零引用时零查询。
func ResolvePolicyIPListRefsForSummary(policies []*models.SecurityPolicy) {
	resolvePolicyIPListRefs(policies, nil)
}

// resolvePolicyIPListRefs 在策略加载路径上完成引用解析：跨整个已加载批次收集
// 引用的列表 id（去重），仅当存在引用时执行恰好一次批量查询，再把每条策略的
// 合并集（inline ∪ 引用条目）附加到 MergedACLList / MergedWhitelist。
// store 与策略预载同源（A-I1 同型约束）：v2 导入事务内重插的 security_ip_lists
// 行只有 tx 视角可见，走 db.DB 会让引用条目在渲染期静默丢失；store=nil 回退
// db.DB（非批量路径）。批次内无任何引用时零查询（性能预算：每次生成至多
// 一次额外查询，与引用数无关）。
func resolvePolicyIPListRefs(policies []*models.SecurityPolicy, store caddyConfigStore) {
	var refIDs []int64
	seen := make(map[int64]struct{})
	for _, p := range policies {
		if p == nil {
			continue
		}
		// SSA-87-01：渲染解析路径（本循环覆盖每条策略两个 refs 列各一次）对
		// 畸形非空 refs 留痕——空/空白不告警（未配置引用）。
		for _, id := range parseIPListRefsLogged(p.ID, "ip_acl_list_refs", p.IPACLListRefs) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			refIDs = append(refIDs, id)
		}
		for _, id := range parseIPListRefsLogged(p.ID, "ip_whitelist_refs", p.IPWhitelistRefs) {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			refIDs = append(refIDs, id)
		}
	}
	if len(refIDs) == 0 {
		return
	}
	effective := store
	if effective == nil {
		effective = db.DB
	}
	if effective == nil {
		return
	}
	listsByID, failedIDs, loadErr := loadIPListEntriesVia(effective, refIDs)
	markLoadFailure := func(p *models.SecurityPolicy, id int64) {
		refErr := fmt.Sprintf("策略 %q 引用的 IP 列表(id=%d)装载失败", p.Name, id)
		if loadErr != nil {
			refErr += fmt.Sprintf(": %v", loadErr)
		}
		if auditFailureShouldLog(refErr) {
			Logf("error", "%s——该策略将被跳过渲染", refErr)
			RecordAuditLog("system", "渲染跳过", "安全策略", refErr+"，已跳过该策略渲染", "")
		}
	}
	// SSA-87-06（历史）：展开结果按「四条来源列完全相同」在本次调用内
	// 去重。多策略引用同一大名单（常见形态）时，per-policy aggregateIPEntries
	// （20 万条 ≈ 19ms）只做一次；单一策略形态零行为差异。键只含策略来源列
	// （纯函数输入，本次调用内 listsByID 固定），故不存在跨 tick 陈旧风险，
	// 也无内存常驻（随调用生命周期回收）。
	expandMemo := make(map[string]policyIPRefExpansion, len(policies))
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, id := range danglingIPListRefs(p, listsByID, failedIDs) {
			msg := fmt.Sprintf("策略 %q 引用的 IP 列表(id=%d)不存在（列表已删除或导入残留），仅保留 inline 条目", p.Name, id)
			if auditFailureShouldLog(msg) {
				Logf("warn", "%s", msg)
			}
		}
		// RDB 严格模式：策略引用的任一列表装载失败（威胁库 .iplist 缺失或
		// 自定义 entries 畸形）→ 标记跳过渲染，绝不以空集静默收窄 ACL 保护面。
		// 历史问题：同一 policy+list+错误文本按 auditFailureShouldLog 限流。
		for _, id := range parseIPListRefs(p.IPACLListRefs) {
			if failedIDs[id] {
				p.IPRefMissing = true
				markLoadFailure(p, id)
				break
			}
		}
		if !p.IPRefMissing {
			for _, id := range parseIPListRefs(p.IPWhitelistRefs) {
				if failedIDs[id] {
					p.IPRefMissing = true
					markLoadFailure(p, id)
					break
				}
			}
		}
		if p.IPRefMissing {
			continue
		}
		key := strings.Join([]string{p.IPACLList, p.IPACLListRefs, string(p.IPWhitelist), p.IPWhitelistRefs}, "\x00")
		exp, cached := expandMemo[key]
		if cached {
			// 命中时不再付聚合成本，但仍按本策略留痕内联畸形（expand 里的
			// 同一消息在限流窗口内会被抑制）。
			logMalformedInlineIPLists(p)
		} else {
			exp = expandPolicyIPRefs(p, listsByID)
			expandMemo[key] = exp
		}
		p.MergedACLList = exp.ACLList
		p.MergedWhitelist = exp.Whitelist
	}
}

// mergedACLList 返回策略生效的 ACL 条目集：加载路径已附加合并集时直接使用，
// 否则（未解析/直接构造的策略）回退 inline-only——保证既有调用与测试不变。
// v2.3.x：返回处统一过 CIDR 聚合（去重/兄弟归并/覆盖剔除，匹配集合不变）——
// 发射面（@ipListFast 文件与残留内联）共享同一规范形态。
func mergedACLList(p *models.SecurityPolicy) []string {
	if p.MergedACLList != nil {
		return p.MergedACLList // 扩展开期已聚合（见 expandPolicyIPRefs），直接返回
	}
	var list []string
	if err := json.Unmarshal([]byte(p.IPACLList), &list); err != nil {
		logMalformedInlineIPList(p.ID, "ip_acl_list", err)
	}
	return aggregateIPEntries(list)
}

// mergedWhitelist 同 mergedACLList，作用于信任名单（ip_whitelist）。
func mergedWhitelist(p *models.SecurityPolicy) []string {
	if p.MergedWhitelist != nil {
		return p.MergedWhitelist // 同上：扩开期已聚合
	}
	var list []string
	if err := json.Unmarshal(p.IPWhitelist, &list); err != nil {
		logMalformedInlineIPList(p.ID, "ip_whitelist", err)
	}
	return aggregateIPEntries(list)
}

// ReadThreatIplistForUI 供 UI 预览调用：按列表名读威胁名单条目。
// 文件不存在返回空集（禁用/未更新源）。与渲染侧 readThreatIplistEntries 共用
// readThreatIplistPath（代际感知：新同步的 .fast 不被陈旧文本遮蔽，历史问题）。
func ReadThreatIplistForUI(listName string) ([]string, error) {
	source := threatSourceByListName(listName)
	if source == "" {
		return nil, nil // 非威胁库列表——调用方处理
	}
	path := filepath.Join(wafDir, "threat-"+source+".iplist")
	vals, err := readThreatIplistPath(path)
	if err != nil {
		if os.IsNotExist(err) {
			// SEC-U2（历史）：从节点 waf_files 只同步 .fast——两个文件都
			// 缺失才视为「未更新源」空集。
			return nil, nil
		}
		return nil, err
	}
	return vals, nil
}

// ReadThreatIplistBySource 按源名读威胁名单内容（导出用）。
// 历史问题：与渲染/UI 共用代际感知读取——从节点文本可能是旧代，导出必须与
// 执行面一致（.fast 较新时展开为文本行）。两文件都缺失返回 nil。
func ReadThreatIplistBySource(source string) ([]byte, error) {
	if source == "" {
		return nil, nil
	}
	vals, err := readThreatIplistPath(filepath.Join(wafDir, "threat-"+source+".iplist"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if len(vals) == 0 {
		return nil, nil
	}
	return []byte(strings.Join(vals, "\n") + "\n"), nil
}
