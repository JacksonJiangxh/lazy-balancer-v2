package handlers

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 受信代理（CDN 真实 IP）写侧校验与归一（v2.3.x）：UpdateConfig 与
// PreviewConfigUpdate 共用——未过校验的载荷不得落库、也不得给出变更清单。
//
// 归一（原地回写 req 字段）：
//   - ranges：裸 IP 补 /32（v4）//128（v6）；条数 ≤64；前缀长度 <8（v4）
//     或 <96（v6）一律拒绝——过宽网段会让伪造头在任意来源被采信。
//   - range_refs（2026-10-12）：引用的 IP 地址列表 id（JSON 整数数组）；
//     每个 id 必须存在且为自定义名单（system=1 内置名单拒绝——U04d-02）；
//     引用名单条目须为合法 IP/CIDR 且与内联通道同宽度判据（U04d-01）；总
//     CIDR 数（内联 + 引用展开）≤ trustedProxyMaxTotalCIDRs。
//   - headers：条数 ≤8；字符集 ^[A-Za-z0-9-]{1,64}$；去重保序；
//     空数组 = 仅 X-Forwarded-For（渲染层省略 client_ip_headers）。
var trustedProxyHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// trustedProxyMaxTotalCIDRs 受信网段总量上限（内联 ∪ 引用展开，去重前
// 按条目计）：Caddy static ranges 是逐条装载的集合，无聚合链路——上限
// 防御单一名单（≤2000 条写侧门，2026-10-14 裁定 500→2000）×多引用的组合膨胀。
const trustedProxyMaxTotalCIDRs = 2000

// trustedProxyListSource 名单解析源行（id → 名单行）。builtin 标记
// system=1 的内置名单（威胁情报/爬虫/自动封禁）——受信代理不允许引用
// （U04d-02：威胁名单真实条目在 .iplist 文件，DB entries 恒空，按 DB 列
// 校验会同时失去条格式门与 2000 条总量门；前端本已只列自定义名单）。
type trustedProxyListSource struct {
	name    string
	entries string
	builtin bool
}

// trustedProxyBackupSource 导入通道的名单解析源（RC-2/F75C-3，历史）。
// 按「备份是否携带 security_ip_lists 表」分流：
//   - carried=true：名单表随备份**全量替换**（W2 先例——备份行才是导入后的
//     真实数据），refs 存在性仅按备份行集合解析；指向库内但不在备份内的 id
//     导入后必然悬空，校验期 400 拒绝（旧「备份内优先 ∪ 库内」口径会借库内
//     命中放行为导入后悬空引用）。
//   - carried=false：备份未携带名单表——导入后名单表保持本地现状（「缺席=
//     保留本地」语义），refs 存在性按库内解析（与保存通道同口径）。
//
// 零值=仅库内解析（保存通道）。
type trustedProxyBackupSource struct {
	lists   map[int64]trustedProxyListSource
	carried bool
}

// validateTrustedProxyFields 保存侧入口（UpdateConfig/PreviewConfigUpdate）：
// 名单解析仅走库内（零值 source）。
func validateTrustedProxyFields(req *models.UpdateConfigRequest) error {
	return validateTrustedProxyFieldsWithSource(req, trustedProxyBackupSource{})
}

func validateTrustedProxyFieldsWithSource(req *models.UpdateConfigRequest, source trustedProxyBackupSource) error {
	if req.TrustedProxyRanges != nil {
		normalized, err := normalizeTrustedProxyRanges(*req.TrustedProxyRanges)
		if err != nil {
			return err
		}
		*req.TrustedProxyRanges = normalized
		// 总量门对称面（SYS-F3，历史 历史问题）：refs 未随载荷时按库中存量
		// 引用展开合计——内联面与引用面合并才是真实展开规模（refs 载荷
		// 分支在下方做同口径判定，此处不重复）。
		if req.TrustedProxyRangeRefs == nil {
			inlineCount, err := trustedProxyInlineCount(req)
			if err != nil {
				return err
			}
			refEntries, err := trustedProxyStoredRefEntriesWithSource(source)
			if err != nil {
				return err
			}
			if inlineCount+refEntries > trustedProxyMaxTotalCIDRs {
				return fmt.Errorf("受信网段总数超过 %d 上限（内联 %d + 引用展开 %d），请收窄内联范围", trustedProxyMaxTotalCIDRs, inlineCount, refEntries)
			}
		}
	}
	if req.TrustedProxyRangeRefs != nil {
		normalized, refEntries, err := normalizeTrustedProxyRangeRefsWithSource(*req.TrustedProxyRangeRefs, source)
		if err != nil {
			return err
		}
		// 总量门（内联 ∪ 引用展开）：载荷未携带 ranges 时按存量值计——
		// 引用面与内联面合并才是真实展开规模。
		inlineCount, err := trustedProxyInlineCount(req)
		if err != nil {
			return err
		}
		if inlineCount+refEntries > trustedProxyMaxTotalCIDRs {
			return fmt.Errorf("受信网段总数超过 %d 上限（内联 %d + 引用展开 %d），请收窄引用范围", trustedProxyMaxTotalCIDRs, inlineCount, refEntries)
		}
		*req.TrustedProxyRangeRefs = normalized
	}
	if req.TrustedProxyHeaders != nil {
		normalized, err := normalizeTrustedProxyHeaders(*req.TrustedProxyHeaders)
		if err != nil {
			return err
		}
		*req.TrustedProxyHeaders = normalized
	}
	return nil
}

// trustedProxyInlineCount 返回总量门所需的内联网段条数：载荷携带 ranges
// 时用归一后值（validateTrustedProxyFields 先归一 ranges 再进本函数）；
// 未携带（nil=保留原值）时读库取存量。
func trustedProxyInlineCount(req *models.UpdateConfigRequest) (int, error) {
	if req.TrustedProxyRanges != nil {
		var entries []string
		if err := json.Unmarshal([]byte(*req.TrustedProxyRanges), &entries); err != nil {
			return 0, fmt.Errorf("受信代理网段必须是 JSON 数组: %v", err)
		}
		return len(entries), nil
	}
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_ranges,'[]') FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		return 0, fmt.Errorf("读取当前受信代理网段失败: %v", err)
	}
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		// 存量畸形（仅见于带外改库）：按 0 计——渲染层对畸形同样 fail-closed
		// 不注入，总量门不因存量畸形拒绝合法的引用清理载荷。
		return 0, nil
	}
	return len(entries), nil
}

// idChunk 是一个 id 分片及其预构造的 IN 子句占位符与参数（SYS-REST-F2 第 73
// 轮：受信代理两处 500 分片样板单源——仅共享分片构造，不合并查询/校验语义）。
type idChunk struct {
	placeholders string
	args         []any
}

// chunkIDs 把 id 列表按 chunkSize 切分为若干分片，每片预构造
// `?,?,...` 占位符与配套参数（SQLite 变量数上限下的分批口径）。
func chunkIDs(ids []int64, chunkSize int) []idChunk {
	if len(ids) == 0 {
		return nil
	}
	chunks := make([]idChunk, 0, (len(ids)+chunkSize-1)/chunkSize)
	for start := 0; start < len(ids); start += chunkSize {
		end := start + chunkSize
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		chunks = append(chunks, idChunk{placeholders: placeholders, args: args})
	}
	return chunks
}

// resolveTrustedProxyRefLists 解析 refs 引用的名单行（RC-2 分流的单点）：
// 备份行命中直取；未命中且备份未携带名单表（carried=false）时分片查库。
// 两通道都带 system 列映射 builtin（U04d-02 写侧拒绝内置名单）。
// carried=true 不回落库内——名单表随备份全量替换，库内命中不代表导入后存在。
func resolveTrustedProxyRefLists(ids []int64, source trustedProxyBackupSource) (map[int64]trustedProxyListSource, error) {
	resolved := make(map[int64]trustedProxyListSource, len(ids))
	var missing []int64
	for _, id := range ids {
		if row, ok := source.lists[id]; ok {
			resolved[id] = row
		} else if !source.carried {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return resolved, nil
	}
	for _, ch := range chunkIDs(missing, 500) {
		rows, err := db.DB.Query(`SELECT id, COALESCE(entries,'[]'), COALESCE(name,''), COALESCE(system,0) FROM security_ip_lists WHERE id IN (`+ch.placeholders+`)`, ch.args...)
		if err != nil {
			return nil, fmt.Errorf("校验受信代理引用列表失败: %v", err)
		}
		for rows.Next() {
			var id int64
			var entriesJSON, name string
			var system int
			if err := rows.Scan(&id, &entriesJSON, &name, &system); err != nil {
				rows.Close()
				return nil, fmt.Errorf("校验受信代理引用列表失败: %v", err)
			}
			resolved[id] = trustedProxyListSource{name: name, entries: entriesJSON, builtin: system == 1}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("校验受信代理引用列表失败: %v", err)
		}
		rows.Close()
	}
	return resolved, nil
}

// trustedProxyStoredRefEntriesWithSource 库中存量 trusted_proxy_range_refs 的
// 引用展开条目总数（总量门的引用面计数——不做存在性门）。source.carried=true
// （导入通道携表）时未命中备份行的存量 ref 不参与计数（导入后该名单不复存在，
// 展开面归零）；载荷未携带 refs 键而备份携带名单表的残留悬空形态（仅手造备份
// 可达——真实导出恒携带全列）不在本门范围内，由渲染层 fail-closed 与名单删除
// 守卫兜底。存量 refs JSON 畸形/条目不可解析（仅见于带外改库）按 0 计。
//
// 内置名单（system=1）引用自 U04d-02 起在写侧拒绝；升级前存量引用仍按 DB
// entries 计数（威胁名单恒 0 条——其真实条目不参与本门，属既有配置的遗留
// 边界：下次保存 refs 载荷时被 400 拒绝并要求改用自定义名单）。
func trustedProxyStoredRefEntriesWithSource(source trustedProxyBackupSource) (int, error) {
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		return 0, fmt.Errorf("读取当前受信代理引用列表失败: %v", err)
	}
	var ids []int64
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &ids); err != nil || len(ids) == 0 {
		return 0, nil
	}
	resolved, err := resolveTrustedProxyRefLists(ids, source)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, row := range resolved {
		var entries []models.IPListEntry
		if row.entries != "" && json.Unmarshal([]byte(row.entries), &entries) == nil {
			total += len(entries)
		}
	}
	return total, nil
}

// normalizeTrustedProxyRangeRefsWithSource 校验并归一引用载荷：空白归一 "[]"；
// 非空须为整数数组 JSON（字符串/对象条目拒绝）；逐 id 校验存在性（内置名单
// 拒绝，U04d-02）与条目格式/宽度（parseTrustedProxyPrefix + services 宽度
// 判据，与内联通道同口径，U04d-01）；去重保序。
// source 按备份是否携带名单表分流（trustedProxyBackupSource）：carried=true
// 时存在性仅按备份行集合解析（RC-2——全量替换后库内行不复存在，悬空 400）；
// carried=false 时未命中备份行的 id 按库内存量解析（保存通道同口径）。
// 返回归一 JSON 与引用名单条目总数（总量门的判定面）。
func normalizeTrustedProxyRangeRefsWithSource(raw string, source trustedProxyBackupSource) (string, int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "[]", 0, nil
	}
	var ids []int64
	if err := json.Unmarshal([]byte(trimmed), &ids); err != nil {
		return "", 0, fmt.Errorf("受信代理引用列表必须是整数 id 的 JSON 数组: %v", err)
	}
	seen := make(map[int64]struct{}, len(ids))
	unique := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return "", 0, fmt.Errorf("受信代理引用列表含无效 id：%d", id)
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 {
		return "[]", 0, nil
	}
	// RC-2 分流单点：备份行命中直取；未命中仅当备份未携名单表才回落库内
	// （resolveTrustedProxyRefLists——chunkIDs 保留 SQLite 变量数上限的批量
	// 口径，手造备份可携带任意长的 refs 数组）。
	resolved, err := resolveTrustedProxyRefLists(unique, source)
	if err != nil {
		return "", 0, err
	}
	total := 0
	for _, id := range unique {
		row, ok := resolved[id]
		if !ok {
			return "", 0, fmt.Errorf("受信代理引用的地址列表不存在：#%d", id)
		}
		// U04d-02：内置名单（威胁情报/爬虫/自动封禁）不得作为受信代理来源——
		// 真实条目在 .iplist 文件、DB entries 恒空，按 DB 列校验会同时失去条
		// 格式门与总量门；且威胁名单与「可信回源」语义相反。与 UI 一致拒绝。
		if row.builtin {
			return "", 0, fmt.Errorf("受信代理不能引用内置地址列表「%s」：内置名单（威胁情报/爬虫/自动封禁）由系统维护，请改用自定义名单", row.name)
		}
		var entries []models.IPListEntry
		if row.entries != "" {
			if err := json.Unmarshal([]byte(row.entries), &entries); err != nil {
				return "", 0, fmt.Errorf("引用的地址列表「%s」条目不可解析，请先修复该列表", row.name)
			}
		}
		for _, entry := range entries {
			value := strings.TrimSpace(entry.Value)
			if value == "" {
				continue
			}
			prefix, err := parseTrustedProxyPrefix(value)
			if err != nil {
				return "", 0, fmt.Errorf("引用的地址列表「%s」含无效 IP/CIDR 条目：%s（受信网段仅接受 IP/CIDR）", row.name, value)
			}
			// U04d-01：与内联通道同一宽度判据——名单通道不得成为过宽网段的
			// 等价绕过入口（否则伪造头可在任意来源被采信）。
			if services.TrustedProxyPrefixAllSpace(prefix) {
				return "", 0, fmt.Errorf("引用的地址列表「%s」含过宽网段 %s：该网段覆盖全部地址空间，等同信任任意来源", row.name, prefix.String())
			}
			if prefix.Bits() < services.TrustedProxyMinPrefixBits(prefix.Addr()) {
				return "", 0, fmt.Errorf("引用的地址列表「%s」含过宽网段 %s：最小允许 /8（IPv4）与 /96（IPv6），请收窄到该 CDN 的回源网段", row.name, prefix.String())
			}
		}
		total += len(entries)
	}
	out, err := json.Marshal(unique)
	if err != nil {
		return "", 0, fmt.Errorf("序列化受信代理引用列表失败: %v", err)
	}
	return string(out), total, nil
}

// parseTrustedProxyPrefix 解析受信网段条目：合法 CIDR 或裸 IP（补 /32 或
// /128）。格式门与渲染层 appendCIDR 同口径；宽度判据由调用方按
// services.TrustedProxy* 执行（两通道不得分叉）。
func parseTrustedProxyPrefix(value string) (netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix, nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func normalizeTrustedProxyRanges(raw string) (string, error) {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", fmt.Errorf("受信代理网段必须是 JSON 数组: %v", err)
	}
	if len(entries) > 64 {
		return "", fmt.Errorf("受信代理网段条数上限 64（当前 %d）", len(entries))
	}
	normalized := make([]string, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		prefix, err := parseTrustedProxyPrefix(entry)
		if err != nil {
			return "", fmt.Errorf("无效的受信代理网段: %s", entry)
		}
		// 历史 历史问题（历史问题）+ U04d-01：全空间形态与最小前缀长度判据
		// 单源在 services（内联/引用/渲染三处同口径）——全空间（0.0.0.0/8、
		// 0.0.0.0/0、::/0、v4-mapped 全零 /96）等同「信任任意来源的伪造头」。
		if services.TrustedProxyPrefixAllSpace(prefix) {
			return "", fmt.Errorf("受信代理网段过宽（%s）：该网段覆盖全部地址空间，等同信任任意来源，请收窄到该 CDN 的回源网段", prefix.String())
		}
		if prefix.Bits() < services.TrustedProxyMinPrefixBits(prefix.Addr()) {
			return "", fmt.Errorf("受信代理网段过宽（%s）：最小允许 /8（IPv4）与 /96（IPv6），请收窄到该 CDN 的回源网段", prefix.String())
		}
		// 去重保序（与 headers 侧同口径，历史补充轮 U6B-7）
		if _, dup := seen[prefix.String()]; dup {
			continue
		}
		seen[prefix.String()] = struct{}{}
		normalized = append(normalized, prefix.String())
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("序列化受信代理网段失败: %v", err)
	}
	return string(out), nil
}

func normalizeTrustedProxyHeaders(raw string) (string, error) {
	var entries []string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", fmt.Errorf("受信代理请求头必须是 JSON 数组: %v", err)
	}
	if len(entries) > 8 {
		return "", fmt.Errorf("受信代理请求头条数上限 8（当前 %d）", len(entries))
	}
	seen := make(map[string]struct{}, len(entries))
	normalized := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !trustedProxyHeaderPattern.MatchString(entry) {
			return "", fmt.Errorf("无效的受信代理请求头: %s（仅允许字母/数字/连字符，1-64 字符）", entry)
		}
		if _, dup := seen[entry]; dup {
			continue
		}
		seen[entry] = struct{}{}
		normalized = append(normalized, entry)
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("序列化受信代理请求头失败: %v", err)
	}
	return string(out), nil
}
