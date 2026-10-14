package handlers

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 受信代理（CDN 真实 IP）写侧校验与归一（v2.3.x）：UpdateConfig 与
// PreviewConfigUpdate 共用——未过校验的载荷不得落库、也不得给出变更清单。
//
// 归一（原地回写 req 字段）：
//   - ranges：裸 IP 补 /32（v4）//128（v6）；条数 ≤64；前缀长度 <8（v4）
//     或 <96（v6）一律拒绝——过宽网段会让伪造头在任意来源被采信。
//   - range_refs（2026-10-12）：引用的 IP 地址列表 id（JSON 整数数组）；
//     每个 id 必须存在；引用名单条目须为合法 IP/CIDR；总 CIDR 数（内联
//   - 引用展开）≤ trustedProxyMaxTotalCIDRs。
//   - headers：条数 ≤8；字符集 ^[A-Za-z0-9-]{1,64}$；去重保序；
//     空数组 = 仅 X-Forwarded-For（渲染层省略 client_ip_headers）。
var trustedProxyHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// trustedProxyMaxTotalCIDRs 受信网段总量上限（内联 ∪ 引用展开，去重前
// 按条目计）：Caddy static ranges 是逐条装载的集合，无聚合链路——上限
// 防御单一名单（≤2000 条写侧门，2026-10-14 裁定 500→2000）×多引用的组合膨胀。
const trustedProxyMaxTotalCIDRs = 2000

// validateTrustedProxyFields 保存侧入口（UpdateConfig/PreviewConfigUpdate）：
// 名单解析仅走库内（overlay=nil）。
func validateTrustedProxyFields(req *models.UpdateConfigRequest) error {
	return validateTrustedProxyFieldsWithSource(req, nil)
}

// trustedProxyListSource 名单解析源（id → 名单行）。nil=仅库内解析（保存
// 通道）。导入通道（D3，历史）传备份 security_ip_lists 行——引用
// 名单随备份全量替换，refs 存在性/条目校验/总量上限须按「备份内优先 ∪
// 库内存量」解析：跨节点还原（备份名单 id 不在本地库）不得误拒；备份携带
// 同 id 行时以其为准（导入后备份行覆盖同 id 库行）。
type trustedProxyListSource struct {
	name    string
	entries string
}

func validateTrustedProxyFieldsWithSource(req *models.UpdateConfigRequest, source map[int64]trustedProxyListSource) error {
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
	ids          []int64
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
		chunks = append(chunks, idChunk{ids: chunk, placeholders: placeholders, args: args})
	}
	return chunks
}

// trustedProxyStoredRefEntries 返回库中存量 trusted_proxy_range_refs 的引用
// 展开条目总数（SYS-F3 总量门对称面：仅更新内联网段时引用面按存量计）。
// 存量 refs JSON 畸形/引用悬空/条目不可解析（仅见于带外改库）按 0 计——与
// trustedProxyInlineCount 存量畸形口径一致：总量门不因存量问题拒绝合法的
// 内联载荷（存量引用的悬空由名单删除守卫与渲染层各自兜底）。
func trustedProxyStoredRefEntries() (int, error) {
	return trustedProxyStoredRefEntriesWithSource(nil)
}

// trustedProxyStoredRefEntriesWithSource 库中存量 trusted_proxy_range_refs 的
// 引用展开条目总数；source 非空时（导入通道）引用名单按「备份内优先 ∪ 库内」
// 解析。存量 refs JSON 畸形/引用悬空/条目不可解析（仅见于带外改库）按 0 计。
func trustedProxyStoredRefEntriesWithSource(source map[int64]trustedProxyListSource) (int, error) {
	var raw string
	if err := db.DB.QueryRow(`SELECT COALESCE(trusted_proxy_range_refs,'[]') FROM global_config WHERE id=1`).Scan(&raw); err != nil {
		return 0, fmt.Errorf("读取当前受信代理引用列表失败: %v", err)
	}
	var ids []int64
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &ids); err != nil || len(ids) == 0 {
		return 0, nil
	}
	// 与 normalizeTrustedProxyRangeRefsWithSource 同构：备份行命中直取，
	// 未命中分片查库。
	resolved := make(map[int64]trustedProxyListSource, len(ids))
	var missing []int64
	for _, id := range ids {
		if row, ok := source[id]; ok {
			resolved[id] = row
		} else {
			missing = append(missing, id)
		}
	}
	for _, ch := range chunkIDs(missing, 500) {
		rows, err := db.DB.Query(`SELECT id, COALESCE(entries,'[]') FROM security_ip_lists WHERE id IN (`+ch.placeholders+`)`, ch.args...)
		if err != nil {
			return 0, fmt.Errorf("读取受信代理引用名单失败: %v", err)
		}
		for rows.Next() {
			var id int64
			var entriesJSON string
			if err := rows.Scan(&id, &entriesJSON); err != nil {
				rows.Close()
				return 0, fmt.Errorf("读取受信代理引用名单失败: %v", err)
			}
			resolved[id] = trustedProxyListSource{entries: entriesJSON}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return 0, fmt.Errorf("读取受信代理引用名单失败: %v", err)
		}
		rows.Close()
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

// normalizeTrustedProxyRangeRefs 保存通道入口（仅库内解析）。
func normalizeTrustedProxyRangeRefs(raw string) (string, int, error) {
	return normalizeTrustedProxyRangeRefsWithSource(raw, nil)
}

// normalizeTrustedProxyRangeRefsWithSource 校验并归一引用载荷：空白归一 "[]"；
// 非空须为整数数组 JSON（字符串/对象条目拒绝）；逐 id 校验存在性与条目格式
// （复用 validIPOrCIDR——带 zone 形态与名单写侧同口径拒绝）；去重保序。
// source 非空时（导入通道）名单按「备份内优先 ∪ 库内存量」解析——引用名单
// 随备份全量替换，跨节点还原（名单 id 仅在备份内）不得误拒。
// 返回归一 JSON 与引用名单条目总数（总量门的判定面）。
func normalizeTrustedProxyRangeRefsWithSource(raw string, source map[int64]trustedProxyListSource) (string, int, error) {
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
	// source（备份行）命中直取；未命中的 id 分片查库（chunkIDs 保留 SQLite
	// 变量数上限的批量口径——手造备份可携带任意长的 refs 数组）。
	resolved := make(map[int64]trustedProxyListSource, len(unique))
	var missing []int64
	for _, id := range unique {
		if row, ok := source[id]; ok {
			resolved[id] = row
		} else {
			missing = append(missing, id)
		}
	}
	for _, ch := range chunkIDs(missing, 500) {
		rows, err := db.DB.Query(`SELECT id, COALESCE(entries,'[]'), COALESCE(name,'') FROM security_ip_lists WHERE id IN (`+ch.placeholders+`)`, ch.args...)
		if err != nil {
			return "", 0, fmt.Errorf("校验受信代理引用列表失败: %v", err)
		}
		for rows.Next() {
			var id int64
			var entriesJSON, name string
			if err := rows.Scan(&id, &entriesJSON, &name); err != nil {
				rows.Close()
				return "", 0, fmt.Errorf("校验受信代理引用列表失败: %v", err)
			}
			resolved[id] = trustedProxyListSource{name: name, entries: entriesJSON}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return "", 0, fmt.Errorf("校验受信代理引用列表失败: %v", err)
		}
		rows.Close()
	}
	total := 0
	for _, id := range unique {
		row, ok := resolved[id]
		if !ok {
			return "", 0, fmt.Errorf("受信代理引用的地址列表不存在：#%d", id)
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
			if !validIPOrCIDR(value) {
				return "", 0, fmt.Errorf("引用的地址列表「%s」含无效 IP/CIDR 条目：%s（受信网段仅接受 IP/CIDR）", row.name, value)
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
		prefix, err := netip.ParsePrefix(entry)
		if err != nil {
			addr, addrErr := netip.ParseAddr(entry)
			if addrErr != nil {
				return "", fmt.Errorf("无效的受信代理网段: %s", entry)
			}
			bits := 32
			if addr.Is6() {
				bits = 128
			}
			prefix = netip.PrefixFrom(addr, bits)
		}
		// 历史 历史问题（历史问题）：全空间形态显式拒绝——/8 的 0.0.0.0/8 覆盖整个
		// IPv4；v4-mapped ::ffff:0:0/96（Is6 含 mapped）内嵌全零 v4 同义。两者
		// 均等同「信任任意来源的伪造头」，与最小前缀长度门的目的相悖。
		allSpace := map[string]bool{
			"0.0.0.0/8":         true, // 整个 IPv4
			"0.0.0.0/0":         true,
			"::/0":              true,
			"::ffff:0.0.0.0/96": true, // v4-mapped 规范形态：内嵌全零 v4
			"::ffff:0:0/96":     true, // 同义的紧凑写法
		}
		if allSpace[prefix.String()] {
			return "", fmt.Errorf("受信代理网段过宽（%s）：该网段覆盖全部地址空间，等同信任任意来源，请收窄到该 CDN 的回源网段", prefix.String())
		}
		minBits := 8
		if prefix.Addr().Is6() {
			minBits = 96
		}
		if prefix.Bits() < minBits {
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
