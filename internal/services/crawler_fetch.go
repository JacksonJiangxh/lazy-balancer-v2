package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// cidrTokenRE / cidrTokenV6RE 通用 CIDR/裸 IP 提取（JSON/HTML 通用）。
// 历史问题（历史）：边界排除「数字/点」——旧 `\b` 会把版本号/日期串中的
// 四段数字收进名单（`not.an.ip.version.1.2.3.4.5` 抽出 1.2.3.4，`2026.10.18`
// 类文本同理），错误页/示例文本即可污染豁免名单。
var (
	cidrTokenRE   = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?`)
	cidrTokenV6RE = regexp.MustCompile(`(?i)(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?:/\d{1,3})?`)
	// 历史问题-01（历史）：360 官方页面只公示通配段（`42.236.10.*`），
	// 词法 CIDR 正则无法命中——旧实现把 UA 版本串 `Chrome/140.0.0.0` 收成
	// /32 并覆盖正确名单（真实 360 爬虫失去豁免、无关地址获得豁免）。
	cidrWildcardRE = regexp.MustCompile(`(?:\d{1,3}\.){3}\*`)
)

// crawlerVersionPrefix 判定 token 起始处是否为 URL/版本串前缀（`Chrome/`、
// `Edg/`、`v1.2.3.4`）——此类四段数字是 UA/版本号而非网段，边界仅排除
// 数字/点不足以拦截（历史问题-02 历史）。
func crawlerVersionPrefix(body string, start int) bool {
	if start == 0 {
		return false
	}
	switch body[start-1] {
	case 'v', 'V':
		return true
	case '/':
		if start >= 2 {
			prev := body[start-2]
			return prev >= 'A' && prev <= 'Z' || prev >= 'a' && prev <= 'z'
		}
	}
	return false
}

// crawlerTokenBoundary 判定 token 边界外字符是否属于「同类」——数字/点（v4）
// 或十六进制/冒号/点（v6）。Go RE2 无 lookaround，用索引手工判界（避免消费
// 边界字符导致相邻 token 漏取）。
func crawlerTokenBoundary(b byte, v6 bool) bool {
	if b >= '0' && b <= '9' || b == '.' {
		return true
	}
	if v6 && (b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F' || b == ':') {
		return true
	}
	return false
}

// findBoundedCrawlerTokens 返回词法命中的 token（两侧边界均非同类字符）。
func findBoundedCrawlerTokens(re *regexp.Regexp, body string, v6 bool) []string {
	idxs := re.FindAllStringIndex(body, -1)
	out := make([]string, 0, len(idxs))
	for _, idx := range idxs {
		start, end := idx[0], idx[1]
		if crawlerVersionPrefix(body, start) {
			continue
		}
		if start > 0 && crawlerTokenBoundary(body[start-1], v6) {
			continue
		}
		if end < len(body) && crawlerTokenBoundary(body[end], v6) {
			continue
		}
		out = append(out, body[start:end])
	}
	return out
}

// parseCrawlerCIDRsForFormat 按源声明格式提取（历史问题：消费 crawlerSource.Format）：
//   - json：响应必须是合法 JSON，且必须命中结构化 ipv4Prefix/ipv6Prefix 字段
//     （历史问题：错误页/限流页的合法 JSON——如 {"error":"rate limited from
//     1.2.3.4"}——此前会走词法兜底把页面内 IP 同形文本写进豁免名单；JSON 源
//     不再做词法提取，结构不符即失败并保留上次快照）；
//   - html/plain/空：仅词法提取；
//   - 统一 netip 校验，裸 IP 归一 /32（IPv4）/ /128（IPv6），非法 token 跳过。
func parseCrawlerCIDRsForFormat(body, format string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, 64)
	add := func(tok string) {
		prefix, ok := normalizeCrawlerPrefixToken(strings.Trim(tok, " \t\r\n,;\"')"))
		if !ok {
			return
		}
		if _, dup := seen[prefix]; dup {
			return
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	isJSON := strings.EqualFold(strings.TrimSpace(format), "json")
	// 1) 结构化字段（JSON 对象/数组递归；ipv4Prefix/ipv6Prefix 大小写不敏感）。
	var parsed any
	jsonErr := json.Unmarshal([]byte(body), &parsed)
	if jsonErr == nil {
		structuredBefore := len(out)
		collectCrawlerPrefixFields(parsed, add)
		if isJSON {
			if len(out) == structuredBefore {
				return nil, fmt.Errorf("JSON 响应未包含结构化 ipv4Prefix/ipv6Prefix 字段（疑似错误页/结构变更），保留上次快照")
			}
			// 历史问题：JSON 源只认结构化字段——其余字段（error/message/note）
			// 中的 IP 同形文本一律不作官方网段。
			return out, nil
		}
	} else if isJSON {
		// 历史问题：JSON 源返回非 JSON（错误页/HTML 劫持）→ 显式失败，绝不把
		// 页面里的 IP 同形文本当官方网段。
		return nil, fmt.Errorf("响应不是合法 JSON（疑似错误页），保留上次快照")
	}
	// 2) 通用词法（HTML/纯文本/未结构化 JSON）。
	// 历史问题-01：官方通配段 `a.b.c.*` 先按 /24 归一（360 页面只公示通配形态）；
	// 版本串前缀已在 findBoundedCrawlerTokens 过滤（Chrome/140.0.0.0 等）。
	for _, tok := range findBoundedCrawlerTokens(cidrWildcardRE, body, false) {
		add(strings.TrimSuffix(tok, "*") + "0/24")
	}
	for _, tok := range findBoundedCrawlerTokens(cidrTokenRE, body, false) {
		add(tok)
	}
	for _, tok := range findBoundedCrawlerTokens(cidrTokenV6RE, body, true) {
		add(tok)
	}
	return out, nil
}

// collectCrawlerPrefixFields 递归收集 JSON 中的 ipv4Prefix/ipv6Prefix 字符串值。
func collectCrawlerPrefixFields(v any, add func(string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if sv, ok := val.(string); ok && (strings.EqualFold(k, "ipv4Prefix") || strings.EqualFold(k, "ipv6Prefix")) {
				add(sv)
				continue
			}
			collectCrawlerPrefixFields(val, add)
		}
	case []any:
		for _, item := range t {
			collectCrawlerPrefixFields(item, add)
		}
	}
}

// normalizeCrawlerPrefixToken 统一 CIDR/裸 IP 归一（掩码对齐、裸 IP 补长度）。
func normalizeCrawlerPrefixToken(tok string) (string, bool) {
	if tok == "" {
		return "", false
	}
	if p, err := netip.ParsePrefix(tok); err == nil {
		return p.Masked().String(), true
	}
	addr, err := netip.ParseAddr(tok)
	if err != nil {
		return "", false
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits).String(), true
}

// crawlerFetchBody 下载源文本（ctx 取消可断；body 上限 16MB）。
func crawlerFetchBody(ctx context.Context, src crawlerSource) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "lazy-balancer-v2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// 历史问题：与 threatupdate 同口径——历史修复 超限提前失败；读取
	// cap+1 后显式拒绝截断文本（旧实现把截断内容当合法文本返回，可能残留
	// 部分 CIDR 而「看似成功」，覆盖上次快照）。
	const crawlerBodyCap = 16 << 20
	if resp.ContentLength > crawlerBodyCap {
		return "", fmt.Errorf("响应体 %d 字节超过上限 %d", resp.ContentLength, crawlerBodyCap)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, crawlerBodyCap+1))
	if err != nil {
		return "", err
	}
	if len(body) > crawlerBodyCap {
		return "", fmt.Errorf("响应体超过上限 %d 字节，已拒绝（保留上次快照）", crawlerBodyCap)
	}
	return string(body), nil
}
