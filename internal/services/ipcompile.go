package services

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"lazy-balancer-v2/wafiplist"
)

// 统一编译器（入口 CompileFromIplistFile/CompileFromEntries/CompileFromPrefixes）：
// 源条目（文本行或 DB entries）→ CIDR 聚合 → 排序 → 序列化 .fast 二进制。
// 所有 IP 列表（威胁库 .iplist 文件 + 自定义列表 DB entries）经同一编译器
// 产出，下游（@ipListFast 算子）只读 .fast。
//
// 编译发生在:
//   - 威胁库定时更新后（源=.iplist 文件）
//   - 自定义列表保存后（源=DB entries JSON）
//   - 集群同步收到 .iplist 后（从节点本地编译）
//   - 容器重启时（ApplyConfigOnStartup → 渲染 → 编译）

// CompileFromIplistFile 从 .iplist 纯文本源文件编译 .fast 二进制。
// 源文件格式：每行一个 IP/CIDR，# 或 ; 开头为注释，空行跳过。
// 非法行跳过并计数（WARN 语义——合法行正常编译，不因单行损坏全量失败）。
func CompileFromIplistFile(iplistPath string) error {
	raw, err := os.ReadFile(iplistPath)
	if err != nil {
		return fmt.Errorf("读取 .iplist %s: %w", iplistPath, err)
	}
	lines := strings.Split(string(raw), "\n")
	entries := make([]string, 0, len(lines))
	skipped := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if _, err := wafiplist.ParseIPEntry(line); err != nil {
			skipped++
			continue
		}
		entries = append(entries, line)
	}
	if skipped > 0 {
		Logf("warn", "编译 %s: 跳过 %d 条非法行", iplistPath, skipped)
	}
	v4, v6 := aggregateAndSplit(entries)
	return wafiplist.WriteFastFile(wafiplist.FastPath(iplistPath), v4, v6)
}

// CompileFromEntries 从 DB entries JSON 字符串编译 .fast 二进制。
// 用于自定义列表保存后即时编译。
func CompileFromEntries(outputPath string, entriesJSON string) error {
	var entries []string
	if err := json.Unmarshal([]byte(entriesJSON), &entries); err != nil {
		return fmt.Errorf("解析 entries JSON: %w", err)
	}
	v4, v6 := aggregateAndSplit(entries)
	return wafiplist.WriteFastFile(outputPath, v4, v6)
}

// CompileFromPrefixes 从已解析的前缀列表编译 .fast 二进制。
// 用于渲染层合并多个列表后写 per-policy 投影。
func CompileFromPrefixes(outputPath string, prefixes []netip.Prefix) error {
	var v4, v6 []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return wafiplist.WriteFastFile(outputPath, v4, v6)
}

// aggregateAndSplit: 条目字符串列表 → CIDR 聚合+排序 → v4/v6 分离
func aggregateAndSplit(entries []string) ([]netip.Prefix, []netip.Prefix) {
	prefixes := wafiplist.AggregatePrefixes(entries)
	var v4, v6 []netip.Prefix
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}
