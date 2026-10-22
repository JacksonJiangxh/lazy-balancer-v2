package services

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"lazy-balancer-v2/wafiplist"
)

// 统一编译器（唯一入口 CompileFromIplistFile）：
// 源条目（.iplist 文本行）→ CIDR 聚合 → 排序 → 序列化 .fast 二进制。
// 产出。@ipListFast 算子恒读渲染期 per-policy.txt 投影
// （iplistfile.go），不读 .fast；.fast 的真实消费方=本包从节点回退
// （securityiplists.go ReadFastFile——waf_files 通道只同步二进制的形态）。
//
// 编译发生在:
//   - 威胁库定时更新后（源=.iplist 文件）
//   - 集群同步收到 .iplist 后（从节点本地编译）
//   - 容器重启时（ApplyConfigOnStartup → 渲染 → 编译）

// iterIPListTextLines 遍历 .iplist 文本的有效条目行（空行与 #/; 注释行
// 跳过）——渲染/UI/下载/编译四处行过滤口径的单一事实源（多处各自实现
// 曾致「补注释行」行为漂移，靠专项钉测才发现分叉）。fn 返回 false 提前
// 终止。回调形态避免为「边过滤边解析」的消费方额外线性分配。
func iterIPListTextLines(raw []byte, fn func(line string) bool) {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if !fn(line) {
			return
		}
	}
}

// CompileFromIplistFile 从 .iplist 纯文本源文件编译 .fast 二进制。
// 源文件格式：每行一个 IP/CIDR，# 或 ; 开头为注释，空行跳过。
// 非法行跳过并计数（WARN 语义——合法行正常编译，不因单行损坏全量失败）。
func CompileFromIplistFile(iplistPath string) error {
	raw, err := os.ReadFile(iplistPath)
	if err != nil {
		return fmt.Errorf("读取 .iplist %s: %w", iplistPath, err)
	}
	// 逐条目只解析一次：解析产物直接进聚合，不再
	// 「校验解析一次 + AggregatePrefixes 再解析一次」。
	lines := strings.Split(string(raw), "\n")
	prefixes := make([]netip.Prefix, 0, len(lines))
	skipped := 0
	iterIPListTextLines(raw, func(line string) bool {
		prefix, err := wafiplist.ParseIPEntry(line)
		if err != nil {
			skipped++
			return true
		}
		prefixes = append(prefixes, prefix)
		return true
	})
	if skipped > 0 {
		Logf("warn", "编译 %s: 跳过 %d 条非法行", iplistPath, skipped)
	}
	v4, v6 := splitV4V6(wafiplist.AggregateParsedPrefixes(prefixes))
	return wafiplist.WriteFastFile(wafiplist.FastPath(iplistPath), v4, v6)
}

// CompileFromEntries/CompileFromPrefixes 已删除（新发现，用户
// 裁定删除）：两函数生产零消费方——注释声称的「自定义列表保存即时编译/
// 渲染层 per-policy 投影」场景不存在（保存路径从不即时编译，per-policy
// 投影是 .txt 文本形态不写 .fast）。

// splitV4V6 前缀按地址族分拣（曾双份同型循环的收敛产物；
// 自此由.fast 编译单点消费，等价于旧的 aggregateAndSplit 末段）。
func splitV4V6(prefixes []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range prefixes {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}
