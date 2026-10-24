package services

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"

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
// 曾致「补注释行」行为漂移，靠专项钉测才发现分叉）。
//
// 回调形态避免为「边过滤边解析」的消费方额外线性分配；切分本身也按
// bytes.IndexByte 原地扫描：不复制整份文本、不生成 []string 头数组，
// 只有真正要交给回调的有效行才做一次 string 转换（注释/空行零分配）。
// 20 万条量级的名单在编译/更新/集群落地时因此不再产生「全文副本 +
// 每行 16 字节头」的 1~2 倍瞬时开销。行分隔沿用 \n，\r 由 TrimSpace 归一
// （CRLF 源与历史 Split 实现同口径）。fn 返回 false 提前终止。
func iterIPListTextLines(raw []byte, fn func(line string) bool) {
	for len(raw) > 0 {
		var line []byte
		if idx := bytes.IndexByte(raw, '\n'); idx >= 0 {
			line, raw = raw[:idx], raw[idx+1:]
		} else {
			line, raw = raw, nil
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}
		if !fn(string(line)) {
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
	// 容量估算用换行计数（bytes.Count 零分配）——旧实现在此再
	// `strings.Split` 一遍整份文本只为取 len(lines)，20 万条名单多出一份
	// []string 头 + 全量字符串复制，且与 iterIPListTextLines 内部的切分重复。
	prefixes := make([]netip.Prefix, 0, bytes.Count(raw, []byte("\n"))+1)
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
