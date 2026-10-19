package wafiplist

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
)

// fastFileMagic 是 .fast 二进制格式的魔数（Lazy Balancer Fast v1）。
const fastFileMagic = "LBF1"

// fastFileHeaderSize 是 .fast 文件头固定长度。
const fastFileHeaderSize = 16

// MaxFastFileBytes 是 ReadFastFile 读取前的体积硬上限（A86 历史问题，历史
// 审计）：.fast 是跨进程输入（节点回传/从节点回退），不能只依赖写侧自律——
// 异常/恶意超大文件必须先过 Stat 体积门，再进入读取与内容校验。与文本名单
// 路径的 MaxFileBytes（iplistfast.go）同型；二进制条目 5B/v4、17B/v6，
// 64MiB 约容纳千万级条目，远超威胁库下载侧 200000 条上限，正常产物远不可及。
// var 形态供测试收窄。
var MaxFastFileBytes int64 = 64 << 20

// FastFileState 是从 .fast 二进制文件加载的内存态（排序不相交前缀集）。
// 生产消费方=services 侧从节点回退（securityiplists.go ReadFastFile）。
type FastFileState struct {
	V4 []netip.Prefix // 排序不相交 IPv4 前缀
	V6 []netip.Prefix // 排序不相交 IPv6 前缀
}

// WriteFastFile 将前缀集序列化为 .fast 二进制格式并原子写入。
// 输入应已聚合为不相交集合；为守住二分查询契约，本函数在**内部副本**上
// 防御性掩码主机位并排序——调用方切片的内容与顺序都不被改写。本函数不
// 聚合/不去重；嵌套/同址形态由 ReadFastFile 拒绝。
//
// 族校验（历史问题）：v4 切片只接受纯 IPv4 前缀，v6 切片只接受纯 IPv6 前缀
// （4in6 映射形态须先 Unmap 归 v4）。族错配返回 error 而不是 panic/静默腐化
// ——As4 对 v6 入参 panic；As16 对 v4 会写出「4-in-6 地址 + v4 bits」的
// 可加载但永不命中形态。主机位未掩码的条目（如 1.2.3.200/24）会让二分查询
// 用未掩码地址比较而假阴性——写侧必须先掩码；读侧亦对每项校验 p==p.Masked()
// （E83-历史问题：.fast 是跨进程输入，不单靠写侧自律）。
//
// 原子写用独占临时名（CreateTemp，历史问题）：固定 path+".tmp" 在并发/多调用
// 方下互相覆盖（rename ENOENT 或旧代际覆盖新代际）。本函数自身不持锁，
// 生产调用方仍须持 wafFileMu 串行化代际。
func WriteFastFile(path string, v4, v6 []netip.Prefix) error {
	for _, p := range v4 {
		if !p.IsValid() || !p.Addr().Is4() {
			return fmt.Errorf("fastfile: v4 条目 %v 不是纯 IPv4 前缀（族错配）", p)
		}
	}
	for _, p := range v6 {
		if !p.IsValid() || !p.Addr().Is6() || p.Addr().Is4In6() {
			return fmt.Errorf("fastfile: v6 条目 %v 不是纯 IPv6 前缀（族错配/无效）", p)
		}
	}
	// 掩码 + 排序都在副本上做：掩码会改变地址（进而改变正确排序次序），
	// 直接原地改调用方切片会静默改写其数据。
	mv4 := make([]netip.Prefix, len(v4))
	for i, p := range v4 {
		mv4[i] = p.Masked()
	}
	mv6 := make([]netip.Prefix, len(v6))
	for i, p := range v6 {
		mv6[i] = p.Masked()
	}
	sort.Slice(mv4, func(i, j int) bool { return mv4[i].Addr().Compare(mv4[j].Addr()) < 0 })
	sort.Slice(mv6, func(i, j int) bool { return mv6[i].Addr().Compare(mv6[j].Addr()) < 0 })

	// 计算总大小
	size := fastFileHeaderSize + len(mv4)*5 + len(mv6)*17
	buf := make([]byte, size)

	// Header
	copy(buf[0:4], fastFileMagic)
	binary.BigEndian.PutUint32(buf[4:8], uint32(len(mv4)))
	binary.BigEndian.PutUint32(buf[8:12], uint32(len(mv6)))
	binary.BigEndian.PutUint32(buf[12:16], 0) // flags reserved

	// v4 entries: [4B addr][1B bits]
	offset := fastFileHeaderSize
	for _, p := range mv4 {
		addr := p.Addr().As4()
		copy(buf[offset:offset+4], addr[:])
		buf[offset+4] = byte(p.Bits())
		offset += 5
	}

	// v6 entries: [16B addr][1B bits]
	for _, p := range mv6 {
		addr := p.Addr().As16()
		copy(buf[offset:offset+16], addr[:])
		buf[offset+16] = byte(p.Bits())
		offset += 17
	}

	// 原子写（与 @ipListFast 投影同模式）：独占临时名 + rename。
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("fastfile mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("fastfile tmp create: %w", err)
	}
	tmpName := tmp.Name()
	discard := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if _, err := tmp.Write(buf); err != nil {
		discard()
		return fmt.Errorf("fastfile tmp write: %w", err)
	}
	// CreateTemp 建 0600，正式文件沿用既有 0644（跨进程可读）。
	if err := tmp.Chmod(0o644); err != nil {
		discard()
		return fmt.Errorf("fastfile tmp chmod: %w", err)
	}
	// 掉电窗口内空/半截 .fast 会被 @ipListFast 当合法空集（fail-open）。
	if err := tmp.Sync(); err != nil {
		discard()
		return fmt.Errorf("fastfile tmp sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("fastfile tmp close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("fastfile rename: %w", err)
	}
	if dir, derr := os.Open(filepath.Dir(path)); derr == nil {
		if serr := dir.Sync(); serr != nil {
			_ = dir.Close()
			return fmt.Errorf("fastfile dir sync: %w", serr)
		}
		_ = dir.Close()
	}
	return nil
}

// ReadFastFile 读取 .fast 二进制文件并展开为内存前缀集。
// 加载成本 O(n) 纯内存拷贝——无文本解析、无排序（20 万条 ~0.2ms）。
func ReadFastFile(path string) (*FastFileState, error) {
	// A86 历史问题：读取前 Stat 体积门——超限文件不进入内存（防 OOM），
	// 读取后的 header/expectedSize 一致性校验保留作第二道。
	if info, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("fastfile stat: %w", err)
	} else if info.Size() > MaxFastFileBytes {
		return nil, fmt.Errorf("fastfile: size %d exceeds cap %d", info.Size(), MaxFastFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fastfile read: %w", err)
	}
	if len(data) < fastFileHeaderSize {
		return nil, fmt.Errorf("fastfile: too short (%d bytes)", len(data))
	}
	if string(data[0:4]) != fastFileMagic {
		return nil, fmt.Errorf("fastfile: bad magic %q", string(data[0:4]))
	}
	v4Count := binary.BigEndian.Uint32(data[4:8])
	v6Count := binary.BigEndian.Uint32(data[8:12])
	// 历史问题：未知 flags 位不得静默忽略（格式演进必须显式：未来的特性位
	// 若被当 0 解析，会按错误的条目布局读数据）。
	if flags := binary.BigEndian.Uint32(data[12:16]); flags != 0 {
		return nil, fmt.Errorf("fastfile: unknown flags %#x", flags)
	}

	expectedSize := fastFileHeaderSize + int(v4Count)*5 + int(v6Count)*17
	if len(data) != expectedSize {
		return nil, fmt.Errorf("fastfile: size mismatch (have %d, want %d)", len(data), expectedSize)
	}

	state := &FastFileState{
		V4: make([]netip.Prefix, v4Count),
		V6: make([]netip.Prefix, v6Count),
	}

	// PLUG-L1（历史 历史问题）：腐化防御——bits 越界（netip.PrefixFrom 产 invalid
	// 前缀）与地址降序都会静默破坏二分判定的排序不变量，响亮拒绝。
	// 展开 v4
	offset := fastFileHeaderSize
	for i := 0; i < int(v4Count); i++ {
		var addr [4]byte
		copy(addr[:], data[offset:offset+4])
		bits := int(data[offset+4])
		if bits > 32 {
			return nil, fmt.Errorf("fastfile: v4 entry %d bits out of range: %d", i, bits)
		}
		state.V4[i] = netip.PrefixFrom(netip.AddrFrom4(addr), bits)
		// E83-历史问题：主机位必须已掩码——与写侧同一不变量。未掩码条目
		// （1.2.3.200/24）地址升序/不相交校验都可能通过，但二分查询用
		// 未掩码地址比较会假阴性（威胁名单静默漏拦）。读侧是跨进程输入
		// （节点回传的 .fast），不能只依赖写侧自律。
		if state.V4[i] != state.V4[i].Masked() {
			return nil, fmt.Errorf("fastfile: v4 entry %d host bits not masked: %s", i, state.V4[i])
		}
		if i > 0 && state.V4[i-1].Addr().Compare(state.V4[i].Addr()) > 0 {
			return nil, fmt.Errorf("fastfile: v4 entries not in ascending order at %d", i)
		}
		// PL-1（历史 历史问题）：嵌套/同址不同 bits（升序合法却互相包含）会被
		// 窄段遮蔽产生二分假阴性——「可加载但查询错误」的最坏静默腐化形态，
		// 响亮拒绝。
		if i > 0 && state.V4[i-1].Contains(state.V4[i].Addr()) {
			return nil, fmt.Errorf("fastfile: v4 entries not disjoint at %d (%s contains %s)", i, state.V4[i-1], state.V4[i])
		}
		offset += 5
	}

	// 展开 v6（同口径校验）
	for i := 0; i < int(v6Count); i++ {
		var addr [16]byte
		copy(addr[:], data[offset:offset+16])
		bits := int(data[offset+16])
		if bits > 128 {
			return nil, fmt.Errorf("fastfile: v6 entry %d bits out of range: %d", i, bits)
		}
		state.V6[i] = netip.PrefixFrom(netip.AddrFrom16(addr), bits)
		// E83-历史问题：v6 同口径——主机位未掩码即拒。
		if state.V6[i] != state.V6[i].Masked() {
			return nil, fmt.Errorf("fastfile: v6 entry %d host bits not masked: %s", i, state.V6[i])
		}
		if i > 0 && state.V6[i-1].Addr().Compare(state.V6[i].Addr()) > 0 {
			return nil, fmt.Errorf("fastfile: v6 entries not in ascending order at %d", i)
		}
		// PL-1：v6 同口径——互相包含即拒。
		if i > 0 && state.V6[i-1].Contains(state.V6[i].Addr()) {
			return nil, fmt.Errorf("fastfile: v6 entries not disjoint at %d (%s contains %s)", i, state.V6[i-1], state.V6[i])
		}
		offset += 17
	}

	return state, nil
}

// FastPath 返回 .iplist 源文件对应的 .fast 编译文件路径。
func FastPath(iplistPath string) string {
	return iplistPath + ".fast"
}
