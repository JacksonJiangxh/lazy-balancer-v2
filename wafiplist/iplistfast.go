// Package wafiplist 提供 coraza 快算子 @ipListFast（v2.3.x）：从文本文件加载
// IP/CIDR 名单（每条一行，支持 #/; 注释），构建「排序不相交前缀集」，每请求
// 一次二分判定（O(log n)），替代 @ipMatch 内联展开（配置体积线性膨胀 +
// coraza seclang bufio.Scanner 64KiB 行上限静默截断悬崖）。
//
// 可靠性立场：
//   - 构建期 fail-closed——文件缺失/不可读/含不可解析行/路径越出白名单 →
//     NewWAF 报错 → Caddy 配置校验拒绝、保存回滚；
//   - 运行期 fail-stale——文件被删/写坏/重建失败时按最近一次成功加载的集合
//     继续判定（在役拒绝面不清空；写入侧是 tmp+rename 原子投影，半截文件
//     本就不会被读到）；
//   - stat 节流（StatCheckInterval，默认 1s）消除每请求 syscall；
//     0=每次 Evaluate 复查（测试与构建期路径恒走新鲜加载）。
//
// 版本解耦：本文件是唯一的 coraza 接触面（plugintypes 三类型 + RegisterOperator
// 注册点）；检索与聚合在 aggregate.go 纯 stdlib 实现——coraza/Caddy 升级
// 只需复核本文件。
package wafiplist

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/experimental/plugins"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// AllowedPathPrefix 是算子参数的目录白名单（防目录穿越）。测试可改。
var AllowedPathPrefix = "/app/waf/"

// MaxFileBytes / MaxEntries 是加载侧体积与条目的硬上限（防异常文件拖垮
// 内存；威胁库下载侧 200000 条上限先行拦截，此为纵深）。测试可收窄。
var (
	MaxFileBytes int64 = 64 << 20
	MaxEntries         = 1_000_000
)

// StatCheckInterval 是 Evaluate 侧复查文件 mtime/size 的最小间隔（默认 1s）。
// 正常变更路径（策略保存/威胁库更新）都会触发 Caddy 重载重建算子实例，
// 本节流只兜底带外文件改动的感知时延；0=每次都 stat（测试用）。
var StatCheckInterval = time.Second

// OnStaleServe 是 fail-stale 事件的观测钩子（运维可见性）：文件被删/重建
// 失败仍按旧集合判定时触发。默认空操作；生产侧不接（渲染日志已覆盖）。
var OnStaleServe = func(path string, err error) {}

// parseCountForTest 解析次数计数（测试观测构建期去重）。
var parseCountForTest atomic.Int64

func init() {
	plugins.RegisterOperator("ipListFast", newIPListFast)
}

type ipListFileState struct {
	mtime time.Time
	size  int64
	v4    []netip.Prefix // 升序、去重、不相交
	v6    []netip.Prefix
	// combined 是 v4∪v6 的只读快照（解析期一次成型）：GetIPRanges 式消费方
	// （http.ip_sources.lb_file）逐请求取用，共享返回零分配。切片归缓存
	// 所有，消费方 MUST NOT 修改。
	combined []netip.Prefix
	// lastCheckNano 是 Evaluate 节流的时间戳（原子读写，免锁热路径）。
	lastCheckNano atomic.Int64
}

var ipListCache = struct {
	sync.RWMutex
	states map[string]*ipListFileState
}{states: make(map[string]*ipListFileState)}

type ipListFastOperator struct {
	path string
}

// NormalizeAllowedPath 白名单路径归一的导出入口（http.ip_sources.lb_file 的
// Provision 持归一后路径作缓存键）。
func NormalizeAllowedPath(path string) (string, error) {
	return resolveAllowedPath(path)
}

// resolveAllowedPath 白名单路径归一（防目录穿越）：绝对路径 ∧ 在
// AllowedPathPrefix 下 ∧ 无 .. 段。算子与导出入口（LoadPrefixesFresh/
// ResolvePrefixes）共用单源。
func resolveAllowedPath(path string) (string, error) {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) || !strings.HasPrefix(cleaned, AllowedPathPrefix) || strings.Contains(path, "..") {
		return "", fmt.Errorf("名单路径越出白名单（须为 %s 下的绝对路径）: %q", AllowedPathPrefix, path)
	}
	return cleaned, nil
}

func newIPListFast(options plugintypes.OperatorOptions) (plugintypes.Operator, error) {
	cleaned, err := resolveAllowedPath(strings.TrimSpace(options.Arguments))
	if err != nil {
		return nil, err
	}
	// 构建期 fail-closed（新鲜加载，不走缓存/节流）：文件缺失/不可读/含坏行
	// → WAF 构建报错 → Caddy 校验拒绝、保存回滚。空文件合法（始终发射收敛，
	// 2026-10-15）：空集永不命中。
	if _, err := loadIPListFileFresh(cleaned); err != nil {
		return nil, err
	}
	return &ipListFastOperator{path: cleaned}, nil
}

// loadIPListFileFresh 构建期路径：stat 未命中（内容变化）才读盘重建，
// stat 命中共享缓存（同 reload 内 N 个引用同一文件的算子只解析一次）；
// 与运行期的差别仅在失败语义——构建期 fail-closed（error），不 fail-stale。
func loadIPListFileFresh(path string) (*ipListFileState, error) {
	return loadIPListFile(path, true)
}

// resolveIPListFile 是 Evaluate 的读路径：节流命中直接返回缓存；stat 失败或
// 重建失败且缓存存在 → fail-stale（返回旧集合）；缓存不存在 → error。
func resolveIPListFile(path string) (*ipListFileState, error) {
	ipListCache.RLock()
	cached := ipListCache.states[path]
	ipListCache.RUnlock()
	if cached != nil && StatCheckInterval > 0 &&
		time.Since(time.Unix(0, cached.lastCheckNano.Load())) < StatCheckInterval {
		return cached, nil
	}
	return loadIPListFile(path, false)
}

// LoadPrefixesFresh 是构建期导出入口（http.ip_sources.lb_file 的 Provision
// 消费，受信代理网段热路径化 2026-10-15）：与算子构建期同语义——新鲜加载，
// 任何失败（缺失/不可读/坏行/超限/路径越白名单）直接报错（fail-closed →
// Caddy 配置校验拒绝、保存回滚）；stat 命中共享缓存（同 reload 内多实例
// 引用同一文件只解析一次）。返回切片为缓存共享只读快照，消费方 MUST NOT
// 修改。
func LoadPrefixesFresh(path string) ([]netip.Prefix, error) {
	cleaned, err := resolveAllowedPath(path)
	if err != nil {
		return nil, err
	}
	state, err := loadIPListFile(cleaned, true)
	if err != nil {
		return nil, err
	}
	return state.combined, nil
}

// ResolvePrefixes 是运行期导出入口（lb_file 的 GetIPRanges 逐请求消费）：
// 白名单同规；节流（StatCheckInterval）命中返回缓存快照；文件变化检出后
// 重建；重建失败且有旧集 → fail-stale 返回旧集（IPRangeSource 契约——运行期
// 取网段 MUST NOT fail，否则取消在途请求）。从未成功加载（Provision 已拦
// 截，缓存被 GC 淘汰+文件消失的残余形态）→ error，由调用方按空集处理
// （信任无来源，fail-closed）。返回切片为缓存共享只读快照，消费方 MUST NOT
// 修改。
func ResolvePrefixes(path string) ([]netip.Prefix, error) {
	cleaned, err := resolveAllowedPath(path)
	if err != nil {
		return nil, err
	}
	state, err := resolveIPListFile(cleaned)
	if err != nil {
		return nil, err
	}
	return state.combined, nil
}

// loadIPListFile 读取并缓存名单文件：stat 形态（mtime+size）一致命中缓存，
// 变化重建。严格解析——任何不可解析行报错（不静默跳过，防名单被削弱）。
// 失败时缓存存在则 fail-stale 返回旧集合（fresh=true 的构建期除外：
// 构建期永远 fail-closed）。
func loadIPListFile(path string, fresh bool) (state *ipListFileState, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return staleOrError(path, nil, fmt.Errorf("IP 名单不可读 %q: %w", path, err), fresh)
	}
	if info.Size() > MaxFileBytes {
		return staleOrError(path, nil, fmt.Errorf("IP 名单 %q 超过体积上限 %dMB", path, MaxFileBytes>>20), fresh)
	}
	ipListCache.RLock()
	cached := ipListCache.states[path]
	ipListCache.RUnlock()
	// stat 形态命中即复用——构建期（fresh）同享：策略名单稳定命名下同路径
	// 同字节跳写（mtime 不变），威胁库/热路径原子重写 mtime 必变；N 规则引用
	// 同一文件只解析一次。
	if cached != nil && cached.mtime.Equal(info.ModTime()) && cached.size == info.Size() {
		cached.lastCheckNano.Store(time.Now().UnixNano())
		return cached, nil
	}

	state, err = parseIPListFile(path, info)
	if err != nil {
		return staleOrError(path, cached, err, fresh)
	}
	ipListCache.Lock()
	// 双检：并发重建只保留一份（后到者若基于同一 stat 形态则为同内容重复）。
	if current := ipListCache.states[path]; current != nil {
		if current.mtime.Equal(info.ModTime()) && current.size == info.Size() && current != cached {
			ipListCache.Unlock()
			current.lastCheckNano.Store(time.Now().UnixNano())
			return current, nil
		}
		// 历史问题（历史）代际守卫：并发重建时缓存里已是更晚 mtime 的
		// 新代际——本代际基于更早 stat 的解析结果不得覆盖（旧内容回流）。
		if current.mtime.After(info.ModTime()) {
			ipListCache.Unlock()
			current.lastCheckNano.Store(time.Now().UnixNano())
			return current, nil
		}
	}
	ipListCache.states[path] = state
	ipListCache.Unlock()
	return state, nil
}

// staleOrError：fail-stale 决策点——非构建期且有旧集合时回退旧集合。
func staleOrError(path string, cached *ipListFileState, err error, fresh bool) (*ipListFileState, error) {
	if cached == nil {
		ipListCache.RLock()
		cached = ipListCache.states[path]
		ipListCache.RUnlock()
	}
	if !fresh && cached != nil {
		cached.lastCheckNano.Store(time.Now().UnixNano())
		OnStaleServe(path, err)
		return cached, nil
	}
	return nil, err
}

// EvictIPListCache 淘汰指定路径的运行期缓存条目（services 侧 GC 删除超龄
// 未引用名单文件后调用）——否则 fail-stale 会把已删文件的集合无限期留在
// 内存。返回实际淘汰条数。
func EvictIPListCache(paths ...string) int {
	ipListCache.Lock()
	defer ipListCache.Unlock()
	evicted := 0
	for _, path := range paths {
		if _, ok := ipListCache.states[path]; ok {
			delete(ipListCache.states, path)
			evicted++
		}
	}
	return evicted
}

// parseIPListFile 读盘+严格解析+防御性归并（写入侧已聚合，加载侧再跑一次
// 保证「排序+去重+不相交」检索不变式——二分正确性依赖不相交）。
func parseIPListFile(path string, info os.FileInfo) (*ipListFileState, error) {
	parseCountForTest.Add(1)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("IP 名单读取失败 %q: %w", path, err)
	}
	var entries []string
	for lineNo, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if _, err := ParseIPEntry(line); err != nil {
			return nil, fmt.Errorf("IP 名单 %q 第 %d 行不可解析: %q", path, lineNo+1, line)
		}
		entries = append(entries, line)
	}
	// 空文件合法（2026-10-15 始终发射收敛）：渲染层空名单投影 0 字节空文件，
	// 空集=匹配器永不命中（与无规则语义等价）——空↔非空纯内容变化走热路径，
	// 构建期报错会使空名单策略的恒发射规则被 Caddy validate 拒绝。含坏行仍
	// 报错（严格解析不变，防名单被静默削弱）。
	if len(entries) > MaxEntries {
		return nil, fmt.Errorf("IP 名单 %q 条目数 %d 超过上限 %d", path, len(entries), MaxEntries)
	}
	prefixes := AggregatePrefixes(entries)
	state := &ipListFileState{mtime: info.ModTime(), size: info.Size()}
	state.lastCheckNano.Store(time.Now().UnixNano())
	for _, p := range prefixes {
		if p.Addr().Is4() {
			state.v4 = append(state.v4, p)
		} else {
			state.v6 = append(state.v6, p)
		}
	}
	state.combined = append(append(make([]netip.Prefix, 0, len(state.v4)+len(state.v6)), state.v4...), state.v6...)
	return state, nil
}

func (op *ipListFastOperator) Evaluate(_ plugintypes.TransactionState, value string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	// 4in6 映射形态归一（netip 的 v4 前缀不含 4in6 地址——不 Unmap 会漏判）。
	addr = addr.Unmap()
	state, err := resolveIPListFile(op.path)
	if err != nil {
		return false // 从未成功加载过（理论上构建期已拦截）——按未命中
	}
	set := state.v4
	if addr.Is6() {
		set = state.v6
	}
	// 排序不相交前缀集：含目标的前缀必为最后一个 start <= 目标的前缀。
	i := sort.Search(len(set), func(i int) bool { return set[i].Addr().Compare(addr) > 0 }) - 1
	return i >= 0 && set[i].Contains(addr)
}

// ParseIPEntry 解析单条名单条目：CIDR 或裸 IP（补 /32 //128，主机位掩码
// 归零）。4in6 映射形态（::ffff:a.b.c.d、::ffff:a.b.c.d/120）Unmap 归一为
// v4 前缀（前缀 bits-96）——netip 的 v4 前缀不含 4in6 地址，Evaluate 侧
// 查询已 Unmap，条目不归一会落入 v6 集导致 v4 查询恒不命中（名单静默失效）。
// 渲染层/威胁库下载解析共用。
func ParseIPEntry(entry string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(entry); err == nil {
		addr := prefix.Addr().Unmap()
		bits := prefix.Bits()
		if addr.Is4() && prefix.Addr().Is4In6() {
			bits -= 96
			if bits < 0 {
				return netip.Prefix{}, fmt.Errorf("4in6 前缀 %q 位数小于 /96，无法归一为 v4", entry)
			}
		}
		return netip.PrefixFrom(addr, bits).Masked(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits), nil
}
