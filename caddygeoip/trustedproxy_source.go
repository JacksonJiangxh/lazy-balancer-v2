package caddygeoip

// http.ip_sources.lb_file（2026-10-15 受信代理网段热路径化）：Caddy 原生
// trusted_proxies 插件口（caddyhttp.IPRangeSource）的文件源。消费 services
// 渲染层投影的稳定路径网段文件（tp.txt——内联 ∪ 引用名单合并网段，与
// @ipListFast 投影同目录同族）：名单/网段内容变化 → 投影文件原子重写 →
// 本模块 ≤1s stat 热感知，零 Caddy /load 收敛。
//
// 复用裁定（不新建平行实现）：文件解析（严格解析+4in6 归一）、排序不相交
// 前缀集聚合、stat（mtime+size）节流缓存、fail-stale 语义，单一来源在
// wafiplist 叶模块（@ipListFast 同一缓存——同一路径共享同一不可变快照，
// 与多算子引用同一名单文件的行为一致；不同路径互不可见，实例各自持 path
// 独立解析，无跨文件共享状态）。本文件只承载 Caddy 模块装配。
//
// 生命周期契约（caddyhttp/ip_range.go IPRangeSource 文档钉）：
//   - Provision 期加载就绪（fail-fast——缺失/坏行/路径越白名单 → 配置校验
//     拒绝、保存回滚）；
//   - GetIPRanges 必须快（节流 stat+共享只读快照，零每请求解析/分配），
//     MUST NOT modify request（本实现不触碰 r）；
//   - 运行期取网段 MUST NOT fail（会取消在途请求）——重建失败 fail-stale
//     返回旧集；缓存被淘汰且文件消失（受信代理停用 24h GC 后的残余形态）
//     返回空集=信任无来源（fail-closed，宁可退回 socket IP 也不采信未
//     校验的头）。

import (
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"lazy-balancer-v2/wafiplist"
)

// FileIPRangeSource 从文本名单文件（每行一条 CIDR/裸 IP，支持 #/; 注释）
// 提供 trusted_proxies 网段。渲染层保证路径在 wafiplist.AllowedPathPrefix
// 白名单下（IPListDataDir 稳定命名 tp.txt）。
type FileIPRangeSource struct {
	// Path 是受信代理网段投影文件绝对路径（trustedProxyServerFields 发射）。
	Path string `json:"path,omitempty"`

	// provisioned 是白名单归一后的路径（Provision 填充；未 Provision 时
	// GetIPRanges 按 fail-closed 返回空集）。
	provisioned string
}

func init() {
	caddy.RegisterModule(FileIPRangeSource{})
}

// CaddyModule returns the Caddy module information.
func (FileIPRangeSource) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.ip_sources.lb_file",
		New: func() caddy.Module { return new(FileIPRangeSource) },
	}
}

// Provision implements caddy.Provisioner. 构建期新鲜加载（fail-fast）：
// 文件缺失/坏行/路径越白名单在这里报错 → Caddy 校验拒绝整份配置、保存
// 回滚。缓存键=白名单归一路径，与 GetIPRanges 读路径一致。
func (s *FileIPRangeSource) Provision(ctx caddy.Context) error {
	cleaned, err := wafiplist.NormalizeAllowedPath(s.Path)
	if err != nil {
		return err
	}
	if _, err := wafiplist.LoadPrefixesFresh(cleaned); err != nil {
		return err
	}
	s.provisioned = cleaned
	return nil
}

// GetIPRanges implements caddyhttp.IPRangeSource.
//
// r 不使用——IPRangeSource 契约：调用方已读 r.RemoteAddr，插件 MUST NOT
// modify request。返回切片为 wafiplist 缓存共享只读快照（Caddy 侧仅遍历
// 判定，不修改）；节流窗口内零开销直取。
func (s *FileIPRangeSource) GetIPRanges(r *http.Request) []netip.Prefix {
	_ = r // MUST NOT modify request
	if s.provisioned == "" {
		return nil // 未 Provision 的防御形态：信任无来源
	}
	prefixes, err := wafiplist.ResolvePrefixesNormalized(s.provisioned)
	if err != nil {
		// Provision 已保证首次加载成功；此处 error = 缓存被 GC 淘汰且文件
		// 已消失。空集=信任无来源（fail-closed）。运行期不得 fail，但该
		// 状态迁移（仍有配置引用、文件却消失）必须留节流 WARN——否则全站
		// 客户端 IP 静默退回 socket 地址（GeoIP/信任名单/限流/审计归属地
		// 全部按错误 IP 判定）而面板零痕迹。
		wafiplist.ReportListUnavailable(s.provisioned, err)
		return nil
	}
	return prefixes
}

// Interface guards（编译期契约，零运行时成本）。
var (
	_ caddy.Provisioner       = (*FileIPRangeSource)(nil)
	_ caddyhttp.IPRangeSource = (*FileIPRangeSource)(nil)
)
