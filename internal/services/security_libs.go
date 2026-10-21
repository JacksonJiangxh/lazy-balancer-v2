package services

import (
	"os"
	"path/filepath"
)

// 缺库降级（2026-09-24 用户裁定）：CRS 规则库或 IP2Region 库缺失时，安全链
// （预检/ACL/限流/WAF/GeoIP/信任直通包裹）整体不渲染——所有安全规则不生效。
// 背景：coraza 指令 Include 缺失文件会让 caddy validate 拒绝整份配置，
// 负载均衡也被拖死；降级为安全段缺席 + 告警日志，补库后渲染自动恢复。
// 面板侧提示：规则库卡片头部摘要（缺库异常描述）+ 本渲染告警日志。

// SecurityLibraryStatus 探测安全链依赖的两类规则库可用性：
// CRS=规则树满足安装完整性探针（≥1 个 .conf + 901 探针文件，与安装/恢复
// 门 crsRulesTreeIntact 同口径；空树/残树下 Include glob 虽可能编译但运行时
// 偏执级守卫空转，面板不得宣称“库可用”）；IP2Region=库文件存在且非空。
func SecurityLibraryStatus() (crsOK, ip2regionOK bool) {
	if crsRulesTreeIntact(filepath.Join(crsDirectivesDir, "rules")) {
		crsOK = true
	}
	if st, err := os.Stat(ip2regionLivePath); err == nil && st.Size() > 0 {
		ip2regionOK = true
	}
	return
}

// SecurityLibrariesAvailable 两类库齐全才允许渲染安全链。
func SecurityLibrariesAvailable() bool {
	crsOK, ip2regionOK := SecurityLibraryStatus()
	return crsOK && ip2regionOK
}

// securityLibrariesMissingDesc 供告警日志的缺失描述（如「CRS 规则库」）。
func securityLibrariesMissingDesc() string {
	crsOK, ip2regionOK := SecurityLibraryStatus()
	missing := ""
	if !crsOK {
		missing = "CRS 规则库"
	}
	if !ip2regionOK {
		if missing != "" {
			missing += "、"
		}
		missing += "IP 地址库（IP2Region）"
	}
	return missing
}

// SetSecurityLibsDirsForTest 注入 CRS/IP2Region 库路径（handlers 等跨包渲染类
// 测试用——缺库形态安全链整体不渲染，名单投影/热路径无从谈起）。返回恢复函数。
func SetSecurityLibsDirsForTest(crsDir, xdbPath string) (restore func()) {
	oldLive, oldCRS, oldXdb := crsLiveDir, crsDirectivesDir, ip2regionLivePath
	crsLiveDir, crsDirectivesDir, ip2regionLivePath = crsDir, crsDir, xdbPath
	return func() { crsLiveDir, crsDirectivesDir, ip2regionLivePath = oldLive, oldCRS, oldXdb }
}
