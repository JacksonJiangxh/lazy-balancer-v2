package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// RefreshBrandingMirror 把主节点 branding.json 原文镜像到
// global_config.branding_json(2026-09-11 裁定)。内容变化才写——触发器
// (branding_json 已入 OF 列表)bump cluster_version,快照缓存随之失效,
// 变更自然流向从节点;内容不变零写入零版本扰动。文件缺失镜像为空串。
// 仅主节点生效(WHERE is_master=1,与触发器 WHEN 同守卫)。
// 调用点:快照服务入口(每同步周期)与 GetBranding(文件变化检测路径)。
func RefreshBrandingMirror(dataDir string) (changed bool, err error) {
	if db.DB == nil {
		return false, nil
	}
	content := ""
	if raw, rerr := os.ReadFile(filepath.Join(dataDir, "branding.json")); rerr == nil {
		content = string(raw)
		// 半截写守卫(2026-09-11 裁定):非法 JSON 不镜像——坏内容永不
		// 经集群通道流向从节点;文件恢复完整后下次轮询自然收敛。
		if content != "" && !json.Valid([]byte(content)) {
			Logf("warn", "品牌配置文件暂不可解析(半截写?),跳过镜像: %s", dataDir)
			return false, nil
		}
	} else if !os.IsNotExist(rerr) {
		return false, fmt.Errorf("读取品牌配置文件: %w", rerr)
	}
	result, err := db.DB.Exec(
		`UPDATE global_config SET branding_json=? WHERE id=1 AND COALESCE(is_master,1)=1 AND COALESCE(branding_json,'')<>?`,
		content, content)
	if err != nil {
		return false, fmt.Errorf("镜像品牌配置: %w", err)
	}
	n, _ := result.RowsAffected()
	return n > 0, nil
}

// emptyBrandingTemplate 与 handlers.EnsureBrandingFile 缺失再生的全空模板
// 逐字节一致(同 map 同 MarshalIndent 参数,键序按字典序稳定)。模板形态的
// 属主在 handlers 侧(启动期 main.go 调用 EnsureBrandingFile),services
// 反向 import 成环无法复用,此处复刻并锚定——字段增减须双侧同步。
var emptyBrandingTemplate = func() string {
	out, _ := json.MarshalIndent(map[string]string{
		"app_name":     "",
		"footer_text":  "",
		"landing_text": "",
		"version":      "",
	}, "", "  ")
	return string(out)
}()

// MaterializeBranding 把 branding_json 镜像值写回其事实源文件，并立即
// 注入 landing 文案。空内容按集群同步既有语义收敛为全空模板。
func MaterializeBranding(dataDir, content string) error {
	if dataDir == "" {
		return fmt.Errorf("品牌配置目录为空")
	}
	if content != "" {
		var object map[string]json.RawMessage
		if err := json.Unmarshal([]byte(content), &object); err != nil || object == nil {
			return fmt.Errorf("品牌配置不是有效 JSON 对象")
		}
	}
	if content == "" {
		content = emptyBrandingTemplate
	}
	path := filepath.Join(dataDir, "branding.json")
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		injectLandingFromBranding(content)
		return nil
	}
	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(path); statErr == nil {
		mode = info.Mode().Perm()
	}
	temporary, err := os.CreateTemp(dataDir, ".branding-*.tmp")
	if err != nil {
		return fmt.Errorf("创建品牌配置临时文件: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("设置品牌配置文件权限: %w", err)
	}
	if _, err := temporary.WriteString(content); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("写入品牌配置临时文件: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("关闭品牌配置临时文件: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("原子替换品牌配置文件: %w", err)
	}
	injectLandingFromBranding(content)
	return nil
}

// applySnapshotBranding 在 global_config 节应用后(事务已提交、Caddy 重载前)
// 把快照携带的 branding.json 写入本地文件并注入 landing 渲染。有差异才写
// (幂等,零 mtime 扰动);内存快照(若有)由 handlers 侧 loadBrandingConfig
// 的 stat 检测在下一次访问时自动重载;landing 立即注入保证随后的 Caddy
// 重载渲染新文案。BrandingJSON 为空=主节点无品牌文件(三分类合并后 users 节
// 恒同步+schema v3 强制,旧语义「开关关闭/旧主节点」消失,历史问题):重置为
// 全空模板收敛默认品牌——不直接删除,loadBrandingConfig 对缺失文件保内存
// 上一份旧值(2026-09-11 半截写窗口裁定),删除会让从端 /branding 长期陈旧。
func applySnapshotBranding(dataDir, content string) {
	if dataDir == "" {
		return
	}
	reset := content == ""
	if err := MaterializeBranding(dataDir, content); err != nil {
		Logf("error", "同步品牌配置落盘失败: %v", err)
		RecordAuditLog("system", "同步失败", "集群同步", fmt.Sprintf("品牌配置落盘失败: %v", err), "")
		return
	}
	if reset {
		RecordAuditLog("system", "同步", "集群同步", "品牌配置已重置为默认（主节点无品牌文件）", "")
	} else {
		RecordAuditLog("system", "同步", "集群同步", "品牌配置已同步生效", "")
	}
}

// injectLandingFromBranding 从 branding JSON 原文提取 landing_text 并注入
// services 渲染(空/缺失/畸形回退默认,与 handlers.loadBrandingConfig 同语义)。
func injectLandingFromBranding(content string) {
	text := extractBrandingStringField(content, "landing_text")
	if text == "" {
		text = DefaultLandingText
	}
	SetDefaultLandingBody(text)
}

// extractBrandingStringField 从 JSON 原文按字段名提取字符串值;任何解析
// 失败回退空串。值经 json.Unmarshal 值级解析(与主节点 loadBrandingConfig
// 同语义——含 \uXXXX/\n 等全部转义形态,SR-1 历史修复)。
func extractBrandingStringField(content, field string) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return ""
	}
	val, ok := raw[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(val, &s); err != nil {
		return "" // 非字符串/畸形值按空处理(消费方回退默认)
	}
	return s
}

// SnapshotForTest 暴露缓存旁路快照供测试断言(生产路径经 Snapshot)。
func (s *ClusterService) SnapshotForTest(ctx context.Context) (models.ClusterSnapshot, error) {
	return s.clusterSnapshotBypassingCache(ctx)
}
