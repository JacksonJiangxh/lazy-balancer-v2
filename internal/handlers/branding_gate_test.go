package handlers

// 公开 GET /branding 的写副作用门与 EnsureBrandingFile 的职责边界：
//   - 稳态（branding.json 内容指纹未变）匿名读完全跳过幂等写副作用，不再
//     每 60s 无条件跑一轮 SQL/播种/镜像；
//   - EnsureBrandingFile 只保证文件字段齐备，不做 landing 文案注入（注释与
//     实现一致，注入由装配方随后调用 SyncDefaultLandingText）。

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
)

func TestBrandingSyncGate_skipsUnchangedFileAndThrottlesChanges(t *testing.T) {
	resetBrandingSyncGateForTest()
	t.Cleanup(resetBrandingSyncGateForTest)
	dir := t.TempDir()
	path := filepath.Join(dir, "branding.json")

	// Given：branding.json 缺失 → 不跑写副作用（boot/装配已负责播种）。
	if brandingSyncGateAllow(dir) {
		t.Fatal("文件缺失时不得触发写副作用")
	}

	// Given：文件存在。
	if err := os.WriteFile(path, []byte(`{"app_name":"甲"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Then：首次放行（处理带外编辑）。
	if !brandingSyncGateAllow(dir) {
		t.Fatal("文件首见应放行一轮同步")
	}
	// Then：内容指纹未变 → 后续匿名读零写（旧实现每 60s 无条件一轮）。
	for range 5 {
		if brandingSyncGateAllow(dir) {
			t.Fatal("文件未变化不得重复触发写副作用（稳态零写）")
		}
	}

	// When：文件被手工编辑（内容/大小变化），仍处 60s 采样窗内。
	if err := os.WriteFile(path, []byte(`{"app_name":"甲乙"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if brandingSyncGateAllow(dir) {
		t.Fatal("60s 采样窗内不得立即处理（连续编辑合并）")
	}

	// When：采样窗过期（模拟 ≥60s）。
	brandingSyncMu.Lock()
	brandingSyncLast = time.Now().Add(-2 * time.Minute)
	brandingSyncMu.Unlock()
	// Then：放行一次，处理编辑。
	if !brandingSyncGateAllow(dir) {
		t.Fatal("采样窗过期后应放行编辑后的同步")
	}
	if brandingSyncGateAllow(dir) {
		t.Fatal("处理完成后同一内容不得重复放行")
	}

	// When：采样窗再次过期但文件内容未变。
	brandingSyncMu.Lock()
	brandingSyncLast = time.Now().Add(-2 * time.Minute)
	brandingSyncMu.Unlock()
	// Then：仍不得放行——指纹门优先于时间门（稳态匿名读零写；仅时间门会在
	// 每分钟无条件跑一轮 SQL/播种/镜像）。
	if brandingSyncGateAllow(dir) {
		t.Fatal("内容未变时采样窗过期也不得触发写副作用（指纹门必须生效）")
	}

	// When：同步失败标记清空指纹。
	brandingSyncMarkFailed()
	// Then：下一轮（采样窗内也会被 60s 门挡，因此先让窗过期）重试。
	brandingSyncMu.Lock()
	brandingSyncLast = time.Now().Add(-2 * time.Minute)
	brandingSyncMu.Unlock()
	if !brandingSyncGateAllow(dir) {
		t.Fatal("失败后必须允许重试，不得把失败固化为已处理")
	}
}

// 「文件已齐备」分支零写入、零注入——单点调用者必须自行随后调用
// SyncDefaultLandingText，注释不得承诺本函数已完成注入（否则新增调用者会
// 得到「文件齐备但默认站点文案未生效」）。
func TestEnsureBrandingFile_completeFileLeavesLandingInjectionToCaller(t *testing.T) {
	const sentinel = "sentinel-landing-body"
	original := services.DefaultLandingBody()
	services.SetDefaultLandingBody(sentinel)
	t.Cleanup(func() { services.SetDefaultLandingBody(original) })

	dir := t.TempDir()
	content := `{"app_name":"甲","footer_text":"乙","landing_text":"丙","version":"1.0.0"}`
	if err := os.WriteFile(filepath.Join(dir, "branding.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := EnsureBrandingFile(dir); err != nil {
		t.Fatalf("EnsureBrandingFile: %v", err)
	}
	if got := services.DefaultLandingBody(); got != sentinel {
		t.Fatalf("landing body=%q, 齐全分支零写入（不得注入）", got)
	}

	// 调用方补齐后的效果：注入落地为文件里的 landing_text。
	if changed, err := SyncDefaultLandingText(dir); err != nil || !changed {
		t.Fatalf("SyncDefaultLandingText changed=%v err=%v, want true/nil", changed, err)
	}
	if got := services.DefaultLandingBody(); got != "丙" {
		t.Fatalf("landing body=%q, want 丙（调用方负责注入）", got)
	}
}

// 同步门指纹必须含 dataDir（与 brandingStore 的键控同构）：同进程切换数据
// 目录时，前一个目录的指纹与 60s 采样窗不得吞掉新目录的首轮同步。
func TestBrandingSyncGate_dataDirChangeResetsThrottle(t *testing.T) {
	resetBrandingSyncGateForTest()
	t.Cleanup(resetBrandingSyncGateForTest)

	dirA, dirB := t.TempDir(), t.TempDir()
	for _, dir := range []string{dirA, dirB} {
		if err := os.WriteFile(filepath.Join(dir, "branding.json"), []byte(`{"app_name":"甲"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Given：目录 A 已完成一轮同步（指纹已记录、60s 窗处于计时中）。
	if !brandingSyncGateAllow(dirA) {
		t.Fatal("目录 A 首见应放行")
	}
	if brandingSyncGateAllow(dirA) {
		t.Fatal("目录 A 内容未变不得重复放行")
	}

	// When/Then：紧接切换到目录 B——60s 采样窗必须重置，不得被 A 的时间窗挡住。
	if !brandingSyncGateAllow(dirB) {
		t.Fatal("切换 dataDir 后首轮必须放行（60s 采样窗按目录重置）")
	}
	if brandingSyncGateAllow(dirB) {
		t.Fatal("目录 B 内容未变不得重复放行")
	}

	// And：切回 A 会重新放行一轮（单槽指纹按目录切换重置；写副作用幂等，
	// 切换本身不是生产形态），随后稳态零写。
	if !brandingSyncGateAllow(dirA) {
		t.Fatal("切回目录 A 后首轮放行（指纹槽随目录重置）")
	}
	if brandingSyncGateAllow(dirA) {
		t.Fatal("目录 A 稳态（内容未变）不得重复触发写副作用")
	}
}
