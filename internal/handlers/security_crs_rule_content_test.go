package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// 穿越门与尺寸门的回归钉：../ 与 / 形态的 filename 必须 400（此前只有
// 测试缝用例覆盖 200 路径）；超 1MB 文件必须 413 而非静默截断。
func TestGetCRSRuleContent_rejectsTraversalAndOversize(t *testing.T) {
	dir := t.TempDir()
	oldDir := crsRulesDir
	crsRulesDir = dir
	t.Cleanup(func() { crsRulesDir = oldDir })

	for _, filename := range []string{"../x.conf", "..\\x.conf", "a/b.conf"} {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		ctx.Request = httptest.NewRequest(http.MethodGet, "/security/crs/rules/"+filename, nil)
		ctx.Params = gin.Params{{Key: "filename", Value: filename}}
		newBackupTestHandlers(t).GetCRSRuleContent(ctx)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("filename %q = %d body=%s, want 400（路径穿越门）", filename, recorder.Code, recorder.Body.String())
		}
	}

	// 超 1MB 规则文件 → 413（LimitReader 1MB+1 哨兵）
	oversize := strings.Repeat("#", 1<<20+8)
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-999-BIG.conf"), []byte(oversize), 0o644); err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/security/crs/rules/REQUEST-999-BIG.conf", nil)
	ctx.Params = gin.Params{{Key: "filename", Value: "REQUEST-999-BIG.conf"}}
	newBackupTestHandlers(t).GetCRSRuleContent(ctx)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize file = %d body=%.200s, want 413", recorder.Code, recorder.Body.String())
	}
}

// （WAF 域划入 handlers/security.go · 批准修复）：GetCRSRuleContent 必须经
// crsRulesDir 测试缝（文件头声明，ListCRSRules 同源）解析规则文件路径——此前
// 局部变量硬编码 "/app/waf/crs/rules" 且遮蔽 filepath 包名，与缝声明构成双真源，
// 规则目录不可注入（测试因此只能钉 400/404 两分支）。
func TestGetCRSRuleContent_resolvesViaCRSRulesDirSeam(t *testing.T) {
	// Given：crsRulesDir 指向临时目录，内含一个规则文件
	dir := t.TempDir()
	const content = "SecRule REQUEST_URI \"@rx /w8-seam\" \"id:942100,phase:1,pass,nolog\"\n"
	if err := os.WriteFile(filepath.Join(dir, "REQUEST-942-SEAM.conf"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	oldDir := crsRulesDir
	crsRulesDir = dir
	t.Cleanup(func() { crsRulesDir = oldDir })

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/security/crs/rules/REQUEST-942-SEAM.conf", nil)
	ctx.Params = gin.Params{{Key: "filename", Value: "REQUEST-942-SEAM.conf"}}

	// When：读取规则文件内容
	newBackupTestHandlers(t).GetCRSRuleContent(ctx)

	// Then：200 且返回注入目录中的文件内容（硬编码 /app 路径下必 404）
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（须经 crsRulesDir 测试缝解析路径）", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "@rx /w8-seam") {
		t.Fatalf("body 不含注入目录中的规则内容: %s", recorder.Body.String())
	}
}
