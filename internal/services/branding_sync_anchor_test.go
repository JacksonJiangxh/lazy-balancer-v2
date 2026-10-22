package services_test

import (
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/services"
)

// services 的空品牌镜像与 handlers 启动期再生模板必须逐字节一致。
// 外部测试包同时导入两侧，避免 services → handlers 的生产依赖环。
func TestBrandingEmptyTemplate_matchesHandlerBytes(t *testing.T) {
	handlerDir := t.TempDir()
	serviceDir := t.TempDir()
	if err := handlers.EnsureBrandingFile(handlerDir); err != nil {
		t.Fatalf("create handler template: %v", err)
	}
	if err := services.MaterializeBranding(serviceDir, ""); err != nil {
		t.Fatalf("materialize service template: %v", err)
	}
	want, err := os.ReadFile(filepath.Join(handlerDir, "branding.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(serviceDir, "branding.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("branding template bytes differ\nhandler=%q\nservice=%q", want, got)
	}
}
