package config

import "testing"

// 代理默认口与面板口来自环境变量（ISSUE #7）；未设/非法回落出厂默认。
func TestLoad_proxyPortsFromEnv(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("HTTP_PORT", "8080")
	t.Setenv("HTTPS_PORT", "8443")
	t.Setenv("PANEL_PORT", "9000")

	cfg := Load("")

	if cfg.HTTPPort != 8080 {
		t.Fatalf("HTTPPort = %d, want 8080", cfg.HTTPPort)
	}
	if cfg.HTTPSPort != 8443 {
		t.Fatalf("HTTPSPort = %d, want 8443", cfg.HTTPSPort)
	}
	if cfg.Port != 9000 {
		t.Fatalf("Port = %d, want 9000", cfg.Port)
	}
}

func TestLoad_proxyPortsDefaultWhenUnset(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")

	cfg := Load("")

	if cfg.HTTPPort != 80 {
		t.Fatalf("HTTPPort = %d, want 80", cfg.HTTPPort)
	}
	if cfg.HTTPSPort != 443 {
		t.Fatalf("HTTPSPort = %d, want 443", cfg.HTTPSPort)
	}
	if cfg.Port != 8000 {
		t.Fatalf("Port = %d, want 8000", cfg.Port)
	}
}

func TestLoad_proxyPortsRejectInvalidEnv(t *testing.T) {
	t.Setenv("JWT_SECRET", "test-secret")
	t.Setenv("HTTP_PORT", "0")
	t.Setenv("HTTPS_PORT", "not-a-port")
	t.Setenv("PANEL_PORT", "70000")

	cfg := Load("")

	if cfg.HTTPPort != 80 {
		t.Fatalf("invalid HTTP_PORT should fall back to 80, got %d", cfg.HTTPPort)
	}
	if cfg.HTTPSPort != 443 {
		t.Fatalf("invalid HTTPS_PORT should fall back to 443, got %d", cfg.HTTPSPort)
	}
	if cfg.Port != 8000 {
		t.Fatalf("invalid PANEL_PORT should fall back to 8000, got %d", cfg.Port)
	}
}
