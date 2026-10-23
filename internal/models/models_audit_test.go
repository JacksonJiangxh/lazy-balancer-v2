package models

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClusterAccessURLTargetsNode(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		ip   string
		port int
		want bool
	}{
		{name: "loopback literal", url: "http://127.0.0.1:8000", ip: "192.168.50.2", port: 8000, want: true},
		{name: "localhost", url: "http://localhost:8000", ip: "192.168.50.2", port: 8000, want: true},
		{name: "IPv6 loopback", url: "https://[::1]:8000", ip: "192.168.50.2", port: 8000, want: true},
		{name: "outbound IP", url: "http://192.168.50.2:8000", ip: "192.168.50.2", port: 8000, want: true},
		{name: "different port", url: "http://192.168.50.2:8001", ip: "192.168.50.2", port: 8000, want: false},
		{name: "different host", url: "http://192.168.50.3:8000", ip: "192.168.50.2", port: 8000, want: false},
		{name: "default HTTP port match", url: "http://192.168.50.2", ip: "192.168.50.2", port: 80, want: true},
		{name: "default HTTPS port match", url: "https://192.168.50.2", ip: "192.168.50.2", port: 443, want: true},
		{name: "default port mismatch", url: "https://192.168.50.2", ip: "192.168.50.2", port: 8000, want: false},
		{name: "hostname alias remains best effort", url: "http://example.com:8000", ip: "192.168.50.2", port: 8000, want: false},
		{name: "invalid URL", url: "://bad", ip: "192.168.50.2", port: 8000, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClusterAccessURLTargetsNode(tc.url, tc.ip, tc.port); got != tc.want {
				t.Fatalf("ClusterAccessURLTargetsNode(%q,%q,%d)=%v, want %v", tc.url, tc.ip, tc.port, got, tc.want)
			}
		})
	}
}

// access_url 的信任锚必须是 IP 字面量来源地址：非 IP（主机名/空串/非法串）
// 不构成可比锚，一律判不一致——曾以请求体自述值传入，双方同源等于未校验。
func TestClusterAccessURLHostMatchesIP(t *testing.T) {
	for _, tc := range []struct {
		name    string
		url     string
		ip      string
		matches bool
	}{
		{name: "empty url is not a claim", url: "", ip: "10.0.0.5", matches: true},
		{name: "same IPv4", url: "https://10.0.0.5:8443", ip: "10.0.0.5", matches: true},
		{name: "same IPv6", url: "https://[2001:db8::1]:8443", ip: "2001:db8::1", matches: true},
		{name: "different IP", url: "https://10.0.0.6:8443", ip: "10.0.0.5", matches: false},
		{name: "hostname is never trusted", url: "https://attacker.example", ip: "attacker.example", matches: false},
		{name: "hostname host is not an IP", url: "https://edge.example:8443", ip: "10.0.0.5", matches: false},
		{name: "empty source address is not an anchor", url: "https://10.0.0.5:8443", ip: "", matches: false},
		{name: "malformed source address is not an anchor", url: "https://10.0.0.5:8443", ip: "10.0.0.500", matches: false},
		{name: "unparsable url", url: "://bad", ip: "10.0.0.5", matches: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClusterAccessURLHostMatchesIP(tc.url, tc.ip); got != tc.matches {
				t.Fatalf("ClusterAccessURLHostMatchesIP(%q,%q)=%v, want %v", tc.url, tc.ip, got, tc.matches)
			}
		})
	}
}

func TestGlobalConfig_serializes_DNS_credentials(t *testing.T) {
	// Given
	config := GlobalConfig{DNSCredentials: "id,token"}

	// When
	data, err := json.Marshal(config)
	// Then
	if err != nil {
		t.Fatalf("marshal GlobalConfig: %v", err)
	}
	if !strings.Contains(string(data), `"dns_credentials":"id,token"`) {
		t.Fatalf("GlobalConfig JSON=%s, want DNS credentials", data)
	}
}

func TestGlobalConfig_omitsClusterInternalState(t *testing.T) {
	// Given：未赋值的响应模型不得凭空发布集群内部状态的零值契约。
	data, err := json.Marshal(GlobalConfig{})
	if err != nil {
		t.Fatalf("marshal GlobalConfig: %v", err)
	}
	body := string(data)
	for _, key := range []string{"cluster_version", "applied_version", "last_sync_error"} {
		if strings.Contains(body, `"`+key+`"`) {
			t.Errorf("GlobalConfig exposes unpopulated %s: %s", key, body)
		}
	}
	// 回归形状：实际由 GetConfig 填载的同步时间字段继续存在。
	if !strings.Contains(body, `"last_sync":null`) || !strings.Contains(body, `"updated_at":null`) {
		t.Fatalf("populated sync timestamps must remain in API: %s", body)
	}
}

func TestUserResponse_serializes_nullable_fields_as_values_or_null(t *testing.T) {
	// Given
	createdAt := time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC)
	lastLogin := createdAt.Add(time.Hour)
	users := []User{
		{ID: 1, Username: "alice", DisplayName: sql.NullString{String: "Alice", Valid: true}, CreatedAt: createdAt, LastLogin: sql.NullTime{Time: lastLogin, Valid: true}},
		{ID: 2, Username: "bob", CreatedAt: createdAt},
	}

	// When
	data, err := json.Marshal([]UserResponse{NewUserResponse(users[0], true), NewUserResponse(users[1], false)})

	// Then
	if err != nil {
		t.Fatalf("marshal user responses: %v", err)
	}
	jsonBody := string(data)
	for _, expected := range []string{`"display_name":"Alice"`, `"last_login":"2026-07-30T02:02:03Z"`, `"display_name":null`, `"last_login":null`, `"mfa_enabled":true`, `"mfa_enabled":false`} {
		if !strings.Contains(jsonBody, expected) {
			t.Fatalf("UserResponse JSON=%s, want %s", jsonBody, expected)
		}
	}
	if strings.Contains(jsonBody, `"Valid"`) || strings.Contains(jsonBody, `"String"`) {
		t.Fatalf("UserResponse leaked sql nullable representation: %s", jsonBody)
	}
}

func TestAPIKeyResponse_serializes_nullable_times_as_values_or_null(t *testing.T) {
	// Given
	createdAt := time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC)
	lastUsed := createdAt.Add(time.Hour)
	key := APIKey{ID: 1, Name: "ci", CreatedAt: createdAt, LastUsed: sql.NullTime{Time: lastUsed, Valid: true}}

	// When
	data, err := json.Marshal([]APIKeyResponse{NewAPIKeyResponse(key), NewAPIKeyResponse(APIKey{ID: 2, CreatedAt: createdAt})})

	// Then
	if err != nil {
		t.Fatalf("marshal API key responses: %v", err)
	}
	jsonBody := string(data)
	for _, expected := range []string{`"last_used":"2026-07-30T02:02:03Z"`, `"last_used":null`, `"expires_at":null`} {
		if !strings.Contains(jsonBody, expected) {
			t.Fatalf("APIKeyResponse JSON=%s, want %s", jsonBody, expected)
		}
	}
	if strings.Contains(jsonBody, `"Valid"`) || strings.Contains(jsonBody, `"Time"`) {
		t.Fatalf("APIKeyResponse leaked sql nullable representation: %s", jsonBody)
	}
}

func TestPublicModelsSerializeNullableTimesAsStringsOrNull(t *testing.T) {
	value := JSONNullTime{NullTime: sql.NullTime{Time: time.Date(2026, time.July, 30, 1, 2, 3, 0, time.UTC), Valid: true}}
	data, err := json.Marshal([]any{
		LbRule{UpdatedAt: value}, GlobalConfig{LastSync: value}, GlobalConfig{}, CertificateConfig{UpdatedAt: value}, CertificateConfig{},
	})
	if err != nil {
		t.Fatalf("marshal public models: %v", err)
	}
	body := string(data)
	if strings.Count(body, `"2026-07-30T01:02:03Z"`) != 3 || !strings.Contains(body, `"updated_at":null`) || !strings.Contains(body, `"last_sync":null`) {
		t.Fatalf("unexpected nullable time JSON: %s", body)
	}
	if strings.Contains(body, `"Time"`) || strings.Contains(body, `"Valid"`) {
		t.Fatalf("public model leaked sql.NullTime representation: %s", body)
	}
}

// 拦截页内容类型白名单必须是封闭常量集：导出可变切片时任意包可
// append/改写，ValidBlockPageContentType 的封闭性随之失效且无测试会红。
// 期望集合在此硬编码（遍历自身白名单是自证型断言）。
func TestBlockPageContentTypeWhitelistIsClosed(t *testing.T) {
	want := []string{
		"text/html; charset=utf-8",
		"application/json; charset=utf-8",
		"application/xml; charset=utf-8",
		"text/plain; charset=utf-8",
	}
	got := BlockPageContentTypeWhitelist()
	if len(got) != len(want) {
		t.Fatalf("白名单=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("白名单[%d]=%q, want %q", i, got[i], want[i])
		}
		if !ValidBlockPageContentType(want[i]) {
			t.Fatalf("白名单成员 %q 必须被校验接受", want[i])
		}
	}
	for _, bad := range []string{"text/css", "application/pdf", "text/html"} {
		if ValidBlockPageContentType(bad) {
			t.Fatalf("白名单外 %q 必须被拒", bad)
		}
	}

	// 返回值是副本：调用方改写不得影响校验面。
	mutated := BlockPageContentTypeWhitelist()
	mutated[0] = "text/css"
	if !ValidBlockPageContentType("text/html; charset=utf-8") || ValidBlockPageContentType("text/css") {
		t.Fatalf("白名单副本被改写后仍污染了 ValidBlockPageContentType")
	}
}
