package models

import (
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

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
	data, err := json.Marshal([]UserResponse{NewUserResponse(users[0]), NewUserResponse(users[1])})

	// Then
	if err != nil {
		t.Fatalf("marshal user responses: %v", err)
	}
	jsonBody := string(data)
	for _, expected := range []string{`"display_name":"Alice"`, `"last_login":"2026-07-30T02:02:03Z"`, `"display_name":null`, `"last_login":null`} {
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
