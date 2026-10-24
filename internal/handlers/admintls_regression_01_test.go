package handlers

import (
	"testing"
	"time"
)

// days_left 与证书信息同口径向零截断（services/certinfo.go int(hours/24)）：
// 此前未过期用 Ceil（23h→1）、已过期用 Floor（过期 1天3h→-2），两处对同一
// 剩余期给出不同天数。统一为向零截断：23h→0、过期 1天3h→-1。
func TestParseAdminTLSCertInfo_daysLeftTruncates(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		notAfter time.Time
		wantDays int
		expired  bool
	}{
		{name: "23h remaining truncates to 0", notAfter: now.Add(23 * time.Hour), wantDays: 0, expired: false},
		{name: "expired 1d3h truncates to -1", notAfter: now.Add(-27 * time.Hour), wantDays: -1, expired: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			certPEM, _, err := generateTestCert("admintls.test", now.Add(-48*time.Hour), tt.notAfter)
			if err != nil {
				t.Fatalf("generate cert: %v", err)
			}

			// When
			info, err := parseAdminTLSCertInfo(certPEM)

			// Then
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if info.DaysLeft != tt.wantDays {
				t.Fatalf("days_left=%d, want %d(历史截断口径)", info.DaysLeft, tt.wantDays)
			}
			if info.Expired != tt.expired {
				t.Fatalf("expired=%v, want %v", info.Expired, tt.expired)
			}
		})
	}
}
