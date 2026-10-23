package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAdminOrSelfParam_allowsSelfAndAdminOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name   string
		role   string
		actor  int
		target string
		want   int
	}{
		{"non-admin self", "user", 5, "5", http.StatusOK},
		{"non-admin other", "user", 5, "6", http.StatusForbidden},
		{"admin other", "admin", 1, "6", http.StatusOK},
		{"invalid id", "user", 5, "abc", http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPut, "/users/"+tc.target, nil)
			c.Params = gin.Params{{Key: "id", Value: tc.target}}
			c.Set("role", tc.role)
			c.Set("user_id", tc.actor)

			adminOrSelfParam()(c)
			got := rec.Code
			if got == 0 {
				got = http.StatusOK
			}
			if got != tc.want {
				t.Fatalf("status=%d body=%s, want %d", got, rec.Body.String(), tc.want)
			}
		})
	}
}
