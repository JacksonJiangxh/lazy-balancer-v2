package apipath

import "testing"

func TestToOpenAPIAndBack_roundTrip(t *testing.T) {
	for _, ginPath := range []string{
		"/users/:id",
		"/security/policies/:id/bind/:caddy_id",
		"/rules",
		"/system/tasks/:id/logs",
	} {
		openAPI := ToOpenAPI(ginPath)
		if got := ToGin(openAPI); got != ginPath {
			t.Errorf("round trip %q → %q → %q", ginPath, openAPI, got)
		}
	}
	if got := ToOpenAPI("/users/:id"); got != "/users/{id}" {
		t.Errorf("ToOpenAPI=%q", got)
	}
	if got := ToGin("/users/{id}/bind/{caddy_id}"); got != "/users/:id/bind/:caddy_id" {
		t.Errorf("ToGin=%q", got)
	}
	// 无参数与未闭合花括号原样透传（防御性，不产生半截转换）。
	if got := ToGin("/rules/{unclosed"); got != "/rules/{unclosed" {
		t.Errorf("ToGin unclosed=%q", got)
	}
}
