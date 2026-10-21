package services

import (
	"net"
	"reflect"
	"testing"
)

func TestNormalizeCIDRsAcceptsBareIPs(t *testing.T) {
	got, err := NormalizeCIDRs([]string{"192.168.1.5", "2001:db8::1", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.1.5/32", "2001:db8::1/128", "10.0.0.0/8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeCIDRs()=%v, want %v", got, want)
	}
}

func TestNormalizeCIDRsRejectsInvalidCIDR(t *testing.T) {
	if _, err := NormalizeCIDRs([]string{"not-an-ip"}); err == nil {
		t.Fatal("NormalizeCIDRs() error=nil, want validation error")
	}
}

func TestNormalizeCIDRs_MappedAndCanonicalForms(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		contains []string
	}{
		{name: "bare IPv4", input: "192.0.2.9", want: "192.0.2.9/32", contains: []string{"192.0.2.9"}},
		{name: "IPv4 CIDR masks host bits", input: "192.0.2.129/24", want: "192.0.2.0/24", contains: []string{"192.0.2.9"}},
		{name: "bare IPv6", input: "2001:db8::1", want: "2001:db8::1/128", contains: []string{"2001:db8::1"}},
		{name: "IPv6 CIDR masks host bits", input: "2001:db8::1/64", want: "2001:db8::/64", contains: []string{"2001:db8::2"}},
		{name: "mapped bare dotted", input: "::ffff:203.0.113.7", want: "203.0.113.7/32", contains: []string{"203.0.113.7"}},
		{name: "mapped bare hexadecimal", input: "::ffff:cb00:7107", want: "203.0.113.7/32", contains: []string{"203.0.113.7"}},
		{name: "mapped CIDR dotted", input: "::ffff:203.0.113.7/120", want: "203.0.113.0/24", contains: []string{"203.0.113.7"}},
		{name: "mapped CIDR hexadecimal", input: "::ffff:cb00:7107/120", want: "203.0.113.0/24", contains: []string{"203.0.113.7"}},
		{name: "mapped host CIDR", input: "::ffff:203.0.113.7/128", want: "203.0.113.7/32", contains: []string{"203.0.113.7"}},
		{name: "mapped whole IPv4 CIDR", input: "::ffff:0.0.0.0/96", want: "0.0.0.0/0", contains: []string{"203.0.113.7"}},
		{name: "non-mapped IPv6 remains IPv6", input: "::1", want: "::1/128", contains: []string{"::1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Given one real net.历史修复 input shape.
			// When normalizing the whitelist entry.
			got, err := NormalizeCIDRs([]string{tc.input})
			if err != nil {
				t.Fatalf("NormalizeCIDRs(%q): %v", tc.input, err)
			}
			if !reflect.DeepEqual(got, []string{tc.want}) {
				t.Fatalf("NormalizeCIDRs(%q)=%v, want [%s]", tc.input, got, tc.want)
			}
			// Then the persisted value must be accepted by the execution side's
			// actual parser and match the intended client address family.
			_, network, err := net.ParseCIDR(got[0])
			if err != nil {
				t.Fatalf("net.ParseCIDR(normalized %q): %v", got[0], err)
			}
			for _, clientIP := range tc.contains {
				if !network.Contains(net.ParseIP(clientIP)) {
					t.Fatalf("normalized network %q does not contain %s", got[0], clientIP)
				}
			}
		})
	}
}

func TestNormalizeCIDRs_RejectsMalformedMappedPrefixes(t *testing.T) {
	for _, input := range []string{
		"::ffff:192.0.2.1/95",
		"::ffff:192.0.2.1/129",
		"::ffff:192.0.2.1/24",
		"fe80::1%eth0",
		"",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := NormalizeCIDRs([]string{input}); err == nil {
				t.Fatalf("NormalizeCIDRs(%q) error=nil, want validation error", input)
			}
		})
	}
}
