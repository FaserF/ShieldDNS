package main

import (
	"net/url"
	"testing"
)

func TestIsValidRedirectUrl(t *testing.T) {
	tests := []struct {
		url   string
		valid bool
	}{
		{"https://example.com", true},
		{"http://example.com/webhook", true},
		{"http://192.168.1.10:8080/sync", true},
		{"https://node2.tailnet.fabiseitz.de:8443/api/cluster/sync", true},
		{"http://127.0.0.1:8080", true},
		{"http://localhost:3000", true},

		// Malicious or disallowed targets
		{"", false},
		{"ftp://example.com", false},
		{"javascript:alert(1)", false},
		{"file:///etc/passwd", false},
		{"http://169.254.169.254/latest/meta-data/", false},
		{"http://169.254.10.20:8080", false},
		{"http://[fe80::1]/", false},
		{"https://", false},
		{"http://bad domain.com", false},
	}

	for _, tt := range tests {
		got := isValidRedirectUrl(tt.url)
		if got != tt.valid {
			t.Errorf("isValidRedirectUrl(%q) = %v; want %v", tt.url, got, tt.valid)
		}
	}
}

func TestIsSafeClusterTarget(t *testing.T) {
	u1, _ := url.Parse("https://primary.tailnet.fabiseitz.de:8443")
	if err := isSafeClusterTarget(u1); err != nil {
		t.Errorf("expected valid target, got error: %v", err)
	}

	uMeta, _ := url.Parse("http://169.254.169.254/latest/meta-data/")
	if err := isSafeClusterTarget(uMeta); err == nil {
		t.Errorf("expected error for cloud metadata target, got nil")
	}

	if err := isSafeClusterTarget(nil); err == nil {
		t.Errorf("expected error for nil URL, got nil")
	}
}
