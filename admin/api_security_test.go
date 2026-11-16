package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
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

func TestSanitizeRedirect(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/admin/", "/admin/"},
		{"/admin/#/settings", "/admin/#/settings"},
		{"https://primary.tailnet.fabiseitz.de:8443/admin/", "https://primary.tailnet.fabiseitz.de:8443/admin/"},
		{"http://192.168.1.100:8080/admin/", "http://192.168.1.100:8080/admin/"},

		// Evasion and Open Redirect vectors
		{"", "/admin/"},
		{"//evil.com", "/admin/"},
		{"//evil.com/admin/", "/admin/"},
		{"/\\evil.com", "/admin/"},
		{"\\evil.com", "/admin/"},
		{"javascript:alert(1)", "/admin/"},
		{"data:text/html,evil", "/admin/"},
		{"ftp://evil.com", "/admin/"},
		{"http://169.254.169.254/latest/meta-data/", "/admin/"},
	}

	for _, tt := range tests {
		got := sanitizeRedirect(tt.input)
		if got != tt.expected {
			t.Errorf("sanitizeRedirect(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestOpenLocalOfficialFile_Allowlist(t *testing.T) {
	tmpDir := t.TempDir()
	officialDir := filepath.Join(tmpDir, "official", "allowlists")
	if err := os.MkdirAll(officialDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(officialDir, "default.txt"), []byte("example.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(tmpDir)

	f, err := openLocalOfficialFile("allowlists/default.txt")
	if err != nil {
		t.Fatalf("expected valid official file to open, got error: %v", err)
	}
	f.Close()

	for _, badPath := range []string{
		"../etc/passwd",
		"..\\etc\\passwd",
		"allowlists/../allowlists/default.txt",
		"blocklists/evil.txt",
		"",
	} {
		if f, err := openLocalOfficialFile(badPath); err == nil {
			f.Close()
			t.Errorf("expected error for disallowed path %q, got file", badPath)
		}
	}
}

func TestFetchBlocklistURL_RejectsUnsafeAndRetriesTransient(t *testing.T) {
	for _, badURL := range []string{
		"ftp://example.com/list.txt",
		"javascript:alert(1)",
		"file:///etc/passwd",
		"http://169.254.169.254/latest/meta-data/",
	} {
		if resp, err := doFetchBlocklistURL(badURL, "TestAgent", nil, 5); err == nil {
			resp.Body.Close()
			t.Errorf("doFetchBlocklistURL(%q) unexpectedly succeeded", badURL)
		}
		if resp, err := fetchBlocklistURLWithContext(context.Background(), badURL, "TestAgent", nil); err == nil {
			resp.Body.Close()
			t.Errorf("fetchBlocklistURLWithContext(%q) unexpectedly succeeded", badURL)
		}
	}

	var attempts int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("0.0.0.0 ad.example.com\n"))
	}))
	defer ts.Close()

	resp, err := fetchBlocklistURL(ts.URL, "TestAgent", nil, 5)
	if err != nil {
		t.Fatalf("expected retry to succeed, got error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200 after retry, got %d", resp.StatusCode)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Errorf("expected 2 fetch attempts, got %d", attempts)
	}
}

func TestHandleConfig_RejectsUnsafeListURLs(t *testing.T) {
	configLock.RLock()
	snapshot := config.Clone()
	configLock.RUnlock()

	snapshot.Lists = []List{{Name: "Bad", URL: "http://169.254.169.254/latest/meta-data/", Enabled: true}}
	body, _ := json.Marshal(snapshot)
	req := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	handleConfig(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsafe blocklist URL, got %d", rr.Code)
	}

	snapshot = config.Clone()
	snapshot.Allowlists = []List{{Name: "BadAllow", URL: "ftp://example.com/allow.txt", Enabled: true}}
	body, _ = json.Marshal(snapshot)
	req = httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	handleConfig(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsafe allowlist URL, got %d", rr.Code)
	}
}
