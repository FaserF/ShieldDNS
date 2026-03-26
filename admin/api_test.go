package main

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthMiddleware(t *testing.T) {
	// Initialize minimal config
	config = Config{
		APIKeys: []APIKey{
			{
				ID: "test-1",
				Name: "Read Only",
				TokenHash: hashToken("test-token-read"),
				Permissions: []string{"read:stats"},
			},
			{
				ID: "test-2",
				Name: "Full Access",
				TokenHash: hashToken("test-token-full"),
				Permissions: []string{"read:all"},
			},
		},
		AdminPasswordHashed: "dummy-hash",
	}

	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		token      string
		path       string
		method     string
		wantStatus int
	}{
		{"No Token", "", "/api/stats", "GET", http.StatusUnauthorized},
		{"Valid Read Token", "test-token-read", "/api/stats", "GET", http.StatusOK},
		{"Forbidden Write", "test-token-read", "/api/filtering/toggle", "POST", http.StatusForbidden},
		{"Valid Full Token Write", "test-token-full", "/api/filtering/toggle", "POST", http.StatusOK},
		{"Invalid Token", "bad-token", "/api/stats", "GET", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.token != "" {
				req.Header.Set("X-API-Key", tt.token)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("got status %v, want %v", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestNoAPIKeysRejectsAll(t *testing.T) {
	config = Config{ APIKeys: []APIKey{} }
	
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("X-API-Key", "any-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %v, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestToggleFiltering(t *testing.T) {
	config = Config{ FilteringEnabled: true }
	
	reqBody, _ := json.Marshal(map[string]bool{"enabled": false})
	req := httptest.NewRequest("POST", "/api/filtering/toggle", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()
	
	handleToggleFiltering(rr, req)
	
	if rr.Code != http.StatusOK {
		t.Errorf("got status %v, want %d", rr.Code, http.StatusOK)
	}
	
	if config.FilteringEnabled != false {
		t.Error("FilteringEnabled should be false")
	}
}

// TestCustomRuleSanitization verifies that http/https prefixes and trailing paths
// are stripped from custom rules when saving the configuration.
func TestCustomRuleSanitization(t *testing.T) {
	config = Config{AdminPasswordHashed: "existing-hash"}
	initPaths()

	testCases := []struct {
		input    string
		expected string
	}{
		{"ads.google.com", "ads.google.com"},
		{"https://ads.google.com", "ads.google.com"},
		{"http://tracking.site.de/analytics/js", "tracking.site.de"},
		{"https://evil.com/foo/bar?q=1", "evil.com"},
		{"  whitespace.com  ", "whitespace.com"},
	}

	for _, tc := range testCases {
		newConfig := Config{
			AdminPasswordHashed: "",
			CustomBlocked:       []string{tc.input},
			CustomAllowed:       []string{tc.input},
		}
		body, _ := json.Marshal(newConfig)
		req := httptest.NewRequest("POST", "/api/config", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()

		handleConfig(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("input %q: got status %v, want 200", tc.input, rr.Code)
			continue
		}
		if len(config.CustomBlocked) == 0 || config.CustomBlocked[0] != tc.expected {
			t.Errorf("CustomBlocked: input %q => got %q, want %q", tc.input, config.CustomBlocked, tc.expected)
		}
		if len(config.CustomAllowed) == 0 || config.CustomAllowed[0] != tc.expected {
			t.Errorf("CustomAllowed: input %q => got %q, want %q", tc.input, config.CustomAllowed, tc.expected)
		}
	}
}

// TestHandleRestore verifies that a valid config JSON can be restored via a multipart upload.
func TestHandleRestore(t *testing.T) {
	config = Config{AdminPasswordHashed: "existing-hash"}
	initPaths()

	restoredConfig := Config{
		AdminPasswordHashed: "", // should be preserved from current config
		CustomBlocked:       []string{"restored-domain.com"},
	}
	configJSON, _ := json.Marshal(restoredConfig)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, _ := w.CreateFormFile("config", "config.json")
	part.Write(configJSON)
	w.Close()

	req := httptest.NewRequest("POST", "/api/restore", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rr := httptest.NewRecorder()

	handleRestore(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("got status %v, want 200", rr.Code)
	}
	if config.AdminPasswordHashed != "existing-hash" {
		t.Errorf("expected existing password hash to be preserved, got %q", config.AdminPasswordHashed)
	}
	if len(config.CustomBlocked) == 0 || config.CustomBlocked[0] != "restored-domain.com" {
		t.Errorf("expected CustomBlocked to be restored, got %v", config.CustomBlocked)
	}
}

// TestHandleRestoreInvalidJSON verifies that a malformed JSON payload is rejected.
func TestHandleRestoreInvalidJSON(t *testing.T) {
	initPaths()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, _ := w.CreateFormFile("config", "config.json")
	part.Write([]byte("this is not json {{{"))
	w.Close()

	req := httptest.NewRequest("POST", "/api/restore", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rr := httptest.NewRecorder()

	handleRestore(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %v", rr.Code)
	}
}

// TestHandleRestoreMethodNotAllowed verifies that GET requests are rejected.
func TestHandleRestoreMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/restore", strings.NewReader(""))
	rr := httptest.NewRecorder()
	handleRestore(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %v", rr.Code)
	}
}
