// Category: API Handler Tests
// Tests for HTTP handler functions: auth middleware, config API, rules API,
// client alias management, QR code generation and restore endpoints.
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
	configLock.Lock()
	config = Config{
		APIKeys: []APIKey{
			{
				ID:          "test-1",
				Name:        "Read Only",
				TokenHash:   hashToken("test-token-read"),
				Permissions: []string{"read:stats"},
			},
			{
				ID:          "test-2",
				Name:        "Full Access",
				TokenHash:   hashToken("test-token-full"),
				Permissions: []string{"read:all"},
			},
		},
		AdminPasswordHashed: "dummy-hash",
	}
	configLock.Unlock()

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
	configLock.Lock()
	config = Config{APIKeys: []APIKey{}}
	configLock.Unlock()

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
	configLock.Lock()
	config = Config{FilteringEnabled: true}
	configLock.Unlock()

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
	configLock.Lock()
	config = Config{AdminPasswordHashed: "existing-hash"}
	configLock.Unlock()

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
		configLock.RLock()
		snapshot := config.Clone()
		configLock.RUnlock()

		snapshot.CustomBlocked = []string{tc.input}
		snapshot.CustomAllowed = []string{tc.input}

		body, _ := json.Marshal(snapshot)
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
	configLock.Lock()
	config = Config{AdminPasswordHashed: "existing-hash"}
	configLock.Unlock()

	// Note: handleConfig actually replaces the global config with what's in the body
	// but it does so under a lock. Direct setup here should also be locked.
	configLock.Lock()
	config.CustomBlocked = []string{"restored-domain.com"}
	configLock.Unlock()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, _ := w.CreateFormFile("config", "config.json")

	configLock.RLock()
	restoredConfigSnap := config.Clone()
	configLock.RUnlock()

	restoredConfigSnap.CustomBlocked = []string{"restored-domain.com"}
	configJSON, _ := json.Marshal(restoredConfigSnap)
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

func TestHandleIPInfo(t *testing.T) {
	// Test Local IP
	req := httptest.NewRequest("GET", "/api/ip-info?ip=127.0.0.1", nil)
	rr := httptest.NewRecorder()
	handleIPInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %v", rr.Code)
	}

	var info IPInfo
	json.NewDecoder(rr.Body).Decode(&info)
	if !info.IsPrivate {
		t.Error("127.0.0.1 should be private")
	}
	if info.IP != "127.0.0.1" {
		t.Errorf("expected IP 127.0.0.1, got %s", info.IP)
	}

	// Test caching (second call)
	rr2 := httptest.NewRecorder()
	handleIPInfo(rr2, req)
	if rr2.Code != http.StatusOK {
		t.Errorf("expected 200 on cached call, got %v", rr2.Code)
	}
}

func TestHandleIPInfoPersistence(t *testing.T) {
	if db == nil {
		t.Skip("DB not initialized")
	}

	ip := "1.2.3.5"
	ua := "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)"

	// 1. Manually save to DB
	saveClientUA(ip, ua)

	// 2. Clear memory cache just in case
	ipToUA.Delete(ip)

	// 3. Call handleIPInfo
	req := httptest.NewRequest("GET", "/api/ip-info?ip="+ip, nil)
	rr := httptest.NewRecorder()
	handleIPInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %v", rr.Code)
	}

	var info IPInfo
	json.NewDecoder(rr.Body).Decode(&info)
	if info.UserAgent != ua {
		t.Errorf("expected UA %q, got %q", ua, info.UserAgent)
	}
	if info.OS != "iOS" {
		t.Errorf("expected OS iOS, got %q", info.OS)
	}
}

func TestHandleQueriesWithFiltering(t *testing.T) {
	// We need to mock DB or at least check if it handles parameters.
	// Since handleQueries uses a global 'db', we can't easily mock it without refactoring.
	// However, we can check if it accepts the parameters without crashing.

	req := httptest.NewRequest("GET", "/api/queries?client_ip=1.2.3.4&limit=10", nil)
	rr := httptest.NewRecorder()

	// This might fail if DB is not initialized, so we skip or handle if it's nil
	if db == nil {
		t.Skip("DB not initialized, skipping integration-style test")
		return
	}

	handleQueries(rr, req)
	// We expect 200 if query is valid SQL (even if empty results)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for filtered queries, got %v", rr.Code)
	}
}
func TestHandleMobileConfig(t *testing.T) {
	configLock.Lock()
	config = Config{
		BlockPageIP: "1.2.3.4",
		AdminDomain: "dns.example.com",
	}
	configLock.Unlock()

	req := httptest.NewRequest("GET", "/api/mobileconfig", nil)
	rr := httptest.NewRecorder()

	handleMobileConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %v", rr.Code)
	}

	body := rr.Body.String()

	// Check for protocols
	if strings.Contains(body, "<string>TLS</string>") {
		t.Error("TLS protocol should not be present in mobileconfig")
	}
	if !strings.Contains(body, "<string>HTTPS</string>") {
		t.Error("Missing HTTPS protocol in mobileconfig")
	}
	// QUIC is NOT supported by Apple's MDM spec and must NOT be in the profile
	if strings.Contains(body, "<string>QUIC</string>") {
		t.Error("QUIC protocol should NOT be present in mobileconfig (not supported by Apple MDM)")
	}

	// Check for correct ServerURL for HTTPS
	expectedHTTPS := "<string>https://dns.example.com/dns-query</string>"
	if !strings.Contains(body, expectedHTTPS) {
		t.Errorf("Missing or incorrect ServerURL for HTTPS. Expected %s", expectedHTTPS)
	}
	// QUIC ServerURL should NOT be present
	if strings.Contains(body, "quic://") {
		t.Error("quic:// URL should NOT be present in mobileconfig")
	}
	// Check that ServerAddresses (127.0.0.1) is NOT present
	if strings.Contains(body, "<string>127.0.0.1</string>") {
		t.Error("Mobileconfig still contains 127.0.0.1 in ServerAddresses")
	}
}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// Valid domains
		{"google.com", true},
		{"sub.domain.example.org", true},
		{"a.bc", true},
		{"my-site.co.uk", true},
		{"t.co", true},
		{"xn--e1afmapc.xn--p1ai", true}, // Punycode IDN

		// Valid IPs
		{"1.2.3.4", true},
		{"192.168.1.1", true},
		{"::1", true},

		// Invalid
		{"", false},
		{"not a domain", false},
		{"has space.com", false},
		{".leading-dot.com", false},
		{"trailing-dot.com.", false},
		{"no_underscores.com", true},
		{"javascript:alert(1)", false},
		{"<script>xss</script>", false},
		{"/etc/passwd", false},
		{"just-a-word", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isValidDomain(tt.input)
			if got != tt.want {
				t.Errorf("isValidDomain(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestHandleRuleAddValidation(t *testing.T) {
	configLock.Lock()
	config = Config{AdminPasswordHashed: "test"}
	configLock.Unlock()

	tests := []struct {
		name       string
		domain     string
		ruleType   string
		wantStatus int
	}{
		{"Valid domain block", "example.com", "block", http.StatusOK},
		{"Valid domain allow", "google.com", "allow", http.StatusOK},
		{"URL stripped to domain", "https://tracking.com/path", "block", http.StatusOK},
		{"Empty domain", "", "block", http.StatusUnprocessableEntity},
		{"Invalid domain", "not valid!", "block", http.StatusBadRequest},
		{"XSS attempt", "<script>alert(1)</script>", "block", http.StatusUnprocessableEntity},
		{"Path traversal", "../../../etc/passwd", "block", http.StatusUnprocessableEntity},
		{"Invalid type", "example.com", "invalid", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"domain": tt.domain, "type": tt.ruleType})
			req := httptest.NewRequest("POST", "/api/rules/add", bytes.NewBuffer(body))
			rr := httptest.NewRecorder()

			handleRuleAdd(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("got status %v, want %v (body: %s)", rr.Code, tt.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestHandleConfigRejectsInvalidCustomRules(t *testing.T) {
	configLock.Lock()
	config = Config{AdminPasswordHashed: "existing-hash"}
	configLock.Unlock()

	configLock.RLock()
	snapshot := config.Clone()
	configLock.RUnlock()

	snapshot.CustomBlocked = []string{"valid.com", "not valid!", "<script>xss</script>", "also-valid.org"}
	snapshot.CustomAllowed = []string{"good.com", "bad domain spaces"}

	body, _ := json.Marshal(snapshot)
	req := httptest.NewRequest("POST", "/api/config", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	handleConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %v", rr.Code)
	}

	// Only valid domains should survive
	if len(config.CustomBlocked) != 2 {
		t.Errorf("expected 2 valid blocked domains, got %d: %v", len(config.CustomBlocked), config.CustomBlocked)
	}
	if len(config.CustomAllowed) != 1 {
		t.Errorf("expected 1 valid allowed domain, got %d: %v", len(config.CustomAllowed), config.CustomAllowed)
	}
}

func TestHandleClientAlias(t *testing.T) {
	configLock.Lock()
	config = Config{
		ClientAliases: map[string]string{
			"1.1.1.1": "Cloudflare",
		},
	}
	configLock.Unlock()

	// Test GET
	req := httptest.NewRequest("GET", "/api/client/alias", nil)
	rr := httptest.NewRecorder()
	handleClientAlias(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET: expected 200, got %v", rr.Code)
	}
	var aliases map[string]string
	json.NewDecoder(rr.Body).Decode(&aliases)
	if aliases["1.1.1.1"] != "Cloudflare" {
		t.Errorf("GET: expected alias 'Cloudflare', got %q", aliases["1.1.1.1"])
	}

	// Test POST (Set)
	body, _ := json.Marshal(map[string]string{"ip": "2.2.2.2", "alias": "Google"})
	req = httptest.NewRequest("POST", "/api/client/alias", bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	handleClientAlias(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("POST set: expected 200, got %v", rr.Code)
	}
	if config.ClientAliases["2.2.2.2"] != "Google" {
		t.Errorf("POST set: expected alias 'Google', got %q", config.ClientAliases["2.2.2.2"])
	}

	// Test POST (Delete)
	body, _ = json.Marshal(map[string]string{"ip": "1.1.1.1", "alias": ""})
	req = httptest.NewRequest("POST", "/api/client/alias", bytes.NewBuffer(body))
	rr = httptest.NewRecorder()
	handleClientAlias(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("POST delete: expected 200, got %v", rr.Code)
	}
	if _, ok := config.ClientAliases["1.1.1.1"]; ok {
		t.Error("POST delete: alias should have been removed")
	}
}

func TestHandleQR(t *testing.T) {
	// Valid request
	req := httptest.NewRequest("GET", "/api/qr?data=dns.example.com", nil)
	rr := httptest.NewRecorder()
	handleQR(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %v", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != "image/png" {
		t.Errorf("expected image/png, got %s", ct)
	}
	if rr.Body.Len() < 100 {
		t.Error("QR PNG body too small")
	}

	// Missing data
	req = httptest.NewRequest("GET", "/api/qr", nil)
	rr = httptest.NewRecorder()
	handleQR(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing data, got %v", rr.Code)
	}

	// Data too long
	longData := strings.Repeat("a", 501)
	req = httptest.NewRequest("GET", "/api/qr?data="+longData, nil)
	rr = httptest.NewRecorder()
	handleQR(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for too-long data, got %v", rr.Code)
	}
}
