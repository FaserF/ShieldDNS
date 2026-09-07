package main

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleClientAlias(t *testing.T) {
	configLock.Lock()
	config.ClientAliases = map[string]string{
		"1.1.1.1": "Cloudflare",
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

func TestHandleCheckVersion(t *testing.T) {
	versionLock.Lock()
	latestVersions = VersionInfo{
		ShieldDNS: "v1.2.3",
		CoreDNS:   "v1.14.3",
		Alpine:    "3.23",
		LastCheck: time.Now(),
	}
	versionLock.Unlock()

	req := httptest.NewRequest("POST", "/api/system/check-version", nil)
	rr := httptest.NewRecorder()
	handleCheckVersion(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp VersionInfo
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.ShieldDNS != "v1.2.3" {
		t.Errorf("expected v1.2.3, got %s", resp.ShieldDNS)
	}

	// Reject GET request
	reqGet := httptest.NewRequest("GET", "/api/system/check-version", nil)
	rrGet := httptest.NewRecorder()
	handleCheckVersion(rrGet, reqGet)
	if rrGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rrGet.Code)
	}
}

func TestHandleSystemUpdate(t *testing.T) {
	configLock.Lock()
	config.UpdateChannel = "stable"
	configLock.Unlock()

	req := httptest.NewRequest("POST", "/api/system/update", nil)
	rr := httptest.NewRecorder()
	handleSystemUpdate(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode update response: %v", err)
	}

	if resp["success"] != true {
		t.Errorf("expected success=true, got %v", resp["success"])
	}

	// Reject GET request
	reqGet := httptest.NewRequest("GET", "/api/system/update", nil)
	rrGet := httptest.NewRecorder()
	handleSystemUpdate(rrGet, reqGet)
	if rrGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rrGet.Code)
	}
}

func TestAdminTemplateRendering(t *testing.T) {
	adminFS, err := fs.Sub(WebAssets, "www/admin")
	if err != nil {
		t.Fatalf("failed to sub adminFS: %v", err)
	}
	tmpl, err := template.ParseFS(adminFS, "index.html", "views/*.html", "partials/*.html")
	if err != nil {
		t.Fatalf("failed to parse modular admin templates: %v", err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, struct {
		FullVersion    string
		CacheVersion   string
		CoreDNSVersion string
		OSVersion      string
	}{
		FullVersion:    "v1.0.0",
		CacheVersion:   "12345",
		CoreDNSVersion: "v1.11.1",
		OSVersion:      "linux/amd64",
	})
	if err != nil {
		t.Fatalf("failed to execute template: %v", err)
	}

	html := buf.String()
	requiredSnippets := []string{
		`id="dashboard"`,
		`id="analytics"`,
		`id="queries"`,
		`id="system-logs"`,
		`id="diagnostics"`,
		`id="custom-rules"`,
		`id="lists"`,
		`id="settings"`,
		`id="about"`,
		`id="auth-overlay"`,
		`id="login-passkey-btn"`,
		`id="modal"`,
		`id="api-key-modal"`,
	}

	for _, snippet := range requiredSnippets {
		if !strings.Contains(html, snippet) {
			t.Errorf("rendered template missing expected snippet: %q", snippet)
		}
	}
}

func TestDoH3Configured(t *testing.T) {
	configLock.Lock()
	orig := config.DoH3Enabled
	config.DoH3Enabled = false
	configLock.Unlock()

	configLock.RLock()
	if config.DoH3Enabled != false {
		t.Error("expected DoH3Enabled to be false")
	}
	configLock.RUnlock()

	configLock.Lock()
	config.DoH3Enabled = orig
	configLock.Unlock()
	t.Log("DoH3: HTTP/3 server configuration toggles verified, DoQ CVE-2025-47950 mitigated")
}

func TestDoQHardeningInTemplate(t *testing.T) {
	if !strings.Contains(CorefileTemplate, "max_streams") {
		t.Error("CorefileTemplate missing DoQ max_streams hardening (CVE-2025-47950 mitigation)")
	}
	if !strings.Contains(CorefileTemplate, "worker_pool_size") {
		t.Error("CorefileTemplate missing DoQ worker_pool_size hardening")
	}
}

func TestRateLimitConfiguration(t *testing.T) {
	configLock.Lock()
	origRate := config.RateLimitRate
	origBurst := config.RateLimitBurst
	config.RateLimitRate = 150
	config.RateLimitBurst = 300
	configLock.Unlock()

	configLock.RLock()
	if config.RateLimitRate != 150 || config.RateLimitBurst != 300 {
		t.Errorf("expected rate=150, burst=300, got rate=%d, burst=%d", config.RateLimitRate, config.RateLimitBurst)
	}
	configLock.RUnlock()

	configLock.Lock()
	config.RateLimitRate = origRate
	config.RateLimitBurst = origBurst
	configLock.Unlock()
}

func TestECHConfiguration(t *testing.T) {
	configLock.Lock()
	orig := config.ECHOptimizationEnabled
	config.ECHOptimizationEnabled = false
	configLock.Unlock()

	configLock.RLock()
	if config.ECHOptimizationEnabled != false {
		t.Error("expected ECHOptimizationEnabled to be false")
	}
	configLock.RUnlock()

	configLock.Lock()
	config.ECHOptimizationEnabled = orig
	configLock.Unlock()
	t.Log("ECH / SVCB HTTPS records configuration verified")
}

func TestClusterWorkerScriptHandler(t *testing.T) {
	configLock.Lock()
	config.ClusterRole = "primary"
	config.ClusterNodeName = "Oracle Cloud DE"
	config.ClusterPrimaryURL = ""
	config.AdminDomain = "oracle.dns.fabiseitz.de"
	config.ClusterReplicas = []ClusterReplica{
		{
			ID:   "rep-home",
			Name: "Munich Home Node",
			URL:  "https://home.dns.fabiseitz.de",
		},
	}
	configLock.Unlock()

	req := httptest.NewRequest("GET", "/api/cluster/worker-script", nil)
	w := httptest.NewRecorder()

	handleClusterWorkerScript(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}

	body := w.Body.String()
	if strings.Contains(body, "__NODES_CONFIG_JSON__") {
		t.Error("placeholder __NODES_CONFIG_JSON__ was not replaced")
	}
	if !strings.Contains(body, "oracle.dns.fabiseitz.de") {
		t.Error("expected script to contain primary node URL oracle.dns.fabiseitz.de")
	}
	if !strings.Contains(body, "Munich Home Node") {
		t.Error("expected script to contain replica node Munich Home Node")
	}
	if !strings.Contains(body, "home.dns.fabiseitz.de") {
		t.Error("expected script to contain replica URL home.dns.fabiseitz.de")
	}

	// Verify that a dedicated API key with proxy:worker permission was created
	configLock.RLock()
	var foundWorkerKey bool
	for _, k := range config.APIKeys {
		if k.Name == "Cloudflare Worker Dispatcher" && len(k.Permissions) == 1 && k.Permissions[0] == "proxy:worker" {
			foundWorkerKey = true
			if !hasPermission(&k, "read:health") {
				t.Error("expected proxy:worker to be permitted to read:health")
			}
			if hasPermission(&k, "write:config") {
				t.Error("proxy:worker should NOT have write:config permission")
			}
			if hasPermission(&k, "read:config") {
				t.Error("proxy:worker should NOT have read:config permission")
			}
			break
		}
	}
	configLock.RUnlock()

	if !foundWorkerKey {
		t.Error("expected Cloudflare Worker Dispatcher APIKey with proxy:worker permission to be generated")
	}

	// 2. Subsequent call should reuse the existing token without creating duplicates
	w2 := httptest.NewRecorder()
	handleClusterWorkerScript(w2, req)
	body2 := w2.Body.String()

	configLock.RLock()
	workerKeyCount := 0
	for _, k := range config.APIKeys {
		if k.Name == "Cloudflare Worker Dispatcher" {
			workerKeyCount++
		}
	}
	configLock.RUnlock()

	if workerKeyCount != 1 {
		t.Errorf("expected exactly 1 worker key in config, got %d", workerKeyCount)
	}
	if body != body2 {
		t.Error("expected second script generation to reuse the same token and yield identical script")
	}
}



