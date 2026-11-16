package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBlockedServicesAndSafeSearchMappings(t *testing.T) {
	cfg := &Config{
		BlockedServices:    []string{"tiktok", "steam"},
		SafeSearchEnabled:  true,
		YouTubeRestriction: "strict",
	}

	domains := GetBlockedServiceDomains(cfg)
	if domains["tiktok.com"] != "Blocked Service: TikTok" {
		t.Errorf("Expected tiktok.com attribution, got %q", domains["tiktok.com"])
	}
	if domains["*.steampowered.com"] != "Blocked Service: Steam" {
		t.Errorf("Expected *.steampowered.com attribution, got %q", domains["*.steampowered.com"])
	}

	mappings := GetSafeSearchMappings(cfg)
	if mappings["www.google.com"] != "216.239.38.120" {
		t.Errorf("Expected Google SafeSearch VIP, got %q", mappings["www.google.com"])
	}
	if mappings["www.youtube.com"] != "216.239.38.120" {
		t.Errorf("Expected YouTube Strict VIP, got %q", mappings["www.youtube.com"])
	}

	cfg.YouTubeRestriction = "moderate"
	mappings = GetSafeSearchMappings(cfg)
	if mappings["www.youtube.com"] != "216.239.38.119" {
		t.Errorf("Expected YouTube Moderate VIP, got %q", mappings["www.youtube.com"])
	}

	target, vip, engine, ok := GetSafeSearchMatch("www.bing.com", cfg)
	if !ok || target != "strict.bing.com" || vip != "204.79.197.220" || engine != "Bing" {
		t.Errorf("Unexpected SafeSearch match: ok=%v target=%s vip=%s engine=%s", ok, target, vip, engine)
	}
}

func TestServicesAPIAndReloadRules(t *testing.T) {
	tmpDir := t.TempDir()
	origDataDir := DataDir
	origConfigPath := ConfigPath
	origCombinedPath := CombinedHostsPath
	origBlocklistPath := BlocklistPath
	origAllowlistPath := AllowlistPath
	origMappingsPath := MappingsPath
	defer func() {
		DataDir = origDataDir
		ConfigPath = origConfigPath
		CombinedHostsPath = origCombinedPath
		BlocklistPath = origBlocklistPath
		AllowlistPath = origAllowlistPath
		MappingsPath = origMappingsPath
	}()

	DataDir = tmpDir
	ConfigPath = filepath.Join(tmpDir, "config.json")
	CombinedHostsPath = filepath.Join(tmpDir, "shielddns.hosts")
	BlocklistPath = filepath.Join(tmpDir, "blocklist.hosts")
	AllowlistPath = filepath.Join(tmpDir, "allowlist.hosts")
	MappingsPath = filepath.Join(tmpDir, "mappings.hosts")

	configLock.Lock()
	config = Config{
		FilteringEnabled:   true,
		BlockPageIP:        "0.0.0.0",
		BlockedServices:    []string{},
		YouTubeRestriction: "none",
		CustomMappings:     map[string]string{},
	}
	configLock.Unlock()

	blockAttributionLock.Lock()
	blockAttribution = make(map[string][]string)
	blockAttributionLock.Unlock()

	// 1. GET /api/services/catalog
	req := httptest.NewRequest(http.MethodGet, "/api/services/catalog", nil)
	rec := httptest.NewRecorder()
	handleServicesCatalog(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
	var catResp map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &catResp); err != nil {
		t.Fatalf("Failed to decode catalog response: %v", err)
	}
	presets, ok := catResp["presets"].([]interface{})
	if !ok || len(presets) < 10 {
		t.Errorf("Expected >= 10 service presets, got %v", len(presets))
	}

	// 2. POST /api/services/update (enable TikTok + SafeSearch)
	body := `{"blocked_services":["tiktok"],"safesearch_enabled":true,"youtube_restriction":"moderate"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/services/update", bytes.NewBufferString(body))
	rec2 := httptest.NewRecorder()
	handleServicesUpdate(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("Expected 200 on update, got %d: %s", rec2.Code, rec2.Body.String())
	}

	blockAttributionLock.RLock()
	attrs := blockAttribution["tiktok.com"]
	blockAttributionLock.RUnlock()
	if len(attrs) == 0 || attrs[0] != "Blocked Service: TikTok" {
		t.Errorf("Expected tiktok.com in blockAttribution, got %v", attrs)
	}

	hostsBytes, err := os.ReadFile(CombinedHostsPath)
	if err != nil {
		t.Fatalf("Failed to read generated hosts file: %v", err)
	}
	hostsStr := string(hostsBytes)
	if !strings.Contains(hostsStr, "216.239.38.120 www.google.com") {
		t.Errorf("Expected SafeSearch mapping in hosts file")
	}
	if !strings.Contains(hostsStr, "216.239.38.119 www.youtube.com") {
		t.Errorf("Expected YouTube moderate mapping in hosts file")
	}

	// 3. Disable TikTok and verify removal
	body3 := `{"blocked_services":[],"safesearch_enabled":false,"youtube_restriction":"none"}`
	req3 := httptest.NewRequest(http.MethodPost, "/api/services/update", bytes.NewBufferString(body3))
	rec3 := httptest.NewRecorder()
	handleServicesUpdate(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("Expected 200 on disable, got %d", rec3.Code)
	}

	blockAttributionLock.RLock()
	_, stillBlocked := blockAttribution["tiktok.com"]
	blockAttributionLock.RUnlock()
	if stillBlocked {
		t.Errorf("Expected tiktok.com to be removed from blockAttribution after disabling")
	}
}
