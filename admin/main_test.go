// Category: Main Setup + Stats Tests
// Foundational tests including test harness bootstrapping (TestMain),
// search APIs, stats processing, corefile generation, and generic utilities.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Create a temporary directory for all test data to avoid writing to system paths like /etc/shielddns/
	tmpDir, err := os.MkdirTemp("", "shielddns-test-*")
	if err != nil {
		fmt.Printf("Failed to create temp dir for tests: %v\n", err)
		os.Exit(1)
	}

	// Redirect all global paths to the temporary directory
	DataDir = tmpDir
	ConfigPath = filepath.Join(tmpDir, "config.json")
	BlocklistPath = filepath.Join(tmpDir, "blocklist.hosts")
	AllowlistPath = filepath.Join(tmpDir, "allowlist.hosts")
	CorefilePath = filepath.Join(tmpDir, "Corefile")
	DBPath = ":memory:" // Use in-memory SQLite for tests

	// Initialize subsystems
	initDB()

	// Run tests
	exitCode := m.Run()

	// Cleanup
	os.RemoveAll(tmpDir)

	os.Exit(exitCode)
}

func TestHandleStats(t *testing.T) {
	statsLock.Lock()
	stats.TotalQueries = 100
	stats.BlockedQueries = 25
	statsLock.Unlock()

	req, err := http.NewRequest("GET", "/api/stats", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleStats)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	var s Stats
	if err := json.Unmarshal(rr.Body.Bytes(), &s); err != nil {
		t.Errorf("failed to unmarshal response: %v", err)
	}

	if s.TotalQueries != 100 || s.BlockedQueries != 25 {
		t.Errorf("unexpected stats: %+v", s)
	}
}

func TestHandleSearch(t *testing.T) {
	blockAttributionLock.Lock()
	blockAttribution = map[string][]string{
		"blocked.com": {"List A", "List B"},
	}
	blockAttributionLock.Unlock()

	req, _ := http.NewRequest("GET", "/api/search?q=blocked.com", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleSearch)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("expected 200, got %v", status)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp["blocked"] != true {
		t.Errorf("expected blocked=true, got %v", resp["blocked"])
	}

	lists := resp["lists"].([]interface{})
	if len(lists) != 2 || lists[0] != "List A" || lists[1] != "List B" {
		t.Errorf("unexpected lists: %v", lists)
	}

	// Test not blocked
	req, _ = http.NewRequest("GET", "/api/search?q=allowed.com", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["blocked"] != false {
		t.Errorf("expected blocked=false for allowed.com")
	}
}

func TestBlockAttribution(t *testing.T) {
	configLock.Lock()
	config.Lists = []List{
		{Name: "Test List", URL: "http://test.loc/list", Enabled: true},
	}
	config.CustomBlocked = []string{"custom.test"}
	configLock.Unlock()

	// Temporarily redirect BlocklistPath
	originalPath := BlocklistPath
	BlocklistPath = "test_blocklist.hosts"
	defer func() {
		BlocklistPath = originalPath
		os.Remove("test_blocklist.hosts")
	}()

	updateBlocklist(nil)

	blockAttributionLock.RLock()
	defer blockAttributionLock.RUnlock()

	if _, ok := blockAttribution["custom.test"]; !ok {
		t.Errorf("custom.test not found in attribution")
	}
	if blockAttribution["custom.test"][0] != "Custom Blocklist" {
		t.Errorf("expected Custom Blocklist attribution, got %v", blockAttribution["custom.test"])
	}
}

func TestParseLogLine_DefaultFormat(t *testing.T) {
	statsLock.Lock()
	stats.TotalQueries = 0
	stats.BlockedQueries = 0
	statsLock.Unlock()

	// Test allowed query - default format
	parseLogLine("127.0.0.1:53 A google-default.com. NOERROR qr,rd,ra 0.0001s \"-\"")

	statsLock.RLock()
	if stats.TotalQueries != 1 || stats.BlockedQueries != 0 {
		t.Errorf("expected 1 total, 0 blocked, got %v/%v", stats.TotalQueries, stats.BlockedQueries)
	}
	statsLock.RUnlock()

	blockAttributionLock.Lock()
	blockAttribution["doubleclick.net"] = []string{"TestList"}
	blockAttributionLock.Unlock()

	// Test blocked query (aa flag)
	parseLogLine("127.0.0.1:53 A doubleclick.net. NOERROR qr,aa,rd 0.0001s \"-\"")

	statsLock.RLock()
	if stats.TotalQueries != 2 || stats.BlockedQueries != 1 {
		t.Errorf("expected 2 total, 1 blocked, got %v/%v", stats.TotalQueries, stats.BlockedQueries)
	}
	statsLock.RUnlock()
}
func TestEqual(t *testing.T) {
	tests := []struct {
		a, b []string
		want bool
	}{
		{[]string{"a", "b"}, []string{"a", "b"}, true},
		{[]string{"a", "b"}, []string{"a", "c"}, false},
		{[]string{"a"}, []string{"a", "b"}, false},
		{[]string{}, []string{}, true},
	}
	for _, tt := range tests {
		if got := equal(tt.a, tt.b); got != tt.want {
			t.Errorf("equal(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestUpdateCorefile(t *testing.T) {
	// Setup
	originalConfig := config
	originalHealthy := healthyUpstreams
	originalPath := CorefilePath

	tmpFile, _ := os.CreateTemp("", "Corefile")
	CorefilePath = tmpFile.Name()

	defer func() {
		configLock.Lock()
		config = originalConfig
		configLock.Unlock()
		healthyUpstreams = originalHealthy
		CorefilePath = originalPath
		os.Remove(CorefilePath)
	}()
    tmpFile.Close() // Close immediately so atomicWriteFile can overwrite it

	configLock.Lock()
	config = Config{
		Upstreams:       []string{"1.1.1.1"},
		PreferEncrypted: false,
	}
	configLock.Unlock()
	healthyUpstreams = []string{"1.1.1.1"}
	healthyDoT = []string{}

	// Test normal DNS
	updateCorefile()
	content, err := os.ReadFile(CorefilePath)
	if err != nil {
		t.Fatalf("failed to read corefile: %v", err)
	}
	if !strings.Contains(string(content), "forward . 1.1.1.1") {
		t.Errorf("corefile missing forward 1.1.1.1: %s", string(content))
	}

	// Test PreferEncrypted
	configLock.Lock()
	config.PreferEncrypted = true
	config.UpstreamDoT = []string{"dns.google"}
	configLock.Unlock()
	// Mock healthy DoT
	healthLock.Lock()
	healthyDoT = []string{"dns.google"}
	healthLock.Unlock()

	updateCorefile()
	content, _ = os.ReadFile(CorefilePath)
	sContent := string(content)

	// Check for tls_servername (since dns.google is a hostname)
	if !strings.Contains(sContent, "tls_servername dns.google") {
		t.Errorf("corefile missing tls_servername dns.google: %s", sContent)
	}

	// Check for forward line with tls://
	// Note: updateCorefile will try to resolve dns.google.
	// In some test environments it might fail and return the hostname.
	if !strings.Contains(sContent, "forward . tls://") {
		t.Errorf("corefile missing tls forward: %s", sContent)
	}
}

func TestConfigDefaults(t *testing.T) {
	// Test loadConfig creating defaults
	originalDir := DataDir
	originalConfigPath := ConfigPath

	tmpDir, _ := os.MkdirTemp("", "shielddns-test")
	DataDir = tmpDir
	ConfigPath = filepath.Join(tmpDir, "config.json")

	defer func() {
		DataDir = originalDir
		ConfigPath = originalConfigPath
		os.RemoveAll(tmpDir)
	}()

	os.Remove(ConfigPath)
	loadConfig()
	if len(config.Upstreams) != 5 {
		t.Errorf("expected 5 default upstreams, got %d", len(config.Upstreams))
	}
	if !config.PreferEncrypted {
		t.Errorf("expected PreferEncrypted to be true by default")
	}
}

func TestQueryTypeTracking_DefaultFormat(t *testing.T) {
	statsLock.Lock()
	stats.QueryTypes = make(map[string]int64)
	statsLock.Unlock()

	parseLogLine("127.0.0.1:53 A google-types.com. NOERROR qr,rd,ra 0.0001s \"-\"")
	parseLogLine("127.0.0.1:53 AAAA google-types.com. NOERROR qr,rd,ra 0.0001s \"-\"")

	statsLock.RLock()
	if stats.QueryTypes["A"] != 1 || stats.QueryTypes["AAAA"] != 1 {
		t.Errorf("unexpected query types: %+v", stats.QueryTypes)
	}
	statsLock.RUnlock()
}

func TestSmartSorting(t *testing.T) {
	// Setup
	originalConfig := config
	originalPath := CorefilePath

	tmpFile, _ := os.CreateTemp("", "Corefile-smart")
	CorefilePath = tmpFile.Name()

	defer func() {
		configLock.Lock()
		config = originalConfig
		configLock.Unlock()
		CorefilePath = originalPath
		os.Remove(CorefilePath)
	}()
    tmpFile.Close() // Close immediately so atomicWriteFile can overwrite it

	configLock.Lock()
	config = Config{
		Upstreams:          []string{"1.1.1.1", "8.8.8.8"},
		UseFastestUpstream: true,
	}
	configLock.Unlock()
	healthyUpstreams = []string{"1.1.1.1", "8.8.8.8"}

	latencyLock.Lock()
	latencyMap["1.1.1.1"] = 50 * time.Millisecond
	latencyMap["8.8.8.8"] = 10 * time.Millisecond
	latencyLock.Unlock()

	updateCorefile()

	content, _ := os.ReadFile(CorefilePath)
	// 8.8.8.8 should come before 1.1.1.1 because it has lower latency
	idx8 := strings.Index(string(content), "8.8.8.8")
	idx1 := strings.Index(string(content), "1.1.1.1")

	if idx8 == -1 || idx1 == -1 || idx8 > idx1 {
		t.Errorf("expected 8.8.8.8 to come before 1.1.1.1 in smart mode. Content: %s", string(content))
	}
}

func TestUpstreamSanitization(t *testing.T) {
	// Setup
	originalDir := DataDir
	originalConfigPath := ConfigPath

	tmpDir, _ := os.MkdirTemp("", "shielddns-test-sanitize")
	DataDir = tmpDir
	ConfigPath = filepath.Join(tmpDir, "config.json")

	defer func() {
		DataDir = originalDir
		ConfigPath = originalConfigPath
		os.RemoveAll(tmpDir)
	}()

	// Create a config with "dirty" upstreams
	dirtyConfig := Config{
		Upstreams:   []string{"1.1.1.1, ", " 8.8.8.8,"},
		UpstreamDoT: []string{"dns.google, ", " one.one.one.one "},
	}
	data, _ := json.Marshal(dirtyConfig)
	os.WriteFile(ConfigPath, data, 0644)

	loadConfig()

	if config.Upstreams[0] != "1.1.1.1" {
		t.Errorf("expected 1.1.1.1, got %q", config.Upstreams[0])
	}
	if config.Upstreams[1] != "8.8.8.8" {
		t.Errorf("expected 8.8.8.8, got %q", config.Upstreams[1])
	}
	if config.UpstreamDoT[0] != "dns.google" {
		t.Errorf("expected dns.google, got %q", config.UpstreamDoT[0])
	}
	if config.UpstreamDoT[1] != "one.one.one.one" {
		t.Errorf("expected one.one.one.one, got %q", config.UpstreamDoT[1])
	}
}

func TestSSEBroadcasting_DefaultFormat(t *testing.T) {
	ch := make(chan Query, 1)
	sseLock.Lock()
	sseClients[ch] = struct{}{}
	sseLock.Unlock()

	defer func() {
		sseLock.Lock()
		delete(sseClients, ch)
		sseLock.Unlock()
	}()

	parseLogLine("127.0.0.1:53 A broadcast.test. NOERROR qr,rd 0.0001s \"-\"")

	select {
	case q := <-ch:
		if q.Domain != "broadcast.test" {
			t.Errorf("expected broadcast.test, got %s", q.Domain)
		}
	case <-time.After(1 * time.Second):
		t.Error("timed out waiting for SSE broadcast")
	}
}
