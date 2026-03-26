package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

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
	// Setup mock blocklist
	tmpFile := "test_blocklist.hosts"
	os.WriteFile(tmpFile, []byte("0.0.0.0 blocked.com\n0.0.0.0 ads.target.net\n"), 0644)
	defer os.Remove(tmpFile)

	// Override BlocklistPath for test
	originalPath := BlocklistPath
	// Note: We'd need to modify main.go to allow injecting paths for true unit testing,
	// but for now we simulate the environment.
	// Since BlocklistPath is a const, we'd need to change it to a var in main.go.
}

func TestAuthMiddleware(t *testing.T) {
	configLock.Lock()
	config.AdminPasswordHashed = "$2a$10$vI8pI.N6uQXq1/v4u.pI9u4/v4u.pI9u4/v4u.pI9u4/v4u.pI9" // dummy hash
	configLock.Unlock()

	rr := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/api/stats", nil)
	
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	handler.ServeHTTP(rr, req)

	// Should be unauthorized without cookie
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected unauthorized, got %v", rr.Code)
	}
}

func TestParseLogLine(t *testing.T) {
	statsLock.Lock()
	stats.TotalQueries = 0
	stats.BlockedQueries = 0
	statsLock.Unlock()

	// Test allowed query
	parseLogLine("[INFO] [::1]:53 - 1 \"A IN google.com. udp 45 false 512\" NOERROR qr,rd,ra 68 0.0001s")
	
	statsLock.RLock()
	if stats.TotalQueries != 1 || stats.BlockedQueries != 0 {
		t.Errorf("expected 1 total, 0 blocked, got %v/%v", stats.TotalQueries, stats.BlockedQueries)
	}
	statsLock.RUnlock()

	// Test blocked query (aa flag)
	parseLogLine("[INFO] [::1]:53 - 2 \"A IN doubleclick.net. udp 45 false 512\" NOERROR qr,aa,rd 68 0.0001s")
	
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
	defer func() {
		config = originalConfig
		healthyUpstreams = originalHealthy
	}()

	config = Config{
		Upstreams:       []string{"1.1.1.1"},
		PreferEncrypted: false,
	}
	healthyUpstreams = []string{"1.1.1.1"}
	healthyDoT = []string{}
	healthyDoH = []string{}

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
	config.PreferEncrypted = true
	config.UpstreamDoT = []string{"dns.google"}
	healthyDoT = []string{"dns.google"}
	updateCorefile()
	content, _ = os.ReadFile(CorefilePath)
	if !strings.Contains(string(content), "forward . tls://dns.google:853 1.1.1.1") {
		t.Errorf("corefile missing tls forward: %s", string(content))
	}
}

func TestConfigDefaults(t *testing.T) {
	// Test loadConfig creating defaults
	os.Remove(ConfigPath)
	loadConfig()
	if len(config.Upstreams) != 5 {
		t.Errorf("expected 5 default upstreams, got %d", len(config.Upstreams))
	}
	if !config.PreferEncrypted {
		t.Errorf("expected PreferEncrypted to be true by default")
	}
}

func TestQueryTypeTracking(t *testing.T) {
	statsLock.Lock()
	stats.QueryTypes = make(map[string]int64)
	statsLock.Unlock()

	parseLogLine("[INFO] [::1]:53 - 1 \"A IN google.com. udp 45 false 512\" NOERROR qr,rd,ra 68 0.0001s")
	parseLogLine("[INFO] [::1]:53 - 2 \"AAAA IN google.com. udp 45 false 512\" NOERROR qr,rd,ra 68 0.0001s")

	statsLock.RLock()
	if stats.QueryTypes["A"] != 1 || stats.QueryTypes["AAAA"] != 1 {
		t.Errorf("unexpected query types: %+v", stats.QueryTypes)
	}
	statsLock.RUnlock()
}

func TestSmartSorting(t *testing.T) {
	// Setup
	originalConfig := config
	defer func() { config = originalConfig }()

	config = Config{
		Upstreams:          []string{"1.1.1.1", "8.8.8.8"},
		UseFastestUpstream: true,
	}
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

func TestSSEBroadcasting(t *testing.T) {
	ch := make(chan Query, 1)
	sseLock.Lock()
	sseClients[ch] = struct{}{}
	sseLock.Unlock()

	defer func() {
		sseLock.Lock()
		delete(sseClients, ch)
		sseLock.Unlock()
	}()

	parseLogLine("[INFO] [::1]:53 - 1 \"A IN broadcast.test. udp 45 false 512\" NOERROR qr,rd 68 0.0001s")

	select {
	case q := <-ch:
		if q.Domain != "broadcast.test" {
			t.Errorf("expected broadcast.test, got %s", q.Domain)
		}
	case <-time.After(1 * time.Second):
		t.Error("timed out waiting for SSE broadcast")
	}
}
