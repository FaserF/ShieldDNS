// Category: DNS Log Parser Tests
// Tests for CoreDNS log parsing logic, including structured and default format
// parsing, SSE broadcasting, and block attribution.
package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestParseLogLine_Structured tests the new structured CoreDNS log format parser.
func TestParseLogLine_Structured(t *testing.T) {
	statsLock.Lock()
	stats.TotalQueries = 0
	stats.BlockedQueries = 0
	stats.QueryTypes = make(map[string]int64)
	statsLock.Unlock()

	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	// Test allowed query in new structured CoreDNS format (with User-Agent)
	parseLogLine(`127.0.0.1:46111 A google.com. NOERROR qr,rd,ra 0.00123s "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)" "-"`)

	bufferLock.Lock()
	length := len(logBuffer)
	var q Query
	if length > 0 {
		q = logBuffer[0]
	}
	bufferLock.Unlock()

	if length != 1 {
		t.Fatalf("Expected 1 query in buffer, got %d", length)
	}
	// Since no real IP was provided, it should still be "DoH Proxy" for UX
	if q.ClientIP != "DoH Proxy" {
		t.Errorf("Expected ClientIP DoH Proxy, got %s", q.ClientIP)
	}
	if q.Type != "A" {
		t.Errorf("Expected Type A, got %s", q.Type)
	}
	if q.Domain != "google.com" {
		t.Errorf("Expected Domain google.com, got %s", q.Domain)
	}
	if q.Status != "Allowed" {
		t.Errorf("Expected Status Allowed, got %s", q.Status)
	}

	// Check User-Agent storage
	if ua, ok := ipToUA.Load("DoH Proxy"); !ok || ua != "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)" {
		t.Errorf("Expected User-Agent to be stored, got %v", ua)
	}
}

func TestParseLogLine_WithRealIP(t *testing.T) {
	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	// Test DoH query arriving via 127.0.0.1 but with a forwarded X-Real-IP
	parseLogLine(`127.0.0.1:55555 A myhome.com. NOERROR qr,rd,ra 0.005s "Mozilla/5.0 (Macintosh)" "10.0.0.42"`)

	bufferLock.Lock()
	q := logBuffer[0]
	bufferLock.Unlock()

	if q.ClientIP != "10.0.0.42" {
		t.Errorf("Expected ClientIP 10.0.0.42 (forwarded), got %s", q.ClientIP)
	}

	// Check User-Agent storage under the REAL IP
	if ua, ok := ipToUA.Load("10.0.0.42"); !ok || ua != "Mozilla/5.0 (Macintosh)" {
		t.Errorf("Expected User-Agent to be stored under real IP, got %v", ua)
	}
}

func TestParseLogLine_Blocked(t *testing.T) {
	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	statsLock.Lock()
	stats.BlockedQueries = 0
	statsLock.Unlock()

	blockAttributionLock.Lock()
	blockAttribution["tiktok.com"] = []string{"TestBlocklist"}
	blockAttributionLock.Unlock()

	// qr,aa flags = blocked (local hosts file match)
	parseLogLine(`10.0.0.5:1234 AAAA tiktok.com. NOERROR qr,aa 0.050s "-"`)

	bufferLock.Lock()
	length := len(logBuffer)
	var q Query
	if length > 0 {
		q = logBuffer[0]
	}
	bufferLock.Unlock()

	if length != 1 {
		t.Fatalf("Expected 1 query in buffer, got %d", length)
	}
	if q.Domain != "tiktok.com" {
		t.Errorf("Expected tiktok.com, got %s", q.Domain)
	}
	if q.Status != "Blocked" {
		t.Errorf("Expected Blocked, got %s", q.Status)
	}
	// 0.05s = 50ms
	if q.DurationMs < 49.9 || q.DurationMs > 50.1 {
		t.Errorf("Expected Duration ~50ms, got %f", q.DurationMs)
	}
}

func TestParseLogLine_DefaultFormat_New(t *testing.T) {
	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	// Default CoreDNS format (no User-Agent, with port)
	parseLogLine(`127.0.0.1:35210 - 0 "A IN outlook.office365.com. tcp 50 true 65535" NOERROR qr,rd,ra 1157 0.002822855s`)

	bufferLock.Lock()
	length := len(logBuffer)
	var q Query
	if length > 0 {
		q = logBuffer[0]
	}
	bufferLock.Unlock()

	if length != 1 {
		t.Fatalf("Expected 1 query in buffer, got %d", length)
	}
	if q.ClientIP != "DoH Proxy" {
		t.Errorf("Expected ClientIP DoH Proxy, got %s", q.ClientIP)
	}
	if q.Type != "A" {
		t.Errorf("Expected Type A, got %s", q.Type)
	}
	if q.Domain != "outlook.office365.com" {
		t.Errorf("Expected Domain outlook.office365.com, got %s", q.Domain)
	}
	if q.Status != "Allowed" {
		t.Errorf("Expected Status Allowed, got %s", q.Status)
	}
	// 0.0028s = 2.8ms
	if q.DurationMs < 2.8 || q.DurationMs > 2.9 {
		t.Errorf("Expected Duration ~2.82ms, got %f", q.DurationMs)
	}
}

func TestParseLogLine_WithPrefixes(t *testing.T) {
	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	statsLock.Lock()
	stats.BlockedQueries = 0
	statsLock.Unlock()

	// [INFO] prefix from docker/system logs
	parseLogLine(`[16:23:02] [CoreDNS] [INFO] 94.31.75.54:56396 - 48996 "AAAA IN eu-office.events.data.microsoft.com. tcp 64 true 65535" NOERROR qr,rd,ra 346 0.011722143s`)

	bufferLock.Lock()
	length := len(logBuffer)
	var q Query
	if length > 0 {
		q = logBuffer[0]
	}
	bufferLock.Unlock()

	if length != 1 {
		t.Fatalf("Expected 1 query in buffer, got %d", length)
	}
	if q.ClientIP != "94.31.75.54" {
		t.Errorf("Expected ClientIP 94.31.75.54, got %s", q.ClientIP)
	}
	if q.Domain != "eu-office.events.data.microsoft.com" {
		t.Errorf("Expected domain eu-office.events.data.microsoft.com, got %s", q.Domain)
	}
}

func TestParseLogLine_ShortLine(t *testing.T) {
	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	// A line with fewer than 6 fields should be ignored
	parseLogLine(`just a short line`)

	bufferLock.Lock()
	length := len(logBuffer)
	bufferLock.Unlock()

	if length != 0 {
		t.Errorf("expected 0 queries for short line, got %d", length)
	}
}

func TestParseLogLine_SSEBroadcast(t *testing.T) {
	ch := make(chan Query, 10)
	sseLock.Lock()
	sseClients[ch] = struct{}{}
	sseLock.Unlock()

	defer func() {
		sseLock.Lock()
		delete(sseClients, ch)
		sseLock.Unlock()
	}()

	parseLogLine(`192.168.1.10:4321 A example.com. NOERROR qr,rd 0.001s "-"`)

	timeout := time.After(1 * time.Second)
	found := false
	for !found {
		select {
		case q := <-ch:
			if q.Domain == "example.com" {
				found = true
			}
		case <-timeout:
			t.Error("timed out waiting for SSE broadcast of example.com")
			return
		}
	}
}

func TestParseLogLine_InvalidLogs(t *testing.T) {
	bufferLock.Lock()
	logBuffer = nil
	bufferLock.Unlock()

	// 1. Startup message - Should be ignored (too short)
	parseLogLine(`maxprocs: Honoring GOMAXPROCS="4" as set in environment`)

	bufferLock.Lock()
	length := len(logBuffer)
	bufferLock.Unlock()

	if length != 0 {
		t.Errorf("expected 0 queries for invalid/non-matching logs, got %d", length)
	}
}
func TestUpdateCorefileTemplate(t *testing.T) {
	// 1. Setup temporary Corefile path
	tmpCorefile := "test_Corefile"
	defer os.Remove(tmpCorefile)

	oldPath := CorefilePath
	CorefilePath = tmpCorefile
	defer func() { CorefilePath = oldPath }()

	// 2. Setup mock environment
	os.Setenv("DNS_PORT", "10053")
	os.Setenv("DOT_PORT", "10853")
	os.Setenv("INTERNAL_DOH_PORT", "15553")
	defer os.Unsetenv("DNS_PORT")
	defer os.Unsetenv("DOT_PORT")
	defer os.Unsetenv("INTERNAL_DOH_PORT")

	// 3. Setup mock config
	configLock.Lock()
	oldConfig := config
	config = Config{
		Upstreams:       []string{"1.1.1.1"},
		PreferEncrypted: false,
		DNSSECEnabled:   true,
		ServeStale:      true,
	}
	configLock.Unlock()
	defer func() {
		configLock.Lock()
		config = oldConfig
		configLock.Unlock()
	}()

	// Mock healthy upstreams
	healthLock.Lock()
	healthyUpstreams = []string{"1.1.1.1"}
	healthLock.Unlock()
	defer func() {
		healthLock.Lock()
		healthyUpstreams = nil
		healthLock.Unlock()
	}()

	// 4. Run update
	updateCorefile()

	// 5. Verify file content
	content, err := os.ReadFile(tmpCorefile)
	if err != nil {
		t.Fatalf("Failed to read generated Corefile: %v", err)
	}

	sContent := string(content)

	expectedSnippets := []string{
		".:10053 {",
		"tls://.:10853 {",
		"https://.:15553 {",
		"dnssec",
		"serve_stale 1h",
		"forward . 1.1.1.1:53",
	}

	for _, snippet := range expectedSnippets {
		if !strings.Contains(sContent, snippet) {
			t.Errorf("Expected Corefile to contain '%s', but it didn't.\nContent:\n%s", snippet, sContent)
		}
	}
}
