package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDGAWhitelist(t *testing.T) {
	// Setup
	configLock.Lock()
	config.AbuseDetectionEnabled = true
	config.AbuseDGAThreshold = 3.8
	config.AbuseDGAMinLen = 8
	configLock.Unlock()

	// Test case 1: Whitelisted suffix should NOT be blocked even with high entropy
	domain := "aksjdhawksjdh.googleusercontent.com"
	clientIP := "1.2.3.4"

	// Reset counters for this IP
	abuseMu.Lock()
	delete(abuseCounters, clientIP)
	abuseMu.Unlock()

	for i := 0; i < 60; i++ {
		analyzeQuery(clientIP, domain, "Allowed")
	}

	configLock.RLock()
	isBlocked := false
	for _, ip := range config.BlockedClients {
		if ip == clientIP {
			isBlocked = true
			break
		}
	}
	configLock.RUnlock()

	if isBlocked {
		t.Errorf("Whitelisted domain %s triggered a block", domain)
	}

	// Test case 2: Non-whitelisted high entropy domain SHOULD be blocked
	domain2 := "v8n2m9p1q6w5x3z0l0k7j4.com"
	clientIP2 := "5.6.7.8"

	for i := 0; i < 60; i++ {
		analyzeQuery(clientIP2, domain2, "Allowed")
	}

	// Polling for the block to be applied (DGA block is async)
	success := false
	for i := 0; i < 30; i++ {
		configLock.RLock()
		for _, ip := range config.BlockedClients {
			if ip == clientIP2 {
				success = true
				break
			}
		}
		configLock.RUnlock()
		if success {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !success {
		t.Errorf("High entropy domain %s failed to trigger a block after 2 seconds", domain2)
	}
}

func TestClearLogs(t *testing.T) {
	if db == nil || db.Ping() != nil {
		initDB()
	}

	// Insert dummy data
	for i := 0; i < 5; i++ {
		logBuffer = append(logBuffer, Query{
			Time:     time.Now(),
			Domain:   "test.com",
			ClientIP: "1.1.1.1",
			Status:   "Allowed",
		})
	}
	flushLogs(logBuffer)
	logBuffer = nil

	// Verify data exists
	var count int
	db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&count)
	if count == 0 {
		t.Fatal("Failed to insert dummy logs for test")
	}

	// Perform clear
	req, _ := http.NewRequest("POST", "/api/logs/clear", nil)
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleClearLogs)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status OK, got %v", rr.Code)
	}

	// Verify data is gone
	db.QueryRow("SELECT COUNT(*) FROM queries").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 logs after clear, got %d", count)
	}
}

func TestTLDExtraction(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"google.com", "com"},
		{"bbc.co.uk", "co.uk"},
		{"test.gv.at", "gv.at"},
		{"sub.domain.local", "local"},
		{"raw", ""},
	}

	for _, tt := range tests {
		if got := extractTLD(tt.domain); got != tt.want {
			t.Errorf("extractTLD(%q) = %q, want %q", tt.domain, got, tt.want)
		}
	}
}
