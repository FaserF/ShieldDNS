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
	config.PasswordHash = "$2a$10$vI8pI.N6uQXq1/v4u.pI9u4/v4u.pI9u4/v4u.pI9u4/v4u.pI9" // dummy hash
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
