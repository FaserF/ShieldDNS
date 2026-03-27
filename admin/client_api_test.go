package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"database/sql"
	"os"
	_ "modernc.org/sqlite"
)

func TestClientAPI(t *testing.T) {
	// Setup a temporary in-memory DB for testing
	tempDBPath := "test_queries.db"
	var err error
	db, err = sql.Open("sqlite", tempDBPath)
	if err != nil {
		t.Fatalf("Failed to open test DB: %v", err)
	}
	defer os.Remove(tempDBPath)
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE queries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME,
			domain TEXT,
			type TEXT,
			status TEXT,
			client_ip TEXT
		);
	`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert test data
	testIP := "10.0.0.5"
	queries := []struct{domain, status, ip string}{
		{"google.com", "Allowed", testIP},
		{"google.com", "Allowed", testIP},
		{"malware.com", "Blocked", testIP},
		{"example.org", "Allowed", "192.168.1.1"},
	}

	for _, q := range queries {
		db.Exec("INSERT INTO queries (timestamp, domain, type, status, client_ip) VALUES (?, ?, ?, ?, ?)",
			time.Now().Format(time.RFC3339), q.domain, "A", q.status, q.ip)
	}

	t.Run("HandleClientStats", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/client/stats?ip="+testIP, nil)
		rr := httptest.NewRecorder()
		handleClientStats(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %v", rr.Code)
		}

		var stats map[string]int
		json.NewDecoder(rr.Body).Decode(&stats)
		if stats["total"] != 3 {
			t.Errorf("expected 3 total queries, got %d", stats["total"])
		}
		if stats["blocked"] != 1 {
			t.Errorf("expected 1 blocked query, got %d", stats["blocked"])
		}
	})

	t.Run("HandleTopDomainsForClient", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/client/top-domains?ip="+testIP, nil)
		rr := httptest.NewRecorder()
		handleTopDomainsForClient(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200, got %v", rr.Code)
		}

		var domains []map[string]interface{}
		json.NewDecoder(rr.Body).Decode(&domains)
		if len(domains) != 2 {
			t.Errorf("expected 2 domains, got %d", len(domains))
		}
		// First should be google.com
		if domains[0]["domain"] != "google.com" {
			t.Errorf("expected top domain google.com, got %v", domains[0]["domain"])
		}
		// Correct count for google.com (float64 because of JSON unmarshal)
		if count := domains[0]["count"].(float64); count != 2 {
			t.Errorf("expected count 2 for google.com, got %v", count)
		}
	})
}
