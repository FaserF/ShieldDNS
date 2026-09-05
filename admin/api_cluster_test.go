package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBuildClusterConfigExport_Profiles(t *testing.T) {
	configLock.Lock()
	config = Config{
		AdminPasswordHashed:        "$2a$10$abcdefghijklmnopqrstuu",
		FilteringEnabled:           true,
		Lists:                      []List{{Name: "TestList", URL: "https://example.com/list.txt", Enabled: true}},
		Allowlists:                 []List{},
		CustomBlocked:              []string{"ads.example.com"},
		CustomAllowed:              []string{"good.example.com"},
		CustomMappings:             map[string]string{"router.lan": "192.168.1.1"},
		AutoblockWhitelist:         []string{"127.0.0.1"},
		BlockedCountries:           []string{"CN"},
		SmartSelectionPolicy:       "fastest",
		ServeStale:                 true,
		DNSSECEnabled:              true,
		AbuseDetectionEnabled:      true,
		AbuseDGAThreshold:          3.8,
		AbuseDGAMinLen:             8,
		MaliciousIPBlockingEnabled: true,
		MaliciousIPInterval:        8,
		VerifyUpstreamTLS:          true,
		PreferEncrypted:            true,
		Upstreams:                  []string{"1.1.1.1", "8.8.8.8"},
		UpstreamDoT:                []string{"one.one.one.one"},
		DoHRateLimit:               50,
		DNSRebindingProtection:     false,
		StripECS:                   false,
	}
	configLock.Unlock()

	// 1. Private profile test
	privExport := buildClusterConfigExport("private", "https://primary.example.com", true)
	if privExport.DoHRateLimit < 200 {
		t.Errorf("Expected DoHRateLimit >= 200 for private profile, got %d", privExport.DoHRateLimit)
	}
	if !privExport.DNSRebindingProtection {
		t.Errorf("Expected DNSRebindingProtection to be true for private profile")
	}

	// 2. Public profile test
	pubExport := buildClusterConfigExport("public", "https://primary.example.com", false)
	if pubExport.DoHRateLimit > 60 {
		t.Errorf("Expected DoHRateLimit <= 60 for public profile, got %d", pubExport.DoHRateLimit)
	}
	if pubExport.DNSRebindingProtection {
		t.Errorf("Expected DNSRebindingProtection to be false for public profile")
	}

	// 3. Hybrid profile test
	hybExport := buildClusterConfigExport("hybrid", "https://primary.example.com", true)
	if hybExport.DoHRateLimit < 120 {
		t.Errorf("Expected DoHRateLimit >= 120 for hybrid profile, got %d", hybExport.DoHRateLimit)
	}
	if !hybExport.MaliciousIPBlockingEnabled {
		t.Errorf("Expected MaliciousIPBlockingEnabled to be true for hybrid profile")
	}
}

func TestClusterStatusHandler(t *testing.T) {
	configLock.Lock()
	config.ClusterRole = "replica"
	config.ClusterInstanceType = "hybrid"
	config.ClusterPrimaryURL = "https://primary.example.com"
	config.ClusterFailoverMode = true
	config.ClusterLastSync = time.Now().UTC()
	configLock.Unlock()

	atomic.StoreInt32(&clusterConnLost, 0)
	clusterLastSyncError = ""

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/status", nil)
	w := httptest.NewRecorder()

	handleClusterStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200, got %d", w.Code)
	}

	var status map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if status["role"] != "replica" {
		t.Errorf("Expected role 'replica', got %v", status["role"])
	}
	if status["instance_type"] != "hybrid" {
		t.Errorf("Expected instance_type 'hybrid', got %v", status["instance_type"])
	}
	if status["failover_mode"] != true {
		t.Errorf("Expected failover_mode true, got %v", status["failover_mode"])
	}
}

func TestClusterOfflineFallback(t *testing.T) {
	atomic.StoreInt32(&clusterConnLost, 1)
	clusterLastSyncError = "connection refused"

	req := httptest.NewRequest(http.MethodGet, "/api/cluster/connection-status", nil)
	w := httptest.NewRecorder()

	handleClusterConnectionStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200, got %d", w.Code)
	}

	var conn map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&conn); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if conn["connection_lost"] != true {
		t.Errorf("Expected connection_lost to be true")
	}
	if conn["last_error"] != "connection refused" {
		t.Errorf("Expected last_error to be 'connection refused', got %v", conn["last_error"])
	}
}
