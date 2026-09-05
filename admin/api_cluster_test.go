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

func TestClusterPermissionCheck(t *testing.T) {
	clusterKey := &APIKey{
		ID:          "key-1",
		Permissions: []string{"cluster:sync"},
	}
	if !hasPermission(clusterKey, "cluster:sync") {
		t.Errorf("Expected clusterKey to have 'cluster:sync' permission")
	}
	if !hasPermission(clusterKey, "read:config") {
		t.Errorf("Expected clusterKey to have implicit 'read:config' permission")
	}
	if !hasPermission(clusterKey, "read:health") {
		t.Errorf("Expected clusterKey to have implicit 'read:health' permission")
	}
	if hasPermission(clusterKey, "write:config") {
		t.Errorf("Expected clusterKey NOT to have 'write:config' permission")
	}
	if hasPermission(clusterKey, "read:logs") {
		t.Errorf("Expected clusterKey NOT to have 'read:logs' permission")
	}

	readOnlyKey := &APIKey{
		ID:          "key-2",
		Permissions: []string{"read:stats"},
	}
	if hasPermission(readOnlyKey, "cluster:sync") {
		t.Errorf("Expected readOnlyKey NOT to have 'cluster:sync' permission")
	}

	adminKey := &APIKey{
		ID:          "key-3",
		Permissions: []string{"admin:all"},
	}
	if !hasPermission(adminKey, "cluster:sync") {
		t.Errorf("Expected adminKey to have 'cluster:sync' permission")
	}
}

func TestClusterLogSharingModes(t *testing.T) {
	configLock.Lock()
	config.ClusterRole = "primary"
	config.ClusterNodeName = "Master Node"
	config.ClusterLogSharingMode = "full_sync"
	configLock.Unlock()

	req, _ := http.NewRequest(http.MethodGet, "/api/cluster/status", nil)
	w := httptest.NewRecorder()
	handleClusterStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200, got %d", w.Code)
	}

	var status map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if status["node_name"] != "Master Node" {
		t.Errorf("Expected node_name to be 'Master Node', got %v", status["node_name"])
	}
	if status["log_sharing_mode"] != "full_sync" {
		t.Errorf("Expected log_sharing_mode to be 'full_sync', got %v", status["log_sharing_mode"])
	}
}
