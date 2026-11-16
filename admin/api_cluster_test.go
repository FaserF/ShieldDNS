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

func TestClusterInstanceSpecificMappings(t *testing.T) {
	origConfig := config.Clone()
	defer func() {
		configLock.Lock()
		config = *origConfig
		configLock.Unlock()
	}()

	// 1. Primary export should strip private/Tailnet IPs for "public" replicas, keep for "private"/"hybrid"
	configLock.Lock()
	config.CustomMappings = map[string]string{
		"internal.tailnet.fabiseitz.de": "100.64.0.1",
		"router.lan":                    "192.168.1.1",
		"public.fabiseitz.de":           "89.168.74.120",
	}
	configLock.Unlock()

	pubExport := buildClusterConfigExport("public", "https://primary.example.com", false)
	if _, exists := pubExport.CustomMappings["internal.tailnet.fabiseitz.de"]; exists {
		t.Errorf("Expected public replica export to strip Tailnet CGNAT IP 100.64.0.1")
	}
	if _, exists := pubExport.CustomMappings["router.lan"]; exists {
		t.Errorf("Expected public replica export to strip private LAN IP 192.168.1.1")
	}
	if pubExport.CustomMappings["public.fabiseitz.de"] != "89.168.74.120" {
		t.Errorf("Expected public replica export to preserve public IP, got %q", pubExport.CustomMappings["public.fabiseitz.de"])
	}

	privExport := buildClusterConfigExport("private", "https://primary.example.com", false)
	if privExport.CustomMappings["internal.tailnet.fabiseitz.de"] != "100.64.0.1" {
		t.Errorf("Expected private replica export to preserve Tailnet IP")
	}

	// 2. Replica applyClusterExport should preserve local exclusions and local overrides
	tmpDir := t.TempDir()
	origDataDir := DataDir
	origConfigPath := ConfigPath
	DataDir = tmpDir
	ConfigPath = tmpDir + "/config.json"
	defer func() {
		DataDir = origDataDir
		ConfigPath = origConfigPath
	}()

	configLock.Lock()
	config.ClusterLocalMappings = map[string]string{
		"ha.fabiseitz.de": "192.168.1.2",
	}
	config.ClusterExcludedMappings = []string{"stream.fabiseitz.de"}
	configLock.Unlock()

	exp := ClusterConfigExport{
		CustomMappings: map[string]string{
			"ha.fabiseitz.de":     "100.64.0.2",
			"stream.fabiseitz.de": "100.64.0.1",
			"jarvis.fabiseitz.de": "100.64.0.1",
		},
	}
	if err := applyClusterExport(exp, "https://dns.fabiseitz.de", "tok", "private", false); err != nil {
		t.Fatalf("applyClusterExport failed: %v", err)
	}

	configLock.RLock()
	defer configLock.RUnlock()
	if _, excluded := config.CustomMappings["stream.fabiseitz.de"]; excluded {
		t.Errorf("Expected stream.fabiseitz.de to remain excluded on replica after sync")
	}
	if config.CustomMappings["ha.fabiseitz.de"] != "192.168.1.2" {
		t.Errorf("Expected local override 192.168.1.2 for ha.fabiseitz.de, got %q", config.CustomMappings["ha.fabiseitz.de"])
	}
	if config.CustomMappings["jarvis.fabiseitz.de"] != "100.64.0.1" {
		t.Errorf("Expected non-overridden mapping jarvis.fabiseitz.de to sync from primary")
	}
}

func TestListsEqual(t *testing.T) {
	a := []List{{Name: "L1", URL: "https://example.com/1.txt", Enabled: true, Entries: 100}}
	b := []List{{Name: "L1", URL: "https://example.com/1.txt", Enabled: true, Entries: 200}}
	if !listsEqual(a, b) {
		t.Errorf("expected listsEqual to ignore Entry counts when URL and Enabled match")
	}
	c := []List{{Name: "L1", URL: "https://example.com/1.txt", Enabled: false, Entries: 100}}
	if listsEqual(a, c) {
		t.Errorf("expected listsEqual to detect Enabled change")
	}
}
