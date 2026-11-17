package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeListPriorities(t *testing.T) {
	cfg := &Config{
		Lists: []List{
			{Name: "ShieldDNS Official Blocklist", URL: "https://example.com/official", Category: "Official", Priority: ""},
			{Name: "Huge Bloat List", URL: "https://example.com/huge", Category: "Other", Entries: 250000, Priority: ""},
			{Name: "Normal List", URL: "https://example.com/normal", Category: "General Blocking", Entries: 15000, Priority: ""},
		},
		Allowlists: []List{
			{Name: "Official Allowlist", URL: "https://example.com/allow", Priority: ""},
		},
	}

	modified := normalizeListPriorities(cfg)
	if !modified {
		t.Fatalf("Expected normalizeListPriorities to modify config")
	}

	if cfg.Lists[0].Priority != "high" {
		t.Errorf("Expected official list priority 'high', got '%s'", cfg.Lists[0].Priority)
	}
	if cfg.Lists[1].Priority != "low" {
		t.Errorf("Expected >200k entries list priority 'low', got '%s'", cfg.Lists[1].Priority)
	}
	if cfg.Lists[2].Priority != "normal" {
		t.Errorf("Expected normal list priority 'normal', got '%s'", cfg.Lists[2].Priority)
	}
	if cfg.Allowlists[0].Priority != "high" {
		t.Errorf("Expected allowlist priority 'high', got '%s'", cfg.Allowlists[0].Priority)
	}
}

func TestEmergencyLoadSheddingOrder(t *testing.T) {
	configLock.Lock()
	origLists := config.Lists
	origActive := config.EmergencySheddingActive
	origShed := config.EmergencyShedLists

	config.Lists = []List{
		{Name: "Core Security", URL: "https://sec.test/list", Enabled: true, Priority: "high", Entries: 50000},
		{Name: "Normal Large", URL: "https://normal.test/list2", Enabled: true, Priority: "normal", Entries: 120000},
		{Name: "Low Small", URL: "https://low.test/small", Enabled: true, Priority: "low", Entries: 10000},
		{Name: "Low Monster", URL: "https://low.test/monster", Enabled: true, Priority: "low", Entries: 300000},
	}
	config.EmergencySheddingActive = false
	config.EmergencyShedLists = nil
	configLock.Unlock()

	defer func() {
		configLock.Lock()
		config.Lists = origLists
		config.EmergencySheddingActive = origActive
		config.EmergencyShedLists = origShed
		configLock.Unlock()
	}()

	// Trigger emergency load shedding
	triggerEmergencyLoadShedding(150.0, 4096.0, 500.0, 3000.0)

	configLock.RLock()
	defer configLock.RUnlock()

	if !config.EmergencySheddingActive {
		t.Fatalf("Expected EmergencySheddingActive to be true")
	}

	// Verify "Low Monster" (low prio with 300k entries) was shed first
	var lowMonster, lowSmall, normalLarge, coreSec *List
	for i := range config.Lists {
		switch config.Lists[i].Name {
		case "Low Monster":
			lowMonster = &config.Lists[i]
		case "Low Small":
			lowSmall = &config.Lists[i]
		case "Normal Large":
			normalLarge = &config.Lists[i]
		case "Core Security":
			coreSec = &config.Lists[i]
		}
	}

	if lowMonster == nil || !lowMonster.EmergencySuspended {
		t.Errorf("Expected 'Low Monster' to be EmergencySuspended first, got suspended=%v", lowMonster != nil && lowMonster.EmergencySuspended)
	}
	if lowSmall != nil && lowSmall.EmergencySuspended {
		t.Errorf("Expected 'Low Small' not to be suspended before Monster")
	}
	if normalLarge != nil && normalLarge.EmergencySuspended {
		t.Errorf("Expected 'Normal Large' not to be suspended while low priority list existed")
	}
	if coreSec != nil && coreSec.EmergencySuspended {
		t.Errorf("Expected 'Core Security' not to be suspended")
	}
}

func TestSetListPriorityAPI(t *testing.T) {
	configLock.Lock()
	origLists := config.Lists
	config.Lists = []List{
		{Name: "Test List", URL: "https://test.local/list.txt", Priority: "normal"},
	}
	configLock.Unlock()

	defer func() {
		configLock.Lock()
		config.Lists = origLists
		configLock.Unlock()
	}()

	body, _ := json.Marshal(map[string]string{
		"url":      "https://test.local/list.txt",
		"priority": "low",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/lists/priority", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handleSetListPriority(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200, got %d: %s", w.Code, w.Body.String())
	}

	configLock.RLock()
	defer configLock.RUnlock()
	if config.Lists[0].Priority != "low" {
		t.Errorf("Expected priority 'low', got '%s'", config.Lists[0].Priority)
	}
}

func TestPeerOffloadSelection(t *testing.T) {
	// 1. Replica in shedding -> offloads to healthy Primary
	replicaCfg := &Config{
		ClusterRole:               "replica",
		ClusterPrimaryURL:         "https://dns.fabiseitz.de",
		ClusterPeerOffloadEnabled: true,
		EmergencySheddingActive:   true,
	}
	if got := selectPeerOffloadCandidate(replicaCfg, false, "oracle-vm.tailnet.fabiseitz.de:53"); got != "oracle-vm.tailnet.fabiseitz.de:53" {
		t.Errorf("Expected replica offload to primary 'oracle-vm.tailnet.fabiseitz.de:53', got '%s'", got)
	}

	// 2. Replica in shedding + Primary ALSO in shedding -> must NOT offload (loop prevention)
	if got := selectPeerOffloadCandidate(replicaCfg, true, "oracle-vm.tailnet.fabiseitz.de:53"); got != "" {
		t.Errorf("Expected no offload when primary is also shedding, got '%s'", got)
	}

	// 3. Primary in shedding -> offloads to healthy Replica
	primaryCfg := &Config{
		ClusterRole:               "primary",
		ClusterPeerOffloadEnabled: true,
		EmergencySheddingActive:   true,
		ClusterReplicas: []ClusterReplica{
			{
				ID:                "ha-slave",
				Name:              "Home Assistant",
				URL:               "https://ha.tailnet.fabiseitz.de:8443",
				EmergencyShedding: false,
			},
		},
	}
	if got := selectPeerOffloadCandidate(primaryCfg, false, ""); got != "ha.tailnet.fabiseitz.de:53" {
		t.Errorf("Expected primary offload to replica 'ha.tailnet.fabiseitz.de:53', got '%s'", got)
	}

	// 4. Primary in shedding + Replica ALSO in shedding -> must NOT offload (loop prevention)
	primaryCfg.ClusterReplicas[0].EmergencyShedding = true
	if got := selectPeerOffloadCandidate(primaryCfg, false, ""); got != "" {
		t.Errorf("Expected no offload when replica is also shedding, got '%s'", got)
	}

	// 5. Node NOT in shedding -> no offload
	replicaCfg.EmergencySheddingActive = false
	if got := selectPeerOffloadCandidate(replicaCfg, false, "oracle-vm.tailnet.fabiseitz.de:53"); got != "" {
		t.Errorf("Expected no offload when node is healthy, got '%s'", got)
	}
}

func TestRestoreShedListsInternal(t *testing.T) {
	testMode = true
	defer func() { testMode = false }()

	configLock.Lock()
	origLists := config.Lists
	origShedding := config.EmergencySheddingActive
	origShedLists := config.EmergencyShedLists

	config.EmergencySheddingActive = true
	config.EmergencyShedLists = []string{"https://test.local/list1.txt"}
	config.Lists = []List{
		{Name: "List 1", URL: "https://test.local/list1.txt", EmergencySuspended: true},
		{Name: "List 2", URL: "https://test.local/list2.txt", EmergencySuspended: false},
	}
	configLock.Unlock()

	defer func() {
		configLock.Lock()
		config.Lists = origLists
		config.EmergencySheddingActive = origShedding
		config.EmergencyShedLists = origShedLists
		configLock.Unlock()
	}()

	restored := restoreShedListsInternal("test")
	if restored != 1 {
		t.Fatalf("Expected 1 restored list, got %d", restored)
	}

	configLock.RLock()
	defer configLock.RUnlock()
	if config.EmergencySheddingActive {
		t.Errorf("Expected EmergencySheddingActive to be false")
	}
	if len(config.EmergencyShedLists) != 0 {
		t.Errorf("Expected EmergencyShedLists to be empty")
	}
	if config.Lists[0].EmergencySuspended {
		t.Errorf("Expected List 1 EmergencySuspended to be false")
	}
}
