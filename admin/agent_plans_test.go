package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentPlansWorkflow(t *testing.T) {
	cleanupDB := setupSimTestDB(t)
	defer cleanupDB()

	tmpDir := t.TempDir()
	origDataDir := DataDir
	origConfigPath := ConfigPath
	origCombined := CombinedHostsPath
	origBlocklist := BlocklistPath
	origAllowlist := AllowlistPath
	origMappings := MappingsPath
	defer func() {
		DataDir = origDataDir
		ConfigPath = origConfigPath
		CombinedHostsPath = origCombined
		BlocklistPath = origBlocklist
		AllowlistPath = origAllowlist
		MappingsPath = origMappings
	}()

	DataDir = tmpDir
	ConfigPath = filepath.Join(tmpDir, "config.json")
	CombinedHostsPath = filepath.Join(tmpDir, "shielddns.hosts")
	BlocklistPath = filepath.Join(tmpDir, "blocklist.hosts")
	AllowlistPath = filepath.Join(tmpDir, "allowlist.hosts")
	MappingsPath = filepath.Join(tmpDir, "mappings.hosts")

	resetAgentPlansForTest()
	resetAnnotationsForTest()

	configLock.Lock()
	origCfg := config
	config = Config{
		FilteringEnabled: true,
		BlockPageIP:      "0.0.0.0",
	}
	configLock.Unlock()
	defer func() {
		configLock.Lock()
		config = origCfg
		configLock.Unlock()
	}()

	blockAttributionLock.Lock()
	blockAttribution = make(map[string][]string)
	blockAttributionLock.Unlock()

	now := time.Now().UTC()
	flushLogs([]Query{
		{Time: now.Add(-10 * time.Minute), Domain: "beacon.badhost.org", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.33"},
		{Time: now.Add(-5 * time.Minute), Domain: "beacon.badhost.org", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.33"},
	})

	// 1. Create Plan
	plan, err := CreateAgentPlan("agent:jarvis", "block_domain", "badhost.org", "", "Detected periodic C2 beacon")
	if err != nil {
		t.Fatalf("CreateAgentPlan failed: %v", err)
	}
	if plan.Status != "pending" || plan.Simulation == nil || plan.Simulation.NewlyBlocked != 2 {
		t.Fatalf("Expected pending plan with 2 newly blocked simulation, got %+v", plan)
	}

	// Verify config has NOT changed yet
	if len(config.CustomBlocked) != 0 {
		t.Fatalf("Config should not be modified while plan is pending")
	}

	// 2. Apply Plan via HTTP handler
	body := `{"plan_id":"` + plan.ID + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/agent/plans/apply", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handleApplyAgentPlan(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on apply, got %d: %s", rec.Code, rec.Body.String())
	}

	var applied AgentPlan
	if err := json.Unmarshal(rec.Body.Bytes(), &applied); err != nil {
		t.Fatalf("Failed to parse applied plan: %v", err)
	}
	if applied.Status != "applied" {
		t.Errorf("Expected status applied, got %s", applied.Status)
	}
	if len(config.CustomBlocked) != 1 || config.CustomBlocked[0] != "badhost.org" {
		t.Errorf("Expected badhost.org in CustomBlocked, got %v", config.CustomBlocked)
	}

	// 3. Create & Discard second plan
	plan2, err := CreateAgentPlan("agent:jarvis", "toggle_service", "tiktok", "", "Test discard")
	if err != nil {
		t.Fatalf("CreateAgentPlan 2 failed: %v", err)
	}
	discarded, err := DiscardAgentPlan(plan2.ID)
	if err != nil || discarded.Status != "rejected" {
		t.Errorf("Expected rejected plan2, got %+v err=%v", discarded, err)
	}
}
