package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupSimTestDB(t *testing.T) func() {
	t.Helper()
	tmpDir := t.TempDir()
	origDB := db
	origDBPath := DBPath
	origDriver := dbDriver

	DBPath = filepath.Join(tmpDir, "queries_sim_test.db")
	dbDriver = "sqlite"
	initDB()

	return func() {
		closeDB()
		db = origDB
		DBPath = origDBPath
		dbDriver = origDriver
	}
}

func TestSimulateChange(t *testing.T) {
	cleanupDB := setupSimTestDB(t)
	defer cleanupDB()

	configLock.Lock()
	origCfg := config
	config = Config{
		ClientAliases: map[string]string{
			"192.168.1.50": "Living Room TV",
		},
	}
	configLock.Unlock()
	defer func() {
		configLock.Lock()
		config = origCfg
		configLock.Unlock()
	}()

	now := time.Now().UTC()
	flushLogs([]Query{
		{Time: now.Add(-1 * time.Hour), Domain: "ads.example.com", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.50"},
		{Time: now.Add(-2 * time.Hour), Domain: "tracker.example.com", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.50"},
		{Time: now.Add(-3 * time.Hour), Domain: "example.com", Type: "AAAA", Status: StatusAllowed, ClientIP: "192.168.1.51"},
		{Time: now.Add(-4 * time.Hour), Domain: "blocked.example.com", Type: "A", Status: StatusBlocked, ClientIP: "192.168.1.50"},
		{Time: now.Add(-2 * time.Hour), Domain: "api.tiktok.com", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.52"},
		{Time: now.Add(-30 * time.Hour), Domain: "old.example.com", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.50"},
	})

	// 1. Simulate blocking example.com over 24h
	res, err := SimulateChange(SimulationRequest{
		Action:      "block_domain",
		Domain:      "example.com",
		WindowHours: 24,
	})
	if err != nil {
		t.Fatalf("SimulateChange block_domain failed: %v", err)
	}
	if res.NewlyBlocked != 3 {
		t.Errorf("Expected 3 newly blocked queries, got %d (analyzed=%d)", res.NewlyBlocked, res.QueriesAnalyzed)
	}
	if res.AffectedClients["Living Room TV (192.168.1.50)"] != 2 {
		t.Errorf("Expected 2 impacted queries for Living Room TV, got %+v", res.AffectedClients)
	}

	// 2. Simulate allowing example.com over 24h
	resAllow, err := SimulateChange(SimulationRequest{
		Action:      "allow_domain",
		Domain:      "example.com",
		WindowHours: 24,
	})
	if err != nil {
		t.Fatalf("SimulateChange allow_domain failed: %v", err)
	}
	if resAllow.NewlyAllowed != 1 {
		t.Errorf("Expected 1 newly allowed query, got %d", resAllow.NewlyAllowed)
	}

	// 3. Simulate toggling service "tiktok"
	resSvc, err := SimulateChange(SimulationRequest{
		Action:      "toggle_service",
		ServiceID:   "tiktok",
		WindowHours: 24,
	})
	if err != nil {
		t.Fatalf("SimulateChange toggle_service failed: %v", err)
	}
	if resSvc.NewlyBlocked != 1 {
		t.Errorf("Expected 1 newly blocked TikTok query, got %d", resSvc.NewlyBlocked)
	}

	// 4. Test ?dryRun=true on handleRuleAdd with AskAI mock
	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": "Low risk: only affects telemetry subdomains."}},
			},
		})
	}))
	defer mockAI.Close()

	configLock.Lock()
	config.AIEnabled = true
	config.AIBaseURL = mockAI.URL
	config.AIModel = "test-model"
	configLock.Unlock()

	resAI, err := SimulateChange(SimulationRequest{
		Action:      "block_domain",
		Domain:      "example.com",
		WindowHours: 24,
		AskAI:       true,
	})
	if err != nil {
		t.Fatalf("SimulateChange AskAI failed: %v", err)
	}
	if !strings.Contains(resAI.AIBlastAssessment, "Low risk") {
		t.Errorf("Expected AIBlastAssessment, got %q", resAI.AIBlastAssessment)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/rules/add?dryRun=true", bytes.NewBufferString(`{"domain":"example.com","type":"block"}`))
	rec := httptest.NewRecorder()
	handleRuleAdd(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 on dryRun rule add, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(config.CustomBlocked) != 0 {
		t.Errorf("Expected CustomBlocked to remain empty on dryRun=true, got %v", config.CustomBlocked)
	}
}
