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

func TestDetectAnomalies(t *testing.T) {
	cleanupDB := setupSimTestDB(t)
	defer cleanupDB()

	origDataDir := DataDir
	DataDir = t.TempDir()
	defer func() { DataDir = origDataDir }()
	resetAnomalyStateForTest()

	configLock.Lock()
	origCfg := config
	config = Config{
		AbuseDGAThreshold: 3.6,
		AbuseDGAMinLen:    10,
		ClientAliases: map[string]string{
			"192.168.1.90": "Suspicious Sensor",
		},
	}
	configLock.Unlock()
	defer func() {
		configLock.Lock()
		config = origCfg
		configLock.Unlock()
	}()

	now := time.Now().UTC()
	var batch []Query

	// 1. Periodic beacon: 12 queries spaced 60s apart
	for i := 12; i >= 1; i-- {
		batch = append(batch, Query{
			Time:     now.Add(-time.Duration(i*60) * time.Second),
			Domain:   "beacon.c2-telemetry.net",
			Type:     "A",
			Status:   StatusAllowed,
			ClientIP: "192.168.1.90",
		})
	}

	// 2. High-entropy DGA domain
	batch = append(batch, Query{
		Time:     now.Add(-5 * time.Minute),
		Domain:   "x9k2m7q4z1v8p3r6n0w5.evil-dga.com",
		Type:     "A",
		Status:   StatusAllowed,
		ClientIP: "192.168.1.91",
	})

	// 3. Block storm: 55 blocked queries from 192.168.1.92
	for i := 0; i < 55; i++ {
		batch = append(batch, Query{
			Time:     now.Add(-time.Duration(i) * time.Second),
			Domain:   "ads.noisy-app.com",
			Type:     "A",
			Status:   StatusBlocked,
			ClientIP: "192.168.1.92",
		})
	}
	flushLogs(batch)

	findings, err := DetectAnomalies()
	if err != nil {
		t.Fatalf("DetectAnomalies failed: %v", err)
	}

	var foundBeacon, foundDGA, foundStorm bool
	var beaconID string
	for _, f := range findings {
		switch f.Kind {
		case "periodic_beacon":
			if f.ClientIP == "192.168.1.90" && f.DominantIntervalSec >= 55 && f.DominantIntervalSec <= 65 {
				foundBeacon = true
				beaconID = f.ID
			}
		case "dga_entropy":
			if f.ClientIP == "192.168.1.91" {
				foundDGA = true
			}
		case "block_storm":
			if f.ClientIP == "192.168.1.92" {
				foundStorm = true
			}
		}
	}

	if !foundBeacon {
		t.Errorf("Expected periodic_beacon finding, got %+v", findings)
	}
	if !foundDGA {
		t.Errorf("Expected dga_entropy finding, got %+v", findings)
	}
	if !foundStorm {
		t.Errorf("Expected block_storm finding, got %+v", findings)
	}

	// Test acknowledge endpoint
	ackBody := `{"id":"` + beaconID + `"}`
	reqAck := httptest.NewRequest(http.MethodPost, "/api/anomalies/acknowledge", bytes.NewBufferString(ackBody))
	recAck := httptest.NewRecorder()
	handleAcknowledgeAnomaly(recAck, reqAck)
	if recAck.Code != http.StatusOK {
		t.Fatalf("Expected 200 on acknowledge, got %d", recAck.Code)
	}

	// Test mute endpoint for block_storm
	muteBody := `{"client_ip":"192.168.1.92","kind":"block_storm"}`
	reqMute := httptest.NewRequest(http.MethodPost, "/api/anomalies/mute", bytes.NewBufferString(muteBody))
	recMute := httptest.NewRecorder()
	handleMuteAnomaly(recMute, reqMute)
	if recMute.Code != http.StatusOK {
		t.Fatalf("Expected 200 on mute, got %d", recMute.Code)
	}

	reqList := httptest.NewRequest(http.MethodGet, "/api/anomalies", nil)
	recList := httptest.NewRecorder()
	handleGetAnomalies(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Fatalf("Expected 200 on GET /api/anomalies, got %d", recList.Code)
	}
	var resp struct {
		Anomalies      []AnomalyFinding `json:"anomalies"`
		Unacknowledged int              `json:"unacknowledged"`
	}
	if err := json.Unmarshal(recList.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to decode anomalies response: %v", err)
	}
	for _, f := range resp.Anomalies {
		if f.Kind == "block_storm" && f.ClientIP == "192.168.1.92" {
			t.Errorf("Muted finding should be hidden by default")
		}
		if f.ID == beaconID && !f.Acknowledged {
			t.Errorf("Expected beacon finding to be marked Acknowledged")
		}
	}
	_ = filepath.Join(DataDir, "anomalies_state.json")
}
