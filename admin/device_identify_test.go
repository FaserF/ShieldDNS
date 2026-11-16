package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIdentifyDevice(t *testing.T) {
	cleanupDB := setupSimTestDB(t)
	defer cleanupDB()

	configLock.Lock()
	origCfg := config
	config = Config{
		ClientAliases: map[string]string{
			"192.168.1.40": "Living-Room-Roku",
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
		// Roku streaming client
		{Time: now, Domain: "api.roku.com", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.40"},
		{Time: now, Domain: "scribe.logs.roku.com", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.40"},
		{Time: now, Domain: "time.rokutime.com", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.40"},
		// PlayStation console (unnamed, pure DNS domain fingerprinting)
		{Time: now, Domain: "telemetry.playstation.net", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.60"},
		{Time: now, Domain: "gs2.ww.prod.dl.playstation.net", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.60"},
		{Time: now, Domain: "account.sonyentertainmentnetwork.com", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.60"},
		// Unrecognized IoT device for AI fallback test
		{Time: now, Domain: "mqtt.custom-thermostat.io", Type: "A", Status: StatusAllowed, ClientIP: "192.168.1.77"},
	})

	// 1. Roku (Domain + Alias)
	roku := IdentifyDevice("192.168.1.40", false)
	if roku.Class != "streaming" || roku.Product != "Roku Player" || roku.Confidence != "likely" {
		t.Errorf("Expected Roku Player likely streaming, got %+v", roku)
	}

	// 2. PlayStation (Unnamed, pure DNS domain traffic)
	ps := IdentifyDevice("192.168.1.60", false)
	if ps.Class != "console" || ps.Product != "Sony PlayStation" || ps.Confidence != "likely" {
		t.Errorf("Expected Sony PlayStation likely console, got %+v", ps)
	}

	// 3. Unknown -> Omniroute AI fallback
	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{
					"content": `{"product":"Smart Thermostat","class":"iot","confidence":"likely","reason":"MQTT telemetry domain"}`,
				}},
			},
		})
	}))
	defer mockAI.Close()

	configLock.Lock()
	config.AIEnabled = true
	config.AIBaseURL = mockAI.URL
	config.AIModel = "test-model"
	configLock.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/client/identity?ip=192.168.1.77&ask_ai=true", nil)
	rec := httptest.NewRecorder()
	handleClientIdentity(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}
	var aiIdent DeviceIdentity
	if err := json.Unmarshal(rec.Body.Bytes(), &aiIdent); err != nil {
		t.Fatalf("Failed to unmarshal identity: %v", err)
	}
	if aiIdent.Product != "Smart Thermostat" || aiIdent.Class != "iot" || aiIdent.Confidence != "likely" {
		t.Errorf("Expected AI Smart Thermostat iot, got %+v", aiIdent)
	}
}
