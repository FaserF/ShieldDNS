package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestConfigPersistenceRegression(t *testing.T) {
	// 1. Initialize global config with sensitive data
	configLock.Lock()
	config.AdminPasswordHashed = "original-password-hash"
	config.APIKeys = []APIKey{
		{ID: "k1", Name: "Key 1", TokenHash: "hash1"},
	}
	config.CustomMappings = map[string]string{"dns.local": "127.0.0.1"}
	config.RetentionDays = 30
	config.SetupDone = true
	config.AdminDomain = "original.domain"
	configLock.Unlock()

	// 2. Simulate a GET request to /api/config (which uses SanitizedCopy)
	// We check if the response is indeed sanitized
	rrGet := httptest.NewRecorder()
	reqGet := httptest.NewRequest("GET", "/api/config", nil)
	handleConfig(rrGet, reqGet)

	if rrGet.Code != http.StatusOK {
		t.Fatalf("GET /api/config failed: %v", rrGet.Code)
	}

	var sanitized Config
	if err := json.Unmarshal(rrGet.Body.Bytes(), &sanitized); err != nil {
		t.Fatalf("Failed to unmarshal sanitized config: %v", err)
	}

	if sanitized.AdminPasswordHashed != "********" {
		t.Errorf("Expected masked password hash, got %s", sanitized.AdminPasswordHashed)
	}
	if sanitized.APIKeys[0].TokenHash != "********" {
		t.Errorf("Expected masked API key hash, got %s", sanitized.APIKeys[0].TokenHash)
	}

	// 3. Simulate a POST request from the frontend using the sanitized config
	// The frontend sends back the masked values.
	sanitized.AdminDomain = "new.domain" // Change a non-sensitive field

	reqBody, _ := json.Marshal(sanitized)
	rrPost := httptest.NewRecorder()
	reqPost := httptest.NewRequest("POST", "/api/config", bytes.NewBuffer(reqBody))
	handleConfig(rrPost, reqPost)

	if rrPost.Code != http.StatusOK {
		t.Fatalf("POST /api/config failed: %v", rrPost.Code)
	}

	// 4. Verify that the global config has RESTORED the sensitive values
	configLock.RLock()
	defer configLock.RUnlock()

	if config.AdminDomain != "new.domain" {
		t.Errorf("AdminDomain was not updated: %s", config.AdminDomain)
	}
	if config.AdminPasswordHashed != "original-password-hash" {
		t.Errorf("CRITICAL REGRESSION: AdminPasswordHashed was lost/overwritten by masked value! Got: %s", config.AdminPasswordHashed)
	}
	if config.APIKeys[0].TokenHash != "hash1" {
		t.Errorf("CRITICAL REGRESSION: APIKey TokenHash was lost/overwritten by masked value! Got: %s", config.APIKeys[0].TokenHash)
	}
	if config.CustomMappings["dns.local"] != "127.0.0.1" {
		t.Errorf("CRITICAL REGRESSION: CustomMappings were lost!")
	}
	if config.RetentionDays != 30 {
		t.Errorf("CRITICAL REGRESSION: RetentionDays were lost!")
	}
	if !config.SetupDone {
		t.Errorf("CRITICAL REGRESSION: SetupDone was lost!")
	}

	// 5. Verify Disk Persistence
	// We need to ensure saveConfigNoLock actually wrote the password to disk
	fileData, err := os.ReadFile(ConfigPath)
	if err != nil {
		t.Fatalf("Failed to read config file from disk: %v", err)
	}

	var diskConfig Config
	if err := json.Unmarshal(fileData, &diskConfig); err != nil {
		t.Fatalf("Failed to unmarshal config from disk: %v", err)
	}

	if diskConfig.AdminPasswordHashed != "original-password-hash" {
		t.Errorf("CRITICAL PERSISTENCE REGRESSION: AdminPasswordHashed was NOT saved to disk! Got: %s", diskConfig.AdminPasswordHashed)
	}
	if diskConfig.APIKeys[0].TokenHash != "hash1" {
		t.Errorf("CRITICAL PERSISTENCE REGRESSION: APIKey TokenHash was NOT saved to disk! Got: %s", diskConfig.APIKeys[0].TokenHash)
	}
}
