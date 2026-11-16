package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSupportPackageAndAnnotations(t *testing.T) {
	cleanupDB := setupSimTestDB(t)
	defer cleanupDB()

	origDataDir := DataDir
	DataDir = t.TempDir()
	defer func() { DataDir = origDataDir }()
	resetAnnotationsForTest()

	configLock.Lock()
	origCfg := config
	config = Config{
		AdminPasswordHashed: "$2a$10$supersecretpasswordhash",
		AIAPIKey:            "sk-omniroute-topsecret-12345",
		WebhookToken:        "whsec-very-secret-token",
		ClusterPrimaryToken: "cluster-secret-key",
		ClientAliases:       map[string]string{"192.168.1.44": "Secret Personal Laptop"},
		CustomBlocked:       []string{"private-tracker.internal"},
		APIKeys: []APIKey{
			{ID: "k1", Name: "AgentKey", TokenHash: "hashed-api-key-999"},
		},
	}
	configLock.Unlock()
	defer func() {
		configLock.Lock()
		config = origCfg
		configLock.Unlock()
	}()

	// 1. Test Annotations
	RecordAnnotation("rule", "admin", "Blocked example.com")
	RecordAnnotation("config", "admin", "Updated DoT upstreams")
	anns := GetAnnotations(10)
	if len(anns) != 2 || anns[0].Summary != "Updated DoT upstreams" {
		t.Fatalf("Unexpected annotations: %+v", anns)
	}

	reqAnn := httptest.NewRequest(http.MethodPost, "/api/annotations", bytes.NewBufferString(`{"kind":"note","actor":"fabian","summary":"Tested failover"}`))
	recAnn := httptest.NewRecorder()
	handleAnnotations(recAnn, reqAnn)
	if recAnn.Code != http.StatusOK {
		t.Fatalf("Expected 200 on POST /api/annotations, got %d", recAnn.Code)
	}

	// 2. Test Support Package (strict)
	zipBytes, err := GenerateSupportPackage("strict")
	if err != nil {
		t.Fatalf("GenerateSupportPackage failed: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("Failed to open generated zip: %v", err)
	}

	filesMap := make(map[string]string)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("Failed to open zip entry %s: %v", f.Name, err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		filesMap[f.Name] = string(data)
	}

	cfgContent, ok := filesMap["config_redacted.json"]
	if !ok {
		t.Fatalf("Missing config_redacted.json in support package")
	}

	leaks := []string{
		"supersecretpasswordhash",
		"sk-omniroute-topsecret-12345",
		"whsec-very-secret-token",
		"cluster-secret-key",
		"hashed-api-key-999",
		"192.168.1.44",
		"Secret Personal Laptop",
		"private-tracker.internal",
	}
	for _, secret := range leaks {
		if strings.Contains(cfgContent, secret) {
			t.Errorf("Support package in strict mode leaked %q", secret)
		}
	}
	if !strings.Contains(cfgContent, "[REDACTED]") {
		t.Errorf("Expected [REDACTED] markers in config_redacted.json")
	}

	var manifest SupportPackageManifest
	if err := json.Unmarshal([]byte(filesMap["manifest.json"]), &manifest); err != nil {
		t.Fatalf("Failed to decode manifest.json: %v", err)
	}
	if manifest.ObfuscationLevel != "strict" || manifest.RedactedSecrets < 4 || manifest.PseudonymizedIPs < 1 {
		t.Errorf("Unexpected manifest counts: %+v", manifest)
	}
}
