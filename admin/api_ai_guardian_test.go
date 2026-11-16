package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAIGuardianOpenAIChat(t *testing.T) {
	// Create mock OpenAI-compatible server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		resp := OpenAIChatResponse{
			Choices: []struct {
				Message struct {
					Role    string `json:"role"`
					Content string `json:"content"`
				} `json:"message"`
			}{
				{
					Message: struct {
						Role    string `json:"role"`
						Content string `json:"content"`
					}{
						Role: "assistant",
						Content: `{
							"is_threat": true,
							"threat_type": "phishing",
							"confidence": 0.95,
							"reason": "Typosquatting against PayPal",
							"recommended_action": "block"
						}`,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	configLock.Lock()
	config.AIEnabled = true
	config.AIBaseURL = mockServer.URL
	config.AIAPIKey = "test-key"
	config.AIModel = "security-threat-cascade"
	config.AITimeoutSeconds = 5
	configLock.Unlock()

	verdict, err := TriageDomainWithAI(context.Background(), "paypa1-security.xyz", "192.168.1.100", false)
	if err != nil {
		t.Fatalf("Expected triage to succeed, got: %v", err)
	}

	if !verdict.IsThreat {
		t.Errorf("Expected domain to be flagged as threat")
	}
	if verdict.ThreatType != "phishing" {
		t.Errorf("Expected threat_type 'phishing', got: %s", verdict.ThreatType)
	}
	if verdict.Confidence < 0.90 {
		t.Errorf("Expected confidence >= 0.90, got: %f", verdict.Confidence)
	}

	// Test cache hit
	verdictCached, err := TriageDomainWithAI(context.Background(), "paypa1-security.xyz", "192.168.1.100", false)
	if err != nil {
		t.Fatalf("Expected cached triage to succeed, got: %v", err)
	}
	if verdictCached.Domain != verdict.Domain {
		t.Errorf("Cached verdict domain mismatch: %s vs %s", verdictCached.Domain, verdict.Domain)
	}
}

func TestAIGuardianMCPTools(t *testing.T) {
	// Verify AI MCP tools exist in allMCPTools
	foundTriage := false
	foundAudit := false
	foundRules := false

	for _, toolDef := range allMCPTools {
		switch toolDef.tool.Name {
		case "ai_triage_domain":
			foundTriage = true
		case "ai_audit_anomalies":
			foundAudit = true
		case "get_ai_rules":
			foundRules = true
		}
	}

	if !foundTriage {
		t.Errorf("Expected MCP tool 'ai_triage_domain' to be registered")
	}
	if !foundAudit {
		t.Errorf("Expected MCP tool 'ai_audit_anomalies' to be registered")
	}
	if !foundRules {
		t.Errorf("Expected MCP tool 'get_ai_rules' to be registered")
	}
}

func TestAIRuleMetadataInConfig(t *testing.T) {
	configLock.Lock()
	if config.AIRules == nil {
		config.AIRules = make(map[string]AIRuleMetadata)
	}
	config.AIRules["malicious-test.com"] = AIRuleMetadata{
		Domain:     "malicious-test.com",
		Action:     "block",
		ThreatType: "malware_c2",
		Confidence: 0.99,
		Reason:     "C2 beacon",
		Model:      "security-threat-cascade",
		CreatedAt:  time.Now().UTC(),
		Source:     "ai_autonomous",
	}
	configLock.Unlock()

	clone := config.Clone()
	if clone.AIRules == nil || clone.AIRules["malicious-test.com"].ThreatType != "malware_c2" {
		t.Errorf("Expected Clone() to preserve AIRules")
	}
}
