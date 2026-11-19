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

func TestTrustedInfrastructureDomain(t *testing.T) {
	configLock.Lock()
	oldDom := config.AdminDomain
	config.AdminDomain = "tailnet.fabiseitz.de"
	setAtomicAdminDomain(config.AdminDomain)
	configLock.Unlock()
	defer func() {
		configLock.Lock()
		config.AdminDomain = oldDom
		setAtomicAdminDomain(oldDom)
		configLock.Unlock()
	}()

	cases := []struct {
		domain  string
		trusted bool
	}{
		{"geller-pa.googleapis.com", true},
		{"*.geller-pa.googleapis.com", true},
		{"cloudcode-pa.googleapis.com", true},
		{"daily-cloudcode-pa.googleapis.com", true},
		{"jules.googleapis.com", true},
		{"cloudbilling.googleapis.com", true},
		{"oauth2.googleapis.com", true},
		{"accounts.google.com", true},
		{"login.microsoft.com", true},
		{"appleid.apple.com", true},
		{"api.github.com", true},
		{"one.one.one.one.cloudflare-dns.com", true},
		{"s3.amazonaws.com", true},
		{"tailscale.com", true},
		{"login.tailnet.fabiseitz.de", true},
		{"evil-phishing-site.xyz", false},
		{"googleapis.com.malicious.net", false},
		{"not-google.com", false},
	}

	for _, tc := range cases {
		got := isTrustedInfrastructureDomain(tc.domain)
		if got != tc.trusted {
			t.Errorf("isTrustedInfrastructureDomain(%q) = %v; want %v", tc.domain, got, tc.trusted)
		}
	}
}

func TestTrustedInfrastructureDomainNoDeadlockUnderConfigLock(t *testing.T) {
	configLock.Lock()
	defer configLock.Unlock()

	// Calling isTrustedInfrastructureDomain while holding configLock.Lock() MUST NOT deadlock
	trusted := isTrustedInfrastructureDomain("cloudcode-pa.googleapis.com")
	if !trusted {
		t.Errorf("Expected cloudcode-pa.googleapis.com to be trusted")
	}
}

func TestApplyCurrentRulesDropsTrustedInfrastructure(t *testing.T) {
	attribution := map[string][]string{
		"ads.tracker.com":          {"AdBlock"},
		"geller-pa.googleapis.com":   {"Custom Blocklist"},
		"*.jules.googleapis.com":   {"Custom Blocklist"},
	}

	applyCurrentRules(attribution, nil, nil, nil, nil, nil, "127.0.0.1", false)

	if _, exists := attribution["geller-pa.googleapis.com"]; exists {
		t.Errorf("Expected geller-pa.googleapis.com to be removed from attribution")
	}
	if _, exists := attribution["*.jules.googleapis.com"]; exists {
		t.Errorf("Expected *.jules.googleapis.com to be removed from attribution")
	}
	if _, exists := attribution["ads.tracker.com"]; !exists {
		t.Errorf("Expected ads.tracker.com to remain in attribution")
	}
}
