package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExplainResolutionPipeline(t *testing.T) {
	configLock.Lock()
	origCfg := config
	config = Config{
		FilteringEnabled:     true,
		BlockPageIP:          "0.0.0.0",
		PreferEncrypted:      true,
		UpstreamDoT:          []string{"dns.quad9.net"},
		SmartSelectionPolicy: "fastest",
		BlockedClients:       []string{"192.168.1.99"},
		ClientAliases:        map[string]string{"192.168.1.50": "Living Room TV"},
		ClientRules: []ClientRule{
			{ClientIP: "192.168.1.50", Domain: "ads.tv.com", IsAllowlist: true},
			{ClientIP: "192.168.1.50", Domain: "telemetry.tv.com", IsAllowlist: false},
		},
		CustomMappings:     map[string]string{"nas.lan": "192.168.1.10"},
		CustomAllowed:      []string{"good-sub.blocked-wildcard.com"},
		BlockedServices:    []string{"tiktok"},
		SafeSearchEnabled:  true,
		YouTubeRestriction: "strict",
		RoutingRules: []RoutingRule{
			{ID: "r1", Match: "internal.corp", MatchType: "domain", Target: "host", HostTarget: "10.0.0.53", Enabled: true},
		},
	}
	configLock.Unlock()
	defer func() {
		configLock.Lock()
		config = origCfg
		configLock.Unlock()
	}()

	blockAttributionLock.Lock()
	blockAttribution = map[string][]string{
		"*.blocked-wildcard.com": {"HaGeZi Multi"},
		"ads.tv.com":             {"AdGuard DNS"},
		"important-tracker.net":  {"Strict Tracker"},
	}
	blockAttributionLock.Unlock()

	importantAttributionLock.Lock()
	importantAttribution = map[string]struct{}{
		"important-tracker.net": {},
	}
	importantAttributionLock.Unlock()

	allowAttributionLock.Lock()
	allowAttribution = map[string][]string{
		"important-tracker.net": {"General Allowlist"},
	}
	allowAttributionLock.Unlock()

	// 1. Blocked client IP
	exp, err := ExplainResolution("example.com", "192.168.1.99", "A", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exp.Outcome != "blocked" || exp.Action != "REFUSED" {
		t.Errorf("Expected blocked REFUSED, got %s %s", exp.Outcome, exp.Action)
	}

	// 2. Client allow rule overrides global blocklist
	exp, err = ExplainResolution("ads.tv.com", "192.168.1.50", "A", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exp.Outcome != "allowed" || exp.ClientAlias != "Living Room TV" {
		t.Errorf("Expected allowed for Living Room TV, got %s alias=%s", exp.Outcome, exp.ClientAlias)
	}

	// 3. SafeSearch match
	exp, err = ExplainResolution("www.google.com", "192.168.1.50", "A", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exp.Outcome != "rewritten" || exp.Answer != "216.239.38.120" {
		t.Errorf("Expected SafeSearch rewrite to 216.239.38.120, got %s %s", exp.Outcome, exp.Answer)
	}

	// 4. Custom mapping
	exp, err = ExplainResolution("nas.lan", "", "A", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exp.Outcome != "rewritten" || exp.Answer != "192.168.1.10" {
		t.Errorf("Expected custom mapping 192.168.1.10, got %s %s", exp.Outcome, exp.Answer)
	}

	// 5. Blocked service
	exp, err = ExplainResolution("api.tiktok.com", "", "A", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exp.Outcome != "blocked" || !strings.Contains(exp.WinningRule, "TikTok") {
		t.Errorf("Expected TikTok blocked, got %s %s", exp.Outcome, exp.WinningRule)
	}

	// 6. Custom allowlist overrides parent wildcard block
	exp, err = ExplainResolution("good-sub.blocked-wildcard.com", "", "A", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exp.Outcome != "allowed" || !strings.Contains(exp.WinningRule, "Custom Allowlist") {
		t.Errorf("Expected Custom Allowlist win, got %s %s", exp.Outcome, exp.WinningRule)
	}

	// 7. $important block resists general allowlist
	exp, err = ExplainResolution("important-tracker.net", "", "A", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exp.Outcome != "blocked" {
		t.Errorf("Expected $important block to resist general allowlist, got %s", exp.Outcome)
	}

	// 8. Conditional routing rule
	exp, err = ExplainResolution("git.internal.corp", "", "A", false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if exp.Outcome != "routed" || !strings.Contains(exp.UpstreamRoute, "10.0.0.53") {
		t.Errorf("Expected routed to 10.0.0.53, got %s %s", exp.Outcome, exp.UpstreamRoute)
	}

	// 9. HTTP API endpoint + Omniroute mock AI evaluation
	mockAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]string{
						"content": `{"is_threat":false,"threat_type":"clean","confidence":0.95,"reason":"Legitimate site","recommended_action":"allow"}`,
					},
				},
			},
		})
	}))
	defer mockAI.Close()

	configLock.Lock()
	config.AIEnabled = true
	config.AIBaseURL = mockAI.URL
	config.AIModel = "test-model"
	configLock.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/explain?domain=wikipedia.org&client_ip=192.168.1.50&ask_ai=true", nil)
	rec := httptest.NewRecorder()
	handleExplainDecision(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var apiResp ResolutionExplanation
	if err := json.Unmarshal(rec.Body.Bytes(), &apiResp); err != nil {
		t.Fatalf("Failed to decode explain response: %v", err)
	}
	if apiResp.Outcome != "allowed" || apiResp.AIVerdict == nil || apiResp.AIVerdict.ThreatType != "clean" {
		t.Errorf("Expected allowed with clean AI verdict, got %+v", apiResp)
	}
}
