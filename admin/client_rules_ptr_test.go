package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAdblockRuleWithClient(t *testing.T) {
	rule := ParseAdblockRule("@@||de.ots.io.mi.com^$client='192.168.1.108'")
	if rule == nil {
		t.Fatal("expected parsed rule, got nil")
	}
	if rule.Domain != "de.ots.io.mi.com" {
		t.Errorf("expected domain de.ots.io.mi.com, got %s", rule.Domain)
	}
	if !rule.IsAllowlist {
		t.Error("expected allowlist rule")
	}
	if rule.ClientIP != "192.168.1.108" {
		t.Errorf("expected client IP 192.168.1.108, got %s", rule.ClientIP)
	}

	blockRule := ParseAdblockRule("||ads.example.com^$client=10.0.0.5")
	if blockRule == nil {
		t.Fatal("expected parsed block rule, got nil")
	}
	if blockRule.Domain != "ads.example.com" {
		t.Errorf("expected domain ads.example.com, got %s", blockRule.Domain)
	}
	if blockRule.IsAllowlist {
		t.Error("expected block rule")
	}
	if blockRule.ClientIP != "10.0.0.5" {
		t.Errorf("expected client IP 10.0.0.5, got %s", blockRule.ClientIP)
	}
}

func TestClientSpecificRulesWorkflow(t *testing.T) {
	configLock.Lock()
	config.ClientRules = []ClientRule{}
	config.CustomBlocked = []string{}
	config.CustomAllowed = []string{}
	configLock.Unlock()

	// 1. Add client rule via handleRuleAdd
	body, _ := json.Marshal(map[string]string{
		"domain":    "special.tracker.com",
		"type":      "block",
		"client_ip": "192.168.1.200",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/rules/add", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	handleRuleAdd(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	configLock.RLock()
	if len(config.ClientRules) != 1 {
		t.Fatalf("expected 1 client rule, got %d", len(config.ClientRules))
	}
	cr := config.ClientRules[0]
	if cr.Domain != "special.tracker.com" || cr.ClientIP != "192.168.1.200" || cr.IsAllowlist {
		t.Errorf("unexpected client rule: %+v", cr)
	}
	configLock.RUnlock()

	// 2. Query search for that client IP
	searchReq := httptest.NewRequest(http.MethodGet, "/api/search?q=special.tracker.com&client_ip=192.168.1.200", nil)
	searchRR := httptest.NewRecorder()
	handleSearch(searchRR, searchReq)

	if searchRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from search, got %d", searchRR.Code)
	}
	var searchResp map[string]interface{}
	json.NewDecoder(searchRR.Body).Decode(&searchResp)
	if searchResp["blocked"] != true || searchResp["client_rule"] != "blocked" {
		t.Errorf("expected blocked by client rule, got %+v", searchResp)
	}

	// 3. Remove client rule
	delBody, _ := json.Marshal(map[string]string{
		"domain":    "special.tracker.com",
		"client_ip": "192.168.1.200",
	})
	delReq := httptest.NewRequest(http.MethodPost, "/api/rules/remove", bytes.NewBuffer(delBody))
	delRR := httptest.NewRecorder()
	handleRuleRemove(delRR, delReq)

	if delRR.Code != http.StatusOK {
		t.Fatalf("expected 200 from delete, got %d", delRR.Code)
	}

	configLock.RLock()
	if len(config.ClientRules) != 0 {
		t.Errorf("expected 0 client rules after removal, got %d", len(config.ClientRules))
	}
	configLock.RUnlock()
}

func TestLocalPTRUpstreamsCorefile(t *testing.T) {
	cfg := &Config{
		LocalPTRUpstreams: []string{"192.168.178.1", "192.168.1.1:53"},
	}
	blocks := getRoutingZoneBlocks(cfg, "53", "853", "5553", false, "", "")

	if !strings.Contains(blocks, "in-addr.arpa:53 {") {
		t.Error("expected in-addr.arpa zone in Corefile blocks")
	}
	if !strings.Contains(blocks, "ip6.arpa:53 {") {
		t.Error("expected ip6.arpa zone in Corefile blocks")
	}
	if !strings.Contains(blocks, "192.168.178.1:53 192.168.1.1:53") {
		t.Errorf("expected PTR upstreams in forward block, got: %s", blocks)
	}
}
