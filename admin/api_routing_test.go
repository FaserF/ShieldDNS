package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleRoutingRules(t *testing.T) {
	configLock.Lock()
	config.AdminPasswordHashed = "test-hash"
	config.RoutingRules = []RoutingRule{
		{
			ID:         "rule-1",
			Name:       "Test Internal",
			Match:      "internal.corp",
			MatchType:  "domain",
			Target:     "host",
			HostTarget: "192.168.1.53",
			Enabled:    true,
		},
	}
	config.WireGuardGateway = "10.0.0.1:53"
	configLock.Unlock()

	// 1. GET routing rules
	reqGet := httptest.NewRequest(http.MethodGet, "/api/routing/rules", nil)
	rrGet := httptest.NewRecorder()
	handleRoutingRules(rrGet, reqGet)

	if rrGet.Code != http.StatusOK {
		t.Fatalf("GET /api/routing/rules expected 200, got %d", rrGet.Code)
	}

	var getResp struct {
		Rules            []RoutingRule `json:"rules"`
		WireGuardGateway string        `json:"wireguard_gateway"`
	}
	if err := json.NewDecoder(rrGet.Body).Decode(&getResp); err != nil {
		t.Fatalf("Failed to decode GET response: %v", err)
	}
	if len(getResp.Rules) != 1 || getResp.Rules[0].Match != "internal.corp" {
		t.Errorf("Unexpected rules in GET: %+v", getResp.Rules)
	}
	if getResp.WireGuardGateway != "10.0.0.1:53" {
		t.Errorf("Expected WireGuardGateway 10.0.0.1:53, got %s", getResp.WireGuardGateway)
	}

	// 2. POST add wireguard routing rule
	postPayload := map[string]interface{}{
		"name":             "VPN Route",
		"match":            "vpn.secure.net",
		"match_type":       "domain",
		"target":           "wireguard",
		"wireguard_config": "10.100.0.1:53",
		"enabled":          true,
	}
	b, _ := json.Marshal(postPayload)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewReader(b))
	rrPost := httptest.NewRecorder()
	handleRoutingRules(rrPost, reqPost)

	if rrPost.Code != http.StatusOK {
		t.Fatalf("POST /api/routing/rules expected 200, got %d (body: %s)", rrPost.Code, rrPost.Body.String())
	}

	configLock.RLock()
	foundVPN := false
	for _, r := range config.RoutingRules {
		if r.Match == "vpn.secure.net" && r.Target == "wireguard" {
			foundVPN = true
			break
		}
	}
	configLock.RUnlock()

	if !foundVPN {
		t.Error("Expected vpn.secure.net rule to be added to config.RoutingRules")
	}

	// 3. DELETE routing rule
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/routing/rules?match=internal.corp", nil)
	rrDel := httptest.NewRecorder()
	handleRoutingRules(rrDel, reqDel)

	if rrDel.Code != http.StatusOK {
		t.Fatalf("DELETE /api/routing/rules expected 200, got %d", rrDel.Code)
	}

	configLock.RLock()
	for _, r := range config.RoutingRules {
		if r.Match == "internal.corp" {
			t.Error("Rule internal.corp should have been deleted")
		}
	}
	configLock.RUnlock()
}

func TestGetRoutingZoneBlocks(t *testing.T) {
	cfg := &Config{
		DNSSECEnabled:    true,
		FilteringEnabled: true,
		WireGuardGateway: "10.0.0.1:53",
		RoutingRules: []RoutingRule{
			{
				ID:         "r1",
				Match:      "corp.internal",
				MatchType:  "domain",
				Target:     "host",
				HostTarget: "192.168.10.1:53",
				Enabled:    true,
			},
			{
				ID:              "r2",
				Match:           "vpn.service",
				MatchType:       "domain",
				Target:          "wireguard",
				WireGuardConfig: "10.200.0.1:53",
				Enabled:         true,
			},
		},
	}

	blocks := getRoutingZoneBlocks(cfg, "53", "853", "5553", true, "/ssl/cert.pem", "/ssl/key.pem")

	if !strings.Contains(blocks, "corp.internal:53 {") {
		t.Errorf("Expected corp.internal zone block, got: %s", blocks)
	}
	if !strings.Contains(blocks, "forward . 192.168.10.1:53") {
		t.Errorf("Expected host forward upstream in block, got: %s", blocks)
	}
	if !strings.Contains(blocks, "vpn.service:53 {") {
		t.Errorf("Expected vpn.service zone block, got: %s", blocks)
	}
	if !strings.Contains(blocks, "forward . 10.200.0.1:53") {
		t.Errorf("Expected wireguard forward upstream in block, got: %s", blocks)
	}
	if !strings.Contains(blocks, "tls://corp.internal:853 {") {
		t.Errorf("Expected DoT block for corp.internal, got: %s", blocks)
	}
}
