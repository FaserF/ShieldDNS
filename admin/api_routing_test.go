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

func TestRoutingRules_EdgeCases(t *testing.T) {
	// 1. Replica Node Forbidden (POST & DELETE)
	configLock.Lock()
	config.ClusterRole = "replica"
	configLock.Unlock()

	reqReplicaPOST := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{}`))
	rrReplicaPOST := httptest.NewRecorder()
	handleRoutingRules(rrReplicaPOST, reqReplicaPOST)
	if rrReplicaPOST.Code != http.StatusForbidden {
		t.Errorf("expected 403 for replica POST, got %d", rrReplicaPOST.Code)
	}

	reqReplicaDEL := httptest.NewRequest(http.MethodDelete, "/api/routing/rules?id=1", nil)
	rrReplicaDEL := httptest.NewRecorder()
	handleRoutingRules(rrReplicaDEL, reqReplicaDEL)
	if rrReplicaDEL.Code != http.StatusForbidden {
		t.Errorf("expected 403 for replica DELETE, got %d", rrReplicaDEL.Code)
	}

	configLock.Lock()
	config.ClusterRole = "primary" // restore
	configLock.Unlock()

	// 2. POST with Empty Match
	reqEmptyMatch := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": ""}`))
	rrEmptyMatch := httptest.NewRecorder()
	handleRoutingRules(rrEmptyMatch, reqEmptyMatch)
	if rrEmptyMatch.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for empty match, got %d", rrEmptyMatch.Code)
	}

	// 3. POST with Invalid matchType
	reqInvalidMatchType := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "example.com", "match_type": "invalid"}`))
	rrInvalidMatchType := httptest.NewRecorder()
	handleRoutingRules(rrInvalidMatchType, reqInvalidMatchType)
	if rrInvalidMatchType.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid match_type, got %d", rrInvalidMatchType.Code)
	}

	// 4. POST with Invalid Domain
	reqInvalidDomain := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "invalid!!domain", "match_type": "domain"}`))
	rrInvalidDomain := httptest.NewRecorder()
	handleRoutingRules(rrInvalidDomain, reqInvalidDomain)
	if rrInvalidDomain.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid domain, got %d", rrInvalidDomain.Code)
	}

	// 5. POST with Invalid IP
	reqInvalidIP := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "999.999.999.999", "match_type": "client_ip"}`))
	rrInvalidIP := httptest.NewRecorder()
	handleRoutingRules(rrInvalidIP, reqInvalidIP)
	if rrInvalidIP.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid IP, got %d", rrInvalidIP.Code)
	}

	// 6. POST with Invalid CIDR
	reqInvalidCIDR := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "192.168.1.0/99", "match_type": "client_ip"}`))
	rrInvalidCIDR := httptest.NewRecorder()
	handleRoutingRules(rrInvalidCIDR, reqInvalidCIDR)
	if rrInvalidCIDR.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid CIDR, got %d", rrInvalidCIDR.Code)
	}

	// 7. POST target=host but no host_target
	reqNoHostTarget := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "example.com", "match_type": "domain", "target": "host"}`))
	rrNoHostTarget := httptest.NewRecorder()
	handleRoutingRules(rrNoHostTarget, reqNoHostTarget)
	if rrNoHostTarget.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing host_target, got %d", rrNoHostTarget.Code)
	}

	// 8. DELETE with missing ID and Match
	reqMissingDel := httptest.NewRequest(http.MethodDelete, "/api/routing/rules", nil)
	rrMissingDel := httptest.NewRecorder()
	handleRoutingRules(rrMissingDel, reqMissingDel)
	if rrMissingDel.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing ID/match on delete, got %d", rrMissingDel.Code)
	}

	// 9. DELETE non-existent rule
	reqDel404 := httptest.NewRequest(http.MethodDelete, "/api/routing/rules?id=nonexistent", nil)
	rrDel404 := httptest.NewRecorder()
	handleRoutingRules(rrDel404, reqDel404)
	if rrDel404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent rule, got %d", rrDel404.Code)
	}
}
