// Category: Client Blocking Tests
// Tests for blocking/unblocking individual client IPs, preventing config state loss,
// and merging client blocks into GeoIP ACL boundaries.
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleClientBlock covers the full lifecycle of the client IP blocking feature:
// listing blocked clients, blocking an IP, unblocking it, and edge-case handling.
func TestHandleClientBlock(t *testing.T) {
	// --- Setup ---
	configLock.Lock()
	config = Config{
		BlockedClients: []string{"10.0.0.5"},
	}
	configLock.Unlock()

	t.Run("GET returns current blocked list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/client/block", nil)
		rr := httptest.NewRecorder()

		handleClientBlock(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("GET: expected 200, got %v", rr.Code)
		}

		var clients map[string]BlockedClientInfo
		if err := json.NewDecoder(rr.Body).Decode(&clients); err != nil {
			t.Fatalf("GET: failed to decode response: %v", err)
		}
		if len(clients) != 1 || clients["10.0.0.5"].Reason == "" {
			t.Errorf("GET: expected map with [10.0.0.5], got %v", clients)
		}
	})

	t.Run("Block a new IP", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"ip": "192.168.1.100", "action": "block"})
		req := httptest.NewRequest(http.MethodPost, "/api/client/block", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handleClientBlock(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("block: expected 200, got %v", rr.Code)
		}

		configLock.RLock()
		found := false
		for _, c := range config.BlockedClients {
			if c == "192.168.1.100" {
				found = true
				break
			}
		}
		configLock.RUnlock()

		if !found {
			t.Error("block: 192.168.1.100 should be in BlockedClients after blocking")
		}
	})

	t.Run("Blocking same IP twice is idempotent", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"ip": "192.168.1.100", "action": "block"})
		req := httptest.NewRequest(http.MethodPost, "/api/client/block", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handleClientBlock(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("idempotent block: expected 200, got %v", rr.Code)
		}

		configLock.RLock()
		count := 0
		for _, c := range config.BlockedClients {
			if c == "192.168.1.100" {
				count++
			}
		}
		configLock.RUnlock()

		if count != 1 {
			t.Errorf("idempotent block: expected 192.168.1.100 to appear exactly once, got %d occurrences", count)
		}
	})

	t.Run("Unblock an IP", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"ip": "10.0.0.5", "action": "unblock"})
		req := httptest.NewRequest(http.MethodPost, "/api/client/block", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handleClientBlock(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("unblock: expected 200, got %v", rr.Code)
		}

		configLock.RLock()
		for _, c := range config.BlockedClients {
			if c == "10.0.0.5" {
				configLock.RUnlock()
				t.Error("unblock: 10.0.0.5 should have been removed from BlockedClients")
				return
			}
		}
		configLock.RUnlock()
	})

	t.Run("Unblocking a non-blocked IP is safe (no-op)", func(t *testing.T) {
		configLock.RLock()
		before := len(config.BlockedClients)
		configLock.RUnlock()

		body, _ := json.Marshal(map[string]string{"ip": "9.9.9.9", "action": "unblock"})
		req := httptest.NewRequest(http.MethodPost, "/api/client/block", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handleClientBlock(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("safe unblock: expected 200, got %v", rr.Code)
		}

		configLock.RLock()
		after := len(config.BlockedClients)
		configLock.RUnlock()

		if after != before {
			t.Errorf("safe unblock: list length changed unexpectedly (%d -> %d)", before, after)
		}
	})

	t.Run("Empty IP is rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]string{"ip": "", "action": "block"})
		req := httptest.NewRequest(http.MethodPost, "/api/client/block", bytes.NewBuffer(body))
		rr := httptest.NewRecorder()

		handleClientBlock(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("empty IP: expected 400, got %v", rr.Code)
		}
	})

	t.Run("Method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/client/block", nil)
		rr := httptest.NewRecorder()

		handleClientBlock(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE: expected 405, got %v", rr.Code)
		}
	})

	t.Run("Invalid JSON body is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/client/block", bytes.NewBufferString("not json {{"))
		rr := httptest.NewRecorder()

		handleClientBlock(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("invalid JSON: expected 400, got %v", rr.Code)
		}
	})
}

// TestBlockedClientsPreservedInConfigUpdate verifies that saving config via
// /api/config does not accidentally clear BlockedClients.
func TestBlockedClientsPreservedInConfigUpdate(t *testing.T) {
	configLock.Lock()
	config.AdminPasswordHashed = "existing-hash"
	config.BlockedClients = []string{"10.10.10.10"}
	configLock.Unlock()

	// Send a partial config update that does NOT include blocked_clients
	configLock.RLock()
	snap := config.Clone()
	configLock.RUnlock()

	snap.BlockedClients = nil // simulate a UI that doesn't send this field
	body, _ := json.Marshal(snap)

	req := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()

	handleConfig(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %v", rr.Code)
	}

	configLock.RLock()
	defer configLock.RUnlock()
	if len(config.BlockedClients) == 0 || config.BlockedClients[0] != "10.10.10.10" {
		t.Errorf("BlockedClients should be preserved after config save, got: %v", config.BlockedClients)
	}
}

// TestGetGeoACLRulesIncludesBlockedClients verifies that manually blocked client IPs
// are included in the CoreDNS ACL rule output alongside geo-blocked countries.
func TestGetGeoACLRulesIncludesBlockedClients(t *testing.T) {
	configLock.Lock()
	config = Config{
		BlockedCountries: []string{}, // no country blocks
		BlockedClients:   []string{"1.2.3.4", "10.20.30.40"},
	}
	configLock.Unlock()

	rules := getGeoACLRules()

	if rules == "" {
		t.Fatal("expected ACL rules to be non-empty when BlockedClients is set")
	}
	if !strings.Contains(rules, "1.2.3.4") {
		t.Error("ACL rules should contain blocked client IP 1.2.3.4")
	}
	if !strings.Contains(rules, "10.20.30.40") {
		t.Error("ACL rules should contain blocked client IP 10.20.30.40")
	}
}
