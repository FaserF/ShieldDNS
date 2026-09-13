package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// handleDNSProbeNew
// ---------------------------------------------------------------------------

func TestHandleDNSProbeNew_ReturnsToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/public/dns-probe-new", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	rr := httptest.NewRecorder()

	handleDNSProbeNew(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if body["id"] == "" {
		t.Error("expected non-empty id")
	}
	if body["probe_domain"] == "" {
		t.Error("expected non-empty probe_domain")
	}
	// Token must be stored in the probe store
	if _, ok := testProbeStore.Load(body["id"]); !ok {
		t.Error("token was not stored in testProbeStore")
	}
}

func TestHandleDNSProbeNew_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/public/dns-probe-new", nil)
	rr := httptest.NewRecorder()
	handleDNSProbeNew(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// handleDNSProbeStatus
// ---------------------------------------------------------------------------

func TestHandleDNSProbeStatus_UnknownToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/public/dns-probe-status?id=doesnotexist", nil)
	rr := httptest.NewRecorder()
	handleDNSProbeStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)
	if body["found"] != false {
		t.Errorf("expected found=false, got %v", body["found"])
	}
}

func TestHandleDNSProbeStatus_KnownToken(t *testing.T) {
	// Pre-populate the store
	token := "test-status-token-abc123"
	testProbeStore.Store(token, &probeEntry{
		CreatedAt: time.Now(),
		Protocol:  "doh",
		Seen:      true,
		LatencyMs: 12.5,
	})
	defer testProbeStore.Delete(token)

	req := httptest.NewRequest(http.MethodGet, "/api/public/dns-probe-status?id="+token, nil)
	rr := httptest.NewRecorder()
	handleDNSProbeStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var body map[string]any
	json.NewDecoder(rr.Body).Decode(&body)
	if body["found"] != true {
		t.Errorf("expected found=true, got %v", body["found"])
	}
	if body["seen"] != true {
		t.Errorf("expected seen=true, got %v", body["seen"])
	}
	if body["protocol"] != "doh" {
		t.Errorf("expected protocol=doh, got %v", body["protocol"])
	}
}

func TestHandleDNSProbeStatus_EmptyID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/public/dns-probe-status", nil)
	rr := httptest.NewRecorder()
	handleDNSProbeStatus(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// handlePublicTestInfo
// ---------------------------------------------------------------------------

func TestHandlePublicTestInfo_ReturnsJSON(t *testing.T) {
	// Set some config fields
	configLock.Lock()
	config.FilteringEnabled = true
	config.StripECS = true
	config.DNSSECEnabled = false
	config.ClusterNodeName = "test-node"
	config.ClusterRole = "standalone"
	configLock.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/public/test-info", nil)
	rr := httptest.NewRecorder()
	handlePublicTestInfo(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("expected application/json, got %s", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}

	requiredFields := []string{
		"filter_active", "strip_ecs", "dnssec_enabled",
		"node_name", "cluster_role", "protocols",
	}
	for _, f := range requiredFields {
		if _, ok := body[f]; !ok {
			t.Errorf("missing field: %s", f)
		}
	}
	if body["filter_active"] != true {
		t.Errorf("expected filter_active=true")
	}
	if body["strip_ecs"] != true {
		t.Errorf("expected strip_ecs=true")
	}
	if body["node_name"] != "test-node" {
		t.Errorf("expected node_name=test-node, got %v", body["node_name"])
	}
}

func TestHandlePublicTestInfo_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/public/test-info", nil)
	rr := httptest.NewRecorder()
	handlePublicTestInfo(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// markProbeSeen
// ---------------------------------------------------------------------------

func TestMarkProbeSeen_UpdatesEntry(t *testing.T) {
	token := "mark-seen-test-token"
	entry := &probeEntry{
		CreatedAt: time.Now(),
		Protocol:  "unknown",
	}
	testProbeStore.Store(token, entry)
	defer testProbeStore.Delete(token)

	markProbeSeen(token, "dot", 8.3)

	if !entry.Seen {
		t.Error("expected entry.Seen=true")
	}
	if entry.Protocol != "dot" {
		t.Errorf("expected protocol=dot, got %s", entry.Protocol)
	}
	if entry.LatencyMs != 8.3 {
		t.Errorf("expected latency=8.3, got %f", entry.LatencyMs)
	}
}

func TestMarkProbeSeen_UnknownToken_NoPanic(t *testing.T) {
	// Should not panic
	markProbeSeen("nonexistent-token-xyz", "doh", 5.0)
}

// ---------------------------------------------------------------------------
// cleanupProbes
// ---------------------------------------------------------------------------

func TestCleanupProbes_RemovesExpiredEntries(t *testing.T) {
	token := "cleanup-test-expired"
	testProbeStore.Store(token, &probeEntry{
		CreatedAt: time.Now().Add(-10 * time.Minute), // expired
	})
	cleanupProbes()
	if _, ok := testProbeStore.Load(token); ok {
		t.Error("expired probe was not cleaned up")
	}
}

func TestCleanupProbes_KeepsFreshEntries(t *testing.T) {
	token := "cleanup-test-fresh"
	testProbeStore.Store(token, &probeEntry{
		CreatedAt: time.Now(), // fresh
	})
	defer testProbeStore.Delete(token)

	cleanupProbes()

	if _, ok := testProbeStore.Load(token); !ok {
		t.Error("fresh probe was incorrectly removed")
	}
}
