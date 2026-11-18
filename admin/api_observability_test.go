package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestObservability_FlowLatencySLOAndPrivacy(t *testing.T) {
	// Test Privacy Levels 0..3
	q := Query{Domain: "secret.internal.lan", ClientIP: "192.168.10.42", ClientAlias: "Laptop"}
	if keep := ApplyPrivacyLevel(&q, 1, "192.168.10.42"); !keep {
		t.Fatalf("privacy level 1 should keep query")
	}
	if !strings.HasPrefix(q.Domain, "h-") || !strings.HasSuffix(q.Domain, ".redacted") || q.ClientAlias != "" {
		t.Fatalf("unexpected level 1 redaction: %+v", q)
	}

	q2 := Query{Domain: "secret.internal.lan", ClientIP: "192.168.10.42"}
	if keep := ApplyPrivacyLevel(&q2, 2, "192.168.10.42"); !keep || q2.Domain != "redacted" || q2.ClientIP != "redacted" {
		t.Fatalf("unexpected level 2 redaction: %+v", q2)
	}

	if keep := ApplyPrivacyLevel(&q2, 3, "192.168.10.42"); keep {
		t.Fatalf("privacy level 3 should drop per-query row")
	}

	// Test Flow, Latency Heatmap & SLO
	RecordFlowAndSLO("kids", "blocked", "local", "NOERROR", 0.2)
	RecordFlowAndSLO("default", "forward", "1.1.1.1", "SERVFAIL", 120.0)
	RecordSLOOffender("192.168.10.42", "slow.example.com")

	req := httptest.NewRequest(http.MethodGet, "/api/stats/flow", nil)
	rec := httptest.NewRecorder()
	handleStatsFlow(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "group:kids") {
		t.Fatalf("unexpected /api/stats/flow response: %d %s", rec.Code, rec.Body.String())
	}

	reqSLO := httptest.NewRequest(http.MethodGet, "/api/stats/slo", nil)
	recSLO := httptest.NewRecorder()
	handleStatsSLO(recSLO, reqSLO)
	if recSLO.Code != http.StatusOK || !strings.Contains(recSLO.Body.String(), "burn_rate") {
		t.Fatalf("unexpected /api/stats/slo response: %d %s", recSLO.Code, recSLO.Body.String())
	}

	// Test Maintenance Mode 503 on /api/health
	configLock.Lock()
	origMaint := config.MaintenanceMode
	origReason := config.MaintenanceReason
	config.MaintenanceMode = true
	config.MaintenanceReason = "Kernel upgrade"
	configLock.Unlock()
	defer func() {
		configLock.Lock()
		config.MaintenanceMode = origMaint
		config.MaintenanceReason = origReason
		configLock.Unlock()
	}()

	reqH := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	recH := httptest.NewRecorder()
	handleHealth(recH, reqH)
	if recH.Code != http.StatusServiceUnavailable || !strings.Contains(recH.Body.String(), "maintenance") {
		t.Fatalf("expected 503 maintenance from /api/health, got %d %s", recH.Code, recH.Body.String())
	}

	_ = time.Now()
}
