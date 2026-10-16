package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSendSecurityWebhook(t *testing.T) {
	var callCount atomic.Int32
	var lastPayload WebhookPayload
	var lastAuthHeader string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		lastAuthHeader = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&lastPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	configLock.Lock()
	origURL := config.WebhookURL
	origToken := config.WebhookToken
	origEnabled := config.WebhookEnabled
	origNode := config.ClusterNodeName

	config.WebhookURL = server.URL
	config.WebhookToken = "test-token-123"
	config.WebhookEnabled = true
	config.ClusterNodeName = "test-node"
	configLock.Unlock()

	defer func() {
		configLock.Lock()
		config.WebhookURL = origURL
		config.WebhookToken = origToken
		config.WebhookEnabled = origEnabled
		config.ClusterNodeName = origNode
		configLock.Unlock()
	}()

	// Send initial webhook
	SendSecurityWebhook("test_event", "Test Alert", map[string]interface{}{
		"client_ip": "1.2.3.4",
		"reason":    "testing",
	})

	time.Sleep(150 * time.Millisecond)

	if callCount.Load() != 1 {
		t.Fatalf("expected 1 webhook call, got %d", callCount.Load())
	}
	if lastAuthHeader != "Bearer test-token-123" {
		t.Errorf("expected Bearer test-token-123, got %s", lastAuthHeader)
	}
	if lastPayload.Event != "test_event" {
		t.Errorf("expected test_event, got %s", lastPayload.Event)
	}
	if lastPayload.Node != "test-node" {
		t.Errorf("expected test-node, got %s", lastPayload.Node)
	}

	// Immediate duplicate call should be debounced
	SendSecurityWebhook("test_event", "Test Alert", map[string]interface{}{
		"client_ip": "1.2.3.4",
	})

	time.Sleep(100 * time.Millisecond)

	if callCount.Load() != 1 {
		t.Fatalf("expected call count to remain 1 due to debounce, got %d", callCount.Load())
	}

	// Different event or target should NOT be debounced
	SendSecurityWebhook("test_event", "Test Alert", map[string]interface{}{
		"client_ip": "5.6.7.8",
	})

	time.Sleep(150 * time.Millisecond)

	if callCount.Load() != 2 {
		t.Fatalf("expected 2 calls after different IP, got %d", callCount.Load())
	}
}
