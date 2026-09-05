package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupMCPTestEnvironment() {
	configLock.Lock()
	defer configLock.Unlock()

	config.MCPServerEnabled = true
	config.APIKeys = []APIKey{
		{
			ID:          "mcp-full-id",
			Name:        "MCP Admin Token",
			TokenHash:   hashToken("mcp-secret-token"),
			Permissions: []string{"exec:mcp", "read:stats", "read:rules", "write:rules", "read:logs", "read:diagnostics", "read:config", "write:config", "write:maintenance", "read:system", "read:health", "admin:all"},
		},
		{
			ID:          "mcp-readonly-id",
			Name:        "MCP ReadOnly Token",
			TokenHash:   hashToken("mcp-read-token"),
			Permissions: []string{"exec:mcp", "read:stats"},
		},
		{
			ID:          "no-mcp-perm-id",
			Name:        "No MCP Perm Token",
			TokenHash:   hashToken("no-mcp-token"),
			Permissions: []string{"read:stats", "write:rules"},
		},
	}
	config.CustomBlocked = []string{"ads.example.com"}
	config.CustomAllowed = []string{"safe.example.com"}
}

func TestMCPDisabledByDefault(t *testing.T) {
	setupMCPTestEnvironment()
	configLock.Lock()
	config.MCPServerEnabled = false
	configLock.Unlock()

	req := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	rr := httptest.NewRecorder()

	handleMCP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503 for disabled MCP server, got %d", rr.Code)
	}
}

func TestMCPAuthentication(t *testing.T) {
	setupMCPTestEnvironment()

	tests := []struct {
		name       string
		url        string
		header     string
		wantStatus int
	}{
		{"No token", "/api/mcp", "", http.StatusUnauthorized},
		{"Invalid token in query", "/api/mcp?token=wrong-token", "", http.StatusUnauthorized},
		{"Token missing exec:mcp permission", "/api/mcp?token=no-mcp-token", "", http.StatusForbidden},
		{"Valid token in query param", "/api/mcp?token=mcp-secret-token", "", http.StatusOK},
		{"Valid token in X-API-Key header", "/api/mcp", "mcp-secret-token", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
			req := httptest.NewRequest("POST", tt.url, reqBody)
			if tt.header != "" {
				req.Header.Set("X-API-Key", tt.header)
			}
			rr := httptest.NewRecorder()

			handleMCP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestMCPInitializeAndToolsList(t *testing.T) {
	setupMCPTestEnvironment()

	// 1. Test initialize
	initReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	req := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", initReq)
	rr := httptest.NewRecorder()
	handleMCP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("initialize failed with status %d: %s", rr.Code, rr.Body.String())
	}

	var initResp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&initResp); err != nil {
		t.Fatalf("failed to decode initialize response: %v", err)
	}
	result, ok := initResp["result"].(map[string]interface{})
	if !ok || result["protocolVersion"] != "2024-11-05" {
		t.Errorf("unexpected initialize result: %v", initResp)
	}

	// 2. Test tools/list with full permissions
	toolsReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	req2 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", toolsReq)
	rr2 := httptest.NewRecorder()
	handleMCP(rr2, req2)

	var toolsResp struct {
		Result struct {
			Tools []mcpTool `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rr2.Body).Decode(&toolsResp); err != nil {
		t.Fatalf("failed to decode tools/list response: %v", err)
	}

	if len(toolsResp.Result.Tools) == 0 {
		t.Errorf("expected tools list to have entries, got 0")
	}

	// 3. Test tools/list with read-only token
	req3 := httptest.NewRequest("POST", "/api/mcp?token=mcp-read-token", bytes.NewBufferString(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`))
	rr3 := httptest.NewRecorder()
	handleMCP(rr3, req3)

	var roToolsResp struct {
		Result struct {
			Tools []mcpTool `json:"tools"`
		} `json:"result"`
	}
	json.NewDecoder(rr3.Body).Decode(&roToolsResp)
	for _, tool := range roToolsResp.Result.Tools {
		if tool.Name == "add_custom_rule" || tool.Name == "trigger_system_refresh" {
			t.Errorf("readonly token should not list write tool %s", tool.Name)
		}
	}
}

func TestMCPToolExecutionPermissions(t *testing.T) {
	setupMCPTestEnvironment()

	// 1. Call get_stats with valid read token -> Success
	statsReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"get_stats","arguments":{}}}`)
	req := httptest.NewRequest("POST", "/api/mcp?token=mcp-read-token", statsReq)
	rr := httptest.NewRecorder()
	handleMCP(rr, req)

	var toolResp struct {
		Result mcpToolResult `json:"result"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&toolResp); err != nil {
		t.Fatalf("failed to decode get_stats tool result: %v", err)
	}
	if toolResp.Result.IsError {
		t.Errorf("expected get_stats to succeed, got error: %v", toolResp.Result.Content)
	}

	// 2. Call add_custom_rule with read-only token -> Denied
	addRuleReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"add_custom_rule","arguments":{"type":"blocked","domain":"tracker.test"}}}`)
	req2 := httptest.NewRequest("POST", "/api/mcp?token=mcp-read-token", addRuleReq)
	rr2 := httptest.NewRecorder()
	handleMCP(rr2, req2)

	var deniedResp struct {
		Result mcpToolResult `json:"result"`
	}
	json.NewDecoder(rr2.Body).Decode(&deniedResp)
	if !deniedResp.Result.IsError {
		t.Errorf("expected add_custom_rule to be denied for read-only token")
	}

	// 3. Call add_custom_rule with full token -> Success
	req3 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", bytes.NewBufferString(`{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"add_custom_rule","arguments":{"type":"blocked","domain":"tracker.test"}}}`))
	rr3 := httptest.NewRecorder()
	handleMCP(rr3, req3)

	var successResp struct {
		Result mcpToolResult `json:"result"`
	}
	json.NewDecoder(rr3.Body).Decode(&successResp)
	if successResp.Result.IsError {
		t.Errorf("expected add_custom_rule to succeed for full token, got: %v", successResp.Result.Content)
	}

	// 4. Test get_help tool
	helpReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"get_help","arguments":{"topic":"all"}}}`)
	req4 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", helpReq)
	rr4 := httptest.NewRecorder()
	handleMCP(rr4, req4)

	var helpResp struct {
		Result mcpToolResult `json:"result"`
	}
	json.NewDecoder(rr4.Body).Decode(&helpResp)
	if helpResp.Result.IsError {
		t.Errorf("expected get_help to succeed, got: %v", helpResp.Result.Content)
	}

	// 5. Test get_catalog_presets
	presetsReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"get_catalog_presets","arguments":{}}}`)
	req5 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", presetsReq)
	rr5 := httptest.NewRecorder()
	handleMCP(rr5, req5)

	var presetsResp struct {
		Result mcpToolResult `json:"result"`
	}
	json.NewDecoder(rr5.Body).Decode(&presetsResp)
	if presetsResp.Result.IsError {
		t.Errorf("expected get_catalog_presets to succeed, got: %v", presetsResp.Result.Content)
	}

	// 6. Test get_blocked_clients
	bcReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"get_blocked_clients","arguments":{}}}`)
	req6 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", bcReq)
	rr6 := httptest.NewRecorder()
	handleMCP(rr6, req6)

	var bcResp struct {
		Result mcpToolResult `json:"result"`
	}
	json.NewDecoder(rr6.Body).Decode(&bcResp)
	if bcResp.Result.IsError {
		t.Errorf("expected get_blocked_clients to succeed, got: %v", bcResp.Result.Content)
	}

	// 7. Test optimize_security_profile
	optReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"optimize_security_profile","arguments":{"doh_rate_limit":60,"abuse_detection_enabled":true,"retention_days":14}}}`)
	req7 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", optReq)
	rr7 := httptest.NewRecorder()
	handleMCP(rr7, req7)

	var optResp struct {
		Result mcpToolResult `json:"result"`
	}
	json.NewDecoder(rr7.Body).Decode(&optResp)
	if optResp.Result.IsError {
		t.Errorf("expected optimize_security_profile to succeed, got: %v", optResp.Result.Content)
	}
}

func TestMCPClusterTools(t *testing.T) {
	setupMCPTestEnvironment()

	// 1. Test get_cluster_status via MCP
	statusReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"get_cluster_status","arguments":{}}}`)
	req1 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", statusReq)
	rr1 := httptest.NewRecorder()
	handleMCP(rr1, req1)

	var statusResp struct {
		Result mcpToolResult `json:"result"`
	}
	json.NewDecoder(rr1.Body).Decode(&statusResp)
	if statusResp.Result.IsError {
		t.Fatalf("expected get_cluster_status to succeed, got error: %v", statusResp.Result.Content)
	}

	// 2. Test diagnose_cluster via MCP
	diagReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"diagnose_cluster","arguments":{}}}`)
	req2 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", diagReq)
	rr2 := httptest.NewRecorder()
	handleMCP(rr2, req2)

	var diagResp struct {
		Result mcpToolResult `json:"result"`
	}
	json.NewDecoder(rr2.Body).Decode(&diagResp)
	if diagResp.Result.IsError {
		t.Fatalf("expected diagnose_cluster to succeed, got error: %v", diagResp.Result.Content)
	}

	// 3. Test update_cluster_settings via MCP
	updateReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":103,"method":"tools/call","params":{"name":"update_cluster_settings","arguments":{"role":"primary","instance_type":"hybrid","node_name":"MCP Test Master","log_sharing_mode":"full_sync"}}}`)
	req3 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", updateReq)
	rr3 := httptest.NewRecorder()
	handleMCP(rr3, req3)

	var updateResp struct {
		Result mcpToolResult `json:"result"`
	}
	json.NewDecoder(rr3.Body).Decode(&updateResp)
	if updateResp.Result.IsError {
		t.Fatalf("expected update_cluster_settings to succeed, got error: %v", updateResp.Result.Content)
	}

	configLock.RLock()
	role := config.ClusterRole
	instType := config.ClusterInstanceType
	nodeName := config.ClusterNodeName
	logMode := config.ClusterLogSharingMode
	configLock.RUnlock()

	if role != "primary" || instType != "hybrid" || nodeName != "MCP Test Master" || logMode != "full_sync" {
		t.Errorf("unexpected config after update_cluster_settings: role=%s, type=%s, name=%s, mode=%s", role, instType, nodeName, logMode)
	}

	// 4. Test MCP prompt audit-cluster-federation
	promptReq := bytes.NewBufferString(`{"jsonrpc":"2.0","id":104,"method":"prompts/get","params":{"name":"audit-cluster-federation"}}`)
	req4 := httptest.NewRequest("POST", "/api/mcp?token=mcp-secret-token", promptReq)
	rr4 := httptest.NewRecorder()
	handleMCP(rr4, req4)

	var promptResp struct {
		Result struct {
			Description string `json:"description"`
		} `json:"result"`
	}
	json.NewDecoder(rr4.Body).Decode(&promptResp)
	if promptResp.Result.Description != "audit-cluster-federation" {
		t.Errorf("expected prompt audit-cluster-federation, got %v", promptResp.Result.Description)
	}
}
