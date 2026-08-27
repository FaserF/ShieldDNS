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
			Permissions: []string{"exec:mcp", "read:stats", "write:rules", "read:logs", "read:diagnostics", "read:config", "write:config", "write:maintenance", "read:system"},
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
}
