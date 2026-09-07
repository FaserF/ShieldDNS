package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

var allMCPTools []mcpToolDefinition

func init() {
	allMCPTools = append(allMCPTools, mcpMonitoringTools...)
	allMCPTools = append(allMCPTools, mcpFilteringTools...)
	allMCPTools = append(allMCPTools, mcpRulesTools...)
	allMCPTools = append(allMCPTools, mcpSystemTools...)
	allMCPTools = append(allMCPTools, mcpAdminTools...)
	allMCPTools = append(allMCPTools, mcpClusterTools...)
}
// getActiveAPIKey extracts and verifies the APIKey for MCP requests
func getActiveAPIKey(r *http.Request) *APIKey {
	token := r.Header.Get("X-API-Key")
	if token == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		return nil
	}

	hashed := hashToken(token)
	configLock.RLock()
	defer configLock.RUnlock()

	for _, k := range config.APIKeys {
		if k.TokenHash == hashed {
			return &k
		}
	}
	return nil
}

// handleMCP handles the /api/mcp endpoint (Streamable JSON-RPC 2.0 / SSE / HTTP POST)
func handleMCP(w http.ResponseWriter, r *http.Request) {
	// 1. Check if MCP server is enabled in settings
	configLock.RLock()
	mcpEnabled := config.MCPServerEnabled
	configLock.RUnlock()

	if !mcpEnabled {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "MCP Server is disabled in ShieldDNS Settings. Enable it in Admin Settings -> Model Context Protocol (MCP).",
			"code":    "MCP_DISABLED",
			"enabled": false,
		})
		return
	}

	// 2. Validate API Key & MCP execution permission
	apiKey := getActiveAPIKey(r)
	if apiKey == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Unauthorized: Valid API Token required via ?token=<TOKEN>, X-API-Key, or Authorization header",
			"code":  "UNAUTHORIZED",
		})
		return
	}

	if !hasPermission(apiKey, "exec:mcp") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Forbidden: API Token lacks 'exec:mcp' (or 'admin:all') permission required for MCP execution",
			"code":  "FORBIDDEN",
		})
		return
	}

	// Handle GET requests (Protocol info or SSE transport)
	if r.Method == http.MethodGet {
		acceptHeader := r.Header.Get("Accept")
		if strings.Contains(acceptHeader, "text/event-stream") {
			// SSE Transport for MCP
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.Header().Set("Access-Control-Allow-Origin", "*")

			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
				return
			}

			// Send endpoint event with session URL
			postURL := r.URL.Path
			if q := r.URL.RawQuery; q != "" {
				postURL += "?" + q
			}
			fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", postURL)
			flusher.Flush()

			// Keep connection open until context ends
			<-r.Context().Done()
			return
		}

		// Plain GET info response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name":        "ShieldDNS MCP Server",
			"version":     FullVersion,
			"protocol":    "mcp",
			"status":      "ready",
			"tools_count": len(allMCPTools),
			"token_name":  apiKey.Name,
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req mcpRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(mcpResponse{
			JSONRPC: "2.0",
			Error: &mcpError{
				Code:    -32700,
				Message: "Parse error: " + err.Error(),
			},
		})
		return
	}

	res := handleMCPMethod(apiKey, req)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// handleMCPMethod routes the JSON-RPC request to the appropriate MCP handler
func handleMCPMethod(apiKey *APIKey, req mcpRequest) mcpResponse {
	resp := mcpResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]interface{}{
				"name":    "shielddns-mcp",
				"version": FullVersion,
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{
					"listChanged": false,
				},
				"resources": map[string]interface{}{
					"subscribe":   false,
					"listChanged": false,
				},
				"prompts": map[string]interface{}{
					"listChanged": false,
				},
			},
		}

	case "notifications/initialized", "initialized":
		// Standard MCP notification acknowledgment
		resp.Result = map[string]interface{}{}

	case "ping":
		resp.Result = map[string]interface{}{}

	case "tools/list":
		// Return only tools for which this API token has permission
		availableTools := make([]mcpTool, 0)
		for _, item := range allMCPTools {
			if hasPermission(apiKey, item.requiredPerm) {
				availableTools = append(availableTools, item.tool)
			}
		}
		resp.Result = map[string]interface{}{
			"tools": availableTools,
		}

	case "tools/call":
		var params struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &mcpError{
				Code:    -32602,
				Message: "Invalid params: " + err.Error(),
			}
			return resp
		}

		// Find tool
		var targetTool *mcpToolDefinition
		for i := range allMCPTools {
			if allMCPTools[i].tool.Name == params.Name {
				targetTool = &allMCPTools[i]
				break
			}
		}

			if targetTool == nil {
			resp.Error = &mcpError{
				Code:    -32601,
				Message: fmt.Sprintf("Tool not found: %s", params.Name),
			}
			return resp
		}

		// Check tool-specific permission
		if !hasPermission(apiKey, targetTool.requiredPerm) {
			resp.Result = mcpToolResult{
				IsError: true,
				Content: []mcpContent{
					{
						Type: "text",
						Text: fmt.Sprintf("Permission Denied: API token '%s' requires permission '%s' to execute '%s'", apiKey.Name, targetTool.requiredPerm, params.Name),
					},
				},
			}
			return resp
		}

		// Execute tool
		if params.Arguments == nil {
			params.Arguments = make(map[string]interface{})
		}
		out, err := targetTool.actionHandler(apiKey, params.Arguments)
		if err != nil {
			resp.Result = mcpToolResult{
				IsError: true,
				Content: []mcpContent{
					{
						Type: "text",
						Text: fmt.Sprintf("Error executing %s: %v", params.Name, err),
					},
				},
			}
			return resp
		}

		outJSON, _ := json.MarshalIndent(out, "", "  ")
		resp.Result = mcpToolResult{
			Content: []mcpContent{
				{
					Type: "text",
					Text: string(outJSON),
				},
			},
		}

	case "resources/list":
		resp.Result = map[string]interface{}{
			"resources": allMCPResources,
		}

	case "resources/read":
		var params struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &mcpError{
				Code:    -32602,
				Message: "Invalid params: " + err.Error(),
			}
			return resp
		}

		switch params.URI {
		case "shielddns://logs/system":
			if !hasPermission(apiKey, "read:system") {
				resp.Error = &mcpError{Code: -32003, Message: "Permission denied: requires read:system"}
				return resp
			}
			systemLogLock.RLock()
			text := strings.Join(systemLogBuffer, "\n")
			systemLogLock.RUnlock()
			resp.Result = map[string]interface{}{
				"contents": []map[string]interface{}{
					{
						"uri":      params.URI,
						"mimeType": "text/plain",
						"text":     text,
					},
				},
			}

		case "shielddns://stats/summary":
			if !hasPermission(apiKey, "read:stats") {
				resp.Error = &mcpError{Code: -32003, Message: "Permission denied: requires read:stats"}
				return resp
			}
			statsLock.RLock()
			s := stats
			statsLock.RUnlock()
			data, _ := json.MarshalIndent(s, "", "  ")
			resp.Result = map[string]interface{}{
				"contents": []map[string]interface{}{
					{
						"uri":      params.URI,
						"mimeType": "application/json",
						"text":     string(data),
					},
				},
			}

		case "shielddns://config/current":
			if !hasPermission(apiKey, "read:config") {
				resp.Error = &mcpError{Code: -32003, Message: "Permission denied: requires read:config"}
				return resp
			}
			configLock.RLock()
			cfg := config.SanitizedCopy()
			configLock.RUnlock()
			data, _ := json.MarshalIndent(cfg, "", "  ")
			resp.Result = map[string]interface{}{
				"contents": []map[string]interface{}{
					{
						"uri":      params.URI,
						"mimeType": "application/json",
						"text":     string(data),
					},
				},
			}

		case "shielddns://cluster/topology":
			if !hasPermission(apiKey, "read:config") {
				resp.Error = &mcpError{Code: -32003, Message: "Permission denied: requires read:config"}
				return resp
			}
			configLock.RLock()
			clusterInfo := map[string]interface{}{
				"role":             config.ClusterRole,
				"instance_type":    config.ClusterInstanceType,
				"node_name":        config.ClusterNodeName,
				"log_sharing_mode": config.ClusterLogSharingMode,
				"primary_url":      config.ClusterPrimaryURL,
				"sync_interval":    config.ClusterSyncInterval,
				"failover_mode":    config.ClusterFailoverMode,
				"last_sync":        config.ClusterLastSync,
				"replicas":         config.ClusterReplicas,
			}
			configLock.RUnlock()
			data, _ := json.MarshalIndent(clusterInfo, "", "  ")
			resp.Result = map[string]interface{}{
				"contents": []map[string]interface{}{
					{
						"uri":      params.URI,
						"mimeType": "application/json",
						"text":     string(data),
					},
				},
			}

		default:
			resp.Error = &mcpError{
				Code:    -32602,
				Message: fmt.Sprintf("Resource not found: %s", params.URI),
			}
		}

	case "prompts/list":
		resp.Result = map[string]interface{}{
			"prompts": allMCPPrompts,
		}

	case "prompts/get":
		var params struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = &mcpError{
				Code:    -32602,
				Message: "Invalid params: " + err.Error(),
			}
			return resp
		}

		promptText := ""
		switch params.Name {
		case "diagnose-network-issues":
			promptText = "Perform a thorough diagnosis of the ShieldDNS appliance: check get_system_diagnostics for upstream server latency, inspect get_stats for query failure ratios, and check get_system_logs for warning/error logs."
		case "security-audit":
			promptText = "Perform a complete security audit on ShieldDNS: check get_geo_block_status for blocked countries, get_top_statistics for suspicious top querying clients or DGA attempts, and inspect blocked clients."
		case "optimize-dns-performance":
			promptText = "Review current DNS performance in ShieldDNS: analyze get_stats (cache hit ratio, avg latency, QPS), get_system_diagnostics for upstream health, and suggest optimal smart selection policies and DoT configurations."
		case "audit-cluster-federation":
			promptText = "Audit ShieldDNS multi-node cluster federation: use get_cluster_status and diagnose_cluster to evaluate master/replica topology, profile constraints (private/public/hybrid), log sharing consistency, and upstream failover health."
		default:
			resp.Error = &mcpError{
				Code:    -32602,
				Message: fmt.Sprintf("Prompt not found: %s", params.Name),
			}
			return resp
		}

		resp.Result = map[string]interface{}{
			"description": params.Name,
			"messages": []map[string]interface{}{
				{
					"role": "user",
					"content": map[string]interface{}{
						"type": "text",
						"text": promptText,
					},
				},
			},
		}

	default:
		resp.Error = &mcpError{
			Code:    -32601,
			Message: fmt.Sprintf("Method not supported: %s", req.Method),
		}
	}

	return resp
}
