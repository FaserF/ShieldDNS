package main

import (
	"encoding/json"
)

type mcpToolDefinition struct {
	tool          mcpTool
	requiredPerm  string
	actionHandler func(apiKey *APIKey, args map[string]interface{}) (interface{}, error)
}
type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *mcpError   `json:"error,omitempty"`
}

type mcpError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type mcpTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type mcpToolResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type mcpResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type mcpPrompt struct {
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Arguments   []mcpPromptArgument `json:"arguments,omitempty"`
}

type mcpPromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// All available MCP tools with their metadata and required specific permission
// Built-in MCP Resources
var allMCPResources = []mcpResource{
	{
		URI:         "shielddns://logs/system",
		Name:        "System Daemon Logs",
		Description: "Live system daemon and CoreDNS runtime logs",
		MimeType:    "text/plain",
	},
	{
		URI:         "shielddns://stats/summary",
		Name:        "DNS Summary Stats",
		Description: "Current DNS traffic, blocking ratio, and performance summary",
		MimeType:    "application/json",
	},
	{
		URI:         "shielddns://config/current",
		Name:        "System Configuration",
		Description: "Active sanitized configuration parameters of ShieldDNS",
		MimeType:    "application/json",
	},
	{
		URI:         "shielddns://cluster/topology",
		Name:        "Cluster Topology & Status",
		Description: "Multi-node federation topology, node roles, replication mode, and synchronization health",
		MimeType:    "application/json",
	},
}

// Built-in MCP Prompts
var allMCPPrompts = []mcpPrompt{
	{
		Name:        "diagnose-network-issues",
		Description: "Analyze current upstream health, query errors, latency, and system logs to identify DNS resolution bottlenecks.",
	},
	{
		Name:        "security-audit",
		Description: "Inspect threat intelligence blocking, abuse detections, high-risk country settings, and unauthenticated traffic.",
	},
	{
		Name:        "optimize-dns-performance",
		Description: "Examine cache hit ratio, upstream RTTs, DoT encryption settings, and provide recommendations for lowest latency.",
	},
	{
		Name:        "audit-cluster-federation",
		Description: "Inspect Primary/Replica cluster topology, environment profiles (private/public/hybrid), log replication mode, and connectivity health.",
	},
}

