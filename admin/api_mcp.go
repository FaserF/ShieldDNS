package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// MCP JSON-RPC protocol types
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
var allMCPTools = []struct {
	tool          mcpTool
	requiredPerm  string
	actionHandler func(apiKey *APIKey, args map[string]interface{}) (interface{}, error)
}{
	// 1. Analytics & Monitoring
	{
		tool: mcpTool{
			Name:        "get_stats",
			Description: "Get complete real-time and 24h ShieldDNS statistics (total queries, blocked count, cache hit ratio, average latency, RAM/CPU usage, active QPS, versions).",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:stats",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			statsLock.RLock()
			s := stats
			statsLock.RUnlock()

			total, blocked, cacheHits, err := Get24hStats()
			if err == nil {
				s.TotalQueries = total
				s.BlockedQueries = blocked
				s.CacheHits = cacheHits
			} else {
				s.TotalQueries = atomic.LoadInt64(&stats.TotalQueries)
				s.BlockedQueries = atomic.LoadInt64(&stats.BlockedQueries)
				s.CacheHits = atomic.LoadInt64(&stats.CacheHits)
			}
			if avg, err := GetAverageLatency(); err == nil {
				s.AverageLatency = avg
			}
			return s, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "get_queries",
			Description: "Fetch recent DNS query logs with optional filtering by domain, client IP, status, or record type.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit":     map[string]interface{}{"type": "integer", "description": "Maximum queries to return (default 50, max 500)"},
					"search":    map[string]interface{}{"type": "string", "description": "Search term across domain or client IP"},
					"status":    map[string]interface{}{"type": "string", "description": "Filter by status: 'Allowed', 'Blocked', etc."},
					"client_ip": map[string]interface{}{"type": "string", "description": "Filter by specific client IP"},
					"from_time": map[string]interface{}{"type": "string", "description": "Start timestamp (ISO format)"},
					"to_time":   map[string]interface{}{"type": "string", "description": "End timestamp (ISO format)"},
				},
			},
		},
		requiredPerm: "read:logs",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			limit := 50
			if l, ok := args["limit"].(float64); ok && l > 0 {
				limit = int(l)
				if limit > 500 {
					limit = 500
				}
			}
			search, _ := args["search"].(string)
			statusFilter, _ := args["status"].(string)
			clientIP, _ := args["client_ip"].(string)
			fromTime, _ := args["from_time"].(string)
			toTime, _ := args["to_time"].(string)

			var baseQuery string
			fields := "timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms"
			if search != "" || clientIP != "" || fromTime != "" || toTime != "" {
				baseQuery = "SELECT " + fields + " FROM queries WHERE 1=1"
			} else {
				baseQuery = "SELECT " + fields + " FROM (SELECT * FROM queries ORDER BY id DESC LIMIT 2000) WHERE 1=1"
			}

			query := baseQuery
			var qArgs []interface{}

			if search != "" {
				query += " AND (domain LIKE ? OR client_ip LIKE ?)"
				qArgs = append(qArgs, "%"+search+"%", "%"+search+"%")
			}
			if statusFilter != "" {
				if statusFilter == "Blocked" {
					query += " AND status LIKE ?"
					qArgs = append(qArgs, StatusBlocked+"%")
				} else {
					query += " AND status = ?"
					qArgs = append(qArgs, statusFilter)
				}
			}
			if clientIP != "" {
				query += " AND client_ip = ?"
				qArgs = append(qArgs, clientIP)
			}
			if fromTime != "" {
				query += " AND timestamp >= ?"
				qArgs = append(qArgs, strings.ReplaceAll(fromTime, "T", " "))
			}
			if toTime != "" {
				query += " AND timestamp <= ?"
				qArgs = append(qArgs, strings.ReplaceAll(toTime, "T", " "))
			}

			query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d", limit)

			rows, err := db.Query(query, qArgs...)
			if err != nil {
				return nil, err
			}
			defer rows.Close()

			configLock.RLock()
			aliases := config.ClientAliases
			configLock.RUnlock()

			queries := make([]Query, 0)
			for rows.Next() {
				var q Query
				var ts string
				if err := rows.Scan(&ts, &q.Domain, &q.Type, &q.Status, &q.ClientIP, &q.IsCacheHit, &q.DurationMs); err != nil {
					continue
				}
				q.Time, _ = ParseFlexibleTime(ts)
				if aliases != nil {
					q.ClientAlias = aliases[q.ClientIP]
				}
				queries = append(queries, q)
			}
			return queries, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "get_top_statistics",
			Description: "Get top blocked domains and top client IPs in the last 24 hours.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"limit": map[string]interface{}{"type": "integer", "description": "Number of top entries (default 10, max 100)"},
				},
			},
		},
		requiredPerm: "read:stats",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			limit := 10
			if l, ok := args["limit"].(float64); ok && l > 0 {
				limit = int(l)
				if limit > 100 {
					limit = 100
				}
			}

			// Top Blocked
			bRows, err := db.Query(`
				SELECT domain, COUNT(*) as count
				FROM queries
				WHERE status LIKE 'Blocked%' AND timestamp > datetime('now', '-24 hours')
				GROUP BY domain
				ORDER BY count DESC
				LIMIT ?
			`, limit)
			topBlocked := make([]map[string]interface{}, 0)
			if err == nil {
				defer bRows.Close()
				for bRows.Next() {
					var domain string
					var count int
					bRows.Scan(&domain, &count)
					topBlocked = append(topBlocked, map[string]interface{}{"domain": domain, "count": count})
				}
			}

			// Top Clients
			cRows, err := db.Query(`
				SELECT client_ip, COUNT(*) as count
				FROM queries
				WHERE timestamp > datetime('now', '-24 hours') AND client_ip != 'DoH Proxy'
				GROUP BY client_ip
				ORDER BY count DESC
				LIMIT ?
			`, limit)
			topClients := make([]map[string]interface{}, 0)
			if err == nil {
				defer cRows.Close()
				configLock.RLock()
				aliases := config.ClientAliases
				configLock.RUnlock()

				for cRows.Next() {
					var clientIP string
					var count int
					cRows.Scan(&clientIP, &count)
					alias := ""
					if aliases != nil {
						alias = aliases[clientIP]
					}
					topClients = append(topClients, map[string]interface{}{
						"client_ip":    clientIP,
						"client_alias": alias,
						"count":        count,
					})
				}
			}

			return map[string]interface{}{
				"top_blocked_domains": topBlocked,
				"top_clients":         topClients,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "get_domain_details",
			Description: "Inspect detailed query analytics and block list matches for a specific domain.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{"type": "string", "description": "The exact domain to inspect (e.g. 'google.com', 'tracker.ads.com')"},
				},
				"required": []string{"domain"},
			},
		},
		requiredPerm: "read:logs",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			domain, _ := args["domain"].(string)
			domain = NormalizeDomain(domain)
			if domain == "" {
				return nil, fmt.Errorf("domain is required")
			}

			ds, err := getDomainStats(domain)
			if err != nil {
				return nil, err
			}
			clients, _ := getDomainClients(domain, 20)

			configLock.RLock()
			isCustomBlocked := false
			for _, d := range config.CustomBlocked {
				if strings.EqualFold(d, domain) {
					isCustomBlocked = true
					break
				}
			}
			isCustomAllowed := false
			for _, d := range config.CustomAllowed {
				if strings.EqualFold(d, domain) {
					isCustomAllowed = true
					break
				}
			}
			configLock.RUnlock()

			return map[string]interface{}{
				"domain":            domain,
				"stats":             ds,
				"top_clients":       clients,
				"is_custom_blocked": isCustomBlocked,
				"is_custom_allowed": isCustomAllowed,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "get_client_details",
			Description: "Get detailed information, query history, and blocking status for a client IP.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"client_ip": map[string]interface{}{"type": "string", "description": "Client IP address (e.g. '192.168.1.50')"},
				},
				"required": []string{"client_ip"},
			},
		},
		requiredPerm: "read:stats",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			clientIP, _ := args["client_ip"].(string)
			clientIP = strings.TrimSpace(clientIP)
			if clientIP == "" {
				return nil, fmt.Errorf("client_ip is required")
			}
			cs, _ := getClientStats(clientIP)
			topBlocked, _ := getClientTopBlocked(clientIP, 10)

			configLock.RLock()
			alias := config.ClientAliases[clientIP]
			isBlocked := false
			for _, b := range config.BlockedClients {
				if b == clientIP {
					isBlocked = true
					break
				}
			}
			blockInfo := config.BlockedClientsInfo[clientIP]
			configLock.RUnlock()

			return map[string]interface{}{
				"client_ip":   clientIP,
				"alias":       alias,
				"is_blocked":  isBlocked,
				"block_info":  blockInfo,
				"stats":       cs,
				"top_blocked": topBlocked,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "list_all_clients",
			Description: "List all known clients that have queried ShieldDNS with their aliases, last seen timestamps, and ban status.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:stats",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			clients, err := getAllClients()
			if err != nil {
				return nil, err
			}
			configLock.RLock()
			aliases := config.ClientAliases
			blockedMap := make(map[string]bool)
			for _, ip := range config.BlockedClients {
				blockedMap[ip] = true
			}
			configLock.RUnlock()

			for _, c := range clients {
				ip, _ := c["ip"].(string)
				if alias, ok := aliases[ip]; ok {
					c["alias"] = alias
				} else {
					c["alias"] = ""
				}
				c["blocked"] = blockedMap[ip]
			}
			return clients, nil
		},
	},

	// 2. Rules & Filtering Management
	{
		tool: mcpTool{
			Name:        "search_domain_status",
			Description: "Check whether a domain is currently blocked, whitelisted, or resolved normally by any active lists or custom rules.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{"type": "string", "description": "The domain name to check"},
				},
				"required": []string{"domain"},
			},
		},
		requiredPerm: "read:logs",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			domain, _ := args["domain"].(string)
			domain = NormalizeDomain(domain)
			if domain == "" {
				return nil, fmt.Errorf("domain is required")
			}
			blockAttributionLock.RLock()
			blockLists := blockAttribution[domain]
			blockAttributionLock.RUnlock()

			allowLists := getAllowlistAttribution(domain)

			isBlocked := len(blockLists) > 0
			isAllowed := len(allowLists) > 0

			return map[string]interface{}{
				"domain":           domain,
				"blocked":          isBlocked,
				"lists":            blockLists,
				"allowed":          isAllowed,
				"allowlists":       allowLists,
				"effective_status": (isAllowed || !isBlocked),
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "add_custom_rule",
			Description: "Add a domain to the Custom Whitelist (allowed) or Custom Blacklist (blocked).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"type":   map[string]interface{}{"type": "string", "enum": []string{"blocked", "allowed"}, "description": "Rule type: 'blocked' or 'allowed'"},
					"domain": map[string]interface{}{"type": "string", "description": "Domain name to add (e.g. 'ads.example.com')"},
				},
				"required": []string{"type", "domain"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			ruleType, _ := args["type"].(string)
			rawDomain, _ := args["domain"].(string)
			domain := NormalizeDomain(rawDomain)
			if domain == "" || !isValidDomain(domain) {
				return nil, fmt.Errorf("invalid domain format: %s", rawDomain)
			}

			configLock.Lock()
			if ruleType == "blocked" {
				for _, d := range config.CustomBlocked {
					if strings.EqualFold(d, domain) {
						configLock.Unlock()
						return map[string]interface{}{"success": true, "message": "Domain already in custom blocklist", "domain": domain}, nil
					}
				}
				config.CustomBlocked = append(config.CustomBlocked, domain)
			} else if ruleType == "allowed" {
				for _, d := range config.CustomAllowed {
					if strings.EqualFold(d, domain) {
						configLock.Unlock()
						return map[string]interface{}{"success": true, "message": "Domain already in custom allowlist", "domain": domain}, nil
					}
				}
				config.CustomAllowed = append(config.CustomAllowed, domain)
			} else {
				configLock.Unlock()
				return nil, fmt.Errorf("invalid type: must be 'blocked' or 'allowed'")
			}

			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			updateCorefile()
			return map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Added %s to %s list", domain, ruleType),
				"type":    ruleType,
				"domain":  domain,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "remove_custom_rule",
			Description: "Remove a domain from Custom Whitelist or Custom Blacklist.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"type":   map[string]interface{}{"type": "string", "enum": []string{"blocked", "allowed"}, "description": "Rule type: 'blocked' or 'allowed'"},
					"domain": map[string]interface{}{"type": "string", "description": "Domain name to remove"},
				},
				"required": []string{"type", "domain"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			ruleType, _ := args["type"].(string)
			rawDomain, _ := args["domain"].(string)
			domain := NormalizeDomain(rawDomain)

			configLock.Lock()
			if ruleType == "blocked" {
				newBlocked := make([]string, 0, len(config.CustomBlocked))
				for _, d := range config.CustomBlocked {
					if !strings.EqualFold(d, domain) {
						newBlocked = append(newBlocked, d)
					}
				}
				config.CustomBlocked = newBlocked
			} else if ruleType == "allowed" {
				newAllowed := make([]string, 0, len(config.CustomAllowed))
				for _, d := range config.CustomAllowed {
					if !strings.EqualFold(d, domain) {
						newAllowed = append(newAllowed, d)
					}
				}
				config.CustomAllowed = newAllowed
			} else {
				configLock.Unlock()
				return nil, fmt.Errorf("invalid type: must be 'blocked' or 'allowed'")
			}

			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			updateCorefile()
			return map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Removed %s from %s list", domain, ruleType),
				"type":    ruleType,
				"domain":  domain,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "set_custom_mapping",
			Description: "Create or update a local DNS override mapping (domain to IP).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{"type": "string", "description": "Domain name (e.g. 'nas.lan')"},
					"ip":     map[string]interface{}{"type": "string", "description": "IP address target (e.g. '192.168.1.100')"},
				},
				"required": []string{"domain", "ip"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			domain, _ := args["domain"].(string)
			ip, _ := args["ip"].(string)
			domain = NormalizeDomain(domain)
			ip = strings.TrimSpace(ip)
			if domain == "" || !isValidDomain(domain) {
				return nil, fmt.Errorf("invalid domain")
			}
			if ip == "" {
				return nil, fmt.Errorf("ip is required")
			}

			configLock.Lock()
			if config.CustomMappings == nil {
				config.CustomMappings = make(map[string]string)
			}
			config.CustomMappings[domain] = ip
			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			updateCorefile()
			return map[string]interface{}{
				"success": true,
				"domain":  domain,
				"ip":      ip,
				"message": fmt.Sprintf("Mapping set: %s -> %s", domain, ip),
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "remove_custom_mapping",
			Description: "Delete a local DNS override mapping.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain": map[string]interface{}{"type": "string", "description": "Domain name to remove mapping for"},
				},
				"required": []string{"domain"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			domain, _ := args["domain"].(string)
			domain = NormalizeDomain(domain)

			configLock.Lock()
			if config.CustomMappings != nil {
				delete(config.CustomMappings, domain)
			}
			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			updateCorefile()
			return map[string]interface{}{
				"success": true,
				"domain":  domain,
				"message": fmt.Sprintf("Mapping removed for %s", domain),
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "toggle_global_filtering",
			Description: "Enable or disable DNS protection and filtering globally (Emergency Kill-Switch).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"enabled": map[string]interface{}{"type": "boolean", "description": "True to enable protection, False to disable"},
				},
				"required": []string{"enabled"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			enabled, ok := args["enabled"].(bool)
			if !ok {
				return nil, fmt.Errorf("enabled (boolean) is required")
			}

			configLock.Lock()
			config.FilteringEnabled = enabled
			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			updateCorefile()
			return map[string]interface{}{
				"success":           true,
				"filtering_enabled": enabled,
				"message":           fmt.Sprintf("Global filtering is now %v", enabled),
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "manage_filter_lists",
			Description: "Inspect, enable, disable, add or remove upstream filter blocklists and allowlists.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"action":    map[string]interface{}{"type": "string", "enum": []string{"list", "add", "remove", "toggle"}, "description": "Action to perform"},
					"list_type": map[string]interface{}{"type": "string", "enum": []string{"block", "allow"}, "description": "Type of list: 'block' or 'allow'"},
					"name":      map[string]interface{}{"type": "string", "description": "Name of the list"},
					"url":       map[string]interface{}{"type": "string", "description": "URL of the list (required for 'add')"},
					"enabled":   map[string]interface{}{"type": "boolean", "description": "Enabled status (for 'toggle' or 'add')"},
					"category":  map[string]interface{}{"type": "string", "description": "Optional category (e.g. 'Adware', 'Malware', 'Tracking')"},
				},
				"required": []string{"action"},
			},
		},
		requiredPerm: "write:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			action, _ := args["action"].(string)
			listType, _ := args["list_type"].(string)
			if listType == "" {
				listType = "block"
			}

			configLock.Lock()
			defer configLock.Unlock()

			if action == "list" {
				return map[string]interface{}{
					"blocklists": config.Lists,
					"allowlists": config.Allowlists,
				}, nil
			}

			name, _ := args["name"].(string)
			url, _ := args["url"].(string)
			category, _ := args["category"].(string)

			if action == "add" {
				if name == "" || url == "" {
					return nil, fmt.Errorf("name and url are required for action 'add'")
				}
				newList := List{
					Name:      name,
					URL:       url,
					Enabled:   true,
					Category:  category,
					UpdatedAt: time.Now(),
				}
				if en, ok := args["enabled"].(bool); ok {
					newList.Enabled = en
				}

				if listType == "block" {
					config.Lists = append(config.Lists, newList)
				} else {
					config.Allowlists = append(config.Allowlists, newList)
				}
			} else if action == "remove" {
				if name == "" && url == "" {
					return nil, fmt.Errorf("name or url is required to remove a list")
				}
				if listType == "block" {
					filtered := make([]List, 0)
					for _, l := range config.Lists {
						if l.Name != name && l.URL != url {
							filtered = append(filtered, l)
						}
					}
					config.Lists = filtered
				} else {
					filtered := make([]List, 0)
					for _, l := range config.Allowlists {
						if l.Name != name && l.URL != url {
							filtered = append(filtered, l)
						}
					}
					config.Allowlists = filtered
				}
			} else if action == "toggle" {
				enabled, ok := args["enabled"].(bool)
				if !ok {
					return nil, fmt.Errorf("enabled (boolean) is required for 'toggle'")
				}
				target := &config.Lists
				if listType == "allow" {
					target = &config.Allowlists
				}
				found := false
				for i := range *target {
					if (*target)[i].Name == name || (*target)[i].URL == url {
						(*target)[i].Enabled = enabled
						found = true
						break
					}
				}
				if !found {
					return nil, fmt.Errorf("list not found")
				}
			} else {
				return nil, fmt.Errorf("unknown action: %s", action)
			}

			if err := saveConfigNoLock(); err != nil {
				return nil, fmt.Errorf("failed to save configuration: %w", err)
			}
			go updateBlocklist(nil, false)

			return map[string]interface{}{
				"success": true,
				"action":  action,
				"type":    listType,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "block_client_ip",
			Description: "Ban or unban a specific client IP address from querying ShieldDNS.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"client_ip": map[string]interface{}{"type": "string", "description": "Client IP address (e.g. '192.168.1.200')"},
					"block":     map[string]interface{}{"type": "boolean", "description": "True to block/ban, False to unblock/unban"},
					"reason":    map[string]interface{}{"type": "string", "description": "Reason for the ban (optional)"},
				},
				"required": []string{"client_ip", "block"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			clientIP, _ := args["client_ip"].(string)
			clientIP = strings.TrimSpace(clientIP)
			block, ok := args["block"].(bool)
			if clientIP == "" || !ok {
				return nil, fmt.Errorf("client_ip and block boolean are required")
			}
			reason, _ := args["reason"].(string)
			if reason == "" {
				reason = "MCP Admin Action"
			}

			// Disallow blocking loopback/core clients
			if block && (clientIP == "127.0.0.1" || clientIP == "::1" || clientIP == "localhost" || clientIP == "DoH Proxy") {
				return nil, fmt.Errorf("cannot block critical internal client: %s", clientIP)
			}

			configLock.Lock()
			if block {
				alreadyBlocked := false
				for _, b := range config.BlockedClients {
					if b == clientIP {
						alreadyBlocked = true
						break
					}
				}
				if !alreadyBlocked {
					config.BlockedClients = append(config.BlockedClients, clientIP)
				}
				if config.BlockedClientsInfo == nil {
					config.BlockedClientsInfo = make(map[string]BlockedClientInfo)
				}
				config.BlockedClientsInfo[clientIP] = BlockedClientInfo{
					Reason:    reason,
					BlockedAt: time.Now(),
					Auto:      false,
				}
			} else {
				newBlocked := make([]string, 0, len(config.BlockedClients))
				for _, b := range config.BlockedClients {
					if b != clientIP {
						newBlocked = append(newBlocked, b)
					}
				}
				config.BlockedClients = newBlocked
				if config.BlockedClientsInfo != nil {
					delete(config.BlockedClientsInfo, clientIP)
				}
			}

			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			updateCorefile()
			return map[string]interface{}{
				"success":   true,
				"client_ip": clientIP,
				"blocked":   block,
				"reason":    reason,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "set_client_alias",
			Description: "Assign a friendly display name/alias to a client IP (e.g. 'Living Room Apple TV').",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"client_ip": map[string]interface{}{"type": "string", "description": "Client IP address"},
					"alias":     map[string]interface{}{"type": "string", "description": "Friendly name to assign (pass empty string to clear)"},
				},
				"required": []string{"client_ip", "alias"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			clientIP, _ := args["client_ip"].(string)
			alias, _ := args["alias"].(string)
			clientIP = strings.TrimSpace(clientIP)
			alias = strings.TrimSpace(alias)
			if clientIP == "" {
				return nil, fmt.Errorf("client_ip is required")
			}

			configLock.Lock()
			if config.ClientAliases == nil {
				config.ClientAliases = make(map[string]string)
			}
			if alias == "" {
				delete(config.ClientAliases, clientIP)
			} else {
				config.ClientAliases[clientIP] = alias
			}

			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			return map[string]interface{}{
				"success":   true,
				"client_ip": clientIP,
				"alias":     alias,
			}, nil
		},
	},

	// 3. Geo-Blocking & Threat Intelligence
	{
		tool: mcpTool{
			Name:        "get_geo_block_status",
			Description: "Get currently blocked countries and detected server country.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.RLock()
			blocked := config.BlockedCountries
			serverCountry := config.ServerCountry
			maliciousEnabled := config.MaliciousIPBlockingEnabled
			maliciousInterval := config.MaliciousIPInterval
			configLock.RUnlock()

			return map[string]interface{}{
				"blocked_countries":          blocked,
				"server_country":             serverCountry,
				"detected_server_country":    detectedServerCountry,
				"malicious_blocking_enabled": maliciousEnabled,
				"malicious_update_interval":  maliciousInterval,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "set_blocked_countries",
			Description: "Set the list of ISO two-letter country codes blocked from resolving through ShieldDNS.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"countries": map[string]interface{}{
						"type":        "array",
						"items":       map[string]interface{}{"type": "string"},
						"description": "List of 2-letter ISO country codes (e.g. ['CN', 'RU', 'KP', 'IR'])",
					},
				},
				"required": []string{"countries"},
			},
		},
		requiredPerm: "write:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			rawCountries, ok := args["countries"].([]interface{})
			if !ok {
				return nil, fmt.Errorf("countries array is required")
			}
			cleanCountries := make([]string, 0, len(rawCountries))
			for _, c := range rawCountries {
				if s, ok := c.(string); ok {
					s = strings.ToUpper(strings.TrimSpace(s))
					if len(s) == 2 {
						// Ensure server country is not blocked
						if detectedServerCountry != "" && strings.EqualFold(s, detectedServerCountry) {
							return nil, fmt.Errorf("cannot block the country where ShieldDNS server is located (%s)", s)
						}
						cleanCountries = append(cleanCountries, s)
					}
				}
			}

			configLock.Lock()
			config.BlockedCountries = cleanCountries
			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			updateCorefile()
			return map[string]interface{}{
				"success":           true,
				"blocked_countries": cleanCountries,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "toggle_malicious_ip_blocking",
			Description: "Configure automated malicious IP threat feed blocking (blocklist.de).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"enabled":  map[string]interface{}{"type": "boolean", "description": "Enable or disable malicious IP blocking"},
					"interval": map[string]interface{}{"type": "integer", "description": "Update interval in hours (1-168)"},
				},
				"required": []string{"enabled"},
			},
		},
		requiredPerm: "write:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			enabled, ok := args["enabled"].(bool)
			if !ok {
				return nil, fmt.Errorf("enabled boolean is required")
			}
			interval := 8
			if iv, ok := args["interval"].(float64); ok && iv >= 1 && iv <= 168 {
				interval = int(iv)
			}

			configLock.Lock()
			config.MaliciousIPBlockingEnabled = enabled
			config.MaliciousIPInterval = interval
			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			restartMaliciousUpdater()
			if enabled {
				go syncMaliciousIPs(true)
			}

			return map[string]interface{}{
				"success":        true,
				"enabled":        enabled,
				"interval_hours": interval,
			}, nil
		},
	},

	// 4. System, Diagnostics & Maintenance
	{
		tool: mcpTool{
			Name:        "get_system_diagnostics",
			Description: "Get complete system health, upstream server RTT latencies, CoreDNS status, memory, CPU, and database size.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:diagnostics",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			sysStats := getSystemStats()

			latencyLock.RLock()
			lats := make(map[string]string)
			for k, v := range latencyMap {
				lats[k] = v.String()
			}
			latencyLock.RUnlock()

			healthLock.RLock()
			hUp := make([]string, len(healthyUpstreams))
			copy(hUp, healthyUpstreams)
			hDoT := make([]string, len(healthyDoT))
			copy(hDoT, healthyDoT)
			healthLock.RUnlock()

			configLock.RLock()
			allUpstreams := config.Upstreams
			allDoT := config.UpstreamDoT
			configLock.RUnlock()

			return map[string]interface{}{
				"system":            sysStats,
				"latencies":         lats,
				"healthy_upstreams": hUp,
				"healthy_dot":       hDoT,
				"all_upstreams":     allUpstreams,
				"all_dot":           allDoT,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "recheck_upstreams",
			Description: "Trigger an immediate live latency and reachability test for all configured upstream DNS servers.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "write:maintenance",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			go checkAll()
			return map[string]interface{}{
				"success": true,
				"message": "Upstream health recheck initiated in background",
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "get_system_logs",
			Description: "Retrieve recent daemon and CoreDNS system log entries.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"lines": map[string]interface{}{"type": "integer", "description": "Number of recent log lines to retrieve (default 50, max 500)"},
				},
			},
		},
		requiredPerm: "read:system",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			lines := 50
			if l, ok := args["lines"].(float64); ok && l > 0 {
				lines = int(l)
				if lines > 500 {
					lines = 500
				}
			}
			systemLogLock.RLock()
			totalLogs := len(systemLogBuffer)
			start := 0
			if totalLogs > lines {
				start = totalLogs - lines
			}
			logsCopy := make([]string, totalLogs-start)
			copy(logsCopy, systemLogBuffer[start:])
			systemLogLock.RUnlock()

			return map[string]interface{}{
				"total_buffered": totalLogs,
				"returned_lines": len(logsCopy),
				"logs":           logsCopy,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "trigger_system_refresh",
			Description: "Trigger a full system refresh: re-downloads all active blocklists, regenerates CoreDNS configuration, flushes cache, and restarts CoreDNS.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "write:maintenance",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			go func() {
				slog.Info("MCP triggered full system refresh")
				updateBlocklist(nil, false)
				syncMaliciousIPs(true)
				updateCorefile()
				restartCoreDNS()
			}()
			return map[string]interface{}{
				"success": true,
				"message": "Full system refresh initiated in background",
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "clear_query_logs",
			Description: "Purge all DNS query records and statistics history from the database.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "write:maintenance",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			if err := ClearQueryLogs(); err != nil {
				return nil, fmt.Errorf("failed to clear query logs: %w", err)
			}
			atomic.StoreInt64(&stats.TotalQueries, 0)
			atomic.StoreInt64(&stats.BlockedQueries, 0)
			atomic.StoreInt64(&stats.CacheHits, 0)
			return map[string]interface{}{
				"success": true,
				"message": "Query logs cleared successfully",
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "get_configuration",
			Description: "Read complete sanitized ShieldDNS configuration (upstreams, DoT, security settings, intervals, rules).",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.RLock()
			cfg := config.SanitizedCopy()
			configLock.RUnlock()
			return cfg, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "update_configuration",
			Description: "Update core DNS settings such as upstreams, DoT, serve stale, rate limits, latency intervals, or admin domain.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"upstreams":               map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Standard upstream DNS IPs"},
					"upstream_dot":           map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "DoT upstream server hostnames"},
					"prefer_encrypted":       map[string]interface{}{"type": "boolean", "description": "Prefer encrypted DoT upstreams"},
					"use_fastest_upstream":   map[string]interface{}{"type": "boolean", "description": "Smart upstream selection based on latency"},
					"smart_selection_policy":  map[string]interface{}{"type": "string", "enum": []string{"fastest", "random", "broadcast"}, "description": "Smart upstream policy"},
					"serve_stale":            map[string]interface{}{"type": "boolean", "description": "Serve expired cache entries when upstreams are slow"},
					"dnssec_enabled":         map[string]interface{}{"type": "boolean", "description": "DNSSEC validation"},
					"verify_upstream_tls":    map[string]interface{}{"type": "boolean", "description": "Strict TLS cert verification for upstreams"},
					"admin_domain":           map[string]interface{}{"type": "string", "description": "Admin UI domain name"},
					"block_page_ip":          map[string]interface{}{"type": "string", "description": "Default IPv4 block page IP"},
					"doh_rate_limit":         map[string]interface{}{"type": "integer", "description": "Max DoH queries per second per client"},
					"retention_days":         map[string]interface{}{"type": "integer", "description": "Query retention in days (1-365)"},
					"abuse_detection_enabled": map[string]interface{}{"type": "boolean", "description": "Enable automated abuse and DGA detection"},
					"debug_mode":             map[string]interface{}{"type": "boolean", "description": "Enable detailed debug logs"},
				},
			},
		},
		requiredPerm: "write:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.Lock()
			defer configLock.Unlock()

			if ups, ok := args["upstreams"].([]interface{}); ok {
				cleanUps := make([]string, 0)
				for _, u := range ups {
					if s, ok := u.(string); ok && isValidUpstream(strings.TrimSpace(s)) {
						cleanUps = append(cleanUps, strings.TrimSpace(s))
					}
				}
				config.Upstreams = cleanUps
			}
			if dots, ok := args["upstream_dot"].([]interface{}); ok {
				cleanDots := make([]string, 0)
				for _, d := range dots {
					if s, ok := d.(string); ok && isValidUpstream(strings.TrimSpace(s)) {
						cleanDots = append(cleanDots, strings.TrimSpace(s))
					}
				}
				config.UpstreamDoT = cleanDots
			}
			if v, ok := args["prefer_encrypted"].(bool); ok {
				config.PreferEncrypted = v
			}
			if v, ok := args["use_fastest_upstream"].(bool); ok {
				config.UseFastestUpstream = v
			}
			if v, ok := args["smart_selection_policy"].(string); ok && (v == "fastest" || v == "random" || v == "broadcast") {
				config.SmartSelectionPolicy = v
			}
			if v, ok := args["serve_stale"].(bool); ok {
				config.ServeStale = v
			}
			if v, ok := args["dnssec_enabled"].(bool); ok {
				config.DNSSECEnabled = v
			}
			if v, ok := args["verify_upstream_tls"].(bool); ok {
				config.VerifyUpstreamTLS = v
			}
			if v, ok := args["admin_domain"].(string); ok && v != "" {
				config.AdminDomain = v
			}
			if v, ok := args["block_page_ip"].(string); ok && v != "" {
				config.BlockPageIP = v
			}
			if v, ok := args["doh_rate_limit"].(float64); ok && v > 0 {
				config.DoHRateLimit = int(v)
			}
			if v, ok := args["retention_days"].(float64); ok && v > 0 {
				config.RetentionDays = int(v)
			}
			if v, ok := args["abuse_detection_enabled"].(bool); ok {
				config.AbuseDetectionEnabled = v
			}
			if v, ok := args["debug_mode"].(bool); ok {
				config.DebugMode = v
			}

			if err := saveConfigNoLock(); err != nil {
				return nil, fmt.Errorf("failed to save config: %w", err)
			}

			updateCorefile()
			restartCoreDNS()

			return map[string]interface{}{
				"success": true,
				"message": "Configuration updated and CoreDNS reloaded",
				"config":  config.SanitizedCopy(),
			}, nil
		},
	},

	// 5. Presets, Catalog & Allowlist Management
	{
		tool: mcpTool{
			Name:        "get_catalog_presets",
			Description: "Get the curated catalog of recommended blocklist and allowlist presets with category filters.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			return map[string]interface{}{
				"blocklist_presets": DefaultPresets,
				"allowlist_presets": DefaultAllowlists,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "apply_recommended_presets",
			Description: "Automatically subscribe to and enable all recommended security, malware, and tracking blocklists.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.Lock()
			added := 0
			for _, rec := range DefaultPresets {
				if !rec.IsRecommended {
					continue
				}
				exists := false
				for _, cur := range config.Lists {
					if cur.URL == rec.URL {
						exists = true
						break
					}
				}
				if !exists {
					config.Lists = append(config.Lists, List{
						Name:      rec.Name,
						URL:       rec.URL,
						Enabled:   true,
						Category:  rec.Category,
						UpdatedAt: time.Now(),
					})
					added++
				}
			}
			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			go updateBlocklist(nil, false)
			return map[string]interface{}{
				"success":     true,
				"added_lists": added,
				"message":     fmt.Sprintf("Applied %d recommended presets and triggered download", added),
			}, nil
		},
	},

	// 6. Abuse Whitelisting & Client Policies
	{
		tool: mcpTool{
			Name:        "manage_autoblock_whitelist",
			Description: "Inspect, add, or remove client IPs/CIDRs exempt from automatic rate-limiting and abuse bans.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"action":    map[string]interface{}{"type": "string", "enum": []string{"list", "add", "remove"}, "description": "Action to perform"},
					"client_ip": map[string]interface{}{"type": "string", "description": "Client IP address (required for add/remove)"},
				},
				"required": []string{"action"},
			},
		},
		requiredPerm: "write:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			action, _ := args["action"].(string)
			clientIP, _ := args["client_ip"].(string)
			clientIP = strings.TrimSpace(clientIP)

			configLock.Lock()
			defer configLock.Unlock()

			if action == "list" {
				return map[string]interface{}{
					"autoblock_whitelist": config.AutoblockWhitelist,
				}, nil
			}

			if clientIP == "" {
				return nil, fmt.Errorf("client_ip is required for add/remove")
			}

			if action == "add" {
				for _, ip := range config.AutoblockWhitelist {
					if ip == clientIP {
						return map[string]interface{}{"success": true, "message": "Already whitelisted", "whitelist": config.AutoblockWhitelist}, nil
					}
				}
				config.AutoblockWhitelist = append(config.AutoblockWhitelist, clientIP)
			} else if action == "remove" {
				filtered := make([]string, 0, len(config.AutoblockWhitelist))
				for _, ip := range config.AutoblockWhitelist {
					if ip != clientIP {
						filtered = append(filtered, ip)
					}
				}
				config.AutoblockWhitelist = filtered
			} else {
				return nil, fmt.Errorf("unknown action: %s", action)
			}

			if err := saveConfigNoLock(); err != nil {
				return nil, fmt.Errorf("failed to save config: %w", err)
			}

			return map[string]interface{}{
				"success":   true,
				"action":    action,
				"client_ip": clientIP,
				"whitelist": config.AutoblockWhitelist,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "get_blocked_clients",
			Description: "List all currently blocked/banned client IPs with reason, timestamp, and geo country code.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.RLock()
			defer configLock.RUnlock()

			type BlockedEntry struct {
				IP          string    `json:"ip"`
				Reason      string    `json:"reason"`
				BlockedAt   time.Time `json:"blocked_at"`
				Auto        bool      `json:"auto"`
				CountryCode string    `json:"country_code"`
				Alias       string    `json:"alias,omitempty"`
			}

			result := make([]BlockedEntry, 0, len(config.BlockedClients))
			for _, ip := range config.BlockedClients {
				info := config.BlockedClientsInfo[ip]
				alias := config.ClientAliases[ip]
				result = append(result, BlockedEntry{
					IP:          ip,
					Reason:      info.Reason,
					BlockedAt:   info.BlockedAt,
					Auto:        info.Auto,
					CountryCode: info.CountryCode,
					Alias:       alias,
				})
			}
			return result, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "get_client_ip_info",
			Description: "Look up IP geolocation, ASN, ISP, hostname, and country info for any client IP address.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"ip": map[string]interface{}{"type": "string", "description": "IP address to look up"},
				},
				"required": []string{"ip"},
			},
		},
		requiredPerm: "read:stats",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			ip, _ := args["ip"].(string)
			ip = strings.TrimSpace(ip)
			if ip == "" {
				return nil, fmt.Errorf("ip is required")
			}
			req, err := http.NewRequest(http.MethodGet, "/api/ip-info?ip="+url.QueryEscape(ip), nil)
			if err != nil {
				return nil, err
			}
			rr := httptest.NewRecorder()
			handleIPInfo(rr, req)
			if rr.Code != http.StatusOK {
				return nil, fmt.Errorf("ip-info lookup failed: %s", rr.Body.String())
			}
			var info IPInfo
			if err := json.Unmarshal(rr.Body.Bytes(), &info); err != nil {
				return nil, err
			}
			return info, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "optimize_security_profile",
			Description: "Tune DNS server protection settings: set DoH rate limits, abuse thresholds, and retention.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"doh_rate_limit":          map[string]interface{}{"type": "integer", "description": "Max queries per second per client (e.g. 30, 50)"},
					"abuse_detection_enabled": map[string]interface{}{"type": "boolean", "description": "Enable automated abuse and DGA detection"},
					"retention_days":          map[string]interface{}{"type": "integer", "description": "Query log retention in days (1-90)"},
				},
			},
		},
		requiredPerm: "write:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.Lock()
			defer configLock.Unlock()

			if rl, ok := args["doh_rate_limit"].(float64); ok && rl > 0 {
				config.DoHRateLimit = int(rl)
			}
			if ad, ok := args["abuse_detection_enabled"].(bool); ok {
				config.AbuseDetectionEnabled = ad
			}
			if rd, ok := args["retention_days"].(float64); ok && rd > 0 && rd <= 365 {
				config.RetentionDays = int(rd)
			}

			if err := saveConfigNoLock(); err != nil {
				return nil, fmt.Errorf("failed to save config: %w", err)
			}

			return map[string]interface{}{
				"success":                 true,
				"doh_rate_limit":          config.DoHRateLimit,
				"abuse_detection_enabled": config.AbuseDetectionEnabled,
				"retention_days":          config.RetentionDays,
				"message":                 "Security profile optimized successfully",
			}, nil
		},
	},

	// 7. API Key & Token Administration
	{
		tool: mcpTool{
			Name:        "list_api_tokens",
			Description: "List all configured API tokens, permissions, creation date, and last used timestamp.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "admin:all",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.RLock()
			defer configLock.RUnlock()

			type TokenView struct {
				ID          string    `json:"id"`
				Name        string    `json:"name"`
				Permissions []string  `json:"permissions"`
				CreatedAt   time.Time `json:"created_at"`
				LastUsed    time.Time `json:"last_used"`
			}
			tokens := make([]TokenView, len(config.APIKeys))
			for i, k := range config.APIKeys {
				tokens[i] = TokenView{
					ID:          k.ID,
					Name:        k.Name,
					Permissions: k.Permissions,
					CreatedAt:   k.CreatedAt,
					LastUsed:    k.LastUsed,
				}
			}
			return tokens, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "create_api_token",
			Description: "Create a new API Key with specified RBAC permissions (e.g. ['read:stats', 'write:rules', 'exec:mcp']). Returns the plaintext token only once.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name":        map[string]interface{}{"type": "string", "description": "Descriptive name for the API key (e.g. 'HomeAssistant Agent')"},
					"permissions": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "List of permissions: 'admin:all', 'exec:mcp', 'read:stats', 'read:logs', 'write:rules', 'read:config', 'write:config', 'write:maintenance', 'read:system', 'read:diagnostics', 'read:health'"},
				},
				"required": []string{"name", "permissions"},
			},
		},
		requiredPerm: "admin:all",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			name, _ := args["name"].(string)
			name = strings.TrimSpace(name)
			if name == "" {
				return nil, fmt.Errorf("name is required")
			}
			rawPerms, ok := args["permissions"].([]interface{})
			if !ok || len(rawPerms) == 0 {
				return nil, fmt.Errorf("permissions array is required")
			}
			perms := make([]string, 0, len(rawPerms))
			for _, p := range rawPerms {
				if s, ok := p.(string); ok && s != "" {
					perms = append(perms, strings.TrimSpace(s))
				}
			}

			rawToken := generateToken()
			newToken := APIKey{
				ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
				Name:        name,
				TokenHash:   hashToken(rawToken),
				Permissions: perms,
				CreatedAt:   time.Now(),
			}

			configLock.Lock()
			config.APIKeys = append(config.APIKeys, newToken)
			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			return map[string]interface{}{
				"success":     true,
				"id":          newToken.ID,
				"name":        newToken.Name,
				"token":       rawToken,
				"permissions": newToken.Permissions,
				"notice":      "Store this token safely now; it cannot be retrieved again.",
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "delete_api_token",
			Description: "Revoke and permanently delete an API token by ID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id": map[string]interface{}{"type": "string", "description": "Token ID to delete"},
				},
				"required": []string{"id"},
			},
		},
		requiredPerm: "admin:all",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			id, _ := args["id"].(string)
			if id == "" {
				return nil, fmt.Errorf("id is required")
			}

			configLock.Lock()
			defer configLock.Unlock()

			filtered := make([]APIKey, 0, len(config.APIKeys))
			found := false
			for _, k := range config.APIKeys {
				if k.ID == id {
					found = true
					continue
				}
				filtered = append(filtered, k)
			}

			if !found {
				return nil, fmt.Errorf("token with ID %s not found", id)
			}

			config.APIKeys = filtered
			if err := saveConfigNoLock(); err != nil {
				return nil, fmt.Errorf("failed to save config: %w", err)
			}

			return map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Token %s revoked and deleted", id),
			}, nil
		},
	},

	// 8. Backup, Restore & Disaster Recovery
	{
		tool: mcpTool{
			Name:        "create_system_backup",
			Description: "Generate a complete backup snapshot of ShieldDNS configuration, lists, database, and certificates.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"include_database": map[string]interface{}{"type": "boolean", "description": "Whether to include historical query database in backup (default true)"},
					"password":         map[string]interface{}{"type": "string", "description": "Optional AES password for encrypted backup"},
				},
			},
		},
		requiredPerm: "write:maintenance",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			includeDB := true
			if v, ok := args["include_database"].(bool); ok {
				includeDB = v
			}
			password, _ := args["password"].(string)

			zipData, err := GenerateBackupZIP(includeDB)
			if err != nil {
				return nil, fmt.Errorf("failed to generate backup: %w", err)
			}

			if password != "" {
				zipData, err = EncryptBackup(zipData, password)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt backup: %w", err)
				}
			}

			backupID := fmt.Sprintf("backup_%s", time.Now().Format("20060102_150405"))
			return map[string]interface{}{
				"success":          true,
				"backup_id":        backupID,
				"size_bytes":       len(zipData),
				"encrypted":        password != "",
				"included_db":      includeDB,
				"created_at":       time.Now().Format(time.RFC3339),
			}, nil
		},
	},

	// 9. Updates & Versioning
	{
		tool: mcpTool{
			Name:        "check_updates",
			Description: "Check for available ShieldDNS container or CoreDNS updates against the configured update channel.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:system",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			latest := checkVersionsNow()
			configLock.RLock()
			channel := config.UpdateChannel
			autoUpdate := config.AutoUpdateEnabled
			autoHour := config.AutoUpdateHour
			configLock.RUnlock()

			return map[string]interface{}{
				"current_version":     FullVersion,
				"update_channel":      channel,
				"auto_update_enabled": autoUpdate,
				"auto_update_hour":    autoHour,
				"update_info":         latest,
			}, nil
		},
	},

	// 10. Help & Introspection
	{
		tool: mcpTool{
			Name:        "get_help",
			Description: "Get complete operational guidance, API permission matrix, troubleshooting advice, and examples for autonomous agents.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"topic": map[string]interface{}{"type": "string", "enum": []string{"all", "permissions", "troubleshooting", "tools", "architecture"}, "description": "Specific topic to read"},
				},
			},
		},
		requiredPerm: "read:health",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			topic, _ := args["topic"].(string)
			if topic == "" {
				topic = "all"
			}

			return map[string]interface{}{
				"appliance": "ShieldDNS",
				"version":   FullVersion,
				"topic":     topic,
				"permission_matrix": map[string]string{
					"exec:mcp":          "Master permission required to connect to /api/mcp",
					"read:stats":        "Real-time & 24h metrics, QPS, top queries, client analytics",
					"read:logs":         "Query log inspection and domain status checks",
					"write:rules":       "Custom block/allow rules, mappings, client bans/aliases, filtering toggle",
					"read:config":       "Read active sanitized configuration and GeoIP status",
					"write:config":      "Modify DNS settings, filter lists, Geo-blocking, malicious feeds, and autowhitelist",
					"read:diagnostics":  "Upstream latency tests and CoreDNS runtime diagnostics",
					"write:maintenance": "System refresh, cache flush, clear logs, backups, and upstream health recheck",
					"read:system":       "Access daemon terminal logs and update checks",
					"admin:all":         "Full master access (required for API token management)",
				},
				"autonomous_tips": []string{
					"Always check search_domain_status before creating custom rules to see existing list matches.",
					"Use get_system_diagnostics and recheck_upstreams to identify resolving slowness.",
					"Use trigger_system_refresh after updating large blocklists to immediately flush CoreDNS cache.",
					"Use manage_autoblock_whitelist to prevent false-positive bans on critical local servers.",
				},
			}, nil
		},
	},
}

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
		var targetTool *struct {
			tool          mcpTool
			requiredPerm  string
			actionHandler func(apiKey *APIKey, args map[string]interface{}) (interface{}, error)
		}

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
