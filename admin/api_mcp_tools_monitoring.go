package main

import (
	"fmt"
	"strings"
)

var mcpMonitoringTools = []mcpToolDefinition{
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
			s := getStatsData()
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

}
