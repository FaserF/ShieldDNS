package main

import (
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"
)

var mcpSystemTools = []mcpToolDefinition{
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
					"routing_rules":          map[string]interface{}{"type": "array", "description": "Routing rules configuration"},
					"local_ptr_upstreams":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "Local PTR / reverse-DNS upstream servers for LAN IP resolution"},
					"wireguard_gateway":      map[string]interface{}{"type": "string", "description": "Default WireGuard DNS gateway IP"},
					"admin_domain":           map[string]interface{}{"type": "string", "description": "Admin UI domain name"},
					"block_page_ip":          map[string]interface{}{"type": "string", "description": "Default IPv4 block page IP"},
					"doh_rate_limit":         map[string]interface{}{"type": "integer", "description": "Max DoH queries per second per client"},
					"retention_days":         map[string]interface{}{"type": "integer", "description": "Query retention in days (1-365)"},
					"doh3_enabled":           map[string]interface{}{"type": "boolean", "description": "Enable DNS-over-HTTP/3 (QUIC) support"},
					"rate_limit_rate":        map[string]interface{}{"type": "integer", "description": "CoreDNS queries/sec limit per client IP (0 = disabled)"},
					"rate_limit_burst":       map[string]interface{}{"type": "integer", "description": "CoreDNS flood burst capacity"},
					"ech_optimization_enabled": map[string]interface{}{"type": "boolean", "description": "Enable HTTPS/SVCB DNS record processing for ECH"},
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
			if ptrs, ok := args["local_ptr_upstreams"].([]interface{}); ok {
				cleanPTRs := make([]string, 0)
				for _, p := range ptrs {
					if s, ok := p.(string); ok && isValidUpstream(strings.TrimSpace(s)) {
						cleanPTRs = append(cleanPTRs, strings.TrimSpace(s))
					}
				}
				config.LocalPTRUpstreams = cleanPTRs
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
			if v, ok := args["doh3_enabled"].(bool); ok {
				config.DoH3Enabled = v
			}
			if v, ok := args["rate_limit_rate"].(float64); ok && v >= 0 {
				config.RateLimitRate = int(v)
			}
			if v, ok := args["rate_limit_burst"].(float64); ok && v > 0 {
				config.RateLimitBurst = int(v)
			}
			if v, ok := args["ech_optimization_enabled"].(bool); ok {
				config.ECHOptimizationEnabled = v
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

}
