package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"
)

var mcpAdminTools = []mcpToolDefinition{
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
