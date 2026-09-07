package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

var mcpRulesTools = []mcpToolDefinition{
	{
		tool: mcpTool{
			Name:        "list_routing_rules",
			Description: "List all policy-based DNS routing rules (Standard, Specific Host/Master-Slave, WireGuard VPN exit).",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.RLock()
			defer configLock.RUnlock()
			return map[string]interface{}{
				"rules":             config.RoutingRules,
				"wireguard_gateway": config.WireGuardGateway,
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "set_routing_rule",
			Description: "Create or update a policy-based DNS routing rule (targets: 'default', 'host', 'wireguard').",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name":             map[string]interface{}{"type": "string", "description": "Optional rule label/name"},
					"match":            map[string]interface{}{"type": "string", "description": "Domain name (e.g. 'internal.lan') or client IP/CIDR (e.g. '192.168.1.50')"},
					"match_type":       map[string]interface{}{"type": "string", "enum": []string{"domain", "client_ip"}, "description": "Type of match criteria (default: auto-detected)"},
					"target":           map[string]interface{}{"type": "string", "enum": []string{"default", "host", "wireguard"}, "description": "Routing target: 'default', 'host', or 'wireguard'"},
					"host_target":      map[string]interface{}{"type": "string", "description": "Upstream host/IP (e.g. '10.0.0.1:53') when target is 'host'"},
					"wireguard_config": map[string]interface{}{"type": "string", "description": "WireGuard DNS resolver / tunnel endpoint when target is 'wireguard'"},
					"enabled":          map[string]interface{}{"type": "boolean", "description": "Whether rule is enabled (default: true)"},
				},
				"required": []string{"match", "target"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			match, _ := args["match"].(string)
			target, _ := args["target"].(string)
			name, _ := args["name"].(string)
			matchType, _ := args["match_type"].(string)
			hostTarget, _ := args["host_target"].(string)
			wgConfig, _ := args["wireguard_config"].(string)
			enabled := true
			if en, ok := args["enabled"].(bool); ok {
				enabled = en
			}

			match = strings.TrimSpace(match)
			if match == "" {
				return nil, fmt.Errorf("match criteria is required")
			}
			if matchType == "" {
				if net.ParseIP(match) != nil || strings.Contains(match, "/") {
					matchType = "client_ip"
				} else {
					matchType = "domain"
				}
			}

			configLock.Lock()
			rule := RoutingRule{
				ID:              match,
				Name:            name,
				Match:           match,
				MatchType:       matchType,
				Target:          target,
				HostTarget:      hostTarget,
				WireGuardConfig: wgConfig,
				Enabled:         enabled,
				CreatedAt:       time.Now().UTC(),
			}

			updated := false
			for i, r := range config.RoutingRules {
				if strings.EqualFold(r.Match, match) {
					config.RoutingRules[i] = rule
					updated = true
					break
				}
			}
			if !updated {
				config.RoutingRules = append(config.RoutingRules, rule)
			}

			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			updateCorefile()
			restartCoreDNS()

			return map[string]interface{}{
				"success": true,
				"rule":    rule,
				"message": fmt.Sprintf("Routing rule saved for %s (target: %s)", match, target),
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "delete_routing_rule",
			Description: "Delete a policy-based DNS routing rule by match or ID.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"match": map[string]interface{}{"type": "string", "description": "Match criteria (domain or IP) of rule to delete"},
				},
				"required": []string{"match"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			match, _ := args["match"].(string)
			match = strings.TrimSpace(match)
			if match == "" {
				return nil, fmt.Errorf("match is required")
			}

			configLock.Lock()
			var filtered []RoutingRule
			found := false
			for _, r := range config.RoutingRules {
				if strings.EqualFold(r.Match, match) || r.ID == match {
					found = true
					continue
				}
				filtered = append(filtered, r)
			}
			if !found {
				configLock.Unlock()
				return nil, fmt.Errorf("routing rule not found for %s", match)
			}
			config.RoutingRules = filtered
			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			updateCorefile()
			restartCoreDNS()

			return map[string]interface{}{
				"success": true,
				"message": fmt.Sprintf("Routing rule deleted for %s", match),
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

}
