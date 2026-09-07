package main

import (
	"fmt"
	"strings"
)

var mcpFilteringTools = []mcpToolDefinition{
	{
		tool: mcpTool{
			Name:        "search_domain_status",
			Description: "Check whether a domain is currently blocked, whitelisted, or resolved normally by any active lists, custom rules, or client-specific rules.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"domain":    map[string]interface{}{"type": "string", "description": "The domain name to check"},
					"client_ip": map[string]interface{}{"type": "string", "description": "Optional client IP to evaluate client-specific filter rules"},
				},
				"required": []string{"domain"},
			},
		},
		requiredPerm: "read:logs",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			domain, _ := args["domain"].(string)
			clientIP, _ := args["client_ip"].(string)
			clientIP = strings.TrimSpace(clientIP)
			domain = NormalizeDomain(domain)
			if domain == "" {
				return nil, fmt.Errorf("domain is required")
			}

			// Check client-specific rules first if client_ip provided
			if clientIP != "" {
				configLock.RLock()
				clientRules := append([]ClientRule{}, config.ClientRules...)
				configLock.RUnlock()
				for _, cr := range clientRules {
					if cr.ClientIP == clientIP && (strings.EqualFold(cr.Domain, domain) || strings.HasSuffix(domain, "."+cr.Domain)) {
						return map[string]interface{}{
							"domain":           domain,
							"client_ip":        clientIP,
							"client_rule":      map[string]interface{}{"domain": cr.Domain, "is_allowlist": cr.IsAllowlist},
							"blocked":          !cr.IsAllowlist,
							"allowed":          cr.IsAllowlist,
							"lists":            []string{"Client Rule"},
							"effective_status": cr.IsAllowlist,
						}, nil
					}
				}
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
			Description: "Add a domain to the Custom Whitelist (allowed) or Custom Blacklist (blocked), optionally scoped to a specific client IP ($client modifier).",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"type":      map[string]interface{}{"type": "string", "enum": []string{"blocked", "allowed"}, "description": "Rule type: 'blocked' or 'allowed'"},
					"domain":    map[string]interface{}{"type": "string", "description": "Domain name to add (e.g. 'ads.example.com' or AdGuard rule format)"},
					"client_ip": map[string]interface{}{"type": "string", "description": "Optional client IP for client-specific filtering ($client='<IP>')"},
				},
				"required": []string{"type", "domain"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			ruleType, _ := args["type"].(string)
			rawDomain, _ := args["domain"].(string)
			clientIP, _ := args["client_ip"].(string)
			clientIP = strings.TrimSpace(clientIP)

			var domain string
			rawTrimmed := strings.TrimSpace(rawDomain)
			if parsedRule := ParseAdblockRule(rawTrimmed); parsedRule != nil && parsedRule.Domain != "" {
				domain = parsedRule.Domain
				if parsedRule.IsAllowlist && ruleType == "blocked" {
					ruleType = "allowed"
				}
				if parsedRule.ClientIP != "" && clientIP == "" {
					clientIP = parsedRule.ClientIP
				}
			} else {
				domain = NormalizeDomain(rawTrimmed)
			}

			if domain == "" || !isValidDomain(domain) {
				return nil, fmt.Errorf("invalid domain format: %s", rawDomain)
			}

			configLock.Lock()
			if clientIP != "" {
				// Client-specific rule
				var cleanClientRules []ClientRule
				for _, cr := range config.ClientRules {
					if !(strings.EqualFold(cr.Domain, domain) && cr.ClientIP == clientIP) {
						cleanClientRules = append(cleanClientRules, cr)
					}
				}
				cleanClientRules = append(cleanClientRules, ClientRule{
					Domain:      domain,
					ClientIP:    clientIP,
					IsAllowlist: (ruleType == "allowed"),
				})
				config.ClientRules = cleanClientRules

				if err := saveConfigNoLock(); err != nil {
					configLock.Unlock()
					return nil, fmt.Errorf("failed to save config: %w", err)
				}
				configLock.Unlock()

				reloadRulesFastNoLock(config.Clone())
				return map[string]interface{}{
					"success":   true,
					"message":   fmt.Sprintf("Added client rule for %s (client: %s, type: %s)", domain, clientIP, ruleType),
					"type":      ruleType,
					"domain":    domain,
					"client_ip": clientIP,
				}, nil
			}
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
			Description: "Remove a domain from Custom Whitelist or Custom Blacklist, or remove a client-specific rule.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"type":      map[string]interface{}{"type": "string", "enum": []string{"blocked", "allowed"}, "description": "Rule type: 'blocked' or 'allowed'"},
					"domain":    map[string]interface{}{"type": "string", "description": "Domain name to remove"},
					"client_ip": map[string]interface{}{"type": "string", "description": "Optional client IP of client-specific rule to remove"},
				},
				"required": []string{"type", "domain"},
			},
		},
		requiredPerm: "write:rules",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			ruleType, _ := args["type"].(string)
			rawDomain, _ := args["domain"].(string)
			clientIP, _ := args["client_ip"].(string)
			clientIP = strings.TrimSpace(clientIP)

			var domain string
			rawTrimmed := strings.TrimSpace(rawDomain)
			if parsedRule := ParseAdblockRule(rawTrimmed); parsedRule != nil && parsedRule.Domain != "" {
				domain = parsedRule.Domain
				if parsedRule.ClientIP != "" && clientIP == "" {
					clientIP = parsedRule.ClientIP
				}
			} else {
				domain = NormalizeDomain(rawTrimmed)
			}

			configLock.Lock()
			if clientIP != "" {
				newClientRules := make([]ClientRule, 0, len(config.ClientRules))
				for _, cr := range config.ClientRules {
					if !(strings.EqualFold(cr.Domain, domain) && cr.ClientIP == clientIP) {
						newClientRules = append(newClientRules, cr)
					}
				}
				config.ClientRules = newClientRules
				if err := saveConfigNoLock(); err != nil {
					configLock.Unlock()
					return nil, fmt.Errorf("failed to save config: %w", err)
				}
				configLock.Unlock()
				reloadRulesFastNoLock(config.Clone())
				return map[string]interface{}{
					"success":   true,
					"message":   fmt.Sprintf("Removed client rule for %s (client: %s)", domain, clientIP),
					"domain":    domain,
					"client_ip": clientIP,
				}, nil
			}

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
			Name:        "list_client_rules",
			Description: "List all active client-specific DNS filtering rules ($client modifiers).",
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
				"client_rules": config.ClientRules,
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
}
