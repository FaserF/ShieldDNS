package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// handleRoutingRules handles GET (list), POST (add/update), and DELETE for routing rules
func handleRoutingRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configLock.RLock()
		rules := append([]RoutingRule{}, config.RoutingRules...)
		wgGateway := config.WireGuardGateway
		configLock.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rules":             rules,
			"wireguard_gateway": wgGateway,
		})

	case http.MethodPost:
		var req struct {
			ID               string `json:"id"`
			Name             string `json:"name"`
			Match            string `json:"match"`
			MatchType        string `json:"match_type"` // "domain" or "client_ip"
			Target           string `json:"target"`     // "default", "host", "wireguard"
			HostTarget       string `json:"host_target"`
			WireGuardConfig  string `json:"wireguard_config"`
			WireGuardGateway string `json:"wireguard_gateway"`
			Enabled          *bool  `json:"enabled"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, "Invalid request payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Optional gateway update
		if req.WireGuardGateway != "" {
			configLock.Lock()
			config.WireGuardGateway = strings.TrimSpace(req.WireGuardGateway)
			_ = saveConfigNoLock()
			configLock.Unlock()
		}

		match := strings.TrimSpace(req.Match)
		if match == "" {
			sendJSONError(w, "Match criteria is required", http.StatusUnprocessableEntity)
			return
		}

		matchType := strings.ToLower(strings.TrimSpace(req.MatchType))
		if matchType == "" {
			if net.ParseIP(match) != nil || strings.Contains(match, "/") {
				matchType = "client_ip"
			} else {
				matchType = "domain"
			}
		}

		if matchType != "domain" && matchType != "client_ip" {
			sendJSONError(w, "match_type must be 'domain' or 'client_ip'", http.StatusBadRequest)
			return
		}

		if matchType == "domain" {
			match = NormalizeDomain(match)
			if match == "" || !isValidDomain(match) {
				sendJSONError(w, "Invalid domain match format", http.StatusBadRequest)
				return
			}
		} else {
			// Validate IP or CIDR
			if strings.Contains(match, "/") {
				if _, _, err := net.ParseCIDR(match); err != nil {
					sendJSONError(w, "Invalid CIDR IP match format", http.StatusBadRequest)
					return
				}
			} else {
				if net.ParseIP(match) == nil {
					sendJSONError(w, "Invalid client IP match format", http.StatusBadRequest)
					return
				}
			}
		}

		target := strings.ToLower(strings.TrimSpace(req.Target))
		if target == "" {
			target = "default"
		}
		if target != "default" && target != "host" && target != "wireguard" {
			sendJSONError(w, "target must be 'default', 'host' or 'wireguard'", http.StatusBadRequest)
			return
		}

		if target == "host" && strings.TrimSpace(req.HostTarget) == "" {
			sendJSONError(w, "host_target is required when target is 'host'", http.StatusBadRequest)
			return
		}

		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}

		ruleID := strings.TrimSpace(req.ID)
		if ruleID == "" {
			ruleID = uuid.New().String()
		}

		rule := RoutingRule{
			ID:              ruleID,
			Name:            strings.TrimSpace(req.Name),
			Match:           match,
			MatchType:       matchType,
			Target:          target,
			HostTarget:      strings.TrimSpace(req.HostTarget),
			WireGuardConfig: strings.TrimSpace(req.WireGuardConfig),
			Enabled:         enabled,
			CreatedAt:       time.Now().UTC(),
		}

		configLock.Lock()
		updated := false
		for i, r := range config.RoutingRules {
			if r.ID == ruleID {
				rule.CreatedAt = r.CreatedAt
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
			slog.Error("Failed to save routing rule", "error", err)
			sendJSONError(w, "Failed to save configuration", http.StatusInternalServerError)
			return
		}
		configLock.Unlock()

		updateCorefile()
		restartCoreDNS()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"rule":    rule,
			"message": fmt.Sprintf("Routing rule saved for %s", match),
		})

	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		match := r.URL.Query().Get("match")
		if id == "" && match == "" {
			sendJSONError(w, "Query parameter 'id' or 'match' is required", http.StatusBadRequest)
			return
		}

		configLock.Lock()
		var filtered []RoutingRule
		found := false
		for _, r := range config.RoutingRules {
			if (id != "" && r.ID == id) || (match != "" && strings.EqualFold(r.Match, match)) {
				found = true
				continue
			}
			filtered = append(filtered, r)
		}

		if !found {
			configLock.Unlock()
			sendJSONError(w, "Routing rule not found", http.StatusNotFound)
			return
		}

		config.RoutingRules = filtered
		if err := saveConfigNoLock(); err != nil {
			configLock.Unlock()
			sendJSONError(w, "Failed to save configuration", http.StatusInternalServerError)
			return
		}
		configLock.Unlock()

		updateCorefile()
		restartCoreDNS()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
