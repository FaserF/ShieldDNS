package main

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

func handleToggleFiltering(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	configLock.Lock()
	config.FilteringEnabled = req.Enabled
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleToggleFiltering", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		configLock.Unlock()
		return
	}
	configLock.Unlock()

	updateCorefile()

	status := "Disabled"
	if req.Enabled {
		status = "Enabled"
	}
	slog.Info("Global protection status changed", "status", status)

	w.WriteHeader(http.StatusOK)
}

func handleFilteringStatus(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	enabled := config.FilteringEnabled
	abuseEnabled := config.AbuseDetectionEnabled
	configLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{
		"enabled":                 enabled,
		"abuse_detection_enabled": abuseEnabled,
	})
}

func handleRuleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
		Type   string `json:"type"` // "block", "allow", "mapping"
		IP     string `json:"ip"`   // only for "mapping"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	domain := NormalizeDomain(req.Domain)
	if domain == "" {
		sendJSONError(w, "Domain required", http.StatusUnprocessableEntity)
		return
	}
	if !isValidDomain(domain) {
		sendJSONError(w, "Invalid domain format", http.StatusBadRequest)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	if req.Type == "block" {
		// Remove from allowed if present
		var clean []string
		for _, d := range config.CustomAllowed {
			if d != domain {
				clean = append(clean, d)
			}
		}
		config.CustomAllowed = clean

		// Add to blocked if not present
		exists := false
		for _, d := range config.CustomBlocked {
			if d == domain {
				exists = true
				break
			}
		}
		if !exists {
			config.CustomBlocked = append(config.CustomBlocked, domain)
		}
	} else if req.Type == "allow" {
		// Remove from blocked if present
		var clean []string
		for _, d := range config.CustomBlocked {
			if d != domain {
				clean = append(clean, d)
			}
		}
		config.CustomBlocked = clean

		// Add to allowed if not present
		exists := false
		for _, d := range config.CustomAllowed {
			if d == domain {
				exists = true
				break
			}
		}
		if !exists {
			config.CustomAllowed = append(config.CustomAllowed, domain)
		}
	} else if req.Type == "mapping" {
		ip := strings.TrimSpace(req.IP)
		if ip == "" {
			sendJSONError(w, "IP address required for mapping", http.StatusBadRequest)
			return
		}
		if net.ParseIP(ip) == nil {
			sendJSONError(w, "Invalid IP address format", http.StatusBadRequest)
			return
		}

		// Remove from others
		newBlocked := []string{}
		for _, d := range config.CustomBlocked {
			if d != domain {
				newBlocked = append(newBlocked, d)
			}
		}
		config.CustomBlocked = newBlocked

		newAllowed := []string{}
		for _, d := range config.CustomAllowed {
			if d != domain {
				newAllowed = append(newAllowed, d)
			}
		}
		config.CustomAllowed = newAllowed

		// Add/Update mapping
		if config.CustomMappings == nil {
			config.CustomMappings = make(map[string]string)
		}
		config.CustomMappings[domain] = ip
	} else {
		sendJSONError(w, "Type must be 'block', 'allow' or 'mapping'", http.StatusBadRequest)
		return
	}

	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleRuleAdd", "error", err)
		sendJSONError(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	reloadRulesFastNoLock(config.Clone())

	w.WriteHeader(http.StatusOK)
}

func handleRuleRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	domain := NormalizeDomain(req.Domain)
	if domain == "" {
		sendJSONError(w, "Domain required", http.StatusUnprocessableEntity)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	var cleanBlocked []string
	for _, d := range config.CustomBlocked {
		if d != domain {
			cleanBlocked = append(cleanBlocked, d)
		}
	}
	config.CustomBlocked = cleanBlocked

	var cleanAllowed []string
	for _, d := range config.CustomAllowed {
		if d != domain {
			cleanAllowed = append(cleanAllowed, d)
		}
	}
	config.CustomAllowed = cleanAllowed

	if config.CustomMappings != nil {
		delete(config.CustomMappings, domain)
	}

	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleRuleRemove", "error", err)
		sendJSONError(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	reloadRulesFastNoLock(config.Clone())

	w.WriteHeader(http.StatusOK)
}

func handleGetCountries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetCountryList())
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.ContentLength > 0 {
		var req struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			if req.Action == "recommended" {
				configLock.Lock()

				// Apply Recommended Blocklists
				for _, rec := range DefaultPresets {
					if !rec.IsRecommended {
						continue
					}
					exists := false
					for i, l := range config.Lists {
						if l.URL == rec.URL {
							config.Lists[i].Enabled = true
							exists = true
							break
						}
					}
					if !exists {
						newList := rec
						newList.Enabled = true
						config.Lists = append(config.Lists, newList)
					}
				}

				// Deduplicate tiers for efficiency (e.g., HaGeZi Multi Tiers)
				// If Pro is enabled, disable Normal and Light
				proEnabled := false
				for _, l := range config.Lists {
					if strings.Contains(l.Name, "(Pro)") && l.Enabled {
						proEnabled = true
						break
					}
				}
				if proEnabled {
					for i, l := range config.Lists {
						if (strings.Contains(l.Name, "(Light)") || strings.Contains(l.Name, "(Normal)")) && strings.Contains(l.Name, "HaGeZi") {
							config.Lists[i].Enabled = false
						}
					}
				}

				// Apply Recommended Allowlists
				for _, rec := range DefaultAllowlists {
					if !rec.IsRecommended {
						continue
					}
					exists := false
					for i, l := range config.Allowlists {
						if l.URL == rec.URL {
							config.Allowlists[i].Enabled = true
							exists = true
							break
						}
					}
					if !exists {
						newList := rec
						newList.Enabled = true
						config.Allowlists = append(config.Allowlists, newList)
					}
				}

				if err := saveConfigNoLock(); err != nil {
					slog.Error("Failed to save config in handleRefresh", "error", err)
					http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
					configLock.Unlock()
					return
				}
				configLock.Unlock()
				go updateBlocklist(nil, true)
				updateCorefile()
				w.WriteHeader(http.StatusOK)
				return
			}
		}
	}

	go updateBlocklist(nil, true)
	go updateVersions()
	w.WriteHeader(http.StatusAccepted)
}

func handlePresets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Merge metadata from cache if available
	response := make([]List, len(DefaultPresets))
	copy(response, DefaultPresets)

	metadataMu.RLock()
	for i, p := range response {
		if m, ok := metadataCache[p.URL]; ok {
			response[i].Entries = m.Entries
			response[i].UpdatedAt = m.UpdatedAt
			response[i].RemoteUpdatedAt = m.RemoteUpdatedAt
		}
	}
	metadataMu.RUnlock()

	json.NewEncoder(w).Encode(response)
}

func handlePresetAllowlists(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Merge metadata from cache if available
	response := make([]List, len(DefaultAllowlists))
	copy(response, DefaultAllowlists)

	metadataMu.RLock()
	for i, p := range response {
		if m, ok := metadataCache[p.URL]; ok {
			response[i].Entries = m.Entries
			response[i].UpdatedAt = m.UpdatedAt
			response[i].RemoteUpdatedAt = m.RemoteUpdatedAt
		}
	}
	metadataMu.RUnlock()

	json.NewEncoder(w).Encode(response)
}

func handleResetLists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.Lock()
	config.Lists = DefaultPresets
	config.Allowlists = DefaultAllowlists
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleResetLists", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		configLock.Unlock()
		return
	}
	configLock.Unlock()

	// Trigger background update only if save succeeded
	go updateBlocklist(nil, true)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query required", http.StatusBadRequest)
		return
	}

	// Standardize query
	query = NormalizeDomain(query)
	if query == "" {
		http.Error(w, "Valid domain query required", http.StatusBadRequest)
		return
	}

	blockAttributionLock.RLock()
	lists, found := blockAttribution[query]
	if !found {
		// Check for wildcard match
		parts := strings.Split(query, ".")
		for i := 1; i < len(parts); i++ {
			wildcard := "*." + strings.Join(parts[i:], ".")
			if l, ok := blockAttribution[wildcard]; ok {
				lists = l
				found = true
				break
			}
		}
	}
	blockAttributionLock.RUnlock()

	// If not found directly, check if the blocklist has even been loaded
	// We can check if the map is empty but the config has lists
	configLock.RLock()
	hasLists := len(config.Lists) > 0 || len(config.CustomBlocked) > 0
	configLock.RUnlock()

	if !found && hasLists && len(blockAttribution) == 0 {
		http.Error(w, "Blocklist still loading", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked": found,
		"lists":   lists,
	})
}
