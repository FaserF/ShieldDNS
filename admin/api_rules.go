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
	saveConfigNoLock()
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
	configLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": enabled})
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

	domain := strings.TrimSpace(req.Domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	for _, sep := range []string{"/", "?", "#"} {
		if idx := strings.Index(domain, sep); idx != -1 {
			domain = domain[:idx]
		}
	}
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}
	if !isValidDomain(domain) {
		http.Error(w, "Invalid domain format", http.StatusBadRequest)
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
			http.Error(w, "IP address required for mapping", http.StatusBadRequest)
			return
		}
		if net.ParseIP(ip) == nil {
			http.Error(w, "Invalid IP address format", http.StatusBadRequest)
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
		http.Error(w, "Type must be 'block', 'allow' or 'mapping'", http.StatusBadRequest)
		return
	}

	saveConfigNoLock()
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

	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
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

	saveConfigNoLock()
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

				saveConfigNoLock()
				configLock.Unlock()
				go updateBlocklist(nil)
				updateCorefile()
				w.WriteHeader(http.StatusOK)
				return
			}
		}
	}

	go updateBlocklist(nil)
	go updateVersions()
	w.WriteHeader(http.StatusAccepted)
}

func handlePresets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DefaultPresets)
}

func handlePresetAllowlists(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DefaultAllowlists)
}

func handleResetLists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.Lock()
	config.Lists = DefaultPresets
	config.Allowlists = DefaultAllowlists
	saveConfigNoLock()
	configLock.Unlock()

	// Trigger background update
	go updateBlocklist(nil)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query required", http.StatusBadRequest)
		return
	}

	// Standardize query (trim http://, paths, trailing dots)
	query = strings.TrimSpace(query)
	query = strings.TrimPrefix(query, "http://")
	query = strings.TrimPrefix(query, "https://")
	query = strings.Split(query, "/")[0]
	query = strings.TrimSuffix(query, ".")

	blockAttributionLock.RLock()
	lists, found := blockAttribution[query]
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
