package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func handleClientStats(w http.ResponseWriter, r *http.Request) {
	clientIP := r.URL.Query().Get("ip")
	if clientIP == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	cs, err := getClientStats(clientIP)
	if err != nil {
		slog.Error("Error fetching client stats", "ip", clientIP, "error", err)
		http.Error(w, "Error fetching client stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cs)
}

func handleClientTopBlocked(w http.ResponseWriter, r *http.Request) {
	clientIP := r.URL.Query().Get("ip")
	if clientIP == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	limit := 10
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil {
			limit = l
		}
	}

	results, err := getClientTopBlocked(clientIP, limit)
	if err != nil {
		slog.Error("Error fetching top blocked for client", "ip", clientIP, "error", err)
		http.Error(w, "Error fetching top blocked", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleClientAlias(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		configLock.RLock()
		defer configLock.RUnlock()

		if config.ClientAliases == nil {
			config.ClientAliases = make(map[string]string)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config.ClientAliases)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			IP    string `json:"ip"`
			Alias string `json:"alias"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.IP == "" {
			http.Error(w, "IP required", http.StatusBadRequest)
			return
		}

		configLock.Lock()
		if config.ClientAliases == nil {
			config.ClientAliases = make(map[string]string)
		}
		if req.Alias == "" {
			delete(config.ClientAliases, req.IP)
		} else {
			config.ClientAliases[req.IP] = req.Alias
		}
		if err := saveConfigNoLock(); err != nil {
			slog.Error("Failed to save config in handleClientAlias", "error", err)
			http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
			configLock.Unlock()
			return
		}
		configLock.Unlock()

		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleClientBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		configLock.Lock() // Use write lock to allow retrofit
		defer configLock.Unlock()
		w.Header().Set("Content-Type", "application/json")

		if config.BlockedClientsInfo == nil {
			config.BlockedClientsInfo = make(map[string]BlockedClientInfo)
		}

		changed := false
		// Retrofit any clients in BlockedClients that don't have info or have missing/pending country codes
		for _, ip := range config.BlockedClients {
			entry, ok := config.BlockedClientsInfo[ip]
			if !ok {
				cc := GetCountryCodeCached(ip)
				config.BlockedClientsInfo[ip] = BlockedClientInfo{
					Reason:      "manual",
					BlockedAt:   time.Now(),
					Auto:        false,
					CountryCode: cc,
				}
				changed = true
			} else if entry.CountryCode == "" || entry.CountryCode == "-" {
				// Initialize or upgrade missing/pending country code
				cc := GetCountryCodeCached(ip)
				if cc != "" && cc != entry.CountryCode {
					entry.CountryCode = cc
					config.BlockedClientsInfo[ip] = entry
					changed = true
				}
			}
		}

		if changed {
			if err := saveConfigNoLock(); err != nil {
				slog.Error("Failed to save config in handleClientBlock", "error", err)
				http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
				configLock.Unlock()
				return
			}
		}

		json.NewEncoder(w).Encode(config.BlockedClientsInfo)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			IP     string `json:"ip"`
			Action string `json:"action"` // "block" or "unblock"
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		ip := strings.TrimSpace(req.IP)
		if ip == "" {
			http.Error(w, "IP required", http.StatusBadRequest)
			return
		}

		configLock.Lock()
		if config.BlockedClients == nil {
			config.BlockedClients = []string{}
		}

		if req.Action == "block" {
			// Protect critical clients from accidental blocking
			if IsCriticalIP(ip, config.BlockPageIP, config.AutoblockWhitelist) {
				http.Error(w, "Cannot block critical internal clients (DoH Proxy, localhost, loopback, or server IP). Blocking these would break internal communications and server stability.", http.StatusForbidden)
				configLock.Unlock()
				return
			}

			// Add if not already present
			found := false
			for _, c := range config.BlockedClients {
				if c == ip {
					found = true
					break
				}
			}
			if !found {
				config.BlockedClients = append(config.BlockedClients, ip)
			}
			if config.BlockedClientsInfo == nil {
				config.BlockedClientsInfo = make(map[string]BlockedClientInfo)
			}
			cc := GetCountryCodeCached(ip)
			config.BlockedClientsInfo[ip] = BlockedClientInfo{
				Reason:      "manual",
				BlockedAt:   time.Now(),
				Auto:        false,
				CountryCode: cc,
			}
		} else {
			// Remove the IP
			updated := config.BlockedClients[:0]
			for _, c := range config.BlockedClients {
				if c != ip {
					updated = append(updated, c)
				}
			}
			config.BlockedClients = updated
			if config.BlockedClientsInfo != nil {
				delete(config.BlockedClientsInfo, ip)
			}
		}

		if err := saveConfigNoLock(); err != nil {
			slog.Error("Failed to save config in handleClientBlock (POST)", "error", err)
			http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
			configLock.Unlock()
			return
		}
		configLock.Unlock()

		// Apply to CoreDNS immediately
		go updateCorefile()

		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
