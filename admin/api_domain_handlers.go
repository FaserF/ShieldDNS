package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

func handleDomainStats(w http.ResponseWriter, r *http.Request) {
	domain := NormalizeDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		http.Error(w, "Valid domain required", http.StatusBadRequest)
		return
	}

	ds, err := getDomainStats(domain)
	if err != nil {
		slog.Error("Error fetching domain stats", "domain", domain, "error", err)
		http.Error(w, "Error fetching domain stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ds)
}

func handleDomainClients(w http.ResponseWriter, r *http.Request) {
	domain := NormalizeDomain(r.URL.Query().Get("domain"))
	if domain == "" {
		http.Error(w, "Valid domain required", http.StatusBadRequest)
		return
	}

	limit := 10
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil {
			limit = l
		}
	}

	results, err := getDomainClients(domain, limit)
	if err != nil {
		slog.Error("Error fetching domain clients", "domain", domain, "error", err)
		http.Error(w, "Error fetching domain clients", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleBlockInfo(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}

	blockAttributionLock.RLock()
	blockLists := blockAttribution[domain]
	blockAttributionLock.RUnlock()

	allowLists := getAllowlistAttribution(domain)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":     domain,
		"blocked":    len(blockLists) > 0,
		"lists":      blockLists,
		"allowlists": allowLists,
	})
}

func getAllowlistAttribution(domain string) []string {
	allowAttributionLock.RLock()
	defer allowAttributionLock.RUnlock()

	searchDomain := strings.ToLower(strings.TrimSpace(domain))

	// Direct match
	if lists, ok := allowAttribution[searchDomain]; ok {
		return lists
	}

	// Subdomain match (e.g. for www.google.com check google.com)
	parts := strings.Split(searchDomain, ".")
	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")
		if lists, ok := allowAttribution[parentDomain]; ok {
			return lists
		}
	}

	return nil
}
