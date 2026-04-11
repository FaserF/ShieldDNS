package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func handleStats(w http.ResponseWriter, r *http.Request) {
	statsLock.RLock()
	s := stats
	// Deep copy QueryTypes map to avoid race condition during JSON encoding
	if stats.QueryTypes != nil {
		s.QueryTypes = make(map[string]int64)
		for k, v := range stats.QueryTypes {
			s.QueryTypes[k] = v
		}
	}
	statsLock.RUnlock()

	// Query unique clients in the last 24 hours from DB
	var uniqueClients int
	row := db.QueryRow("SELECT COUNT(DISTINCT client_ip) FROM queries WHERE timestamp > datetime('now', '-24 hours')")
	if err := row.Scan(&uniqueClients); err == nil {
		s.UniqueClients = uniqueClients
	}

	s.Version = Version
	s.CoreDNSVersion = getCoreDNSVersion()

	// Try to read Alpine version
	alpineVer := "3.23"
	if b, err := os.ReadFile("/etc/alpine-release"); err == nil {
		alpineVer = strings.TrimSpace(string(b))
	}
	s.AlpineVersion = alpineVer

	// Get latest versions for update check
	latest := getLatestVersions()
	s.LatestVersion = latest.ShieldDNS
	s.LatestCoreDNSVersion = latest.CoreDNS
	s.LatestAlpineVersion = latest.Alpine

	// Calculate DB size
	if info, err := os.Stat(DBPath); err == nil {
		s.DBSizeMB = float64(info.Size()) / (1024 * 1024)
	}

	// System Stats
	sysStats := make(map[string]interface{})
	fillCPUStats(sysStats)
	fillRAMStats(sysStats)
	fillUptimeStats(sysStats)

	if val, ok := sysStats["ram_used_mb"]; ok {
		s.RAMUsedMB = float64(val.(int64))
	}
	if val, ok := sysStats["ram_total_mb"]; ok {
		s.RAMTotalMB = float64(val.(int64))
	}
	if val, ok := sysStats["uptime_seconds"]; ok {
		s.UptimeSeconds = val.(int64)
	}
	if val, ok := sysStats["cpu_percent"]; ok {
		// Note: stats_linux.go doesn't currently provide cpu_percent, but we can add it or just use load
		s.CPUUsage = val.(float64)
	} else if val, ok := sysStats["cpu_load"]; ok {
		load := val.([]string)
		if len(load) > 0 {
			if f, err := strconv.ParseFloat(load[0], 64); err == nil {
				s.CPUUsage = f
			}
		}
	}

	// Abuse Detection Stats
	configLock.RLock()
	s.NumAutoBlocked = len(config.BlockedClientsInfo)
	configLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func handleQueries(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	statusFilter := r.URL.Query().Get("status")
	clientIP := r.URL.Query().Get("client_ip")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := fmt.Sscanf(limitStr, "%d", &limit); err == nil && l > 0 {
			// limit already set
		}
	}

	// To ensure high performance, we only search within the last 2000 entries if no other strict filters are applied.
	// This prevents full table scans on domain LIKE '%...%' which are unavoidable in SQLite without FTS.
	query := "SELECT timestamp, domain, type, status, client_ip FROM (SELECT * FROM queries ORDER BY id DESC LIMIT 2000) WHERE 1=1"
	var args []interface{}

	if search != "" {
		query += " AND (domain LIKE ? OR client_ip LIKE ?)"
		args = append(args, "%"+search+"%", "%"+search+"%")
	}
	if statusFilter != "" {
		query += " AND status = ?"
		args = append(args, statusFilter)
	}
	if clientIP != "" {
		query += " AND client_ip = ?"
		args = append(args, clientIP)
	}

	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d", limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		slog.Error("Error querying history/logs", "query", query, "error", err)
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	configLock.RLock()
	aliases := config.ClientAliases
	configLock.RUnlock()

	queries := make([]Query, 0)
	for rows.Next() {
		var q Query
		var ts string
		rows.Scan(&ts, &q.Domain, &q.Type, &q.Status, &q.ClientIP)
		q.Time, _ = time.Parse(time.RFC3339, ts)
		if aliases != nil {
			q.ClientAlias = aliases[q.ClientIP]
		}
		queries = append(queries, q)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(queries)
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT
			strftime('%H', timestamp) as hr,
			COUNT(*) as total,
			SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END) as blocked
		FROM queries
		WHERE timestamp > datetime('now', '-24 hours')
		GROUP BY hr
		ORDER BY timestamp ASC
	`)
	if err != nil {
		http.Error(w, "Error querying history", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var result [24]HourStats
	for rows.Next() {
		var hr int
		var total, blocked int64
		rows.Scan(&hr, &total, &blocked)
		if hr >= 0 && hr < 24 {
			result[hr] = HourStats{Total: total, Blocked: blocked}
		}
	}

	currentHr := time.Now().Hour()
	var rotated [24]HourStats
	for i := 0; i < 24; i++ {
		rotated[i] = result[(currentHr+1+i)%24]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rotated)
}

func handleTopBlocked(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT domain, COUNT(*) as count
		FROM queries
		WHERE status = 'Blocked'
		GROUP BY domain
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var domain string
		var count int
		rows.Scan(&domain, &count)
		result = append(result, map[string]interface{}{"domain": domain, "count": count})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleTopClients(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT client_ip, COUNT(*) as count
		FROM queries
		GROUP BY client_ip
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	configLock.RLock()
	aliases := config.ClientAliases
	configLock.RUnlock()

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var client_ip string
		var count int
		rows.Scan(&client_ip, &count)
		if client_ip == "" {
			client_ip = "Unknown"
		}
		alias := ""
		if aliases != nil {
			alias = aliases[client_ip]
		}
		result = append(result, map[string]interface{}{
			"client_ip":    client_ip,
			"client_alias": alias,
			"count":        count,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleTopDomainsForClient(w http.ResponseWriter, r *http.Request) {
	clientIP := r.URL.Query().Get("ip")
	if clientIP == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	rows, err := db.Query(`
		SELECT domain, COUNT(*) as count
		FROM queries
		WHERE client_ip = ?
		GROUP BY domain
		ORDER BY count DESC
		LIMIT 10
	`, clientIP)
	if err != nil {
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var domain string
		var count int
		rows.Scan(&domain, &count)
		result = append(result, map[string]interface{}{"domain": domain, "count": count})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

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
		saveConfigNoLock()
		configLock.Unlock()

		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleClientBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		configLock.RLock()
		defer configLock.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		
		info := config.BlockedClientsInfo
		if info == nil {
			info = make(map[string]BlockedClientInfo)
			// Retrofit any clients in BlockedClients that don't have info
			for _, ip := range config.BlockedClients {
				info[ip] = BlockedClientInfo{Reason: "manual", BlockedAt: time.Now(), Auto: false}
			}
		} else {
			// Ensure all blocked clients are represented
			for _, ip := range config.BlockedClients {
				if _, ok := info[ip]; !ok {
					info[ip] = BlockedClientInfo{Reason: "manual", BlockedAt: time.Now(), Auto: false}
				}
			}
		}
		json.NewEncoder(w).Encode(info)
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
			config.BlockedClientsInfo[ip] = BlockedClientInfo{
				Reason:    "manual",
				BlockedAt: time.Now(),
				Auto:      false,
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

		saveConfigNoLock()
		configLock.Unlock()

		// Apply to CoreDNS immediately
		go updateCorefile()

		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleDomainStats(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
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
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
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

func handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	rows, err := db.Query("SELECT timestamp, domain, type, status, client_ip FROM queries ORDER BY timestamp DESC")
	if err != nil {
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment;filename=shielddns_export.csv")
		fmt.Fprintln(w, "Timestamp,Domain,Type,Status,ClientIP")
		for rows.Next() {
			var ts, domain, qtype, status, ip string
			rows.Scan(&ts, &domain, &qtype, &status, &ip)
			fmt.Fprintf(w, "%s,%s,%s,%s,%s\n", ts, domain, qtype, status, ip)
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment;filename=shielddns_export.json")
		var queries []map[string]string
		for rows.Next() {
			var ts, domain, qtype, status, ip string
			rows.Scan(&ts, &domain, &qtype, &status, &ip)
			queries = append(queries, map[string]string{
				"timestamp": ts,
				"domain":    domain,
				"type":      qtype,
				"status":    status,
				"client_ip": ip,
			})
		}
		json.NewEncoder(w).Encode(queries)
	}
}

func handleBlockInfo(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}

	blockAttributionLock.RLock()
	lists := blockAttribution[domain]
	blockAttributionLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain": domain,
		"lists":  lists,
	})
}
