package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	cachedUniqueClients int
	lastUniqueUpdate    time.Time
)

func handleStats(w http.ResponseWriter, r *http.Request) {
	statsLock.RLock()
	s := stats
	
	// Reload atomic counters to get latest values safely
	s.TotalQueries = atomic.LoadInt64(&stats.TotalQueries)
	s.BlockedQueries = atomic.LoadInt64(&stats.BlockedQueries)
	s.CacheHits = atomic.LoadInt64(&stats.CacheHits)

	if len(s.QueryTypes) > 0 {
		// Deep copy map under read lock
		newQt := make(map[string]int64)
		for k, v := range s.QueryTypes {
			newQt[k] = v
		}
		s.QueryTypes = newQt
	}
	statsLock.RUnlock()

	// Query unique clients (cached for 1 minute)
	statsLock.RLock()
	lastUpdate := lastUniqueUpdate
	statsLock.RUnlock()

	if db != nil && time.Since(lastUpdate) > 1*time.Minute {
		var uniqueClients int
		err := db.QueryRow("SELECT COUNT(DISTINCT client_ip) FROM queries WHERE timestamp > datetime('now', '-24 hours')").Scan(&uniqueClients)
		if err == nil {
			statsLock.Lock()
			cachedUniqueClients = uniqueClients
			lastUniqueUpdate = time.Now()
			statsLock.Unlock()
		} else {
			slog.Debug("Failed to query unique clients for stats", "error", err)
		}
	}
	
	statsLock.RLock()
	s.UniqueClients = cachedUniqueClients
	statsLock.RUnlock()

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
	} else if ram, ok := sysStats["ram"].(map[string]interface{}); ok {
		if used, ok := ram["used"].(float64); ok {
			s.RAMUsedMB = used / (1024 * 1024)
		}
	}

	if val, ok := sysStats["ram_total_mb"]; ok {
		s.RAMTotalMB = float64(val.(int64))
	} else if ram, ok := sysStats["ram"].(map[string]interface{}); ok {
		if total, ok := ram["total"].(float64); ok {
			s.RAMTotalMB = total / (1024 * 1024)
		}
	}
	if val, ok := sysStats["uptime_seconds"]; ok {
		s.UptimeSeconds = val.(int64)
	}
	if val, ok := sysStats["cpu_percent"]; ok {
		// Note: stats_linux.go doesn't currently provide cpu_percent, but we can add it or just use load
		s.CPUUsage = val.(float64)
	} else if val, ok := sysStats["cpu_load"]; ok {
		// Handle different types depending on platform (string slice from linux, float slice from others)
		if load, ok := val.([]string); ok && len(load) > 0 {
			if f, err := strconv.ParseFloat(load[0], 64); err == nil {
				s.CPUUsage = f
			}
		} else if load, ok := val.([]float64); ok && len(load) > 0 {
			s.CPUUsage = load[0]
		}
	}

	// Abuse Detection Stats
	configLock.RLock()
	s.NumAutoBlocked = len(config.BlockedClientsInfo)
	configLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func handleGetAllClients(w http.ResponseWriter, r *http.Request) {
	clients, err := getAllClients()
	if err != nil {
		slog.Error("Error fetching all clients", "error", err)
		http.Error(w, "Error fetching clients", http.StatusInternalServerError)
		return
	}

	configLock.RLock()
	aliases := config.ClientAliases
	blockedMap := make(map[string]bool)
	for _, ip := range config.BlockedClients {
		blockedMap[ip] = true
	}
	configLock.RUnlock()

	for _, c := range clients {
		ip := c["ip"].(string)
		if alias, ok := aliases[ip]; ok {
			c["alias"] = alias
		} else {
			c["alias"] = ""
		}
		c["blocked"] = blockedMap[ip]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clients)
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

	// Optimization: If a specific client_ip is provided, we can skip the subquery/limit-2000 optimization
	// because client_ip is indexed and exact matches are very fast.
	var baseQuery string
	if clientIP != "" {
		baseQuery = "SELECT timestamp, domain, type, status, client_ip FROM queries WHERE 1=1"
	} else {
		// General search/overview: only search within last 2000 for performance
		baseQuery = "SELECT timestamp, domain, type, status, client_ip FROM (SELECT * FROM queries ORDER BY id DESC LIMIT 2000) WHERE 1=1"
	}
	
	query := baseQuery
	var args []interface{}

	if search != "" {
		query += " AND (domain LIKE ? OR client_ip LIKE ?)"
		args = append(args, "%"+search+"%", "%"+search+"%")
	}
	if statusFilter != "" {
		if statusFilter == "Blocked" {
			query += " AND status LIKE ?"
			args = append(args, StatusBlocked+"%")
		} else {
			query += " AND status = ?"
			args = append(args, statusFilter)
		}
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
			SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END) as blocked
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
		WHERE status LIKE 'Blocked%'
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
			// Protect critical clients from accidental blocking
			if ip == "DoH Proxy" || ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
				http.Error(w, "Cannot block critical internal clients (DoH Proxy, localhost, loopback). Blocking these would break internal communications and server stability.", http.StatusForbidden)
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

func handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	rows, err := db.Query("SELECT timestamp, domain, type, status, client_ip FROM queries ORDER BY timestamp DESC")
	if err != nil {
		slog.Error("Export failed: DB query error", "error", err)
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment;filename=shielddns_export.csv")
		
		writer := csv.NewWriter(w)
		defer writer.Flush()

		// Header
		writer.Write([]string{"Timestamp", "Domain", "Type", "Status", "ClientIP"})

		for rows.Next() {
			var ts, domain, qtype, status, ip string
			if err := rows.Scan(&ts, &domain, &qtype, &status, &ip); err == nil {
				writer.Write([]string{ts, domain, qtype, status, ip})
			}
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment;filename=shielddns_export.json")
		
		// Use a streaming JSON encoder
		enc := json.NewEncoder(w)
		w.Write([]byte("["))
		
		first := true
		for rows.Next() {
			var ts, domain, qtype, status, ip string
			if err := rows.Scan(&ts, &domain, &qtype, &status, &ip); err == nil {
				if !first {
					w.Write([]byte(","))
				}
				first = false
				enc.Encode(map[string]string{
					"timestamp": ts,
					"domain":    domain,
					"type":      qtype,
					"status":    status,
					"client_ip": ip,
				})
			}
		}
		w.Write([]byte("]"))
	}
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

	// Check allowlists only if not explicitly blocked by a custom rule
	allowLists := getAllowlistAttribution(domain)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain":     domain,
		"blocked":    len(blockLists) > 0,
		"lists":      blockLists,
		"allowlists": allowLists,
	})
}

// getAllowlistAttribution scans all enabled allowlists for the given domain.
// This is done on-demand as allowlist attribution is not stored globally for performance reasons.
func getAllowlistAttribution(domain string) []string {
	configLock.RLock()
	enabledAllowlists := make([]List, 0)
	for _, l := range config.Allowlists {
		if l.Enabled {
			enabledAllowlists = append(enabledAllowlists, l)
		}
	}
	configLock.RUnlock()

	if len(enabledAllowlists) == 0 {
		return nil
	}

	var matchedLists []string
	searchDomain := strings.ToLower(strings.TrimSpace(domain))

	for _, list := range enabledAllowlists {
		// Read the list file directly to check for the domain
		// This ensures we're accurate without keeping all allowlist mappings in RAM
		filePath := filepath.Join(DataDir, "lists", "allow", fmt.Sprintf("%x.txt", strings.ToLower(list.URL)))
		if _, err := os.Stat(filePath); err != nil {
			// Fallback to name-based if hash fails (legacy)
			filePath = filepath.Join(DataDir, "lists", "allow", list.Name+".txt")
		}

		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		// Fast check: is the domain in the file?
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}
			// Handle ||domain^ or 0.0.0.0 domain or raw domain
			parsed := line
			if strings.HasPrefix(parsed, "@@") {
				parsed = parsed[2:]
			}
			if strings.HasPrefix(parsed, "||") {
				parsed = strings.Split(strings.TrimPrefix(parsed, "||"), "^")[0]
			} else if strings.Contains(parsed, " ") {
				parts := strings.Fields(parsed)
				if len(parts) >= 2 {
					parsed = parts[1]
				}
			}

			if strings.ToLower(parsed) == searchDomain {
				matchedLists = append(matchedLists, list.Name)
				break
			}
		}
	}

	return matchedLists
}
func handleStatsHistory(w http.ResponseWriter, r *http.Request) {
	daysStr := r.URL.Query().Get("days")
	days := 7
	if d, err := strconv.Atoi(daysStr); err == nil && d > 0 {
		days = d
	}
	if days > 365 {
		days = 365
	}

	rows, err := db.Query(`
		SELECT timestamp, total, blocked, cache_hits 
		FROM hourly_stats 
		WHERE timestamp > datetime('now', ?)
		ORDER BY timestamp ASC
	`, fmt.Sprintf("-%d days", days))

	if err != nil {
		slog.Error("Error querying historical stats", "error", err)
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type HistoryPoint struct {
		Time      time.Time `json:"time"`
		Total     int64     `json:"total"`
		Blocked   int64     `json:"blocked"`
		CacheHits int64     `json:"cache_hits"`
	}

	history := make([]HistoryPoint, 0)
	for rows.Next() {
		var hp HistoryPoint
		var ts string
		rows.Scan(&ts, &hp.Total, &hp.Blocked, &hp.CacheHits)
		hp.Time, _ = ParseFlexibleTime(ts)
		history = append(history, hp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

func handleClearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := ClearQueryLogs(); err != nil {
		http.Error(w, "Error clearing logs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
