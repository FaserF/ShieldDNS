package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	cachedUniqueClients int
	lastUniqueUpdate    time.Time
	statsCache          Stats
	statsCacheTime      time.Time
	statsCacheMu        sync.Mutex
)

func handleStats(w http.ResponseWriter, r *http.Request) {
	statsCacheMu.Lock()
	if time.Since(statsCacheTime) < 10*time.Second {
		s := statsCache
		statsCacheMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(s)
		return
	}
	statsCacheMu.Unlock()

	statsLock.RLock()
	s := stats
	statsLock.RUnlock()

	// 1. Get true 24h rolling totals from DB
	total, blocked, cacheHits, err := Get24hStats()
	if err != nil {
		slog.Error("Error getting 24h stats for API", "error", err)
		// Fallback to atomic counters if DB fails
		s.TotalQueries = atomic.LoadInt64(&stats.TotalQueries)
		s.BlockedQueries = atomic.LoadInt64(&stats.BlockedQueries)
		s.CacheHits = atomic.LoadInt64(&stats.CacheHits)
	} else {
		s.TotalQueries = total
		s.BlockedQueries = blocked
		s.CacheHits = cacheHits
	}

	// 2. Refresh dynamic fields
	blockAttributionLock.RLock()
	s.BlockedDomains = int64(len(blockAttribution))
	blockAttributionLock.RUnlock()

	// Unique clients (cached for 1 minute independently)
	statsLock.RLock()
	lastUpdate := lastUniqueUpdate
	cachedUC := cachedUniqueClients
	statsLock.RUnlock()

	if db != nil && time.Since(lastUpdate) > 1*time.Minute {
		var uniqueClients int
		err := db.QueryRow("SELECT COUNT(DISTINCT client_ip) FROM queries WHERE timestamp > datetime('now', '-24 hours') AND client_ip != 'DoH Proxy'").Scan(&uniqueClients)
		if err == nil {
			statsLock.Lock()
			cachedUniqueClients = uniqueClients
			lastUniqueUpdate = time.Now()
			statsLock.Unlock()
			s.UniqueClients = uniqueClients
		} else {
			s.UniqueClients = cachedUC
		}
	} else {
		s.UniqueClients = cachedUC
	}

	// 3. Versions and Metadata
	s.Version = Version
	s.CoreDNSVersion = getCoreDNSVersion()
	s.AlpineVersion = getOSVersion()
	latest := getLatestVersions()
	s.LatestVersion = latest.ShieldDNS
	s.LatestCoreDNSVersion = latest.CoreDNS
	s.LatestAlpineVersion = latest.Alpine

	if info, err := os.Stat(DBPath); err == nil {
		s.DBSizeMB = float64(info.Size()) / (1024 * 1024)
	}

	// 4. System Resource Usage
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
		s.CPUUsage = val.(float64)
	} else if val, ok := sysStats["cpu_load"]; ok {
		if load, ok := val.([]string); ok && len(load) > 0 {
			if f, err := strconv.ParseFloat(load[0], 64); err == nil {
				s.CPUUsage = f
			}
		}
	}

	configLock.RLock()
	s.NumAutoBlocked = len(config.BlockedClientsInfo)
	configLock.RUnlock()

	// Update Cache
	statsCacheMu.Lock()
	statsCache = s
	statsCacheTime = time.Now()
	statsCacheMu.Unlock()

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
	fromTime := r.URL.Query().Get("from_time")
	toTime := r.URL.Query().Get("to_time")

	limit := 100
	if limitStr != "" {
		if l, err := fmt.Sscanf(limitStr, "%d", &limit); err == nil && l > 0 {
			// limit already set
		}
	}

	// Optimization: If searching or filtering by client, we search the full table.
	// Only for general overview (no filters) we limit to the latest 2000 for performance.
	var baseQuery string
	fields := "timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms"
	if search != "" || clientIP != "" || fromTime != "" || toTime != "" {
		baseQuery = "SELECT " + fields + " FROM queries WHERE 1=1"
	} else {
		baseQuery = "SELECT " + fields + " FROM (SELECT * FROM queries ORDER BY id DESC LIMIT 2000) WHERE 1=1"
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
	if fromTime != "" {
		// Replace 'T' with space for SQLite datetime comparison
		query += " AND timestamp >= ?"
		args = append(args, strings.ReplaceAll(fromTime, "T", " "))
	}
	if toTime != "" {
		query += " AND timestamp <= ?"
		args = append(args, strings.ReplaceAll(toTime, "T", " "))
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
		if err := rows.Scan(&ts, &q.Domain, &q.Type, &q.Status, &q.ClientIP, &q.IsCacheHit, &q.DurationMs); err != nil {
			continue
		}
		q.Time, _ = ParseFlexibleTime(ts)
		if aliases != nil {
			q.ClientAlias = aliases[q.ClientIP]
		}
		queries = append(queries, q)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(queries)
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()

	// Self-repair: Ensure last 24h are aggregated whenever someone looks at history
	go func() {
		for i := 0; i < 24; i++ {
			target := now.Add(time.Duration(-i) * time.Hour).Truncate(time.Hour).Format("2006-01-02 15:04:05")
			aggregateHourlyStats(appCtx, target)
		}
	}()

	// Build 24 slots: slot 0 = oldest hour, slot 23 = current hour
	// Each slot represents one clock hour in the last 24h window.
	type slot struct {
		hour    time.Time // truncated to hour (UTC)
		total   int64
		blocked int64
	}
	slots := make([]slot, 24)
	for i := 0; i < 24; i++ {
		slots[i].hour = now.Add(time.Duration(i-23) * time.Hour).Truncate(time.Hour)
	}

	// Query aggregated stats for hours 1-23 (all but the current hour) from hourly_stats
	cutoff := slots[0].hour.Format("2006-01-02 15:04:05")
	rows, err := db.Query(`
		SELECT timestamp, total, blocked
		FROM hourly_stats
		WHERE timestamp >= ?
		ORDER BY timestamp ASC
	`, cutoff)
	if err != nil {
		http.Error(w, "Error querying history", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Map timestamp → (total, blocked)
	type agg struct{ total, blocked int64 }
	aggMap := make(map[string]agg)
	for rows.Next() {
		var ts string
		var total, blocked int64
		if err := rows.Scan(&ts, &total, &blocked); err != nil {
			continue
		}
		t, _ := ParseFlexibleTime(ts)
		key := t.UTC().Truncate(time.Hour).Format("2006-01-02 15:04:05")
		aggMap[key] = agg{total: total, blocked: blocked}
	}

	// 2. Add current hour from queries table
	var curTotal, curBlocked int64
	curHour := now.Truncate(time.Hour)
	curHourStr := curHour.Format("2006-01-02 15:04:05")
	nextHour := curHour.Add(1 * time.Hour)
	nextHourStr := nextHour.Format("2006-01-02 15:04:05")

	db.QueryRow(`
		SELECT
			COUNT(*),
			COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0)
		FROM queries
		WHERE timestamp >= ? AND timestamp < ?
	`, curHourStr, nextHourStr).Scan(&curTotal, &curBlocked)

	aggMap[curHourStr] = agg{total: curTotal, blocked: curBlocked}

	// 3. Construct result array
	result := make([]HourStats, 24)
	for i, s := range slots {
		key := s.hour.Format("2006-01-02 15:04:05")
		res := HourStats{
			Time: s.hour,
		}
		if a, ok := aggMap[key]; ok {
			res.Total = a.total
			res.Blocked = a.blocked
			// Ensure allowed is not negative and total is consistent
			if res.Total < res.Blocked {
				res.Total = res.Blocked
			}
			res.Allowed = res.Total - res.Blocked
		}
		result[i] = res
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleTopBlocked(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT domain, COUNT(*) as count
		FROM queries
		WHERE status LIKE 'Blocked%' AND timestamp > datetime('now', '-24 hours')
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
		WHERE timestamp > datetime('now', '-24 hours') AND client_ip != 'DoH Proxy'
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
		// Look up the country code from any available cache
		countryCode := ""
		if val, ok := ipInfoCache.Load(client_ip); ok {
			countryCode = val.(IPInfo).CountryCode
		}
		if countryCode == "" || countryCode == "-" || countryCode == "geo" {
			countryCode = GetCountryCodeCached(client_ip)
		}

		if countryCode == "geo" || countryCode == "-" {
			countryCode = ""
		}
		result = append(result, map[string]interface{}{
			"client_ip":    client_ip,
			"client_alias": alias,
			"count":        count,
			"country_code": strings.ToLower(countryCode),
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
		WHERE client_ip = ? AND timestamp > datetime('now', '-24 hours')
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
			saveConfigNoLock()
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
	search := r.URL.Query().Get("search")
	statusFilter := r.URL.Query().Get("status")
	fromTime := r.URL.Query().Get("from_time")
	toTime := r.URL.Query().Get("to_time")

	query := "SELECT timestamp, domain, type, status, client_ip FROM queries WHERE 1=1"
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
	if fromTime != "" {
		query += " AND timestamp >= ?"
		args = append(args, strings.ReplaceAll(fromTime, "T", " "))
	}
	if toTime != "" {
		query += " AND timestamp <= ?"
		args = append(args, strings.ReplaceAll(toTime, "T", " "))
	}

	query += " ORDER BY timestamp DESC LIMIT 50000"

	rows, err := db.Query(query, args...)
	if err != nil {
		slog.Error("Export failed: DB query error", "error", err, "query", query)
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
