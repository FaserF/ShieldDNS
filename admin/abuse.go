package main

import (
	"log/slog"
	"strings"
	"sync"
	"time"
)

type clientAbuseCounters struct {
	domainTimes   map[string][]time.Time
	allQueryTimes []time.Time
	nxdomainTimes []time.Time
	tldCounts     map[string][]time.Time
}

var (
	abuseMu       sync.Mutex
	abuseCounters = make(map[string]*clientAbuseCounters)
)

// analyzeQuery is the entry point for the abuse detection engine.
// It checks the query against four patterns: domain flood, rate limit, NXDOMAIN flood, and TLD scan.
func analyzeQuery(clientIP, domain, status string) {
	configLock.RLock()
	enabled := config.AbuseDetectionEnabled
	disabledList := config.BlockedClients
	isBlocked := false
	for _, blockedIP := range disabledList {
		if blockedIP == clientIP {
			isBlocked = true
			break
		}
	}
	configLock.RUnlock()

	if !enabled || isBlocked {
		return
	}

	now := time.Now()
	
	abuseMu.Lock()
	defer abuseMu.Unlock()

	counters, exists := abuseCounters[clientIP]
	if !exists {
		counters = &clientAbuseCounters{
			domainTimes:   make(map[string][]time.Time),
			tldCounts:     make(map[string][]time.Time),
		}
		abuseCounters[clientIP] = counters
	}

	// --- 1. Total Query Rate Limit (>= 1000 queries / 60s) ---
	counters.allQueryTimes = append(counters.allQueryTimes, now)
	counters.allQueryTimes = pruneWindow(counters.allQueryTimes, now, 60*time.Second)
	if len(counters.allQueryTimes) >= 1000 {
		go blockClientAuto(clientIP, "auto:rate_limit")
		return // Blocked, we can stop analysis for this query
	}

	// --- 2. Single Domain Flood (>= 120 queries / 60s) ---
	counters.domainTimes[domain] = append(counters.domainTimes[domain], now)
	counters.domainTimes[domain] = pruneWindow(counters.domainTimes[domain], now, 60*time.Second)
	if len(counters.domainTimes[domain]) >= 120 {
		go blockClientAuto(clientIP, "auto:domain_flood")
		return
	}

	// --- 3. NXDOMAIN Flood (>= 300 / 60s) ---
	if status == "NXDOMAIN" {
		counters.nxdomainTimes = append(counters.nxdomainTimes, now)
		counters.nxdomainTimes = pruneWindow(counters.nxdomainTimes, now, 60*time.Second)
		if len(counters.nxdomainTimes) >= 300 {
			go blockClientAuto(clientIP, "auto:nxdomain_flood")
			return
		}
	}

	// --- 4. Special TLD Scan (>= 1000 queries targeting one TLD, and that TLD covers >= 90% of total queries in 5 min) ---
	tld := extractTLD(domain)
	if tld != "" {
		counters.tldCounts[tld] = append(counters.tldCounts[tld], now)
		counters.tldCounts[tld] = pruneWindow(counters.tldCounts[tld], now, 5*time.Minute)
		
		// For TLD checks, we need total queries in the last 5 mins. Since allQueryTimes only tracks 60s,
		// we'll just sum all tldCounts (approx. total queries in 5m).
		total5m := 0
		for _, times := range counters.tldCounts {
			total5m += len(times)
		}
		
		if len(counters.tldCounts[tld]) >= 1000 && float64(len(counters.tldCounts[tld]))/float64(total5m) >= 0.90 {
			go blockClientAuto(clientIP, "auto:tld_scan")
			return
		}
	}
}

func pruneWindow(times []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	// Find first index that is AFTER the cutoff
	idx := -1
	for i, t := range times {
		if t.After(cutoff) {
			idx = i
			break
		}
	}
	
	if idx == -1 {
		// All times are older than the window
		return nil
	}
	if idx == 0 {
		// All times are within the window
		return times
	}
	return times[idx:]
}

func extractTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

func blockClientAuto(ip, reason string) {
	slog.Warn("Abuse Detection triggered", "ip", ip, "reason", reason)

	configLock.Lock()
	if config.BlockedClients == nil {
		config.BlockedClients = []string{}
	}
	if config.BlockedClientsInfo == nil {
		config.BlockedClientsInfo = make(map[string]BlockedClientInfo)
	}

	// Check if already blocked (to be safe against race conditions since analyzeQuery spans a goroutine)
	for _, c := range config.BlockedClients {
		if c == ip {
			configLock.Unlock()
			return 
		}
	}

	config.BlockedClients = append(config.BlockedClients, ip)
	config.BlockedClientsInfo[ip] = BlockedClientInfo{
		Reason:    reason,
		BlockedAt: time.Now(),
		Auto:      true,
	}

	saveConfigNoLock()
	RecordAbuseBlock()
	configLock.Unlock()

	go updateCorefile() // Instantly apply ACL update
}

// startAbuseCleanup runs every 5 minutes and removes entirely stale counter data
// to prevent memory leaks from one-off clients.
func startAbuseCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		now := time.Now()
		
		abuseMu.Lock()
		for ip, counters := range abuseCounters {
			active := false
			
			// If recent queries were within the last 5 minutes, we keep the client mapping
			counters.allQueryTimes = pruneWindow(counters.allQueryTimes, now, 5*time.Minute)
			if len(counters.allQueryTimes) > 0 {
				active = true
			}

			if !active {
				delete(abuseCounters, ip)
			}
		}
		abuseMu.Unlock()
	}
}
