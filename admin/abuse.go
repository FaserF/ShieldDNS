package main

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type clientAbuseCounters struct {
	sync.Mutex
	domainTimes   map[string][]time.Time
	allQueryTimes []time.Time
	nxdomainTimes []time.Time
	tldCounts     map[string][]time.Time
	dgaTimes      []time.Time
}

var (
	abuseMu       sync.Mutex
	abuseCounters = make(map[string]*clientAbuseCounters)
)

// analyzeQuery is the entry point for the abuse detection engine.
// It checks the query against four patterns: domain flood, rate limit, NXDOMAIN flood, and TLD scan.
func analyzeQuery(clientIP, domain, status string) {
	// 1. Get or create counter (with global lock only for map access)
	abuseMu.Lock()
	counters, exists := abuseCounters[clientIP]
	if !exists {
		counters = &clientAbuseCounters{
			domainTimes: make(map[string][]time.Time),
			tldCounts:   make(map[string][]time.Time),
		}
		abuseCounters[clientIP] = counters
	}
	abuseMu.Unlock()

	// 2. Perform client-specific analysis with per-client lock
	counters.Lock()
	defer counters.Unlock()

	now := time.Now()

	// --- 1. Total Query Rate Limit (>= 1000 queries / 60s) ---
	counters.allQueryTimes = append(counters.allQueryTimes, now)
	counters.allQueryTimes = pruneWindow(counters.allQueryTimes, now, 60*time.Second)
	if len(counters.allQueryTimes) >= 1000 {
		go blockClientAuto(clientIP, "auto:rate_limit")
		return // Blocked, we can stop analysis for this query
	}

	// --- 2. Single Domain Flood (>= 300 queries / 60s) ---
	if !isInfrastructureDomain(domain) {
		counters.domainTimes[domain] = append(counters.domainTimes[domain], now)
		counters.domainTimes[domain] = pruneWindow(counters.domainTimes[domain], now, 60*time.Second)
		if len(counters.domainTimes[domain]) >= 300 {
			go blockClientAuto(clientIP, "auto:domain_flood")
			return
		}
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

	// --- 5. DGA Detection (High Entropy Subdomains) ---
	configLock.RLock()
	dgaThreshold := config.AbuseDGAThreshold
	dgaMinLen := config.AbuseDGAMinLen
	configLock.RUnlock()

	// Focus on subdomains longer than dgaMinLen chars with high entropy
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		sub := parts[0]

		// Bypass DGA check for internal domains and common high-provider/infra domains
		bypass := false
		suffix := strings.ToLower(domain)
		if isInfrastructureDomain(suffix) {
			bypass = true
		} else {
			for _, b := range []string{
				".local", ".lan", ".home.arpa", "duckdns.org",
				"no-ip.org", "dyndns.org", "dynamic-dns.net",
			} {
				if strings.HasSuffix(suffix, b) {
					bypass = true
					break
				}
			}
		}

		if !bypass && len(sub) > dgaMinLen && CalculateEntropy(sub) > dgaThreshold {
			counters.dgaTimes = append(counters.dgaTimes, now)
			counters.dgaTimes = pruneWindow(counters.dgaTimes, now, 5*time.Minute)
			if len(counters.dgaTimes) >= 15 {
				go blockClientAuto(clientIP, "auto:dga_detected")
				return
			}
		}
	}
}

func pruneWindow(times []time.Time, now time.Time, window time.Duration) []time.Time {
	if len(times) == 0 {
		return times
	}
	cutoff := now.Add(-window)

	// Fast path: if the oldest entry is within the window, nothing to prune
	if !times[0].Before(cutoff) {
		return times
	}

	// Find first index that is AFTER the cutoff
	idx := -1
	for i, t := range times {
		if t.After(cutoff) {
			idx = i
			break
		}
	}

	if idx == -1 {
		return nil
	}
	return times[idx:]
}

func extractTLD(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return ""
	}

	last := parts[len(parts)-1]
	secondLast := parts[len(parts)-2]

	// Handle common two-part TLDs (e.g., co.uk, gv.at, com.br)
	// This is a heuristic; for perfect accuracy one would need the Public Suffix List
	twoPartTLDs := map[string]bool{
		"co": true, "com": true, "net": true, "org": true, "gov": true, "gv": true, "ac": true, "edu": true,
	}

	if len(parts) >= 3 && twoPartTLDs[secondLast] && len(last) == 2 {
		return secondLast + "." + last
	}

	return last
}

func blockClientAuto(ip, reason string) {
	configLock.RLock()
	bpIP := config.BlockPageIP
	configLock.RUnlock()

	if IsCriticalIP(ip, bpIP) {
		slog.Info("Skipping auto-block for critical IP", "ip", ip, "reason", reason)
		return
	}
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

	cc := GetCountryCodeCached(ip)
	config.BlockedClients = append(config.BlockedClients, ip)
	config.BlockedClientsInfo[ip] = BlockedClientInfo{
		Reason:      reason,
		BlockedAt:   time.Now(),
		Auto:        true,
		CountryCode: cc,
	}

	saveConfigNoLock()
	RecordAbuseBlock()
	configLock.Unlock()

	go updateCorefile() // Instantly apply ACL update
}

func startAbuseCleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()

			abuseMu.Lock()
			for ip, counters := range abuseCounters {
				// 1. Prune nested domain counters and remove empty ones
				for domain, dTimes := range counters.domainTimes {
					counters.domainTimes[domain] = pruneWindow(dTimes, now, 10*time.Minute)
					if len(counters.domainTimes[domain]) == 0 {
						delete(counters.domainTimes, domain)
					}
				}

				// 2. Prune TLD counters
				for tld, tTimes := range counters.tldCounts {
					counters.tldCounts[tld] = pruneWindow(tTimes, now, 10*time.Minute)
					if len(counters.tldCounts[tld]) == 0 {
						delete(counters.tldCounts, tld)
					}
				}

				// 3. Prune general counters
				counters.allQueryTimes = pruneWindow(counters.allQueryTimes, now, 10*time.Minute)
				counters.nxdomainTimes = pruneWindow(counters.nxdomainTimes, now, 10*time.Minute)
				counters.dgaTimes = pruneWindow(counters.dgaTimes, now, 10*time.Minute)

				// 4. If no activity at all in last 10 mins, remove the client from map
				if len(counters.allQueryTimes) == 0 && len(counters.domainTimes) == 0 && len(counters.nxdomainTimes) == 0 && len(counters.dgaTimes) == 0 {
					delete(abuseCounters, ip)
				}
			}
			abuseMu.Unlock()
		}
	}
}

func isInfrastructureDomain(domain string) bool {
	infraSuffixes := []string{
		"google.com", "googleapis.com", "gstatic.com", "googlevideo.com", "googleusercontent.com",
		"apple.com", "icloud.com", "mzstatic.com", "apple-dns.net",
		"microsoft.com", "office.com", "office365.com", "windows.com", "live.com", "outlook.com", "msftncsi.com", "windows.net", "visualstudio.com",
		"amazon.com", "amazonaws.com", "amzn.to",
		"cloudflare.com", "cloudflare.net",
		"akamai.net", "akamaized.net",
		"fastly.net",
		"github.com", "githubusercontent.com",
		"fabiseitz.de",
	}
	d := strings.ToLower(domain)
	for _, s := range infraSuffixes {
		if d == s || strings.HasSuffix(d, "."+s) {
			return true
		}
	}
	return false
}
