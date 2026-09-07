package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func parseLogLine(line string) {
	// 1. Strip common prefixes added by CoreDNS or system logging
	for {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}

		prefixes := []string{"[INFO]", "[DEBUG]", "[ERROR]", "[CoreDNS]", "[CoreDNS-ERR]"}
		found := false
		for _, p := range prefixes {
			if strings.HasPrefix(line, p) {
				line = strings.TrimSpace(strings.TrimPrefix(line, p))
				found = true
				break
			}
		}

		// Handle timestamp prefix like [16:23:02]
		if !found && len(line) > 10 && line[0] == '[' && line[9] == ']' {
			line = strings.TrimSpace(line[10:])
			found = true
		}

		if !found {
			break
		}
	}

	if line == "" {
		return
	}

	// 2. Identification & Field Extraction using a robust field-based approach
	// FORMAT A (Custom): remote type name rcode rflags duration "user-agent" "x-real-ip"
	// FORMAT B (Default): remote:port - id "query_info" rcode rflags size duration

	var remote, qType, qDomain, rcode, rflags, durationStr, userAgent, realIP string

	// Extract quoted parts first as they are most likely metadata or query_info
	quotes := extractQuotes(line)

	if len(quotes) >= 1 {
		firstQuoteIdx := strings.Index(line, "\"")
		prefix := strings.TrimSpace(line[:firstQuoteIdx])
		pFields := strings.Fields(prefix)

		if strings.Contains(prefix, " - ") && len(pFields) >= 3 {
			// FORMAT B (Default CoreDNS format)
			remote = pFields[0]
			qFields := strings.Fields(quotes[0]) // "query_info" usually is "TYPE CLASS NAME +flags"
			if len(qFields) >= 3 {
				qType = qFields[0]
				qDomain = NormalizeDomain(qFields[2])
			}

			// Suffix after the last quote
			lastQuoteIdx := strings.LastIndex(line, "\"")
			suffix := strings.TrimSpace(line[lastQuoteIdx+1:])
			sFields := strings.Fields(suffix)
			if len(sFields) >= 3 {
				rcode = sFields[0]
				rflags = sFields[1]
				durationStr = sFields[len(sFields)-1]
			}
			userAgent = "-"
		} else if len(pFields) >= 6 {
			// FORMAT A (ShieldDNS specific custom format)
			remote = pFields[0]
			qType = pFields[1]
			qDomain = NormalizeDomain(pFields[2])
			rcode = pFields[3]
			rflags = pFields[4]
			durationStr = pFields[5]

			userAgent = quotes[0]
			if len(quotes) >= 2 {
				realIP = quotes[1]
			}
		}
	}

	if qType == "" || qDomain == "" || rcode == "" {
		return
	}

	// Extract Client IP
	clientIP := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		clientIP = host
	}

	// Prefer X-Real-IP if provided by Nginx (metadata plugin)
	if realIP != "" && realIP != "-" && realIP != "none" && realIP != "{>X-Real-IP}" {
		clientIP = realIP
	}

	if !strings.Contains(rflags, "qr") {
		// Only log responses
		return
	}

	isLocal := clientIP == "127.0.0.1" || clientIP == "::1"
	sigKey := qDomain + "|" + qType

	recentQueriesLock.Lock()
	if sig, ok := recentQueries[sigKey]; ok {
		if time.Since(sig.time) < 2*time.Second {
			// If identical query within 2s and this one is local, skip it
			if isLocal {
				recentQueriesLock.Unlock()
				return
			}
			// If not local, always log and update the signature to external
			recentQueries[sigKey] = querySignature{ip: clientIP, time: time.Now()}
		} else {
			recentQueries[sigKey] = querySignature{ip: clientIP, time: time.Now()}
		}
	} else {
		recentQueries[sigKey] = querySignature{ip: clientIP, time: time.Now()}
	}
	recentQueriesLock.Unlock()

	// Rename local IP for better UX if we don't have a real forwarded IP
	if isLocal && (realIP == "" || realIP == "-" || realIP == "none" || realIP == "{>X-Real-IP}") {
		clientIP = "DoH Proxy"
	}

	// Filter out internal health checks (the watchdog) from statistics and logs.
	// We only show these if they come from actual external clients.
	if (qDomain == "shielddns-maleware.test" || qDomain == "google.com") && clientIP == "DoH Proxy" {
		return
	}

	slog.Debug("Parsed Query", "type", qType, "domain", qDomain, "client", clientIP, "duration", durationStr)

	// Update latest User-Agent for this IP with throttling
	if userAgent != "" && userAgent != "-" && userAgent != "none" && userAgent != "{>User-Agent}" {
		oldUA, _ := ipToUA.Swap(clientIP, userAgent)

		shouldPersist := false
		if oldUA == nil || oldUA.(string) != userAgent {
			shouldPersist = true
		} else {
			if last, ok := lastUAUpdate.Load(clientIP); ok {
				if time.Since(last.(time.Time)) > 1*time.Hour {
					shouldPersist = true
				}
			} else {
				shouldPersist = true
			}
		}

		if shouldPersist {
			saveClientUA(clientIP, userAgent)
			lastUAUpdate.Store(clientIP, time.Now())
		}
	}

	duration := 0.0
	if strings.HasSuffix(durationStr, "s") {
		if d, err := time.ParseDuration(durationStr); err == nil {
			duration = float64(d.Microseconds()) / 1000.0 // in ms
		}
	} else if durationStr != "" {
		// Try as raw float (seconds)
		if f, err := strconv.ParseFloat(durationStr, 64); err == nil {
			duration = f * 1000.0 // convert s to ms
		}
	}

	blockAttributionLock.RLock()
	found := false
	if _, ok := blockAttribution[qDomain]; ok {
		found = true
	} else {
		// Check for wildcard match (*.domain.com, *.com, etc.)
		parts := strings.Split(qDomain, ".")
		for i := 1; i < len(parts); i++ {
			wildcard := "*." + strings.Join(parts[i:], ".")
			if _, ok := blockAttribution[wildcard]; ok {
				found = true
				break
			}
		}
	}
	blockAttributionLock.RUnlock()

	isBlocked := found

	// Client-specific filter rules override ($client modifier)
	configLock.RLock()
	clientRules := append([]ClientRule{}, config.ClientRules...)
	configLock.RUnlock()

	for _, cr := range clientRules {
		if cr.ClientIP == clientIP && (strings.EqualFold(cr.Domain, qDomain) || strings.HasSuffix(qDomain, "."+cr.Domain)) {
			isBlocked = !cr.IsAllowlist
			break
		}
	}

	status := StatusAllowed
	if isBlocked {
		status = StatusBlocked
	}

	// ACL / Client / Geo Blocking check
	// CoreDNS acl plugin returns REFUSED for blocked clients/CIDRs
	if rcode == "REFUSED" {
		isBlocked = true
		status = StatusBlockedPolicy

		// Check if it was blocked by the automated malicious IP intelligence feed
		if IsMaliciousIP(clientIP) {
			status = StatusBlockedMalicious
		}

		// Check if it was a specifically blocked client IP (Manual block has highest priority)
		configLock.RLock()
		for _, bip := range config.BlockedClients {
			if bip == clientIP {
				status = StatusBlockedClient
				break
			}
		}
		configLock.RUnlock()
	}

	// Heuristic for Cache Hit: Very low latency (< 1.5ms) and valid response.
	// In local container environments, 5ms is often too high for a real cache hit threshold.
	isCacheHit := !isBlocked && duration > 0 && duration < 1.5

	// Update memory stats for real-time dashboard (Atomic for core counters)
	atomic.AddInt64(&stats.TotalQueries, 1)
	if isBlocked {
		atomic.AddInt64(&stats.BlockedQueries, 1)
	}
	if isCacheHit {
		atomic.AddInt64(&stats.CacheHits, 1)
	}

	// Update locked stats (Query types and latency)
	statsLock.Lock()
	if duration > 0 {
		if stats.AverageLatency == 0 {
			stats.AverageLatency = duration
		} else {
			stats.AverageLatency = (stats.AverageLatency*99 + duration) / 100
		}
	}

	if stats.QueryTypes == nil {
		stats.QueryTypes = make(map[string]int64)
	}
	stats.QueryTypes[qType]++

	if stats.TopCountries == nil {
		stats.TopCountries = make(map[string]int64)
	}
	cc := GetCountryCodeCached(clientIP)
	if cc != "" && cc != "-" {
		stats.TopCountries[cc]++
	}
	statsLock.Unlock()

	configLock.RLock()
	alias := config.ClientAliases[clientIP]
	anonymizeIP := config.AnonymizeClientIPs
	configLock.RUnlock()

	loggedClientIP := clientIP
	if anonymizeIP {
		loggedClientIP = AnonymizeIP(clientIP)
	}

	q := Query{
		Time:        time.Now(),
		Domain:      qDomain,
		Type:        qType,
		Status:      status,
		ClientIP:    loggedClientIP,
		ClientAlias: alias,
		IsCacheHit:  isCacheHit,
		DurationMs:  duration,
		CountryCode: GetCountryCodeCached(clientIP),
	}

	// Record real-time metrics and QPS
	RecordQuery(q)

	bufferLock.Lock()
	logBuffer = append(logBuffer, q)
	bufferLock.Unlock()

	// Feed query to Abuse Detection Engine via worker channel to avoid goroutine churn
	select {
	case abuseChan <- abuseJob{ip: clientIP, domain: qDomain, status: status}:
	default:
		// Drop if analyzer is overwhelmed
	}

	// Broadcast to SSE clients via central channel
	select {
	case sseChan <- q:
	default:
		// Drop broadcast if internal channel is full
	}
}

type abuseJob struct {
	ip, domain, status string
}

var abuseChan = make(chan abuseJob, 1000)

func startAbuseAnalyzer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-abuseChan:
			configLock.RLock()
			enabled := config.AbuseDetectionEnabled
			configLock.RUnlock()
			if enabled {
				analyzeQuery(job.ip, job.domain, job.status)
			}
		}
	}
}

type rateLimitEntry struct {
	Count      int
	LastAccess time.Time
	mu         sync.Mutex
}

var (
	dohRateLimits sync.Map // IP -> *rateLimitEntry
)

// DoHRateLimitMiddleware prevents DoS on the DoH proxy endpoint
func DoHRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.Header.Get("X-Real-IP")
		if clientIP == "" {
			clientIP, _, _ = net.SplitHostPort(r.RemoteAddr)
		}

		if clientIP == "" || clientIP == "127.0.0.1" || clientIP == "::1" {
			next.ServeHTTP(w, r)
			return
		}

		now := time.Now()
		v, _ := dohRateLimits.LoadOrStore(clientIP, &rateLimitEntry{LastAccess: now})
		entry := v.(*rateLimitEntry)

		entry.mu.Lock()
		// Simple fixed-window rate limit: X requests per 1 second
		if now.Sub(entry.LastAccess) > 1*time.Second {
			entry.Count = 1
			entry.LastAccess = now
		} else {
			entry.Count++
		}
		currentCount := entry.Count
		entry.mu.Unlock()

		configLock.RLock()
		limit := config.DoHRateLimit
		configLock.RUnlock()

		if currentCount > limit {
			if !testMode {
				slog.Warn("DoH Rate limit exceeded", "ip", clientIP, "limit", limit)
			}
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Proactively harvest User-Agent and Metadata for the client info dashboard
		ua := r.Header.Get("User-Agent")
		if ua != "" && ua != "-" && ua != "none" {
			oldUA, _ := ipToUA.Swap(clientIP, ua)
			if oldUA == nil || oldUA.(string) != ua {
				// Record seen clients for dashboard usage
				go func(ip, userAgent string) {
					saveClientUA(ip, userAgent)
				}(clientIP, ua)
			}
		}

		next.ServeHTTP(w, r)
	})
}
