package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
)

type CorefileData struct {
	DNSPort         string
	DOTPort         string
	InternalDOHPort string
	DNSSEC          bool
	ServeStale      bool
	Upstreams       string
	TLSServerName   string
	Policy          string
	HostsPath       string
	GeoACLRules     string
	CertFile        string
	KeyFile         string
	FilteringEnabled bool
}

const CorefileTemplate = `.:{{.DNSPort}} {
    bind 0.0.0.0
    {{if .DNSSEC}}dnssec{{end}}
    metadata
    health :8082
    reload 5s
    cache 7200 {
        success 50000
        denial 10000
        prefetch 3 10m 20%
        {{if .ServeStale}}serve_stale 1h{{end}}
    }
    forward . {{.Upstreams}} {
        health_check 10s
        {{if .TLSServerName}}tls_servername {{.TLSServerName}}{{end}}
        {{if .Policy}}policy {{.Policy}}{{end}}
    }
    {{if .FilteringEnabled}}
    hosts {{.HostsPath}} {
        reload 5s
        fallthrough
    }
    {{end}}
    {{.GeoACLRules}}
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"-\""
    errors
}

tls://.:{{.DOTPort}} {
    bind 0.0.0.0
    tls {{.CertFile}} {{.KeyFile}}
    {{if .DNSSEC}}dnssec{{end}}
    metadata
    reload 5s
    cache 7200 {
        success 50000
        denial 10000
        prefetch 3 10m 20%
        {{if .ServeStale}}serve_stale 1h{{end}}
    }
    forward . {{.Upstreams}} {
        health_check 10s
        {{if .TLSServerName}}tls_servername {{.TLSServerName}}{{end}}
        {{if .Policy}}policy {{.Policy}}{{end}}
    }
    hosts {{.HostsPath}} {
        reload 5s
        fallthrough
    }
    {{.GeoACLRules}}
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"-\""
    errors
}

https://.:{{.InternalDOHPort}} {
    bind 0.0.0.0
    tls {{.CertFile}} {{.KeyFile}}
    {{if .DNSSEC}}dnssec{{end}}
    metadata
    reload 5s
    cache 7200 {
        success 50000
        denial 10000
        prefetch 3 10m 20%
        {{if .ServeStale}}serve_stale 1h{{end}}
    }
    forward . {{.Upstreams}} {
        health_check 10s
        {{if .TLSServerName}}tls_servername {{.TLSServerName}}{{end}}
        {{if .Policy}}policy {{.Policy}}{{end}}
    }
    hosts {{.HostsPath}} {
        reload 5s
        fallthrough
    }
    {{.GeoACLRules}}
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"-\""
    errors
}

quic://.:{{.DOTPort}} {
    tls {{.CertFile}} {{.KeyFile}}
    {{if .DNSSEC}}dnssec{{end}}
    metadata
    reload 5s
    cache 7200 {
        success 50000
        denial 10000
        prefetch 3 10m 20%
        {{if .ServeStale}}serve_stale 1h{{end}}
    }
    forward . {{.Upstreams}} {
        health_check 10s
        {{if .TLSServerName}}tls_servername {{.TLSServerName}}{{end}}
        {{if .Policy}}policy {{.Policy}}{{end}}
    }
    hosts {{.HostsPath}} {
        reload 5s
        fallthrough
    }
    {{.GeoACLRules}}
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"-\""
    errors
}
`

func startHealthChecker() {
	for {
		checkAll()
		configLock.RLock()
		interval := config.LatencyTestInterval
		configLock.RUnlock()
		if interval < 1 {
			interval = 1
		}
		time.Sleep(time.Duration(interval) * time.Minute)
	}
}

func checkAll() {
	configLock.RLock()
	upstreams := config.Upstreams
	dots := config.UpstreamDoT
	smart := config.UseFastestUpstream
	configLock.RUnlock()

	var newHealthyUpstreams []string
	var newHealthyDoT []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Check Upstreams in parallel
	for _, u := range upstreams {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			host, port := splitAddr(addr, "53")
			ip := resolveHost(host)
			resolvedAddr := net.JoinHostPort(ip, port)

			start := time.Now()
			if checkDNS(resolvedAddr) {
				lat := time.Since(start)
				mu.Lock()
				latencyLock.Lock()
				latencyMap[addr] = lat
				latencyLock.Unlock()
				newHealthyUpstreams = append(newHealthyUpstreams, addr)
				mu.Unlock()
			}
		}(u)
	}

	// Check DoT in parallel
	for _, u := range dots {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			host, port := splitAddr(addr, "853")
			ip := resolveHost(host)
			resolvedAddr := net.JoinHostPort(ip, port)

			start := time.Now()
			if checkDoT(resolvedAddr, host) {
				lat := time.Since(start)
				mu.Lock()
				latencyLock.Lock()
				latencyMap[addr] = lat
				latencyLock.Unlock()
				newHealthyDoT = append(newHealthyDoT, addr)
				mu.Unlock()
			}
		}(u)
	}

	wg.Wait()

	healthLock.Lock()
	healthyUpstreams = newHealthyUpstreams
	healthyDoT = newHealthyDoT

	if smart {
		latencyLock.RLock()
		sort.Slice(healthyUpstreams, func(i, j int) bool {
			return latencyMap[healthyUpstreams[i]] < latencyMap[healthyUpstreams[j]]
		})
		sort.Slice(healthyDoT, func(i, j int) bool {
			return latencyMap[healthyDoT[i]] < latencyMap[healthyDoT[j]]
		})
		latencyLock.RUnlock()
	}
	healthLock.Unlock()

	if smart {
		updateCorefile()
	}
}

func splitAddr(addr, defaultPort string) (host, port string) {
	// Strip protocol prefixes if present (e.g., tls://, https://)
	cleanAddr := addr
	if idx := strings.Index(addr, "://"); idx != -1 {
		cleanAddr = addr[idx+3:]
	}

	host = cleanAddr
	port = defaultPort
	if strings.Contains(cleanAddr, ":") {
		if h, p, err := net.SplitHostPort(cleanAddr); err == nil {
			host = h
			port = p
		}
	}
	return host, port
}

func checkDNS(addr string) bool {
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}

	for i := 0; i < 3; i++ { // 3 attempts
		if checkDNSOnce(addr) {
			return true
		}
		if i < 2 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	return false
}

func checkDNSOnce(addr string) bool {
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Minimal DNS query for google.com IN A
	query := []byte{
		0x12, 0x34, // Transaction ID
		0x01, 0x00, // Flags: Standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, // google.com
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}

	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return false
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil || n < 2 {
		return false
	}
	// Verify Transaction ID (first 2 bytes)
	return resp[0] == 0x12 && resp[1] == 0x34
}

func checkDoT(addr, serverName string) bool {
	for i := 0; i < 3; i++ { // 3 attempts
		if checkDoTOnce(addr, serverName) {
			return true
		}
		if i < 2 {
			time.Sleep(300 * time.Millisecond)
		}
	}
	return false
}

func checkDoTOnce(addr, serverName string) bool {
	conf := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", addr, conf)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type cacheEntry struct {
	ip        string
	expiresAt time.Time
}

var (
	resolveCache     = make(map[string]cacheEntry)
	resolveCacheLock sync.Mutex
)

type querySignature struct {
	ip   string
	time time.Time
}

var (
	recentQueries     = make(map[string]querySignature)
	recentQueriesLock sync.Mutex
)

func resolveHost(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}

	resolveCacheLock.Lock()
	if entry, ok := resolveCache[host]; ok {
		if time.Now().Before(entry.expiresAt) {
			resolveCacheLock.Unlock()
			return entry.ip
		}
	}
	resolveCacheLock.Unlock()

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return host
	}

	// Prefer IPv4 for better compatibility in many networks/containers
	var ip string
	for _, i := range ips {
		if i.To4() != nil {
			ip = i.String()
			break
		}
	}
	if ip == "" {
		ip = ips[0].String()
	}

	resolveCacheLock.Lock()
	resolveCache[host] = cacheEntry{
		ip:        ip,
		expiresAt: time.Now().Add(1 * time.Hour), // 1 hour TTL
	}
	resolveCacheLock.Unlock()
	return ip
}

func updateCorefile() {
	configLock.RLock()
	preferEncrypted := config.PreferEncrypted
	smart := config.UseFastestUpstream
	policy := config.SmartSelectionPolicy
	serveStale := config.ServeStale
	dnssec := config.DNSSECEnabled
	filtering := config.FilteringEnabled
	configLock.RUnlock()

	healthLock.RLock()
	hDNS := make([]string, len(healthyUpstreams))
	copy(hDNS, healthyUpstreams)
	hDoT := make([]string, len(healthyDoT))
	copy(hDoT, healthyDoT)
	healthLock.RUnlock()

	if smart {
		latencyLock.RLock()
		sort.Slice(hDNS, func(i, j int) bool {
			return latencyMap[hDNS[i]] < latencyMap[hDNS[j]]
		})
		sort.Slice(hDoT, func(i, j int) bool {
			return latencyMap[hDoT[i]] < latencyMap[hDoT[j]]
		})
		latencyLock.RUnlock()
	}

	var upstreams []string
	var dotServerName string
	if preferEncrypted {
		for _, u := range hDoT {
			host, port := splitAddr(u, "853")
			ip := resolveHost(host)
			if dotServerName == "" && ip != host {
				dotServerName = host
			}
			upstreams = append(upstreams, fmt.Sprintf("tls://%s:%s", ip, port))
		}
	}

	for _, u := range hDNS {
		host, port := splitAddr(u, "53")
		ip := resolveHost(host)
		upstreams = append(upstreams, fmt.Sprintf("%s:%s", ip, port))
	}

	if len(upstreams) == 0 {
		upstreams = []string{"8.8.8.8", "1.1.1.1"}
	}

	upstreamStr := strings.Join(upstreams, " ")

	policyVal := ""
	if smart {
		if policy == "random" {
			policyVal = "random"
		} else if policy == "broadcast" {
			policyVal = "broadcast"
			if preferEncrypted && len(hDoT) > 0 {
				upstreamStr = "tls://" + strings.Join(hDoT, " tls://")
			}
		} else {
			policyVal = "sequential"
		}
	}

	certFile := os.Getenv("CERT_FILE")
	if certFile == "" {
		certFile = "/ssl/fullchain.pem"
	}
	keyFile := os.Getenv("KEY_FILE")
	if keyFile == "" {
		keyFile = "/ssl/privkey.pem"
	}

	dnsPort := os.Getenv("DNS_PORT")
	if dnsPort == "" {
		dnsPort = "53"
	}
	dotPort := os.Getenv("DOT_PORT")
	if dotPort == "" {
		dotPort = "853"
	}
	internalDOHPort := os.Getenv("INTERNAL_DOH_PORT")
	if internalDOHPort == "" {
		internalDOHPort = "5553"
	}

	data := CorefileData{
		DNSPort:         dnsPort,
		DOTPort:         dotPort,
		InternalDOHPort: internalDOHPort,
		DNSSEC:          dnssec,
		ServeStale:      serveStale,
		Upstreams:       upstreamStr,
		TLSServerName:   dotServerName,
		Policy:          policyVal,
		HostsPath:       CombinedHostsPath,
		GeoACLRules:     getGeoACLRules(),
		CertFile:        certFile,
		KeyFile:         keyFile,
		FilteringEnabled: filtering,
	}

	tmpl, err := template.New("corefile").Parse(CorefileTemplate)
	if err != nil {
		slog.Error("Error parsing Corefile template", "error", err)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		slog.Error("Error executing Corefile template", "error", err)
		return
	}

	atomicWriteFile(CorefilePath, buf.Bytes())
}

func startCoreDNS() {
	for {
		slog.Info("Starting CoreDNS")
		dnsCmd = exec.Command("coredns", "-conf", CorefilePath)
		stdout, _ := dnsCmd.StdoutPipe()
		stderr, _ := dnsCmd.StderrPipe()

		if err := dnsCmd.Start(); err != nil {
			slog.Error("Error starting CoreDNS", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		go func(reader io.Reader) {
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				line := scanner.Text()
				configLock.RLock()
				debug := config.DebugMode
				configLock.RUnlock()
				if debug {
					slog.Info(line, "source", "coredns")
				}
				go parseLogLine(line)
			}
		}(stdout)

		go func(reader io.Reader) {
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				line := scanner.Text()
				configLock.RLock()
				debug := config.DebugMode
				configLock.RUnlock()
				if debug {
					slog.Error(line, "source", "coredns-err")
				}
			}
		}(stderr)

		dnsCmd.Wait()
		slog.Warn("CoreDNS exited. Restarting...")
		time.Sleep(1 * time.Second)
	}
}

func restartCoreDNS() {
	if dnsCmd != nil && dnsCmd.Process != nil {
		slog.Info("Restarting CoreDNS to flush cache and apply updated lists")
		dnsCmd.Process.Kill()
	}
}

func parseLogLine(line string) {
	// 1. Strip common prefixes added by CoreDNS or system logging
	// Handle: "[INFO] ", "[DEBUG] ", "[CoreDNS] ", "[CoreDNS-ERR] ", "[16:23:02] "
	for {
		clean := false
		line = strings.TrimSpace(line)
		prefixes := []string{"[INFO]", "[DEBUG]", "[ERROR]", "[CoreDNS]", "[CoreDNS-ERR]"}
		for _, p := range prefixes {
			if strings.HasPrefix(line, p) {
				line = strings.TrimSpace(strings.TrimPrefix(line, p))
				clean = true
			}
		}
		// Handle timestamp prefix like [16:23:02]
		if len(line) > 10 && line[0] == '[' && line[9] == ']' {
			line = strings.TrimSpace(line[10:])
			clean = true
		}
		if !clean {
			break
		}
	}

	if line == "" {
		return
	}

	var remote, qType, qDomain, rcode, rflags, durationStr, userAgent string

	// 2. Identify Format and Parse
	// FORMAT A (Custom): remote type name rcode rflags duration "user-agent"
	// FORMAT B (Default): remote:port - id "query_info" rcode rflags size duration

	lastQuote := strings.LastIndex(line, "\"")
	if lastQuote <= 0 {
		return
	}

	firstQuote := strings.LastIndex(line[:lastQuote], "\"")
	if firstQuote <= 0 {
		return
	}

	middlePart := line[firstQuote+1 : lastQuote]
	prefix := strings.TrimSpace(line[:firstQuote])
	suffix := strings.TrimSpace(line[lastQuote+1:])

	pFields := strings.Fields(prefix)

	if len(pFields) >= 6 {
		// Likely FORMAT A (Custom)
		remote = pFields[0]
		qType = pFields[1]
		qDomain = strings.TrimSuffix(pFields[2], ".")
		rcode = pFields[3]
		rflags = pFields[4]
		durationStr = pFields[5]
		userAgent = middlePart
	} else if len(pFields) >= 3 && strings.Contains(line[:firstQuote], " - ") {
		// Likely FORMAT B (Default): remote - id "query_info" rcode rflags size duration
		remote = pFields[0]

		// Query info is in quotes: "TYPE CLASS NAME PROTO SIZE FLAGS"
		qFields := strings.Fields(middlePart)
		if len(qFields) >= 3 {
			qType = qFields[0]
			qDomain = strings.TrimSuffix(qFields[2], ".")
		}

		sFields := strings.Fields(suffix)
		if len(sFields) >= 3 {
			rcode = sFields[0]
			rflags = sFields[1]
			// size is sFields[2]
			if len(sFields) >= 4 {
				durationStr = sFields[3]
			}
		}
		userAgent = "-" // Default format doesn't have User-Agent
	} else {
		slog.Debug("Parsing failed: unknown format or too few fields in prefix", "prefix", prefix)
		return
	}

	if qType == "" || qDomain == "" || rcode == "" {
		return
	}

	// Extract Client IP
	clientIP := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		clientIP = host
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
			if !isLocal {
				recentQueries[sigKey] = querySignature{ip: clientIP, time: time.Now()}
			}
		} else {
			recentQueries[sigKey] = querySignature{ip: clientIP, time: time.Now()}
		}
	} else {
		recentQueries[sigKey] = querySignature{ip: clientIP, time: time.Now()}
	}

	// Simple cleanup to prevent unbounded growth
	if len(recentQueries) > 1000 {
		now := time.Now()
		for k, v := range recentQueries {
			if now.Sub(v.time) > 10*time.Second {
				delete(recentQueries, k)
			}
		}
	}
	recentQueriesLock.Unlock()

	// Rename local IP for better UX
	if isLocal {
		clientIP = "DoH Proxy"
	}

	slog.Debug("Parsed Query", "type", qType, "domain", qDomain, "client", clientIP, "duration", durationStr)

	// Update latest User-Agent for this IP
	if userAgent != "" && userAgent != "-" && userAgent != "none" {
		ipToUA.Store(clientIP, userAgent)
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
	_, isBlocked := blockAttribution[qDomain]
	blockAttributionLock.RUnlock()

	status := "Allowed"
	if isBlocked {
		status = "Blocked"
	}

	// ACL / Client / Geo Blocking check
	// CoreDNS acl plugin returns REFUSED for blocked clients/CIDRs
	if rcode == "REFUSED" {
		isBlocked = true
		status = "Blocked (Policy)"

		// Check if it was a specifically blocked client IP
		configLock.RLock()
		for _, bip := range config.BlockedClients {
			if bip == clientIP {
				status = "Blocked (Client IP)"
				break
			}
		}
		configLock.RUnlock()
	}

	isCacheHit := !isBlocked && duration < 5.0

	// Update memory stats for real-time dashboard
	statsLock.Lock()
	stats.TotalQueries++
	if isBlocked {
		stats.BlockedQueries++
	}
	if isCacheHit {
		stats.CacheHits++
	}

	// Moving average for latency
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
	statsLock.Unlock()

	configLock.RLock()
	alias := config.ClientAliases[clientIP]
	configLock.RUnlock()

	q := Query{
		Time:        time.Now(),
		Domain:      qDomain,
		Type:        qType,
		Status:      status,
		ClientIP:    clientIP,
		ClientAlias: alias,
		IsCacheHit:  isCacheHit,
		DurationMs:  duration,
	}

	bufferLock.Lock()
	logBuffer = append(logBuffer, q)
	bufferLock.Unlock()

	// Feed query to Abuse Detection Engine
	go analyzeQuery(clientIP, qDomain, status)

	// Broadcast to SSE clients
	go func(query Query) {
		sseLock.Lock()
		if len(sseClients) == 0 {
			sseLock.Unlock()
			return
		}
		// Create a local copy of clients to broadcast outside the lock
		clients := make([]chan Query, 0, len(sseClients))
		for ch := range sseClients {
			clients = append(clients, ch)
		}
		sseLock.Unlock()

		for _, ch := range clients {
			select {
			case ch <- query:
			default:
				// If channel is full, we skip this query for this client to avoid stalling the broadcaster
				// This might happen during massive bursts
				// DebugLog("SSE channel full, skipping query broadcast for one client")
			}
		}
	}(q)
}
