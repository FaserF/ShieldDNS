package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"
)

func startHealthChecker() {
	for {
		checkAll()
		configLock.RLock()
		interval := config.LatencyTestInterval
		configLock.RUnlock()
		if interval < 1 { interval = 1 }
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
	if !strings.Contains(addr, ":") { addr += ":53" }
	
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
	if err != nil { return false }
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
	if _, err := conn.Read(resp); err != nil {
		return false
	}
	return true
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
	if err != nil { return false }
	conn.Close()
	return true
}

func equal(a, b []string) bool {
	if len(a) != len(b) { return false }
	for i := range a {
		if a[i] != b[i] { return false }
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
	configLock.RUnlock()

	healthLock.RLock()
	hDNS := make([]string, len(healthyUpstreams))
	copy(hDNS, healthyUpstreams)
	hDoT := make([]string, len(healthyDoT))
	copy(hDoT, healthyDoT)
	healthLock.RUnlock()

	// Sorting is already handled in checkAll for the global lists, 
	// but we do it again on local copies to be certain and safe for future changes.
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
			host := u
			port := "853"
			if strings.Contains(u, ":") {
				h, p, err := net.SplitHostPort(u)
				if err == nil {
					host = h
					port = p
				}
			}
			
			ip := resolveHost(host)
			if dotServerName == "" && ip != host {
				dotServerName = host // Use first hostname found as server name
			}
			upstreams = append(upstreams, fmt.Sprintf("tls://%s:%s", ip, port))
		}
	}
	// Fallback to normal DNS
	for _, u := range hDNS {
		host := u
		port := "53"
		if strings.Contains(u, ":") {
			h, p, err := net.SplitHostPort(u)
			if err == nil {
				host = h
				port = p
			}
		}
		ip := resolveHost(host)
		upstreams = append(upstreams, fmt.Sprintf("%s:%s", ip, port))
	}

	// If everything is down, use defaults as last resort to avoid total failure
	if len(upstreams) == 0 {
		upstreams = []string{"8.8.8.8", "1.1.1.1"}
	}

	upstreamStr := strings.Join(upstreams, " ")

	// Get cert paths from environment (provided by run.sh)
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	if certFile == "" { certFile = "/ssl/fullchain.pem" }
	if keyFile == "" { keyFile = "/ssl/privkey.pem" }

    // Get filtering status
    configLock.RLock()
    filteringEnabled := config.FilteringEnabled
    configLock.RUnlock()

    hostsBlock := ""
    if filteringEnabled {
        hostsBlock = fmt.Sprintf(`
    hosts %s {
        reload 5s
        fallthrough
    }`, BlocklistPath)
    }

    tlsBlock := ""
    if dotServerName != "" {
        tlsBlock = fmt.Sprintf("    tls_servername %s", dotServerName)
    }

    dnssecBlock := ""
    if dnssec {
        dnssecBlock = "    dnssec"
    }

    staleBlock := ""
    if serveStale {
        staleBlock = "        serve_stale 1h"
    }

    policyBlock := ""
    if smart {
        if policy == "random" {
            policyBlock = "        policy random"
        } else if policy == "broadcast" {
            policyBlock = "        policy broadcast"
            // If broadcast and preferEncrypted, we only want to forward to DoT servers
            if preferEncrypted && len(hDoT) > 0 {
                upstreamStr = strings.Join(hDoT, " tls://")
                if !strings.HasPrefix(upstreamStr, "tls://") {
                    upstreamStr = "tls://" + upstreamStr
                }
            }
        } else {
            policyBlock = "        policy sequential"
        }
    }

    geoBlock := getGeoACLRules()
    metadataPlugin := "    metadata"

    corefile := fmt.Sprintf(`.:53 {
    bind 0.0.0.0
    %s
    %s
    health :8082
    reload 5s
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
        %s
    }
    forward . %s {
        health_check 10s
        %s
        %s
    }%s%s
    log . '{remote} {type} {name} {rcode} {rflags} {duration} "{metadata/http/user-agent}"'
    errors
}
`, dnssecBlock, metadataPlugin, staleBlock, upstreamStr, tlsBlock, policyBlock, hostsBlock, geoBlock)

    // Repeat for TLS and HTTPS blocks
    corefile += fmt.Sprintf(`
tls://.:853 {
    bind 0.0.0.0
    tls %s %s
    %s
    %s
    reload 5s
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
        %s
    }
    forward . %s {
        health_check 10s
        %s
        %s
    }%s%s
    log . '{remote} {type} {name} {rcode} {rflags} {duration} "{metadata/http/user-agent}"'
    errors
}

https://.:5553 {
    bind 0.0.0.0
    tls %s %s
    %s
    %s
    reload 5s
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
        %s
    }
    forward . %s {
        health_check 10s
        %s
        %s
    }%s%s
    log . '{remote} {type} {name} {rcode} {rflags} {duration} "{metadata/http/user-agent}"'
    errors
}

quic://.:853 {
    tls %s %s
    %s
    %s
    reload 5s
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
        %s
    }
    forward . %s {
        health_check 10s
        %s
        %s
    }%s%s
    log . '{remote} {type} {name} {rcode} {rflags} {duration} "{metadata/http/user-agent}"'
    errors
}
`, certFile, keyFile, dnssecBlock, metadataPlugin, staleBlock, upstreamStr, tlsBlock, policyBlock, hostsBlock, geoBlock, certFile, keyFile, dnssecBlock, metadataPlugin, staleBlock, upstreamStr, tlsBlock, policyBlock, hostsBlock, geoBlock, certFile, keyFile, dnssecBlock, metadataPlugin, staleBlock, upstreamStr, tlsBlock, policyBlock, hostsBlock, geoBlock)

	os.WriteFile(CorefilePath, []byte(corefile), 0644)
}

func startCoreDNS() {
	for {
		log.Println("Starting CoreDNS...")
		dnsCmd = exec.Command("coredns", "-conf", CorefilePath)
		stdout, _ := dnsCmd.StdoutPipe()
		stderr, _ := dnsCmd.StderrPipe()

		if err := dnsCmd.Start(); err != nil {
			log.Printf("Error starting CoreDNS: %v", err)
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
					AddSystemLog("[CoreDNS] " + line)
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
					AddSystemLog("[CoreDNS-ERR] " + line)
				}
			}
		}(stderr)

		dnsCmd.Wait()
		log.Println("CoreDNS exited. Restarting...")
		time.Sleep(1 * time.Second)
	}
}

func parseLogLine(line string) {
	// Simple and robust parsing for format: 
	// {remote} {type} {name} {rcode} {rflags} {duration} "{user-agent}"
	
	lastQuote := strings.LastIndex(line, "\"")
	if lastQuote <= 0 { return }
	
	firstQuote := strings.LastIndex(line[:lastQuote], "\"")
	if firstQuote <= 0 { return }
	
	userAgent := line[firstQuote+1 : lastQuote]
	prefix := strings.TrimSpace(line[:firstQuote])
	fields := strings.Fields(prefix)
	
	// Expecting: [remote, type, name, rcode, rflags, duration]
	if len(fields) < 6 { 
		DebugLog(fmt.Sprintf("Parsing failed: too few fields (%d) in prefix: %s", len(fields), prefix))
		return 
	}
	
	remote := fields[0]
	qType := fields[1]
	qDomain := strings.TrimSuffix(fields[2], ".")
	rcode := fields[3]
	rflags := fields[4]
	durationStr := fields[5]

	// Extract Client IP
	clientIP := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		clientIP = host
	}

	if !strings.Contains(rflags, "qr") {
		// Only log responses
		return
	}

	DebugLog(fmt.Sprintf("Parsed Query: %s %s from %s (Duration: %s)", qType, qDomain, clientIP, durationStr))

	// Update latest User-Agent for this IP
	if userAgent != "" && userAgent != "-" && userAgent != "none" {
		ipToUA.Store(clientIP, userAgent)
	}

	duration := 0.0
	if strings.HasSuffix(durationStr, "s") {
		if d, err := time.ParseDuration(durationStr); err == nil {
			duration = float64(d.Microseconds()) / 1000.0 // in ms
		}
	} else {
		// Try as raw float (seconds)
		if f, err := strconv.ParseFloat(durationStr, 64); err == nil {
			duration = f * 1000.0 // convert s to ms
		}
	}

	isBlocked := rcode == "REFUSED" || rcode == "NXDOMAIN" || strings.Contains(rflags, "qr,aa")
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

	status := "Allowed"
	if isBlocked {
		status = "Blocked"
	}

	q := Query{
		Time:       time.Now(),
		Domain:     qDomain,
		Type:       qType,
		Status:     status,
		ClientIP:   clientIP,
		IsCacheHit: isCacheHit,
		DurationMs: duration,
	}

	bufferLock.Lock()
	logBuffer = append(logBuffer, q)
	bufferLock.Unlock()

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
