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
	checkAll() // Initial check
	for {
		time.Sleep(60 * time.Second)
		checkAll()
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

	// Sequential Check for Upstreams with delay for absolute reliability
	for _, u := range upstreams {
		host, port := splitAddr(u, "53")
		ip := resolveHost(host)
		resolvedAddr := net.JoinHostPort(ip, port)

		start := time.Now()
		if checkDNS(resolvedAddr) {
			lat := time.Since(start)
			latencyLock.Lock()
			latencyMap[u] = lat
			latencyLock.Unlock()
			newHealthyUpstreams = append(newHealthyUpstreams, u)
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Sequential Check for DoT
	for _, u := range dots {
		host, port := splitAddr(u, "853")
		ip := resolveHost(host)
		resolvedAddr := net.JoinHostPort(ip, port)

		start := time.Now()
		if checkDoT(resolvedAddr, host) {
			lat := time.Since(start)
			latencyLock.Lock()
			latencyMap[u] = lat
			latencyLock.Unlock()
			newHealthyDoT = append(newHealthyDoT, u)
		}
		time.Sleep(500 * time.Millisecond)
	}

	healthLock.Lock()
	healthyUpstreams = newHealthyUpstreams
	healthyDoT = newHealthyDoT
	healthLock.Unlock()

	if smart {
		updateCorefile()
	}
}

func splitAddr(addr, defaultPort string) (host, port string) {
	host = addr
	port = defaultPort
	if strings.Contains(addr, ":") {
		if h, p, err := net.SplitHostPort(addr); err == nil {
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

var (
	resolveCache     = make(map[string]string)
	resolveCacheLock sync.Mutex
)

func resolveHost(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}

	resolveCacheLock.Lock()
	if ip, ok := resolveCache[host]; ok {
		resolveCacheLock.Unlock()
		return ip
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
	resolveCache[host] = ip
	resolveCacheLock.Unlock()
	return ip
}

func updateCorefile() {
	configLock.RLock()
	preferEncrypted := config.PreferEncrypted
	smart := config.UseFastestUpstream
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

    corefile := fmt.Sprintf(`.:53 {
    bind 0.0.0.0
    dnssec
    health :8082
    reload 5s
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
        %s
    }%s
    log . "{remote} {type} {name} {rcode} {rflags} {duration}"
    errors
}
`, upstreamStr, tlsBlock, hostsBlock)

    // Repeat for TLS and HTTPS blocks
    corefile += fmt.Sprintf(`
tls://.:853 {
    bind 0.0.0.0
    tls %s %s
    dnssec
    reload 5s
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
        %s
    }%s
    log . "{remote} {type} {name} {rcode} {rflags} {duration}"
    errors
}

https://.:5553 {
    bind 0.0.0.0
    tls %s %s
    dnssec
    reload 5s
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
        %s
    }%s
    log . "{remote} {type} {name} {rcode} {rflags} {duration}"
    errors
}
`, certFile, keyFile, upstreamStr, tlsBlock, hostsBlock, certFile, keyFile, upstreamStr, tlsBlock, hostsBlock)

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
				AddSystemLog("[CoreDNS] " + line)
				parseLogLine(line)
			}
		}(stdout)

		go func(reader io.Reader) {
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				line := scanner.Text()
				AddSystemLog("[CoreDNS-ERR] " + line)
			}
		}(stderr)

		dnsCmd.Wait()
		log.Println("CoreDNS exited. Restarting...")
		time.Sleep(1 * time.Second)
	}
}

func parseLogLine(line string) {
	fields := strings.Fields(line)
	
	// Validation
	if len(fields) < 6 {
		log.Printf("DEBUG: parseLogLine: too few fields (%d): %s", len(fields), line)
		return
	}

	durationStr := fields[len(fields)-1]
	rflags      := fields[len(fields)-2]
	
	if !strings.HasSuffix(durationStr, "s") {
		// Possibly a different log format or non-query log
		return
	}

	if !strings.Contains(rflags, "qr") {
		log.Printf("DEBUG: parseLogLine: not a response (no qr): %s", line)
		return
	}

	// rcode    := fields[len(fields)-3]
	qDomain     := strings.TrimSuffix(fields[len(fields)-4], ".")
	qType       := fields[len(fields)-5]
	remote      := fields[len(fields)-6]

	if strings.Contains(qType, "=") || len(qType) > 10 || qType == "-" {
		log.Printf("DEBUG: parseLogLine: invalid qType (%s): %s", qType, line)
		return
	}

	// Extract Client IP
	clientIP := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		clientIP = host
	}

	isBlocked := strings.Contains(rflags, "qr,aa") // typical for local hosts block
	isCacheHit := strings.Contains(rflags, "qr,aa") && !isBlocked // Fallback heuristic

	// Extract Duration
	duration := 0.0
	if strings.HasSuffix(durationStr, "s") {
		if d, err := time.ParseDuration(durationStr); err == nil {
			duration = float64(d.Microseconds()) / 1000.0 // in ms
		}
	}

	// Update memory stats for real-time dashboard
	statsLock.Lock()
	stats.TotalQueries++
	if isBlocked {
		stats.BlockedQueries++
	}
	if isCacheHit {
		stats.CacheHits++
	}
	
	// Moving average for latency (last 100 queries for responsiveness)
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

	// Buffer for batch SQLite insert
	q := Query{
		Time:     time.Now(),
		Domain:   qDomain,
		Type:     qType,
		Status:   status,
		ClientIP: clientIP,
		Duration: duration,
	}

	// Broadcast to SSE clients
	go func(query Query) {
		sseLock.Lock()
		defer sseLock.Unlock()
		for ch := range sseClients {
			select {
			case ch <- query:
			default:
			}
		}
	}(q)

	bufferLock.Lock()
	logBuffer = append(logBuffer, q)
	bufferLock.Unlock()
}
