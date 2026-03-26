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
	"time"
)

func startHealthChecker() {
	checkAll() // Initial check
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
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
	for _, u := range upstreams {
		start := time.Now()
		if checkDNS(u) {
			lat := time.Since(start)
			latencyLock.Lock()
			latencyMap[u] = lat
			latencyLock.Unlock()
			newHealthyUpstreams = append(newHealthyUpstreams, u)
		}
	}

	var newHealthyDoT []string
	for _, u := range dots {
		start := time.Now()
		if checkDoT(u) {
			lat := time.Since(start)
			latencyLock.Lock()
			latencyMap[u] = lat
			latencyLock.Unlock()
			newHealthyDoT = append(newHealthyDoT, u)
		}
	}

	healthLock.Lock()
	healthyUpstreams = newHealthyUpstreams
	healthyDoT = newHealthyDoT
	healthLock.Unlock()

	if smart {
		updateCorefile()
	}
}

func checkDNS(addr string) bool {
	if !strings.Contains(addr, ":") { addr += ":53" }
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil { return false }
	conn.Close()
	return true
}

func checkDoT(addr string) bool {
	host := addr
	if !strings.Contains(host, ":") { host += ":853" }
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", host, conf)
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
	if preferEncrypted {
		for _, u := range hDoT {
			if !strings.Contains(u, ":") { u += ":853" }
			upstreams = append(upstreams, "tls://"+u)
		}
	}
	// Fallback to normal DNS
	upstreams = append(upstreams, hDNS...)

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

    corefile := fmt.Sprintf(`.:53 {
    bind 0.0.0.0
    dnssec
    health :8082
    serve_stale
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
    }%s
    log
    errors
}
`, upstreamStr, hostsBlock)

    // Repeat for TLS and HTTPS blocks
    corefile += fmt.Sprintf(`
tls://.:853 {
    tls %s %s {
        protocols tls1.2 tls1.3
        ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305
    }
    dnssec
    health :8082
    serve_stale
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
    }%s
    log
    errors
}

https://.:5553 {
    tls %s %s {
        protocols tls1.2 tls1.3
        ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305
    }
    dnssec
    health :8082
    serve_stale
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
    }%s
    log
    errors
}
`, certFile, keyFile, upstreamStr, hostsBlock, certFile, keyFile, upstreamStr, hostsBlock)

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
	if !strings.Contains(line, " \"") {
		return
	}

	// Extract Client IP (IPv4/IPv6 safe)
	fields := strings.Fields(line)
	clientIP := ""
	if len(fields) > 1 {
		host, _, err := net.SplitHostPort(fields[1])
		if err == nil {
			clientIP = host
		} else {
			clientIP = fields[1] // Fallback if no port
		}
	}

	parts := strings.Split(line, "\"")
	if len(parts) < 2 {
		return
	}
	queryPart := parts[1]
	queryFields := strings.Fields(queryPart)
	if len(queryFields) < 3 {
		return
	}

	qType := queryFields[0]
	qDomain := strings.TrimSuffix(queryFields[2], ".")
	isBlocked := strings.Contains(line, "qr,aa")
	isCacheHit := strings.Contains(line, "qr,aa") && !isBlocked // Simple heuristic for CoreDNS with cache plugin

	// Update memory stats for real-time dashboard
	statsLock.Lock()
	stats.TotalQueries++
	if isBlocked {
		stats.BlockedQueries++
	}
	if isCacheHit {
		stats.CacheHits++
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
