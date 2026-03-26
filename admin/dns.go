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
    reload 5s
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
    }%s
    log . "{remote} {type} {name} {rcode} {rflags} {duration}"
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
    reload 5s
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
    }%s
    log . "{remote} {type} {name} {rcode} {rflags} {duration}"
    errors
}

https://.:5553 {
    tls %s %s {
        protocols tls1.2 tls1.3
        ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305
    }
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
    }%s
    log . "{remote} {type} {name} {rcode} {rflags} {duration}"
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
	// Our custom Corefile format is:
	// log . "{remote} {type} {name} {rcode} {rflags} {duration}"
	// This makes parsing robust. We parse backwards to ignore any [INFO] prefixes.
	// Example: ... 127.0.0.1:46111 A google.com. NOERROR qr,rd,ra 0.00123s
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return
	}

	durationStr := fields[len(fields)-1]
	rflags      := fields[len(fields)-2]
	// rcode    := fields[len(fields)-3]
	qDomain     := strings.TrimSuffix(fields[len(fields)-4], ".")
	qType       := fields[len(fields)-5]
	remote      := fields[len(fields)-6]

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
