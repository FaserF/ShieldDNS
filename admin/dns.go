package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"
)

type CorefileData struct {
	DNSPort          string
	DOTPort          string
	InternalDOHPort  string
	DNSSEC           bool
	ServeStale       bool
	Upstreams        string
	TLSServerName    string
	Policy           string
	HostsPath        string
	GeoACLRules      string
	CertFile         string
	KeyFile          string
	FilteringEnabled bool
	HasCerts         bool
}

const CorefileTemplate = `.:{{.DNSPort}} {
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
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}

{{if .HasCerts}}
tls://.:{{.DOTPort}} {
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
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}

https://.:{{.InternalDOHPort}} {
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
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
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
    log . "{remote} {type} {name} {rcode} {>rflags} {duration} \"{>User-Agent}\" \"{>X-Real-IP}\""
    errors
}
{{end}}
`

func startHealthChecker(ctx context.Context) {
	// Run an initial check immediately so stats aren't empty for the first minute
	checkAll()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAll()
			configLock.RLock()
			interval := config.LatencyTestInterval
			configLock.RUnlock()
			if interval < 1 {
				interval = 1
			}
			ticker.Reset(time.Duration(interval) * time.Minute)
		}
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
	if err != nil || n < 12 { // DNS header is 12 bytes minimum
		return false
	}
	// Verify Transaction ID (first 2 bytes) AND that it is a response (bit 7 of 3rd byte set)
	return resp[0] == 0x12 && resp[1] == 0x34 && (resp[2]&0x80 != 0)
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
	configLock.RLock()
	verify := config.VerifyUpstreamTLS
	configLock.RUnlock()

	conf := &tls.Config{
		InsecureSkipVerify: !verify,
		ServerName:         serverName,
	}

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, conf)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Perform a minimal DNS query over DoT to ensure the resolver is alive
	// DoT adds a 2-byte length prefix (RFC 7858)
	query := []byte{
		0x00, 0x1c, // Length (28 bytes)
		0xab, 0xcd, // Transaction ID
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

	respHeader := make([]byte, 2)
	if _, err := io.ReadFull(conn, respHeader); err != nil {
		return false
	}

	respLen := int(respHeader[0])<<8 | int(respHeader[1])
	if respLen < 12 || respLen > 512 {
		return false
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return false
	}

	// Verify Transaction ID and QR bit
	return resp[0] == 0xab && resp[1] == 0xcd && (resp[2]&0x80 != 0)
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
	sseChan           = make(chan Query, 1024)
	logQueue          = make(chan string, 10000)
)

func startDNSWorkers(ctx context.Context) {
	// 1. Background cleanup for recent query signatures
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupRecentQueries()
			}
		}
	}()

	// 2. Central SSE Broadcaster
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case q := <-sseChan:
				broadcastSSE(q)
			}
		}
	}()

	// 3. Abuse Detection Analyzer
	go startAbuseAnalyzer(ctx)

	// 4. Log Parsing Worker Pool
	startLogParsers(ctx)
}

func startLogParsers(ctx context.Context) {
	numWorkers := 4 // Scale based on expected CPU cores if needed
	for i := 0; i < numWorkers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case line := <-logQueue:
					parseLogLine(line)
				}
			}
		}()
	}
}

func broadcastSSE(query Query) {
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
			// Full channel, skip to avoid stalling the broadcaster
		}
	}
}

func cleanupRecentQueries() {
	now := time.Now()
	recentQueriesLock.Lock()
	defer recentQueriesLock.Unlock()

	// Keep if less than 10s old
	for k, v := range recentQueries {
		if now.Sub(v.time) > 10*time.Second {
			delete(recentQueries, k)
		}
	}
}

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

	// Only enable encrypted listeners if certificates exist
	hasCerts := false
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			hasCerts = true
		}
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
		DNSPort:          dnsPort,
		DOTPort:          dotPort,
		InternalDOHPort:  internalDOHPort,
		DNSSEC:           dnssec,
		ServeStale:       serveStale,
		Upstreams:        upstreamStr,
		TLSServerName:    dotServerName,
		Policy:           policyVal,
		HostsPath:        CombinedHostsPath,
		GeoACLRules:      getGeoACLRules(),
		CertFile:         certFile,
		KeyFile:          keyFile,
		FilteringEnabled: filtering,
		HasCerts:         hasCerts,
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

func startCoreDNS(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			if dnsCmd != nil && dnsCmd.Process != nil {
				dnsCmd.Process.Signal(os.Interrupt)
			}
			return
		default:
			slog.Info("Starting CoreDNS")
			dnsCmd = exec.CommandContext(ctx, "coredns", "-conf", CorefilePath)
			stdout, _ := dnsCmd.StdoutPipe()
			stderr, _ := dnsCmd.StderrPipe()

			if err := dnsCmd.Start(); err != nil {
				slog.Error("Error starting CoreDNS (executable missing or permission denied?)", "error", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(1 * time.Second):
					continue
				}
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
					select {
					case logQueue <- line:
					default:
						// Queue full, drop log to avoid blocking CoreDNS under extreme load
						if debug {
							slog.Debug("Log queue full, dropping line", "source", "coredns")
						}
					}
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

			select {
			case <-ctx.Done():
				return
			default:
				slog.Warn("CoreDNS exited. Restarting...")
				time.Sleep(1 * time.Second)
			}
		}
	}
}

func restartCoreDNS() {
	if dnsCmd != nil && dnsCmd.Process != nil {
		slog.Info("Restarting CoreDNS to flush cache and apply updated lists")
		// Try graceful termination first (SIGINT/SIGTERM)
		dnsCmd.Process.Signal(os.Interrupt)

		// Start a watchdog to force kill if it hangs
		go func(p *os.Process) {
			time.Sleep(2 * time.Second)
			p.Kill() // Fallback
		}(dnsCmd.Process)

		// Give the old process a moment to release ports before the main loop restarts it
		time.Sleep(500 * time.Millisecond)
	}
}

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
	_, isBlocked := blockAttribution[qDomain]
	blockAttributionLock.RUnlock()

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
			slog.Warn("DoH Rate limit exceeded", "ip", clientIP, "limit", limit)
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
