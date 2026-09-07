package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

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
	if _, err = conn.Write(query); err != nil {
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
