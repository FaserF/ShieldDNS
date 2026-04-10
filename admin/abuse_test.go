package main

import (
	"fmt"
	"testing"
	"time"
)

func TestAnalyzeQueryDomainFlood(t *testing.T) {
	// Reset state
	configLock.Lock()
	config = Config{
		AbuseDetectionEnabled: true,
		BlockedClients:        []string{},
		BlockedClientsInfo:    make(map[string]BlockedClientInfo),
	}
	configLock.Unlock()

	abuseMu.Lock()
	abuseCounters = make(map[string]*clientAbuseCounters)
	abuseMu.Unlock()

	ip := "1.2.3.4"
	domain := "flood.com"
	
	// Send 119 queries (threshold is 120)
	for i := 0; i < 119; i++ {
		analyzeQuery(ip, domain, "NOERROR")
	}

	configLock.RLock()
	blocked := false
	for _, c := range config.BlockedClients {
		if c == ip {
			blocked = true
		}
	}
	configLock.RUnlock()

	if blocked {
		t.Fatal("Client should not be blocked at 119 queries")
	}

	// 120th query should trigger block
	analyzeQuery(ip, domain, "NOERROR")

	// Wait briefly for goroutine to finish (blockClientAuto runs in goroutine inside analyzeQuery? No, blockClientAuto is asynchronous if we called `go blockClientAuto`, wait, let me check abuse.go: yes `go blockClientAuto`)
	time.Sleep(10 * time.Millisecond)

	configLock.RLock()
	blocked = false
	info, hasInfo := config.BlockedClientsInfo[ip]
	for _, c := range config.BlockedClients {
		if c == ip {
			blocked = true
		}
	}
	configLock.RUnlock()

	if !blocked {
		t.Fatal("Client should be blocked at 120 queries")
	}
	if !hasInfo || info.Reason != "auto:domain_flood" || !info.Auto {
		t.Fatalf("Missing or incorrect block reason: %v", info)
	}
}

func TestAnalyzeQueryNXDomainFlood(t *testing.T) {
	// Reset state
	configLock.Lock()
	config = Config{
		AbuseDetectionEnabled: true,
		BlockedClients:        []string{},
		BlockedClientsInfo:    make(map[string]BlockedClientInfo),
	}
	configLock.Unlock()

	abuseMu.Lock()
	abuseCounters = make(map[string]*clientAbuseCounters)
	abuseMu.Unlock()

	ip := "5.5.5.5"
	
	// Send 299 queries (threshold is 300)
	for i := 0; i < 299; i++ {
		// Use unique domains to avoid triggering Single Domain Flood logic (120 queries/domain)
		domain := fmt.Sprintf("random-dga-%d.com", i)
		analyzeQuery(ip, domain, "NXDOMAIN")
	}

	configLock.RLock()
	if len(config.BlockedClients) > 0 {
		t.Fatal("Client should not be blocked at 299 queries")
	}
	configLock.RUnlock()

	// 300th query should trigger block
	analyzeQuery(ip, "random-dga-300.com", "NXDOMAIN")
	time.Sleep(10 * time.Millisecond)

	configLock.RLock()
	info, hasInfo := config.BlockedClientsInfo[ip]
	configLock.RUnlock()

	if !hasInfo || info.Reason != "auto:nxdomain_flood" {
		t.Fatalf("Client should be blocked for nxdomain_flood, got info: %v", info)
	}
}

func TestAbuseDetectionDisabled(t *testing.T) {
	// Reset state
	configLock.Lock()
	config = Config{
		AbuseDetectionEnabled: false,
		BlockedClients:        []string{},
	}
	configLock.Unlock()

	ip := "9.9.9.9"
	
	for i := 0; i < 100; i++ {
		analyzeQuery(ip, "safe.com", "NOERROR")
	}

	configLock.RLock()
	blocked := len(config.BlockedClients) > 0
	configLock.RUnlock()

	if blocked {
		t.Fatal("Client should not be blocked when detection is disabled")
	}
}
