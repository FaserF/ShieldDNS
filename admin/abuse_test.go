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
		AbuseDGAThreshold:     3.8,
		AbuseDGAMinLen:        8,
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

	// Wait for background goroutine to update config
	for i := 0; i < 20; i++ {
		configLock.RLock()
		found := false
		for _, c := range config.BlockedClients {
			if c == ip {
				found = true
				break
			}
		}
		configLock.RUnlock()
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

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
		AbuseDGAThreshold:     3.8,
		AbuseDGAMinLen:        8,
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

	// Wait for background goroutine to update config
	for i := 0; i < 20; i++ {
		configLock.RLock()
		_, found := config.BlockedClientsInfo[ip]
		configLock.RUnlock()
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	configLock.RLock()
	info, hasInfo := config.BlockedClientsInfo[ip]
	configLock.RUnlock()

	if !hasInfo || info.Reason != "auto:nxdomain_flood" {
		t.Fatalf("Client should be blocked for nxdomain_flood, got info: %v", info)
	}
}

func TestAbuseDetectionDisabled(t *testing.T) {
	// ... (rest of old TestAbuseDetectionDisabled)
	// Reset state
	configLock.Lock()
	config = Config{
		AbuseDetectionEnabled: false,
		AbuseDGAThreshold:     3.8,
		AbuseDGAMinLen:        8,
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

func TestAbuseCountersCleanup(t *testing.T) {
	// Setup: Add some counters
	abuseMu.Lock()
	abuseCounters = make(map[string]*clientAbuseCounters)
	ip := "7.7.7.7"
	counters := &clientAbuseCounters{
		domainTimes: map[string][]time.Time{
			"stale.com": {time.Now().Add(-20 * time.Minute)},
			"fresh.com": {time.Now()},
		},
		allQueryTimes: []time.Time{time.Now()},
		nxdomainTimes: []time.Time{time.Now().Add(-20 * time.Minute)},
		dgaTimes:      []time.Time{time.Now().Add(-20 * time.Minute)},
	}
	abuseCounters[ip] = counters
	abuseMu.Unlock()

	// Manually trigger cleanup worker logic for test
	now := time.Now()
	abuseMu.Lock()
	for ip, counters := range abuseCounters {
		for domain, dTimes := range counters.domainTimes {
			counters.domainTimes[domain] = pruneWindow(dTimes, now, 10*time.Minute)
			if len(counters.domainTimes[domain]) == 0 {
				delete(counters.domainTimes, domain)
			}
		}
		counters.allQueryTimes = pruneWindow(counters.allQueryTimes, now, 10*time.Minute)
		counters.nxdomainTimes = pruneWindow(counters.nxdomainTimes, now, 10*time.Minute)
		counters.dgaTimes = pruneWindow(counters.dgaTimes, now, 10*time.Minute)

		if len(counters.allQueryTimes) == 0 && len(counters.domainTimes) == 0 && len(counters.nxdomainTimes) == 0 && len(counters.dgaTimes) == 0 {
			delete(abuseCounters, ip)
		}
	}
	abuseMu.Unlock()

	abuseMu.Lock()
	defer abuseMu.Unlock()
	c, exists := abuseCounters[ip]
	if !exists {
		t.Fatal("Counter entry for IP should still exist because fresh.com is within window")
	}
	if _, staleExists := c.domainTimes["stale.com"]; staleExists {
		t.Error("stale.com should have been purged from domainTimes")
	}
	if _, freshExists := c.domainTimes["fresh.com"]; !freshExists {
		t.Error("fresh.com should NOT have been purged from domainTimes")
	}
}
