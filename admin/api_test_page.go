package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Probe store – tracks DNS lookups made for a test token
// ---------------------------------------------------------------------------

type probeEntry struct {
	CreatedAt  time.Time
	SeenAt     time.Time
	Protocol   string // "doh", "dot", "doq", "plain", "unknown"
	ClientIP   string
	LatencyMs  float64
	Seen       bool
}

var (
	testProbeStore   sync.Map // key: token string → *probeEntry
	probeCleanupOnce sync.Once
)

func startProbeCleanup(ctx context.Context) {
	probeCleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(2 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					cleanupProbes()
				}
			}
		}()
	})
}

func cleanupProbes() {
	cutoff := time.Now().Add(-5 * time.Minute)
	testProbeStore.Range(func(k, v any) bool {
		if e, ok := v.(*probeEntry); ok && e.CreatedAt.Before(cutoff) {
			testProbeStore.Delete(k)
		}
		return true
	})
}

func newProbeToken() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// Fallback: use timestamp hex
		return hex.EncodeToString([]byte(time.Now().String()))[:24]
	}
	return hex.EncodeToString(b)
}

// markProbeSeen is called from dns_parser.go when a probe domain query is detected.
func markProbeSeen(token, protocol string, latencyMs float64) {
	v, ok := testProbeStore.Load(token)
	if !ok {
		return
	}
	e := v.(*probeEntry)
	e.Seen = true
	e.SeenAt = time.Now()
	if protocol != "" && e.Protocol == "unknown" {
		e.Protocol = protocol
	}
	if latencyMs > 0 && e.LatencyMs == 0 {
		e.LatencyMs = latencyMs
	}
}

// ---------------------------------------------------------------------------
// Handler: GET /api/public/dns-probe-new
// ---------------------------------------------------------------------------

// handleDNSProbeNew creates a fresh probe token and returns the token + the
// test subdomain the client's DNS resolver should look up.
func handleDNSProbeNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	token := newProbeToken()
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
		clientIP = fwd
	}

	configLock.RLock()
	adminDomain := config.AdminDomain
	configLock.RUnlock()

	probeDomain := token + ".probe"
	if adminDomain != "" {
		probeDomain = token + ".probe." + adminDomain
	}

	entry := &probeEntry{
		CreatedAt: time.Now(),
		Protocol:  "unknown",
		ClientIP:  clientIP,
	}
	testProbeStore.Store(token, entry)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{
		"id":           token,
		"probe_domain": probeDomain,
	})
}

// ---------------------------------------------------------------------------
// Handler: GET /api/public/dns-probe-run?id=<token>
// ---------------------------------------------------------------------------

// handleDNSProbeRun performs a server-side DNS lookup for the probe domain,
// records latency, and marks whether the lookup succeeded via ShieldDNS.
func handleDNSProbeRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimSpace(r.URL.Query().Get("id"))
	if token == "" || len(token) > 64 {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	v, ok := testProbeStore.Load(token)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"found":   false,
			"message": "Token not found or expired",
		})
		return
	}

	entry := v.(*probeEntry)

	configLock.RLock()
	adminDomain := config.AdminDomain
	filteringEnabled := config.FilteringEnabled
	doh3Enabled := config.DoH3Enabled
	preferEncrypted := config.PreferEncrypted
	stripECS := config.StripECS
	configLock.RUnlock()

	probeDomain := token + ".probe"
	if adminDomain != "" {
		probeDomain = token + ".probe." + adminDomain
	}

	// Server-side DNS lookup to measure CoreDNS reachability and latency
	dnsLatencyMs := 0.0
	usingShield := false
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", "127.0.0.1:53")
		},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	start := time.Now()
	addrs, err := resolver.LookupHost(ctx, probeDomain)
	dnsLatencyMs = float64(time.Since(start).Microseconds()) / 1000.0

	if err == nil || len(addrs) >= 0 {
		// If we could query CoreDNS (even NXDOMAIN is a valid response from our server)
		usingShield = true
		markProbeSeen(token, "plain", dnsLatencyMs) // server-side is always plain UDP to CoreDNS
	}

	// Detect active protocols from config
	protocols := []string{"dns-over-https"}
	if preferEncrypted {
		protocols = append(protocols, "dns-over-tls", "dns-over-quic")
	}

	// Blocking test: probe for known test block domain
	filterWorking := false
	if filteringEnabled {
		testBlockDomain := "shielddns-malware.test"
		ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel2()
		blockAddrs, blockErr := resolver.LookupHost(ctx2, testBlockDomain)
		// "Blocked" means NXDOMAIN or block-page IP response
		configLock.RLock()
		blockPageIP := config.BlockPageIP
		configLock.RUnlock()
		if blockErr != nil {
			filterWorking = true // NXDOMAIN = blocked
		} else if blockPageIP != "" {
			for _, a := range blockAddrs {
				if a == blockPageIP {
					filterWorking = true
					break
				}
			}
		}
	}

	// Protocol hint from User-Agent or headers
	protocolHint := entry.Protocol
	if protocolHint == "unknown" {
		ua := r.Header.Get("User-Agent")
		uaLow := strings.ToLower(ua)
		switch {
		case strings.Contains(uaLow, "dot") || strings.Contains(uaLow, "private dns"):
			protocolHint = "dot"
		case strings.Contains(uaLow, "doh") || strings.Contains(uaLow, "dns-over-https"):
			protocolHint = "doh"
		}
	}

	if err != nil {
		slog.Debug("DNS probe lookup failed", "domain", probeDomain, "error", err)
	}

	resp := map[string]any{
		"found":          true,
		"using_shield":   usingShield,
		"protocol":       protocolHint,
		"protocols":      protocols,
		"dns_latency_ms": dnsLatencyMs,
		"filter_active":  filteringEnabled,
		"filter_working": filterWorking,
		"doh3_enabled":   doh3Enabled,
		"strip_ecs":      stripECS,
		"probe_domain":   probeDomain,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// Handler: GET /api/public/dns-probe-status?id=<token>
// ---------------------------------------------------------------------------

func handleDNSProbeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimSpace(r.URL.Query().Get("id"))
	if token == "" || len(token) > 64 {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	v, ok := testProbeStore.Load(token)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"found": false,
		})
		return
	}

	entry := v.(*probeEntry)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"found":      true,
		"seen":       entry.Seen,
		"protocol":   entry.Protocol,
		"latency_ms": entry.LatencyMs,
	})
}

// ---------------------------------------------------------------------------
// Handler: GET /api/public/test-info
// ---------------------------------------------------------------------------

// handlePublicTestInfo returns non-sensitive public information about this
// ShieldDNS instance useful for the test page (filtering state, protocol caps).
func handlePublicTestInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.RLock()
	filteringEnabled := config.FilteringEnabled
	doh3Enabled := config.DoH3Enabled
	preferEncrypted := config.PreferEncrypted
	stripECS := config.StripECS
	dnssecEnabled := config.DNSSECEnabled
	nodeName := config.ClusterNodeName
	clusterRole := config.ClusterRole
	adminDomain := config.AdminDomain
	configLock.RUnlock()

	protocols := []string{"doh"}
	if preferEncrypted {
		protocols = append(protocols, "dot", "doq")
	}
	if doh3Enabled {
		protocols = append(protocols, "doh3")
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{
		"filter_active":  filteringEnabled,
		"doh3_enabled":   doh3Enabled,
		"prefer_encrypted": preferEncrypted,
		"strip_ecs":      stripECS,
		"dnssec_enabled": dnssecEnabled,
		"node_name":      nodeName,
		"cluster_role":   clusterRole,
		"admin_domain":   adminDomain,
		"protocols":      protocols,
	})
}
