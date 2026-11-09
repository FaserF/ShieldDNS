package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleRoutingRules(t *testing.T) {
	configLock.Lock()
	config.AdminPasswordHashed = "test-hash"
	config.RoutingRules = []RoutingRule{
		{
			ID:         "rule-1",
			Name:       "Test Internal",
			Match:      "internal.corp",
			MatchType:  "domain",
			Target:     "host",
			HostTarget: "192.168.1.53",
			Enabled:    true,
		},
	}
	config.WireGuardGateway = "10.0.0.1:53"
	configLock.Unlock()

	// 1. GET routing rules
	reqGet := httptest.NewRequest(http.MethodGet, "/api/routing/rules", nil)
	rrGet := httptest.NewRecorder()
	handleRoutingRules(rrGet, reqGet)

	if rrGet.Code != http.StatusOK {
		t.Fatalf("GET /api/routing/rules expected 200, got %d", rrGet.Code)
	}

	var getResp struct {
		Rules            []RoutingRule `json:"rules"`
		WireGuardGateway string        `json:"wireguard_gateway"`
	}
	if err := json.NewDecoder(rrGet.Body).Decode(&getResp); err != nil {
		t.Fatalf("Failed to decode GET response: %v", err)
	}
	if len(getResp.Rules) != 1 || getResp.Rules[0].Match != "internal.corp" {
		t.Errorf("Unexpected rules in GET: %+v", getResp.Rules)
	}
	if getResp.WireGuardGateway != "10.0.0.1:53" {
		t.Errorf("Expected WireGuardGateway 10.0.0.1:53, got %s", getResp.WireGuardGateway)
	}

	// 2. POST add wireguard routing rule
	postPayload := map[string]interface{}{
		"name":             "VPN Route",
		"match":            "vpn.secure.net",
		"match_type":       "domain",
		"target":           "wireguard",
		"wireguard_config": "10.100.0.1:53",
		"enabled":          true,
	}
	b, _ := json.Marshal(postPayload)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewReader(b))
	rrPost := httptest.NewRecorder()
	handleRoutingRules(rrPost, reqPost)

	if rrPost.Code != http.StatusOK {
		t.Fatalf("POST /api/routing/rules expected 200, got %d (body: %s)", rrPost.Code, rrPost.Body.String())
	}

	configLock.RLock()
	foundVPN := false
	for _, r := range config.RoutingRules {
		if r.Match == "vpn.secure.net" && r.Target == "wireguard" {
			foundVPN = true
			break
		}
	}
	configLock.RUnlock()

	if !foundVPN {
		t.Error("Expected vpn.secure.net rule to be added to config.RoutingRules")
	}

	// 3. DELETE routing rule
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/routing/rules?match=internal.corp", nil)
	rrDel := httptest.NewRecorder()
	handleRoutingRules(rrDel, reqDel)

	if rrDel.Code != http.StatusOK {
		t.Fatalf("DELETE /api/routing/rules expected 200, got %d", rrDel.Code)
	}

	configLock.RLock()
	for _, r := range config.RoutingRules {
		if r.Match == "internal.corp" {
			t.Error("Rule internal.corp should have been deleted")
		}
	}
	configLock.RUnlock()
}

func TestGetRoutingZoneBlocks(t *testing.T) {
	cfg := &Config{
		DNSSECEnabled:    true,
		FilteringEnabled: true,
		WireGuardGateway: "10.0.0.1:53",
		RoutingRules: []RoutingRule{
			{
				ID:         "r1",
				Match:      "corp.internal",
				MatchType:  "domain",
				Target:     "host",
				HostTarget: "192.168.10.1:53",
				Enabled:    true,
			},
			{
				ID:              "r2",
				Match:           "vpn.service",
				MatchType:       "domain",
				Target:          "wireguard",
				WireGuardConfig: "10.200.0.1:53",
				Enabled:         true,
			},
		},
	}

	blocks := getRoutingZoneBlocks(cfg, "53", "853", "5553", true, "/ssl/cert.pem", "/ssl/key.pem")

	if !strings.Contains(blocks, "corp.internal:53 {") {
		t.Errorf("Expected corp.internal zone block, got: %s", blocks)
	}
	if !strings.Contains(blocks, "forward . 192.168.10.1:53") {
		t.Errorf("Expected host forward upstream in block, got: %s", blocks)
	}
	if !strings.Contains(blocks, "vpn.service:53 {") {
		t.Errorf("Expected vpn.service zone block, got: %s", blocks)
	}
	if !strings.Contains(blocks, "forward . 10.200.0.1:53") {
		t.Errorf("Expected wireguard forward upstream in block, got: %s", blocks)
	}
	if !strings.Contains(blocks, "tls://corp.internal:853 {") {
		t.Errorf("Expected DoT block for corp.internal, got: %s", blocks)
	}
}

func TestRoutingRules_EdgeCases(t *testing.T) {
	// 1. Replica Node Forbidden (POST & DELETE)
	configLock.Lock()
	config.ClusterRole = "replica"
	configLock.Unlock()

	reqReplicaPOST := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{}`))
	rrReplicaPOST := httptest.NewRecorder()
	handleRoutingRules(rrReplicaPOST, reqReplicaPOST)
	if rrReplicaPOST.Code != http.StatusForbidden {
		t.Errorf("expected 403 for replica POST, got %d", rrReplicaPOST.Code)
	}

	reqReplicaDEL := httptest.NewRequest(http.MethodDelete, "/api/routing/rules?id=1", nil)
	rrReplicaDEL := httptest.NewRecorder()
	handleRoutingRules(rrReplicaDEL, reqReplicaDEL)
	if rrReplicaDEL.Code != http.StatusForbidden {
		t.Errorf("expected 403 for replica DELETE, got %d", rrReplicaDEL.Code)
	}

	configLock.Lock()
	config.ClusterRole = "primary" // restore
	configLock.Unlock()

	// 2. POST with Empty Match
	reqEmptyMatch := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": ""}`))
	rrEmptyMatch := httptest.NewRecorder()
	handleRoutingRules(rrEmptyMatch, reqEmptyMatch)
	if rrEmptyMatch.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for empty match, got %d", rrEmptyMatch.Code)
	}

	// 3. POST with Invalid matchType
	reqInvalidMatchType := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "example.com", "match_type": "invalid"}`))
	rrInvalidMatchType := httptest.NewRecorder()
	handleRoutingRules(rrInvalidMatchType, reqInvalidMatchType)
	if rrInvalidMatchType.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid match_type, got %d", rrInvalidMatchType.Code)
	}

	// 4. POST with Invalid Domain
	reqInvalidDomain := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "invalid!!domain", "match_type": "domain"}`))
	rrInvalidDomain := httptest.NewRecorder()
	handleRoutingRules(rrInvalidDomain, reqInvalidDomain)
	if rrInvalidDomain.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid domain, got %d", rrInvalidDomain.Code)
	}

	// 5. POST with Invalid IP
	reqInvalidIP := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "999.999.999.999", "match_type": "client_ip"}`))
	rrInvalidIP := httptest.NewRecorder()
	handleRoutingRules(rrInvalidIP, reqInvalidIP)
	if rrInvalidIP.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid IP, got %d", rrInvalidIP.Code)
	}

	// 6. POST with Invalid CIDR
	reqInvalidCIDR := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "192.168.1.0/99", "match_type": "client_ip"}`))
	rrInvalidCIDR := httptest.NewRecorder()
	handleRoutingRules(rrInvalidCIDR, reqInvalidCIDR)
	if rrInvalidCIDR.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid CIDR, got %d", rrInvalidCIDR.Code)
	}

	// 7. POST target=host but no host_target
	reqNoHostTarget := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewBufferString(`{"match": "example.com", "match_type": "domain", "target": "host"}`))
	rrNoHostTarget := httptest.NewRecorder()
	handleRoutingRules(rrNoHostTarget, reqNoHostTarget)
	if rrNoHostTarget.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing host_target, got %d", rrNoHostTarget.Code)
	}

	// 8. DELETE with missing ID and Match
	reqMissingDel := httptest.NewRequest(http.MethodDelete, "/api/routing/rules", nil)
	rrMissingDel := httptest.NewRecorder()
	handleRoutingRules(rrMissingDel, reqMissingDel)
	if rrMissingDel.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing ID/match on delete, got %d", rrMissingDel.Code)
	}

	// 9. DELETE non-existent rule
	reqDel404 := httptest.NewRequest(http.MethodDelete, "/api/routing/rules?id=nonexistent", nil)
	rrDel404 := httptest.NewRecorder()
	handleRoutingRules(rrDel404, reqDel404)
	if rrDel404.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent rule, got %d", rrDel404.Code)
	}
}

func TestYouTubeAdblockAndSNIGeoRouting(t *testing.T) {
	cfg := &Config{
		AdminDomain:           "dns.example.com",
		BlockPageIP:           "89.168.74.120",
		YouTubeAdblockEnabled: false,
		VPNProvider:           "privado",
		VPNDefaultCountry:     "AL",
		VPNProxyURL:           "http://127.0.0.1:8888",
	}

	// 1. Default OFF: no YouTube domains should match SNI Geo-Route or generate template blocks
	if _, matched := MatchSNIGeoRoute(cfg, "youtubei.googleapis.com"); matched {
		t.Errorf("expected youtubei.googleapis.com NOT to match when YouTubeAdblockEnabled is false")
	}
	if zones := GetGeoRoutedZones(cfg); len(zones) != 0 {
		t.Errorf("expected 0 geo-routed zones when disabled, got %v", zones)
	}

	// 2. Enable YouTube Adblock: YouTube & GoogleVideo domains should match, AdminDomain and unrelated domains must NOT match
	cfg.YouTubeAdblockEnabled = true
	proxyURL, matched := MatchSNIGeoRoute(cfg, "rr1---sn-4g5ednsd.googlevideo.com")
	if !matched || proxyURL != "http://127.0.0.1:8888" {
		t.Errorf("expected googlevideo subdomain to match with proxy URL, got matched=%v proxy=%s", matched, proxyURL)
	}
	if _, matched := MatchSNIGeoRoute(cfg, "youtubei.googleapis.com"); !matched {
		t.Errorf("expected youtubei.googleapis.com to match when YouTubeAdblockEnabled is true")
	}
	if _, matched := MatchSNIGeoRoute(cfg, "dns.example.com"); matched {
		t.Errorf("expected AdminDomain dns.example.com never to match SNI Geo-Proxy")
	}
	if _, matched := MatchSNIGeoRoute(cfg, "evil-open-proxy-test.com"); matched {
		t.Errorf("expected unauthorized domain not to match SNI Geo-Proxy")
	}

	// 3. Verify Corefile template blocks redirect A to GeoProxyIP and suppress AAAA / HTTPS (type 65 QUIC)
	tmpl := getTemplateBlocks(cfg)
	if !strings.Contains(tmpl, "template IN A googlevideo.com") || !strings.Contains(tmpl, "89.168.74.120") {
		t.Errorf("expected Corefile template IN A googlevideo.com -> 89.168.74.120, got:\n%s", tmpl)
	}
	if !strings.Contains(tmpl, "template IN HTTPS googlevideo.com") || !strings.Contains(tmpl, "template IN AAAA googlevideo.com") {
		t.Errorf("expected AAAA and HTTPS suppression templates for googlevideo.com, got:\n%s", tmpl)
	}

	// 4. Verify custom RoutingRule with target="vpn" and country="AL"
	postPayload := map[string]interface{}{
		"name":       "Custom Geo Service",
		"match":      "stream.example.org",
		"match_type": "domain",
		"target":     "vpn",
		"country":    "AL",
		"proxy_url":  "socks5://127.0.0.1:1080",
		"enabled":    true,
	}
	b, _ := json.Marshal(postPayload)
	reqPost := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewReader(b))
	rrPost := httptest.NewRecorder()
	handleRoutingRules(rrPost, reqPost)
	if rrPost.Code != http.StatusOK {
		t.Fatalf("POST /api/routing/rules for target=vpn expected 200, got %d (%s)", rrPost.Code, rrPost.Body.String())
	}

	// 5. Verify multi-service SmartDNS toggles (Twitch, Reddit, Spotify/SoundCloud, Social, SmartTV) and VPNCountryProxies map
	cfg.TwitchAdblockEnabled = true
	cfg.RedditAdblockEnabled = true
	cfg.SpotifyAdblockEnabled = true
	cfg.SocialAdblockEnabled = true
	cfg.SmartTVAdblockEnabled = true
	for _, domain := range []string{"usher.ttvnw.net", "gql.reddit.com", "spclient.wg.spotify.com", "api16-normal-c-useast1a.tiktokv.com", "ads.samsung.com"} {
		if _, ok := MatchSNIGeoRoute(cfg, domain); !ok {
			t.Errorf("expected %s to match SNI Geo-Route when service toggle is enabled", domain)
		}
	}

	// 6. Verify TLS ClientHello SNI extraction
	clientHello := buildTestClientHello("youtubei.googleapis.com")
	if sni := ExtractTLSSNI(clientHello); sni != "youtubei.googleapis.com" {
		t.Errorf("expected extracted SNI 'youtubei.googleapis.com', got %q", sni)
	}

	// 7. Verify Native VPN Mode & Status API (/api/vpn/status)
	configLock.Lock()
	config.VPNMode = "native_openvpn"
	config.VPNProvider = "privado"
	config.VPNDefaultCountry = "AL"
	config.VPNInterface = "tun_shield"
	config.VPNPassword = "secret-password"
	configLock.Unlock()

	sanitized := config.SanitizedCopy()
	if sanitized.VPNPassword != "********" {
		t.Errorf("expected VPNPassword to be masked in SanitizedCopy, got %q", sanitized.VPNPassword)
	}

	reqVPN := httptest.NewRequest(http.MethodGet, "/api/vpn/status", nil)
	rrVPN := httptest.NewRecorder()
	handleVPNStatus(rrVPN, reqVPN)
	if rrVPN.Code != http.StatusOK {
		t.Fatalf("GET /api/vpn/status expected 200, got %d", rrVPN.Code)
	}
	var vpnStatus map[string]interface{}
	if err := json.Unmarshal(rrVPN.Body.Bytes(), &vpnStatus); err != nil {
		t.Fatalf("failed to decode /api/vpn/status: %v", err)
	}
	if vpnStatus["vpn_mode"] != "native_openvpn" || vpnStatus["vpn_country"] != "AL" {
		t.Errorf("unexpected vpnStatus response: %+v", vpnStatus)
	}

	// 8. Verify NextDNS Routing and DoT Corefile generation
	configLock.Lock()
	config.NextDNSProfileID = "2351bb"
	config.NextDNSAPIKey = "3be9cf7680280fc4e73c59b52a1bc3b6bea250fb"
	config.NextDNSYouTube = true
	config.NextDNSReddit = true
	configLock.Unlock()

	sanitizedNextDNS := config.SanitizedCopy()
	if sanitizedNextDNS.NextDNSAPIKey != "********" {
		t.Errorf("expected NextDNSAPIKey to be masked in SanitizedCopy, got %q", sanitizedNextDNS.NextDNSAPIKey)
	}

	coreBlocks := getRoutingZoneBlocks(&config, "53", "853", "443", true, "/ssl/cert.pem", "/ssl/key.pem")
	if !strings.Contains(coreBlocks, "youtube.com:53 {") {
		t.Errorf("expected youtube.com:53 block in Corefile when NextDNSYouTube is true, got:\n%s", coreBlocks)
	}
	if !strings.Contains(coreBlocks, "tls_servername 2351bb.dns.nextdns.io") {
		t.Errorf("expected tls_servername 2351bb.dns.nextdns.io in Corefile, got:\n%s", coreBlocks)
	}
	if !strings.Contains(coreBlocks, "reddit.com:53 {") {
		t.Errorf("expected reddit.com:53 block in Corefile when NextDNSReddit is true, got:\n%s", coreBlocks)
	}

	// Verify custom rule with target="nextdns"
	postNextDNS := map[string]interface{}{
		"name":       "NextDNS Custom Rule",
		"match":      "custom-feed.org",
		"match_type": "domain",
		"target":     "nextdns",
		"enabled":    true,
	}
	bNext, _ := json.Marshal(postNextDNS)
	reqNext := httptest.NewRequest(http.MethodPost, "/api/routing/rules", bytes.NewReader(bNext))
	rrNext := httptest.NewRecorder()
	handleRoutingRules(rrNext, reqNext)
	if rrNext.Code != http.StatusOK {
		t.Fatalf("POST /api/routing/rules for target=nextdns expected 200, got %d (%s)", rrNext.Code, rrNext.Body.String())
	}

	// 9. Test NextDNS Monthly Limit & Automatic Quota Fallback
	configLock.Lock()
	config.NextDNSMonthlyLimit = 500
	configLock.Unlock()

	if limit := GetNextDNSMonthlyLimit(&config); limit != 500 {
		t.Errorf("expected GetNextDNSMonthlyLimit to return 500, got %d", limit)
	}

	// Below limit: not exceeded
	nextDNSCacheMu.Lock()
	cachedNextDNSQueries = 100
	cachedNextDNSMonth = time.Now().UTC().Month()
	cachedNextDNSYear = time.Now().UTC().Year()
	lastNextDNSQueryCheck = time.Now().UTC()
	cachedNextDNSExceeded.Store(false)
	nextDNSCacheMu.Unlock()

	if isNextDNSQuotaExceeded(&config) {
		t.Errorf("expected isNextDNSQuotaExceeded to be false when queries(100) < limit(500)")
	}

	// Simulate exceeding monthly limit
	nextDNSCacheMu.Lock()
	cachedNextDNSQueries = 500
	lastNextDNSQueryCheck = time.Now().UTC()
	nextDNSCacheMu.Unlock()

	if !isNextDNSQuotaExceeded(&config) {
		t.Errorf("expected isNextDNSQuotaExceeded to be true when queries(500) >= limit(500)")
	}

	// Corefile should NOT generate NextDNS blocks when quota is exceeded, falling back to standard/geoproxy
	fallbackCoreBlocks := getRoutingZoneBlocks(&config, "53", "853", "443", true, "/ssl/cert.pem", "/ssl/key.pem")
	if strings.Contains(fallbackCoreBlocks, "tls_servername 2351bb.dns.nextdns.io") {
		t.Errorf("expected NextDNS blocks to be omitted when quota exceeded, got:\n%s", fallbackCoreBlocks)
	}

	// Test GET /api/routing/nextdns-status endpoint
	statusReq := httptest.NewRequest(http.MethodGet, "/api/routing/nextdns-status", nil)
	statusRR := httptest.NewRecorder()
	handleNextDNSStatus(statusRR, statusReq)
	if statusRR.Code != http.StatusOK {
		t.Fatalf("GET /api/routing/nextdns-status expected 200, got %d", statusRR.Code)
	}
	var statusData map[string]interface{}
	if err := json.Unmarshal(statusRR.Body.Bytes(), &statusData); err != nil {
		t.Fatalf("failed to decode nextdns-status JSON: %v", err)
	}
	if statusData["quota_exceeded"] != true {
		t.Errorf("expected quota_exceeded true in status response, got %v", statusData["quota_exceeded"])
	}
	if statusData["current_routing"] != "fallback_standard" {
		t.Errorf("expected current_routing fallback_standard, got %v", statusData["current_routing"])
	}
}

func buildTestClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	// server_name extension payload: listLen(2) + nameType(1=0x00) + nameLen(2) + sniBytes
	extDataLen := 2 + 1 + 2 + len(sniBytes)
	// extensions total length: extType(2=0x0000) + extLen(2) + extDataLen
	extsLen := 2 + 2 + extDataLen
	// ClientHello body: Version(2) + Random(32) + SessionID(1=0) + CipherSuites(2+2) + Compression(1+1) + ExtsLen(2) + Exts
	chBodyLen := 2 + 32 + 1 + 4 + 2 + 2 + extsLen
	// Handshake record: Type(1=0x01) + Len(3) + chBodyLen
	hsLen := 1 + 3 + chBodyLen

	buf := make([]byte, 0, 5+hsLen)
	// TLS Record header
	buf = append(buf, 0x16, 0x03, 0x01, byte(hsLen>>8), byte(hsLen))
	// Handshake header
	buf = append(buf, 0x01, byte(chBodyLen>>16), byte(chBodyLen>>8), byte(chBodyLen))
	// Version TLS 1.2
	buf = append(buf, 0x03, 0x03)
	// Random (32B)
	buf = append(buf, make([]byte, 32)...)
	// SessionID (0)
	buf = append(buf, 0x00)
	// CipherSuites (len 2, 0x1301)
	buf = append(buf, 0x00, 0x02, 0x13, 0x01)
	// Compression (len 1, 0x00)
	buf = append(buf, 0x01, 0x00)
	// Extensions length
	buf = append(buf, byte(extsLen>>8), byte(extsLen))
	// Extension: server_name (0x0000)
	buf = append(buf, 0x00, 0x00, byte(extDataLen>>8), byte(extDataLen))
	listLen := 1 + 2 + len(sniBytes)
	buf = append(buf, byte(listLen>>8), byte(listLen), 0x00, byte(len(sniBytes)>>8), byte(len(sniBytes)))
	buf = append(buf, sniBytes...)
	return buf
}
