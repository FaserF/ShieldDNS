package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"text/template"
	"time"
)

func getInternalEnginePort() string {
	p := os.Getenv("INTERNAL_ENGINE_PORT")
	if p == "" {
		return "11053"
	}
	return p
}

var corefileTmpl = template.Must(template.New("corefile").Parse(CorefileTemplate))

func updateCorefile() bool {
	configLock.RLock()
	cfg := config.Clone()
	configLock.RUnlock()
	debugModeAtomic.Store(cfg.DebugMode)
	syncContainerResolvConf(cfg)

	healthLock.RLock()
	hDNS := make([]string, len(healthyUpstreams))
	copy(hDNS, healthyUpstreams)
	hDoT := make([]string, len(healthyDoT))
	copy(hDoT, healthyDoT)
	healthLock.RUnlock()

	if cfg.UseFastestUpstream {
		const latencyBucket = 15 * time.Millisecond
		latencyLock.RLock()
		sort.SliceStable(hDNS, func(i, j int) bool {
			return latencyMap[hDNS[i]]/latencyBucket < latencyMap[hDNS[j]]/latencyBucket
		})
		sort.SliceStable(hDoT, func(i, j int) bool {
			return latencyMap[hDoT[i]]/latencyBucket < latencyMap[hDoT[j]]/latencyBucket
		})
		latencyLock.RUnlock()
	}

	var upstreams []string
	var dotServerName string
	var distinctDoTHosts []string
	if cfg.PreferEncrypted {
		for _, u := range hDoT {
			host, _ := splitAddr(u, "853")
			if net.ParseIP(host) == nil {
				found := false
				for _, h := range distinctDoTHosts {
					if h == host {
						found = true
						break
					}
				}
				if !found {
					distinctDoTHosts = append(distinctDoTHosts, host)
				}
			}
		}
		for _, u := range hDoT {
			host, port := splitAddr(u, "853")
			if len(distinctDoTHosts) > 1 && net.ParseIP(host) == nil {
				upstreams = append(upstreams, fmt.Sprintf("tls://%s:%s", host, port))
			} else {
				ip := resolveHost(host)
				upstreams = append(upstreams, fmt.Sprintf("tls://%s:%s", ip, port))
			}
		}
		if len(distinctDoTHosts) == 1 {
			dotServerName = distinctDoTHosts[0]
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
	if cfg.UseFastestUpstream {
		if cfg.SmartSelectionPolicy == "random" {
			policyVal = "random"
		} else if cfg.SmartSelectionPolicy == "broadcast" {
			policyVal = "broadcast"
			if len(distinctDoTHosts) > 1 {
				dotServerName = ""
			}
		} else {
			policyVal = "sequential"
		}
	}

	if peerAddr := getActivePeerOffloadAddr(); peerAddr != "" && cfg.ClusterPeerOffloadEnabled {
		peerUpstreams := []string{peerAddr}
		for _, u := range hDNS {
			host, port := splitAddr(u, "53")
			ip := resolveHost(host)
			peerUpstreams = append(peerUpstreams, fmt.Sprintf("%s:%s", ip, port))
		}
		if len(peerUpstreams) == 1 {
			peerUpstreams = append(peerUpstreams, "1.1.1.1:53", "8.8.8.8:53")
		}
		upstreamStr = strings.Join(peerUpstreams, " ")
		policyVal = "sequential"
		dotServerName = ""
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
	internalEnginePort := getInternalEnginePort()
	internalPolicyPort := os.Getenv("INTERNAL_POLICY_PORT")
	if internalPolicyPort == "" {
		internalPolicyPort = policyProxyPort
	}
	if os.Getenv("DISABLE_POLICY_PROXY") == "true" {
		internalPolicyPort = internalEnginePort
	}

	data := CorefileData{
		DNSPort:            dnsPort,
		DOTPort:            dotPort,
		InternalDOHPort:    internalDOHPort,
		InternalEnginePort: internalEnginePort,
		InternalPolicyPort: internalPolicyPort,
		DNSSEC:             cfg.DNSSECEnabled,
		ServeStale:         cfg.ServeStale,
		Upstreams:          upstreamStr,
		TLSServerName:      dotServerName,
		Policy:             policyVal,
		HostsPath:          CombinedHostsPath,
		GeoACLRules:        getGeoACLRules(cfg),
		CertFile:           certFile,
		KeyFile:            keyFile,
		FilteringEnabled:   cfg.FilteringEnabled,
		HasCerts:           hasCerts,
		RateLimitRate:      cfg.RateLimitRate,
		RateLimitBurst:     cfg.RateLimitBurst,
		RoutingBlocks:      getRoutingZoneBlocks(cfg, dnsPort, dotPort, internalDOHPort, hasCerts, certFile, keyFile),
		TemplateBlocks:     getTemplateBlocks(cfg),
	}

	var buf bytes.Buffer
	if err := corefileTmpl.Execute(&buf, data); err != nil {
		slog.Error("Error executing Corefile template", "error", err)
		return false
	}

	newBytes := buf.Bytes()
	if existing, err := os.ReadFile(CorefilePath); err == nil && bytes.Equal(existing, newBytes) {
		return false
	}

	if err := atomicWriteFile(CorefilePath, newBytes); err != nil {
		slog.Error("Error writing Corefile", "error", err)
		return false
	}
	return true
}

// syncContainerResolvConf keeps the container's /etc/resolv.conf aligned with the UI-configured
// plain DNS upstreams (excluding loopback/Tailnet self-IPs so CoreDNS never loops back into itself).
func syncContainerResolvConf(cfg *Config) {
	if testMode || cfg == nil {
		return
	}
	// Never overwrite resolv.conf in Home Assistant addon environment or when supervisor is present
	if os.Getenv("SUPERVISOR_TOKEN") != "" || os.Getenv("HASSIO_TOKEN") != "" {
		return
	}
	if _, err := os.Stat("/data/options.json"); err == nil {
		return
	}
	if os.Getenv("DISABLE_RESOLV_SYNC") == "true" {
		return
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		return
	}
	// Preserve Docker embedded DNS (127.0.0.11) and internal search domains
	if existing, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		sExisting := string(existing)
		if strings.Contains(sExisting, "127.0.0.11") || strings.Contains(sExisting, "local.hass.io") {
			return
		}
	}
	var sb strings.Builder
	sb.WriteString("# Automatically managed from ShieldDNS UI Upstreams\n")
	count := 0
	for _, u := range cfg.Upstreams {
		host, _ := splitAddr(strings.TrimSpace(u), "53")
		parsed := net.ParseIP(host)
		if parsed == nil || parsed.IsLoopback() || parsed.IsUnspecified() || IsPrivateOrTailnetIP(host) {
			continue
		}
		sb.WriteString("nameserver " + host + "\n")
		count++
	}
	if count == 0 {
		return
	}
	sb.WriteString("options timeout:2 attempts:2 rotate\n")
	desired := []byte(sb.String())
	if existing, err := os.ReadFile("/etc/resolv.conf"); err == nil && bytes.Equal(existing, desired) {
		return
	}
	_ = os.WriteFile("/etc/resolv.conf", desired, 0644)
}

func getRoutingZoneBlocks(cfg *Config, dnsPort, dotPort, dohPort string, hasCerts bool, certFile, keyFile string) string {
	if cfg == nil {
		return ""
	}

	var sb strings.Builder

	// Local PTR / Reverse DNS Upstreams (e.g. 192.168.178.1, 192.168.1.1)
	if len(cfg.LocalPTRUpstreams) > 0 {
		var ptrUpstreams []string
		for _, u := range cfg.LocalPTRUpstreams {
			host, port := splitAddr(u, "53")
			ip := resolveHost(host)
			ptrUpstreams = append(ptrUpstreams, net.JoinHostPort(ip, port))
		}
		if len(ptrUpstreams) > 0 {
			upstreamStr := strings.Join(ptrUpstreams, " ")
			for _, zone := range []string{"in-addr.arpa", "ip6.arpa"} {
				sb.WriteString(fmt.Sprintf("%s:%s {\n", zone, dnsPort))
				sb.WriteString("    cache 300\n")
				sb.WriteString(fmt.Sprintf("    forward . %s {\n        health_check 5s\n    }\n", upstreamStr))
				sb.WriteString("    errors\n}\n\n")

				if hasCerts {
					sb.WriteString(fmt.Sprintf("tls://%s:%s {\n    tls %s %s\n", zone, dotPort, certFile, keyFile))
					sb.WriteString("    cache 300\n")
					sb.WriteString(fmt.Sprintf("    forward . %s {\n        health_check 5s\n    }\n", upstreamStr))
					sb.WriteString("    errors\n}\n\n")

					sb.WriteString(fmt.Sprintf("https://%s:%s {\n    tls %s %s\n", zone, dohPort, certFile, keyFile))
					sb.WriteString("    cache 300\n")
					sb.WriteString(fmt.Sprintf("    forward . %s {\n        health_check 5s\n    }\n", upstreamStr))
					sb.WriteString("    errors\n}\n\n")

					sb.WriteString(fmt.Sprintf("quic://%s:%s {\n    tls %s %s\n", zone, dotPort, certFile, keyFile))
					sb.WriteString("    quic {\n        max_streams 50\n        worker_pool_size 256\n    }\n")
					sb.WriteString("    cache 300\n")
					sb.WriteString(fmt.Sprintf("    forward . %s {\n        health_check 5s\n    }\n", upstreamStr))
					sb.WriteString("    errors\n}\n\n")
				}
			}
		}
	}

	type routingTarget struct {
		upstreams     []string
		tlsServerName string
	}
	zoneTargets := make(map[string]routingTarget)

	for _, rule := range cfg.RoutingRules {
		if !rule.Enabled {
			continue
		}

		matchDomain := strings.TrimSpace(rule.Match)
		if rule.MatchType == "client_ip" || matchDomain == "" || !isValidDomain(matchDomain) {
			continue
		}
		// CoreDNS expects normalized root without wildcards in zone names
		matchDomain = strings.ToLower(strings.Trim(strings.TrimPrefix(matchDomain, "*."), "."))

		var upstreams []string
		var tlsServerName string
		switch rule.Target {
		case "host":
			h := strings.TrimSpace(rule.HostTarget)
			if h != "" {
				host, port := splitAddr(h, "53")
				ip := resolveHost(host)
				upstreams = append(upstreams, net.JoinHostPort(ip, port))
			}
		case "wireguard":
			wgTarget := strings.TrimSpace(rule.WireGuardConfig)
			if wgTarget == "" {
				wgTarget = strings.TrimSpace(cfg.WireGuardGateway)
			}
			if wgTarget != "" {
				host, port := splitAddr(wgTarget, "53")
				ip := resolveHost(host)
				upstreams = append(upstreams, net.JoinHostPort(ip, port))
			}
		case "nextdns":
			if isNextDNSQuotaExceeded(cfg) {
				slog.Warn("NextDNS monthly quota exceeded; skipping rule routing to NextDNS", "rule_id", rule.ID, "match", rule.Match)
				continue
			}
			profileID := strings.TrimSpace(rule.HostTarget)
			if profileID == "" {
				profileID = strings.TrimSpace(cfg.NextDNSProfileID)
			}
			if profileID != "" {
				upstreams = []string{"tls://45.90.28.0:853", "tls://45.90.30.0:853"}
				tlsServerName = fmt.Sprintf("%s.dns.nextdns.io", profileID)
			}
		case "vpn", "geo_proxy":
			// Only emit a pure DNS forward zone if SNI Geo-Proxy IP is not active and VPNDNSUpstream is configured
			if GetEffectiveGeoProxyIP(cfg) == "" {
				vpnDNS := strings.TrimSpace(cfg.VPNDNSUpstream)
				if vpnDNS != "" {
					host, port := splitAddr(vpnDNS, "53")
					ip := resolveHost(host)
					upstreams = append(upstreams, net.JoinHostPort(ip, port))
				}
			}
		default: // "default" or unrecognized
			continue
		}

		if len(upstreams) > 0 {
			zoneTargets[matchDomain] = routingTarget{upstreams: upstreams, tlsServerName: tlsServerName}
		}
	}

	// Automatic NextDNS routing for YouTube and Reddit ad-free playback (falls back to standard ShieldDNS / Geo-Proxy if monthly quota is exceeded)
	if nextProfile := strings.TrimSpace(cfg.NextDNSProfileID); nextProfile != "" && !isNextDNSQuotaExceeded(cfg) {
		nextUpstreams := []string{"tls://45.90.28.0:853", "tls://45.90.30.0:853"}
		nextSNI := fmt.Sprintf("%s.dns.nextdns.io", nextProfile)

		if cfg.NextDNSYouTube {
			for _, d := range defaultYouTubeGeoDomains {
				dom := strings.ToLower(strings.Trim(strings.TrimPrefix(d, "*."), "."))
				if _, exists := zoneTargets[dom]; !exists && isValidDomain(dom) {
					zoneTargets[dom] = routingTarget{upstreams: nextUpstreams, tlsServerName: nextSNI}
				}
			}
		}
		if cfg.NextDNSReddit {
			redditDomains := append([]string{}, defaultRedditGeoDomains...)
			redditDomains = append(redditDomains, "reddit.com")
			for _, d := range redditDomains {
				dom := strings.ToLower(strings.Trim(strings.TrimPrefix(d, "*."), "."))
				if _, exists := zoneTargets[dom]; !exists && isValidDomain(dom) {
					zoneTargets[dom] = routingTarget{upstreams: nextUpstreams, tlsServerName: nextSNI}
				}
			}
		}
	}

	if len(zoneTargets) == 0 {
		return strings.TrimSpace(sb.String())
	}

	sortedDomains := make([]string, 0, len(zoneTargets))
	for d := range zoneTargets {
		sortedDomains = append(sortedDomains, d)
	}
	sort.Strings(sortedDomains)

	// Group domains sharing the same upstream target into a single internal engine block
	// so hosts/log/GeoACL run uniformly on external listeners without 60+ redundant TLS/QUIC blocks.
	type targetGroupKey struct {
		upstreamStr   string
		tlsServerName string
	}
	groupedDomains := make(map[targetGroupKey][]string)
	var groupKeys []targetGroupKey
	for _, matchDomain := range sortedDomains {
		target := zoneTargets[matchDomain]
		k := targetGroupKey{
			upstreamStr:   strings.Join(target.upstreams, " "),
			tlsServerName: target.tlsServerName,
		}
		if _, exists := groupedDomains[k]; !exists {
			groupKeys = append(groupKeys, k)
		}
		groupedDomains[k] = append(groupedDomains[k], matchDomain)
	}

	enginePort := getInternalEnginePort()
	for _, k := range groupKeys {
		domains := groupedDomains[k]
		zoneHeaders := make([]string, 0, len(domains))
		for _, d := range domains {
			zoneHeaders = append(zoneHeaders, fmt.Sprintf("%s:%s", d, enginePort))
		}
		sb.WriteString(strings.Join(zoneHeaders, " ") + " {\n")
		sb.WriteString("    bind 127.0.0.1\n")
		if cfg.DNSSECEnabled {
			sb.WriteString("    dnssec\n")
		}
		sb.WriteString("    metadata\n")
		sb.WriteString("    cache 300 {\n        success 10000\n        denial 5000\n        prefetch 5 1m 10%\n        serve_stale 1h\n    }\n")
		for _, d := range domains {
			// Suppress HTTPS/SVCB (type 65) for geo/NextDNS zones to prevent HTTP/3 direct handshake bypass and NextDNS FORMERR
			sb.WriteString(fmt.Sprintf("    template IN HTTPS %s {\n        rcode NOERROR\n    }\n", d))
		}
		sb.WriteString(fmt.Sprintf("    forward . %s {\n        health_check 5s\n", k.upstreamStr))
		if k.tlsServerName != "" {
			sb.WriteString(fmt.Sprintf("        tls_servername %s\n", k.tlsServerName))
		}
		sb.WriteString("    }\n")
		sb.WriteString("    errors\n}\n\n")
	}

	return strings.TrimSpace(sb.String())
}

func getTemplateBlocks(cfg *Config) string {
	if cfg == nil {
		return ""
	}

	var sb strings.Builder

	// 1. SmartDNS / Geo-Proxy Redirection Blocks (YouTube Ad-Free & VPN Geo-Routed Domains)
	geoIP := GetEffectiveGeoProxyIP(cfg)
	if geoIP != "" {
		geoZones := GetGeoRoutedZones(cfg)
		for _, zone := range geoZones {
			parsedGeo := net.ParseIP(geoIP)
			if parsedGeo != nil && parsedGeo.To4() == nil {
				sb.WriteString(fmt.Sprintf("    template IN AAAA %s {\n", zone))
				sb.WriteString(fmt.Sprintf("        answer \"{{ .Name }} 60 IN AAAA %s\"\n", geoIP))
				sb.WriteString("    }\n")
				sb.WriteString(fmt.Sprintf("    template IN A %s {\n        rcode NOERROR\n    }\n", zone))
			} else {
				sb.WriteString(fmt.Sprintf("    template IN A %s {\n", zone))
				sb.WriteString(fmt.Sprintf("        answer \"{{ .Name }} 60 IN A %s\"\n", geoIP))
				sb.WriteString("    }\n")
				// Suppress AAAA and HTTPS (type 65 / QUIC) so Smart TVs & mobile apps connect via IPv4 TLS:443 to the SNI Geo-Proxy
				sb.WriteString(fmt.Sprintf("    template IN AAAA %s {\n        rcode NOERROR\n    }\n", zone))
			}
			sb.WriteString(fmt.Sprintf("    template IN HTTPS %s {\n        rcode NOERROR\n    }\n", zone))
		}
	}

	if len(cfg.CustomMappings) == 0 {
		return sb.String()
	}

	type wildcardEntry struct {
		pattern  string
		apexZone string
		ip       string
	}
	var wildcards []wildcardEntry
	for domain, ip := range cfg.CustomMappings {
		d := strings.ToLower(strings.TrimSpace(domain))
		if strings.HasPrefix(d, "*.") || strings.HasPrefix(d, "*") {
			apex := strings.TrimPrefix(d, "*.")
			apex = strings.TrimPrefix(apex, "*")
			apex = strings.Trim(apex, ".")
			if apex != "" {
				wildcards = append(wildcards, wildcardEntry{
					pattern:  d,
					apexZone: apex,
					ip:       strings.TrimSpace(ip),
				})
			}
		}
	}

	sort.Slice(wildcards, func(i, j int) bool {
		return len(wildcards[i].apexZone) > len(wildcards[j].apexZone)
	})

	writeMappingTemplate := func(domain, ip string) {
		parsed := net.ParseIP(ip)
		if parsed != nil && parsed.To4() == nil {
			sb.WriteString(fmt.Sprintf("    template IN AAAA %s {\n", domain))
			sb.WriteString(fmt.Sprintf("        answer \"{{ .Name }} 60 IN AAAA %s\"\n", ip))
			sb.WriteString("    }\n")
		} else {
			sb.WriteString(fmt.Sprintf("    template IN A %s {\n", domain))
			sb.WriteString(fmt.Sprintf("        answer \"{{ .Name }} 60 IN A %s\"\n", ip))
			sb.WriteString("    }\n")
		}
	}

	handledExact := make(map[string]bool)

	for _, wc := range wildcards {
		var exacts []struct{ domain, ip string }
		for domain, ip := range cfg.CustomMappings {
			d := strings.ToLower(strings.TrimSpace(domain))
			if strings.HasPrefix(d, "*") {
				continue
			}
			d = strings.Trim(d, ".")
			if d == wc.apexZone || strings.HasSuffix(d, "."+wc.apexZone) {
				if !handledExact[d] {
					exacts = append(exacts, struct{ domain, ip string }{domain: d, ip: strings.TrimSpace(ip)})
					handledExact[d] = true
				}
			}
		}

		sort.Slice(exacts, func(i, j int) bool {
			return exacts[i].domain < exacts[j].domain
		})

		for _, ex := range exacts {
			writeMappingTemplate(ex.domain, ex.ip)
		}
		writeMappingTemplate(wc.apexZone, wc.ip)
	}

	var remainingExacts []struct{ domain, ip string }
	for domain, ip := range cfg.CustomMappings {
		d := strings.ToLower(strings.TrimSpace(domain))
		if strings.HasPrefix(d, "*") {
			continue
		}
		d = strings.Trim(d, ".")
		if d != "" && !handledExact[d] {
			remainingExacts = append(remainingExacts, struct{ domain, ip string }{domain: d, ip: strings.TrimSpace(ip)})
			handledExact[d] = true
		}
	}
	sort.Slice(remainingExacts, func(i, j int) bool {
		return remainingExacts[i].domain < remainingExacts[j].domain
	})
	for _, ex := range remainingExacts {
		writeMappingTemplate(ex.domain, ex.ip)
	}

	return sb.String()
}
