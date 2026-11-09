package main

import (
	"bytes"
	"fmt"
	"text/template"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
)

func updateCorefile() {
	configLock.RLock()
	cfg := config.Clone()
	configLock.RUnlock()

	healthLock.RLock()
	hDNS := make([]string, len(healthyUpstreams))
	copy(hDNS, healthyUpstreams)
	hDoT := make([]string, len(healthyDoT))
	copy(hDoT, healthyDoT)
	healthLock.RUnlock()

	if cfg.UseFastestUpstream {
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
	if cfg.PreferEncrypted {
		var distinctDoTHosts []string
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
			if cfg.PreferEncrypted && len(hDoT) > 0 {
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
		DNSSEC:           cfg.DNSSECEnabled,
		ServeStale:       cfg.ServeStale,
		Upstreams:        upstreamStr,
		TLSServerName:    dotServerName,
		Policy:           policyVal,
		HostsPath:        CombinedHostsPath,
		GeoACLRules:      getGeoACLRules(cfg),
		CertFile:         certFile,
		KeyFile:          keyFile,
		FilteringEnabled: cfg.FilteringEnabled,
		HasCerts:         hasCerts,
		RateLimitRate:    cfg.RateLimitRate,
		RateLimitBurst:   cfg.RateLimitBurst,
		RoutingBlocks:    getRoutingZoneBlocks(cfg, dnsPort, dotPort, internalDOHPort, hasCerts, certFile, keyFile),
		TemplateBlocks:   getTemplateBlocks(cfg),
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

	// Automatic NextDNS routing for YouTube and Reddit ad-free playback
	if nextProfile := strings.TrimSpace(cfg.NextDNSProfileID); nextProfile != "" {
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
			redditDomains = append(redditDomains, "reddit.com", "redd.it")
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

	filteringBlock := ""
	if cfg.FilteringEnabled {
		filteringBlock = fmt.Sprintf("    hosts %s {\n        reload 5s\n        fallthrough\n    }\n", CombinedHostsPath)
	}

	for _, matchDomain := range sortedDomains {
		target := zoneTargets[matchDomain]
		upstreamStr := strings.Join(target.upstreams, " ")

		writeZone := func(prefix string) {
			if prefix == "" {
				sb.WriteString(fmt.Sprintf("%s:%s {\n", matchDomain, dnsPort))
			} else if prefix == "tls" {
				sb.WriteString(fmt.Sprintf("tls://%s:%s {\n    tls %s %s\n", matchDomain, dotPort, certFile, keyFile))
			} else if prefix == "https" {
				sb.WriteString(fmt.Sprintf("https://%s:%s {\n    tls %s %s\n", matchDomain, dohPort, certFile, keyFile))
			}
			if cfg.DNSSECEnabled {
				sb.WriteString("    dnssec\n")
			}
			sb.WriteString("    metadata\n    reload 5s\n")
			sb.WriteString(filteringBlock)
			sb.WriteString("    cache 3600\n")
			sb.WriteString(fmt.Sprintf("    forward . %s {\n        health_check 5s\n", upstreamStr))
			if target.tlsServerName != "" {
				sb.WriteString(fmt.Sprintf("        tls_servername %s\n", target.tlsServerName))
			}
			sb.WriteString("    }\n")
			sb.WriteString(fmt.Sprintf("%s\n", getGeoACLRules(cfg)))
			sb.WriteString("    errors\n}\n\n")
		}

		writeZone("")
		if hasCerts {
			writeZone("tls")
			writeZone("https")
		}
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

	if len(wildcards) == 0 {
		return sb.String()
	}

	sort.Slice(wildcards, func(i, j int) bool {
		return len(wildcards[i].apexZone) > len(wildcards[j].apexZone)
	})

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
			parsed := net.ParseIP(ex.ip)
			if parsed != nil && parsed.To4() == nil {
				sb.WriteString(fmt.Sprintf("    template IN AAAA %s {\n", ex.domain))
				sb.WriteString(fmt.Sprintf("        answer \"{{ .Name }} 60 IN AAAA %s\"\n", ex.ip))
				sb.WriteString("    }\n")
			} else {
				sb.WriteString(fmt.Sprintf("    template IN A %s {\n", ex.domain))
				sb.WriteString(fmt.Sprintf("        answer \"{{ .Name }} 60 IN A %s\"\n", ex.ip))
				sb.WriteString("    }\n")
			}
		}

		parsedWC := net.ParseIP(wc.ip)
		if parsedWC != nil && parsedWC.To4() == nil {
			sb.WriteString(fmt.Sprintf("    template IN AAAA %s {\n", wc.apexZone))
			sb.WriteString(fmt.Sprintf("        answer \"{{ .Name }} 60 IN AAAA %s\"\n", wc.ip))
			sb.WriteString("    }\n")
		} else {
			sb.WriteString(fmt.Sprintf("    template IN A %s {\n", wc.apexZone))
			sb.WriteString(fmt.Sprintf("        answer \"{{ .Name }} 60 IN A %s\"\n", wc.ip))
			sb.WriteString("    }\n")
		}
	}

	return sb.String()
}
