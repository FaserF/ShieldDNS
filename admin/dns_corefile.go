package main

import (
	"bytes"
	"fmt"
	"html/template"
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

	if len(cfg.RoutingRules) == 0 {
		return strings.TrimSpace(sb.String())
	}

	for _, rule := range cfg.RoutingRules {
		if !rule.Enabled {
			continue
		}

		matchDomain := strings.TrimSpace(rule.Match)
		if rule.MatchType == "client_ip" || matchDomain == "" || !isValidDomain(matchDomain) {
			continue
		}
		// CoreDNS expects normalized root without wildcards in zone names
		matchDomain = strings.TrimPrefix(matchDomain, "*.")
		matchDomain = strings.Trim(matchDomain, ".")

		var upstreams []string
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
		default: // "default" or unrecognized
			continue
		}

		if len(upstreams) == 0 {
			continue
		}

		upstreamStr := strings.Join(upstreams, " ")
		filteringBlock := ""
		if cfg.FilteringEnabled {
			filteringBlock = fmt.Sprintf("    hosts %s {\n        reload 5s\n        fallthrough\n    }\n", CombinedHostsPath)
		}

		sb.WriteString(fmt.Sprintf("%s:%s {\n", matchDomain, dnsPort))
		if cfg.DNSSECEnabled {
			sb.WriteString("    dnssec\n")
		}
		sb.WriteString("    metadata\n    reload 5s\n")
		sb.WriteString(filteringBlock)
		sb.WriteString("    cache 3600\n")
		sb.WriteString(fmt.Sprintf("    forward . %s {\n        health_check 5s\n    }\n", upstreamStr))
		sb.WriteString(fmt.Sprintf("%s\n", getGeoACLRules(cfg)))
		sb.WriteString("    errors\n}\n\n")

		if hasCerts {
			sb.WriteString(fmt.Sprintf("tls://%s:%s {\n    tls %s %s\n", matchDomain, dotPort, certFile, keyFile))
			if cfg.DNSSECEnabled {
				sb.WriteString("    dnssec\n")
			}
			sb.WriteString("    metadata\n    reload 5s\n")
			sb.WriteString(filteringBlock)
			sb.WriteString("    cache 3600\n")
			sb.WriteString(fmt.Sprintf("    forward . %s {\n        health_check 5s\n    }\n", upstreamStr))
			sb.WriteString(fmt.Sprintf("%s\n", getGeoACLRules(cfg)))
			sb.WriteString("    errors\n}\n\n")

			sb.WriteString(fmt.Sprintf("https://%s:%s {\n    tls %s %s\n", matchDomain, dohPort, certFile, keyFile))
			if cfg.DNSSECEnabled {
				sb.WriteString("    dnssec\n")
			}
			sb.WriteString("    metadata\n    reload 5s\n")
			sb.WriteString(filteringBlock)
			sb.WriteString("    cache 3600\n")
			sb.WriteString(fmt.Sprintf("    forward . %s {\n        health_check 5s\n    }\n", upstreamStr))
			sb.WriteString(fmt.Sprintf("%s\n", getGeoACLRules(cfg)))
			sb.WriteString("    errors\n}\n\n")
		}
	}

	return strings.TrimSpace(sb.String())
}

