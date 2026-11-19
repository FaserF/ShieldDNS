package main

import (
	"time"
)

// buildClusterConfigExport generates an export tailored for a replica, considering instance type.
func buildClusterConfigExport(replicaType string, primaryURL string, failoverMode bool) ClusterConfigExport {
	configLock.RLock()
	defer configLock.RUnlock()

	exp := ClusterConfigExport{
		PrimaryURL:                 primaryURL,
		PrimaryEmergencyShedding:   config.EmergencySheddingActive,
		PrimaryDNSTarget:           resolvePeerDNSTarget(primaryURL),
		AdminPasswordHashed:        config.AdminPasswordHashed,
		AdminDomain:                config.AdminDomain,
		ClusterWorkerDomain:        config.ClusterWorkerDomain,
		ClusterLogSharingMode:      config.ClusterLogSharingMode,
		FilteringEnabled:           config.FilteringEnabled,
		Lists:                      make([]List, len(config.Lists)),
		Allowlists:                 make([]List, len(config.Allowlists)),
		CustomBlocked:              append([]string{}, config.CustomBlocked...),
		CustomAllowed:              append([]string{}, config.CustomAllowed...),
		CustomMappings:             make(map[string]string),
		AutoblockWhitelist:         append([]string{}, config.AutoblockWhitelist...),
		BlockedCountries:           append([]string{}, config.BlockedCountries...),
		SmartSelectionPolicy:       config.SmartSelectionPolicy,
		ServeStale:                 config.ServeStale,
		DNSSECEnabled:              config.DNSSECEnabled,
		AbuseDetectionEnabled:      config.AbuseDetectionEnabled,
		AbuseDGAThreshold:          config.AbuseDGAThreshold,
		AbuseDGAMinLen:             config.AbuseDGAMinLen,
		MaliciousIPBlockingEnabled: config.MaliciousIPBlockingEnabled,
		MaliciousIPInterval:        config.MaliciousIPInterval,
		VerifyUpstreamTLS:          config.VerifyUpstreamTLS,
		PreferEncrypted:            config.PreferEncrypted,
		Upstreams:                  append([]string{}, config.Upstreams...),
		UpstreamDoT:                append([]string{}, config.UpstreamDoT...),
		DoHRateLimit:               config.DoHRateLimit,
		DoH3Enabled:                config.DoH3Enabled,
		RateLimitRate:              config.RateLimitRate,
		RateLimitBurst:             config.RateLimitBurst,
		ECHOptimizationEnabled:     config.ECHOptimizationEnabled,
		DNSRebindingProtection:     config.DNSRebindingProtection,
		StripECS:                   config.StripECS,
		RoutingRules:               append([]RoutingRule{}, config.RoutingRules...),
		WireGuardGateway:           config.WireGuardGateway,
		YouTubeAdblockEnabled:      config.YouTubeAdblockEnabled,
		TwitchAdblockEnabled:       config.TwitchAdblockEnabled,
		RedditAdblockEnabled:       config.RedditAdblockEnabled,
		SpotifyAdblockEnabled:      config.SpotifyAdblockEnabled,
		SocialAdblockEnabled:       config.SocialAdblockEnabled,
		SmartTVAdblockEnabled:      config.SmartTVAdblockEnabled,
		BlockedServices:            append([]string{}, config.BlockedServices...),
		SafeSearchEnabled:          config.SafeSearchEnabled,
		YouTubeRestriction:         config.YouTubeRestriction,
		VPNProvider:                config.VPNProvider,
		VPNMode:                    config.VPNMode,
		VPNDefaultCountry:          config.VPNDefaultCountry,
		VPNProxyURL:                config.VPNProxyURL,
		VPNCountryProxies:          make(map[string]string),
		VPNInterface:               config.VPNInterface,
		VPNConfigContent:           config.VPNConfigContent,
		VPNUsername:                config.VPNUsername,
		VPNPassword:                config.VPNPassword,
		VPNDNSUpstream:             config.VPNDNSUpstream,
		GeoProxyIP:                 config.GeoProxyIP,
		SNIProxyPort:               config.SNIProxyPort,
		NextDNSProfileID:           config.NextDNSProfileID,
		NextDNSAPIKey:              config.NextDNSAPIKey,
		NextDNSMonthlyLimit:        config.NextDNSMonthlyLimit,
		NextDNSYouTube:             config.NextDNSYouTube,
		NextDNSReddit:              config.NextDNSReddit,
		RAMProtectionEnabled:       config.RAMProtectionEnabled,
		MaxRAMBudgetMB:             config.MaxRAMBudgetMB,
		RAMSafetyBufferMB:          config.RAMSafetyBufferMB,
		BlockedClients:             append([]string{}, config.BlockedClients...),
		BlockedClientsInfo:         make(map[string]BlockedClientInfo),
		ClientRules:                append([]ClientRule{}, config.ClientRules...),
		ClientAliases:              make(map[string]string),
		Groups:                     append([]ClientGroup{}, config.Groups...),
		Schedules:                  append([]ScheduleRule{}, config.Schedules...),
		QuickRules:                 append([]QuickRule{}, config.QuickRules...),
		LocalRecords:               append([]LocalRecord{}, config.LocalRecords...),
		LocalPTRUpstreams:          append([]string{}, config.LocalPTRUpstreams...),
		AutoPTR:                    config.AutoPTR,
		CNAMECloakingEnabled:       config.CNAMECloakingEnabled,
		MCPServerEnabled:           config.MCPServerEnabled,
		AIEnabled:                  config.AIEnabled,
		AIBaseURL:                  config.AIBaseURL,
		AIModel:                    config.AIModel,
		APIKeys:                    append([]APIKey{}, config.APIKeys...),
		Timestamp:                  time.Now().UTC(),
	}

	copy(exp.Lists, config.Lists)
	copy(exp.Allowlists, config.Allowlists)
	for k, v := range config.CustomMappings {
		if replicaType == "public" && isPrivateOrTailnetIP(v) {
			continue
		}
		exp.CustomMappings[k] = v
	}
	for k, v := range config.BlockedClientsInfo {
		exp.BlockedClientsInfo[k] = v
	}
	for k, v := range config.ClientAliases {
		exp.ClientAliases[k] = v
	}
	for k, v := range config.VPNCountryProxies {
		exp.VPNCountryProxies[k] = v
	}

	// Instance-type specific optimizations
	if replicaType == "public" {
		// Public nodes: stricter rate limits, always enforce malicious IP blocking and DGA detection
		if exp.DoHRateLimit == 0 || exp.DoHRateLimit > 60 {
			exp.DoHRateLimit = 60
		}
		exp.MaliciousIPBlockingEnabled = true
		exp.AbuseDetectionEnabled = true
		exp.DNSRebindingProtection = false // Usually not applicable/helpful for public resolvers
	} else if replicaType == "hybrid" {
		// Hybrid nodes: accessible publicly but also used as LAN/VPN resolver
		if exp.DoHRateLimit == 0 || exp.DoHRateLimit < 120 {
			exp.DoHRateLimit = 120
		}
		exp.MaliciousIPBlockingEnabled = true
		exp.AbuseDetectionEnabled = true
		exp.DNSRebindingProtection = false // Allow resolving external & internal domains without rejection
	} else {
		// Private (LAN) nodes: higher rate limit headroom, rebinding protection enabled
		if exp.DoHRateLimit < 200 {
			exp.DoHRateLimit = 200
		}
		exp.DNSRebindingProtection = true
		if !failoverMode {
			exp.MaliciousIPBlockingEnabled = false
		}
	}

	return exp
}
