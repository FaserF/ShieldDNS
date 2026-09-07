package main

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func initPaths() {
	if dd := os.Getenv("DATA_DIR"); dd != "" {
		DataDir = dd
	} else {
		// Backward compatibility: If old path exists but new one doesn't, fallback to old path
		if _, err := os.Stat("/etc/shielddns/config.json"); err == nil {
			if _, errNew := os.Stat("/data/config.json"); os.IsNotExist(errNew) {
				DataDir = "/etc/shielddns"
				slog.Info("Legacy data directory detected", "path", DataDir)
			}
		}
	}
	ConfigPath = filepath.Join(DataDir, "config.json")
	BlocklistPath = filepath.Join(DataDir, "blocklist.hosts")
	AllowlistPath = filepath.Join(DataDir, "allowlist.hosts")
	MappingsPath = filepath.Join(DataDir, "mappings.hosts")
	DBPath = filepath.Join(DataDir, "queries.db")
	CombinedHostsPath = filepath.Join(DataDir, "shielddns.hosts")

	if cp := os.Getenv("COREFILE_PATH"); cp != "" {
		CorefilePath = cp
	}
}

func loadConfig() {
	configLock.Lock()
	defer configLock.Unlock()

	// 1. Initialize with current defaults
	config = Config{
		Upstreams:                  []string{"86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"},
		UpstreamDoT:                []string{"unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"},
		PreferEncrypted:            true,
		FilteringEnabled:           true,
		AdminDomain:                "shielddns.local",
		BlockPageIP:                "127.0.0.1",
		Lists:                      DefaultPresets,
		Allowlists:                 DefaultAllowlists,
		LatencyTestInterval:        10,
		SmartSelectionPolicy:       "fastest",
		DiagnosticsRefreshInterval: 30, // Default to 30s
		ServeStale:                 true,
		DNSSECEnabled:              true,
		SignMobileConfig:           true,
		VerifyUpstreamTLS:          true,
		AbuseDetectionEnabled:      true,
		AbuseDGAThreshold:          3.8,
		AbuseDGAMinLen:             8,
		CustomMappings:             map[string]string{"fritz.box": "192.168.178.1", "openwrt.lan": "192.168.1.1", "router.miwifi.com": "192.168.31.1"},
		MaliciousIPBlockingEnabled: true,
		MaliciousIPInterval:        8,
		DoHRateLimit:               50,
		DoH3Enabled:                true,
		RateLimitRate:              100, // 100 queries/sec per client IP
		RateLimitBurst:             250, // 250 burst allowance
		ECHOptimizationEnabled:     true,
		AutoblockWhitelist:         []string{"127.0.0.1", "::1"},
		AutoUpdateEnabled:          false,
		AutoUpdateHour:             3,
		UpdateChannel:              "stable",
		MCPServerEnabled:           false,
		AnonymizeClientIPs:         false,
		DNSRebindingProtection:     false,
		StripECS:                   false,
		ClusterRole:                "standalone",
		ClusterInstanceType:        "private",
		ClusterPrimaryURL:          "",
		ClusterPrimaryToken:        "",
		ClusterSyncInterval:        0,
		ClusterFailoverMode:        false,
		ClusterReplicas:            []ClusterReplica{},
		RoutingRules:               []RoutingRule{},
		WireGuardGateway:           "",
	}

	isNew := false
	file, err := os.ReadFile(ConfigPath)
	if err == nil {
		// This will overwrite defaults with values from file
		if err := json.Unmarshal(file, &config); err != nil {
			slog.Error("CRITICAL: Failed to parse config.json. The file might be corrupted. To prevent data loss, ShieldDNS will not start with an invalid config.", "error", err)
			// Create a backup of the corrupted file for the user to rescue
			backupPath := ConfigPath + ".corrupted"
			os.WriteFile(backupPath, file, 0644)
			slog.Info("A backup of the corrupted config has been saved", "path", backupPath)
			log.Fatal("ShieldDNS stopped to protect your configuration. Please check config.json or restore from config.json.corrupted.")
		}
		if config.Lists == nil {
			config.Lists = []List{}
		}
		if config.Allowlists == nil {
			config.Allowlists = []List{}
		}
		if config.DoHRateLimit == 0 {
			config.DoHRateLimit = 50
		}
		if config.AutoblockWhitelist == nil {
			config.AutoblockWhitelist = []string{"127.0.0.1", "::1"}
		}
		if config.UpdateChannel == "" {
			config.UpdateChannel = "stable"
		}
		if config.ClusterRole == "" {
			config.ClusterRole = "standalone"
		}
		if config.ClusterInstanceType == "" {
			config.ClusterInstanceType = "private"
		}
		if config.ClusterReplicas == nil {
			config.ClusterReplicas = []ClusterReplica{}
		}
	} else {
		isNew = true
		slog.Info("Creating default config", "path", ConfigPath)
	}

	// 3. Check environment variables for overrides ONLY on initial setup
	// This ensures that settings configured via the UI remain persistent across restarts.
	if isNew {
		if envDNS := os.Getenv("UPSTREAM_DNS"); envDNS != "" {
			parts := strings.Fields(strings.ReplaceAll(envDNS, ",", " "))
			if len(parts) > 0 {
				config.Upstreams = parts
			}
		}
		if envDoT := os.Getenv("UPSTREAM_DOT"); envDoT != "" {
			parts := strings.Fields(strings.ReplaceAll(envDoT, ",", " "))
			if len(parts) > 0 {
				config.UpstreamDoT = parts
			}
		}
		if envBlockIP := os.Getenv("BLOCK_PAGE_IP"); envBlockIP != "" {
			config.BlockPageIP = strings.TrimSpace(envBlockIP)
		}
	}

	// If it was newly created, save the config immediately after env overrides
	if isNew {
		if err := saveConfigNoLock(); err != nil {
			slog.Error("Failed to save initial default config", "error", err)
		}
	}

	// 4. Prepend official lists if missing
	ensureOfficialLists()

	// 5. Final Sanitization & Constraints
	if len(config.Upstreams) == 0 {
		config.Upstreams = []string{"86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"}
	}
	if len(config.UpstreamDoT) == 0 {
		config.UpstreamDoT = []string{"unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"}
	}
	// Limit to max 5
	if len(config.Upstreams) > 5 {
		config.Upstreams = config.Upstreams[:5]
	}
	if len(config.UpstreamDoT) > 5 {
		config.UpstreamDoT = config.UpstreamDoT[:5]
	}

	// Sanitize upstreams strings
	for i, u := range config.Upstreams {
		config.Upstreams[i] = strings.Trim(u, " ,")
	}
	for i, u := range config.UpstreamDoT {
		config.UpstreamDoT[i] = strings.Trim(u, " ,")
	}

	if config.AdminDomain == "" {
		config.AdminDomain = "shielddns.local"
	}
	if config.BlockPageIP == "" {
		config.BlockPageIP = "127.0.0.1"
	}
	if config.LatencyTestInterval == 0 {
		config.LatencyTestInterval = 10
	}
	if config.SmartSelectionPolicy == "" {
		config.SmartSelectionPolicy = "fastest"
	}
	if config.DiagnosticsRefreshInterval == 0 {
		config.DiagnosticsRefreshInterval = 30
	}
	if config.CustomMappings == nil {
		config.CustomMappings = make(map[string]string)
	}
	if config.AbuseDGAThreshold == 0 {
		config.AbuseDGAThreshold = 3.8
	}
	if config.AbuseDGAMinLen == 0 {
		config.AbuseDGAMinLen = 8
	}
	debugModeEnabled.Store(config.DebugMode)
}

func ensureOfficialLists() {
	// Auto-migrate broken/outdated upstream URLs from previous versions
	urlMigrations := map[string]string{
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt":      "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/light.txt":    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt":    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt",
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.plus.txt",
		"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt": "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/ultimate.txt",
	}

	for i := range config.Lists {
		if newURL, ok := urlMigrations[config.Lists[i].URL]; ok {
			slog.Info("Migrated outdated list URL", "name", config.Lists[i].Name, "old_url", config.Lists[i].URL, "new_url", newURL)
			config.Lists[i].URL = newURL
		}
	}
	for i := range config.Allowlists {
		if newURL, ok := urlMigrations[config.Allowlists[i].URL]; ok {
			slog.Info("Migrated outdated allowlist URL", "name", config.Allowlists[i].Name, "old_url", config.Allowlists[i].URL, "new_url", newURL)
			config.Allowlists[i].URL = newURL
		}
	}

	hasOfficialBlock := false
	for _, l := range config.Lists {
		if strings.Contains(l.URL, "FaserF/ShieldDNS") {
			hasOfficialBlock = true
			break
		}
	}
	if !hasOfficialBlock {
		config.Lists = append([]List{{
			Name:    "ShieldDNS Official Blocklist",
			URL:     "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/blocklists/default.txt",
			Enabled: true,
		}}, config.Lists...)
	}

	hasOfficialWhite := false
	for _, l := range config.Allowlists {
		if strings.Contains(l.URL, "FaserF/ShieldDNS") {
			hasOfficialWhite = true
			break
		}
	}
	if !hasOfficialWhite {
		config.Allowlists = append([]List{{
			Name:    "ShieldDNS Official Allowlist",
			URL:     "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/allowlists/default.txt",
			Enabled: true,
		}}, config.Allowlists...)
	}
}

func saveConfig() error {
	configLock.Lock()
	defer configLock.Unlock()
	return saveConfigNoLock()
}

func saveConfigNoLock() error {
	// CRITICAL SAFETY CHECK: Never save an empty or masked password/API keys if setup is done.
	// This prevents the "json:-" regression from corrupting the config on disk.
	if config.SetupDone {
		if config.AdminPasswordHashed == "" || config.AdminPasswordHashed == "********" {
			return fmt.Errorf("attempted to save config with invalid password hash")
		}
		for _, k := range config.APIKeys {
			if k.TokenHash == "********" {
				return fmt.Errorf("attempted to save config with masked API key hashes")
			}
		}
		if config.MFAEnabled && len(config.TOTPConfigs) == 0 && len(config.WebAuthnCredentials) == 0 {
			return fmt.Errorf("attempted to save config with MFA enabled but NO methods registered")
		}
	}

	debugModeEnabled.Store(config.DebugMode)
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	os.MkdirAll(filepath.Dir(ConfigPath), 0755)
	if err := atomicWriteFile(ConfigPath, data); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}
	slog.Debug("Config saved", "path", ConfigPath)
	return nil
}

// RetrofitBlockedClientsInfo ensures all blocked clients have metadata including country codes.
// Returns true if any changes were made to the config.
func RetrofitBlockedClientsInfo() bool {
	if config.BlockedClientsInfo == nil {
		config.BlockedClientsInfo = make(map[string]BlockedClientInfo)
	}

	changed := false
	// Retrofit any clients in BlockedClients that don't have info or have missing/pending country codes
	for _, ip := range config.BlockedClients {
		entry, ok := config.BlockedClientsInfo[ip]
		if !ok {
			cc := GetCountryCodeCached(ip)
			config.BlockedClientsInfo[ip] = BlockedClientInfo{
				Reason:      "manual",
				BlockedAt:   time.Now(),
				Auto:        false,
				CountryCode: cc,
			}
			changed = true
		} else if entry.CountryCode == "" || entry.CountryCode == "-" {
			// Initialize or upgrade missing/pending country code
			cc := GetCountryCodeCached(ip)
			if cc != "" && cc != entry.CountryCode {
				entry.CountryCode = cc
				config.BlockedClientsInfo[ip] = entry
				changed = true
			}
		}
	}
	return changed
}

func atomicWriteFile(filename string, data []byte) error {
	tmpFile := filename + ".tmp"
	f, err := os.OpenFile(tmpFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return err
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return err
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpFile)
		return err
	}

	if err := os.Rename(tmpFile, filename); err != nil {
		// On Windows, rename fails if the target file already exists
		_ = os.Remove(filename)
		if errRetry := os.Rename(tmpFile, filename); errRetry != nil {
			// Fallback: write directly to target file
			if errWrite := os.WriteFile(filename, data, 0644); errWrite != nil {
				os.Remove(tmpFile)
				return errRetry
			}
			os.Remove(tmpFile)
		}
	}
	return nil
}

func buildClusterConfigExport(replicaType string, primaryURL string, failoverMode bool) ClusterConfigExport {
	configLock.RLock()
	defer configLock.RUnlock()

	exp := ClusterConfigExport{
		PrimaryURL:                 primaryURL,
		AdminPasswordHashed:        config.AdminPasswordHashed,
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
		Timestamp:                  time.Now().UTC(),
	}

	copy(exp.Lists, config.Lists)
	copy(exp.Allowlists, config.Allowlists)
	for k, v := range config.CustomMappings {
		exp.CustomMappings[k] = v
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
	}

	return exp
}

