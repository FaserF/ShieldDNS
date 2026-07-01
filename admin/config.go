package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
		AutoblockWhitelist:         []string{"127.0.0.1", "::1"},
		AutoUpdateEnabled:          false,
		AutoUpdateHour:             3,
		UpdateChannel:              "stable",
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
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}

	if err := f.Sync(); err != nil {
		return err
	}

	if err := f.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpFile, filename); err != nil {
		return err
	}
	return nil
}

var blocklistUpdateLock sync.Mutex

func updateBlocklist(cfg *Config, restartCore bool) {
	blocklistUpdateLock.Lock()
	defer blocklistUpdateLock.Unlock()

	if cfg == nil {
		configLock.RLock()
		cfg = config.Clone()
		configLock.RUnlock()
	}
	slog.Info("Updating blocklists")

	blocklists := cfg.Lists
	allowlists := cfg.Allowlists
	customBlocked := cfg.CustomBlocked
	customAllowed := cfg.CustomAllowed
	customMappings := cfg.CustomMappings
	blockPageIP := cfg.BlockPageIP

	newBlockAttribution := make(map[string][]string)
	newAllowAttribution := make(map[string][]string)
	allowDomains := make(map[string]struct{})

	for i := range blocklists {
		list := &blocklists[i]
		if !list.Enabled {
			continue
		}
		slog.Info("Processing blocklist", "name", list.Name)
		processList(list, newBlockAttribution, allowDomains, nil)
	}

	for i := range allowlists {
		list := &allowlists[i]
		if !list.Enabled {
			continue
		}
		slog.Info("Processing allowlist", "name", list.Name)
		processList(list, nil, allowDomains, newAllowAttribution) // Allowlists populate allowDomains and allowAttribution
	}

	// Update the config lists with the new metadata (Entries, UpdatedAt, and RemoteUpdatedAt)
	configLock.Lock()
	for _, l := range blocklists {
		targetURL := strings.ToLower(strings.TrimSpace(l.URL))
		for j, cl := range config.Lists {
			if strings.ToLower(strings.TrimSpace(cl.URL)) == targetURL {
				config.Lists[j].Entries = l.Entries
				config.Lists[j].UpdatedAt = l.UpdatedAt
				config.Lists[j].RemoteUpdatedAt = l.RemoteUpdatedAt
				break
			}
		}
	}
	for _, l := range allowlists {
		targetURL := strings.ToLower(strings.TrimSpace(l.URL))
		for j, cl := range config.Allowlists {
			if strings.ToLower(strings.TrimSpace(cl.URL)) == targetURL {
				config.Allowlists[j].Entries = l.Entries
				config.Allowlists[j].UpdatedAt = l.UpdatedAt
				config.Allowlists[j].RemoteUpdatedAt = l.RemoteUpdatedAt
				break
			}
		}
	}
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config after blocklist update", "error", err)
	}
	configLock.Unlock()

	// Add Custom Rules
	for _, d := range customBlocked {
		newBlockAttribution[d] = append(newBlockAttribution[d], "Custom Blocklist")
		if !strings.HasPrefix(d, "*.") {
			newBlockAttribution["*."+d] = append(newBlockAttribution["*."+d], "Custom Blocklist")
		}
	}
	for _, d := range customAllowed {
		allowDomains[d] = struct{}{}
		newAllowAttribution[d] = append(newAllowAttribution[d], "Custom Allowlist")
		if !strings.HasPrefix(d, "*.") {
			allowDomains["*."+d] = struct{}{}
			newAllowAttribution["*."+d] = append(newAllowAttribution["*."+d], "Custom Allowlist")
		}
	}

	if err := saveConfig(); err != nil {
		slog.Error("Failed to save config in updateBlocklist", "error", err)
	}
	applyCurrentRules(newBlockAttribution, newAllowAttribution, allowDomains, customMappings, blockPageIP, restartCore)
}

func applyCurrentRules(attribution map[string][]string, allowAttr map[string][]string, allowSet map[string]struct{}, mappings map[string]string, blockIP string, restartCore bool) {
	// Remove allowlisted domains (and their subdomains) from attribution in O(N) time
	for ad := range attribution {
		// Exact match
		if _, ok := allowSet[ad]; ok {
			delete(attribution, ad)
			continue
		}

		// Wildcard match for subdomains (check parent domains)
		// e.g., for "www.google.com", check "google.com" and "com"
		parts := strings.Split(ad, ".")
		for i := 1; i < len(parts); i++ {
			parentDomain := strings.Join(parts[i:], ".")
			if _, ok := allowSet[parentDomain]; ok {
				delete(attribution, ad)
				break
			}
		}
	}

	blockDomains := make(map[string]struct{})

	// Always enforce blocking for the built-in test domain regardless of allowlists
	attribution["shielddns-maleware.test"] = []string{"ShieldDNS Built-in Test Domain"}

	for d := range attribution {
		blockDomains[d] = struct{}{}
	}

	// Update global attribution map
	blockAttributionLock.Lock()
	blockAttribution = attribution
	slog.Info("Blocklist attribution updated", "total_blocked_domains", len(blockAttribution))
	blockAttributionLock.Unlock()

	// Update global allow attribution map
	allowAttributionLock.Lock()
	allowAttribution = allowAttr
	allowAttributionLock.Unlock()

	// Write Combined Hosts File for CoreDNS
	var combinedBuilder strings.Builder
	combinedBuilder.WriteString("# ShieldDNS Combined Hosts File\n")
	combinedBuilder.WriteString("# Generated at " + time.Now().Format(time.RFC3339) + "\n\n")

	// 1. Custom Mappings (Highest Priority)
	combinedBuilder.WriteString("# Custom Mappings\n")
	for domain, ip := range mappings {
		combinedBuilder.WriteString(fmt.Sprintf("%s %s\n", ip, domain))
	}

	// 2. Blocklist
	combinedBuilder.WriteString("\n# Blocked Domains\n")
	if blockIP == "" {
		blockIP = "127.0.0.1"
	}
	for domain := range blockDomains {
		combinedBuilder.WriteString(fmt.Sprintf("%s %s\n", blockIP, domain))
	}

	os.MkdirAll(filepath.Dir(CombinedHostsPath), 0755)
	atomicWriteFile(CombinedHostsPath, []byte(combinedBuilder.String()))
	atomicWriteFile(BlocklistPath, []byte(combinedBuilder.String()))

	// Write Allowlist for tracking
	var allowBuilder strings.Builder
	for domain := range allowSet {
		allowBuilder.WriteString(fmt.Sprintf("127.0.0.1 %s\n", domain))
	}
	atomicWriteFile(AllowlistPath, []byte(allowBuilder.String()))

	// Write Custom Mappings separately too
	var mappingsBuilder strings.Builder
	for domain, ip := range mappings {
		mappingsBuilder.WriteString(fmt.Sprintf("%s %s\n", ip, domain))
	}
	os.WriteFile(MappingsPath, []byte(mappingsBuilder.String()), 0644)

	slog.Info("Rules updated", "host_file", CombinedHostsPath, "count", len(attribution))
	if restartCore {
		restartCoreDNS()
	}
}

func reloadRulesFast() {
	configLock.RLock()
	cfg := config.Clone()
	configLock.RUnlock()

	reloadRulesFastNoLock(cfg)
}

func reloadRulesFastNoLock(cfg *Config) {
	// We start with a copy of current attribution IF it exists, otherwise full update required
	blockAttributionLock.RLock()
	if blockAttribution == nil {
		blockAttributionLock.RUnlock()
		go updateBlocklist(cfg, true)
		return
	}

	// Filter out existing "Custom Blocklist" entries as we will re-apply them from current config
	newAttribution := make(map[string][]string)
	for d, lists := range blockAttribution {
		var filtered []string
		for _, l := range lists {
			if l != "Custom Blocklist" && l != "ShieldDNS Built-in Test Domain" {
				filtered = append(filtered, l)
			}
		}
		if len(filtered) > 0 {
			newAttribution[d] = filtered
		}
	}
	blockAttributionLock.RUnlock()

	allowDomains := make(map[string]struct{})
	newAllowAttribution := make(map[string][]string)

	// RE-APPLY CURRENT CUSTOM RULES
	for _, d := range cfg.CustomBlocked {
		newAttribution[d] = append(newAttribution[d], "Custom Blocklist")
		if !strings.HasPrefix(d, "*.") {
			wildcard := "*." + d
			newAttribution[wildcard] = append(newAttribution[wildcard], "Custom Blocklist")
		}
	}
	for _, d := range cfg.CustomAllowed {
		allowDomains[d] = struct{}{}
		newAllowAttribution[d] = append(newAllowAttribution[d], "Custom Allowlist")
		// For allowlists, we don't strictly need to add *.d because applyCurrentRules
		// already handles subdomain allowance by checking parent domains.
		// However, adding it explicitly doesn't hurt and makes attribution clearer.
		if !strings.HasPrefix(d, "*.") {
			allowDomains["*."+d] = struct{}{}
			newAllowAttribution["*."+d] = append(newAllowAttribution["*."+d], "Custom Allowlist")
		}
	}

	applyCurrentRules(newAttribution, newAllowAttribution, allowDomains, cfg.CustomMappings, cfg.BlockPageIP, true)
}

func processList(list *List, blockMap map[string][]string, allowMap map[string]struct{}, allowAttr map[string][]string) {
	var reader io.Reader

	if strings.HasPrefix(list.URL, "file://") {
		path := strings.TrimPrefix(list.URL, "file://")

		// Security: Restrict local file access to within DataDir
		absDataDir, _ := filepath.Abs(DataDir)
		absPath, _ := filepath.Abs(path)
		if !strings.HasPrefix(absPath, absDataDir) {
			slog.Warn("Access denied: local list file must be within DataDir", "name", list.Name, "path", path)
			return
		}

		file, err := os.Open(path)
		if err != nil {
			slog.Warn("Could not open local list file", "name", list.Name, "path", path, "error", err)
			return
		}
		defer file.Close()
		reader = file
	} else {
		useLocal := false
		var localPath string
		if strings.Contains(list.URL, "raw.githubusercontent.com/FaserF/ShieldDNS/") {
			parts := strings.Split(list.URL, "/official/")
			if len(parts) == 2 {
				localPath = filepath.Join("official", parts[1])
				if rel, err := filepath.Rel("official", localPath); err == nil && !strings.HasPrefix(rel, "..") && rel != ".." {
					if _, err := os.Stat(localPath); err == nil {
						useLocal = true
					}
				}
			}
		}

		if useLocal {
			file, err := os.Open(localPath)
			if err != nil {
				slog.Warn("Could not open local official list fallback file", "name", list.Name, "path", localPath, "error", err)
				return
			}
			defer file.Close()
			list.RemoteUpdatedAt = time.Now()
			if info, err := file.Stat(); err == nil {
				list.RemoteUpdatedAt = info.ModTime()
			}
			reader = file
		} else {
			if !isValidListURL(list.URL) {
				slog.Warn("Blocklist URL rejected: not a safe remote URL", "name", list.Name, "url", list.URL)
				return
			}
			client := &http.Client{Timeout: 30 * time.Second}
			req, err := http.NewRequest("GET", list.URL, nil)
			if err != nil {
				slog.Warn("Could not create request for remote list", "name", list.Name, "url", list.URL, "error", err)
				return
			}

			// Use a browser-like User-Agent to avoid being blocked by strict servers (e.g., Frogeye)
			req.Header.Set("User-Agent", fmt.Sprintf("ShieldDNS/%s (https://github.com/FaserF/ShieldDNS)", FullVersion))
			req.Header.Set("Accept", "text/plain, */*")

			resp, err := client.Do(req)
			if err != nil {
				slog.Warn("Could not fetch remote list", "name", list.Name, "url", list.URL, "error", err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				slog.Warn("Remote list returned non-OK status", "name", list.Name, "status", resp.StatusCode)
				return
			}

			// Capture remote update time with specialized GitHub support
			list.RemoteUpdatedAt = getRemoteUpdateTime(list.URL, resp.Header)

			reader = resp.Body
		}
	}

	scanner := bufio.NewScanner(reader)
	// Some list lines might be long, increase buffer size if needed
	const maxCapacity = 1024 * 1024 // 1MB line buffer
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Skip AdGuard/uBlock Origin cosmetic filters and advanced rules
		if strings.Contains(line, "##") || strings.Contains(line, "#?#") || strings.Contains(line, "#$#") {
			continue
		}

		isAllowlist := false
		if strings.HasPrefix(line, "@@") {
			isAllowlist = true
			line = line[2:]
		}

		// 3. Handle AdGuard / AdBlock: ||domain^
		if strings.HasPrefix(line, "||") {
			content := strings.TrimPrefix(line, "||")
			domainPart := content
			if idx := strings.IndexAny(content, "^$"); idx != -1 {
				domainPart = content[:idx]
			}
			d := NormalizeDomain(domainPart)
			if d != "" {
				if added := addDomain(d, isAllowlist, list.Name, true, blockMap, allowMap, allowAttr); added {
					count++
				}
			}
			continue
		}

		// 4. Handle Hosts: 0.0.0.0 domain
		if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") || strings.HasPrefix(line, "::1 ") || strings.HasPrefix(line, ":: ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				d := NormalizeDomain(parts[1])
				if d != "" {
					if added := addDomain(d, isAllowlist, list.Name, false, blockMap, allowMap, allowAttr); added {
						count++
					}
				}
			}
			continue
		}

		// 5. Handle Dnsmasq: address=/domain/0.0.0.0
		if strings.HasPrefix(line, "address=/") {
			parts := strings.Split(line, "/")
			if len(parts) >= 3 {
				d := NormalizeDomain(parts[1])
				if d != "" {
					if added := addDomain(d, isAllowlist, list.Name, true, blockMap, allowMap, allowAttr); added {
						count++
					}
				}
			}
			continue
		}

		// 6. Fallback: Raw domain or comma-separated list
		lineContent := strings.Split(line, "#")[0]
		lineContent = strings.Split(lineContent, "!")[0]
		parts := strings.Fields(lineContent)
		for _, p := range parts {
			subParts := strings.Split(p, ",")
			for _, sub := range subParts {
				d := NormalizeDomain(sub)
				if d != "" {
					if added := addDomain(d, isAllowlist, list.Name, false, blockMap, allowMap, allowAttr); added {
						count++
					}
				}
			}
		}
	}

	list.Entries = count
	list.UpdatedAt = time.Now()
	slog.Info("List processed", "name", list.Name, "entries", count, "url", list.URL)

	if err := scanner.Err(); err != nil {
		slog.Error("Error reading lines for list", "name", list.Name, "error", err)
	}
}

func addDomain(domain string, isAllowlist bool, listName string, isWildcard bool, blockMap map[string][]string, allowSet map[string]struct{}, allowAttr map[string][]string) bool {
	domains := []string{domain}
	if isWildcard && !strings.HasPrefix(domain, "*.") {
		domains = append(domains, "*."+domain)
	}

	addedAny := false
	for _, d := range domains {
		if isAllowlist {
			if allowSet != nil {
				if _, exists := allowSet[d]; !exists {
					allowSet[d] = struct{}{}
					addedAny = true
				}
				if allowAttr != nil {
					allowAttr[d] = append(allowAttr[d], listName)
				}
			}
		} else if blockMap != nil {
			alreadyPresent := false
			for _, name := range blockMap[d] {
				if name == listName {
					alreadyPresent = true
					break
				}
			}
			if !alreadyPresent {
				blockMap[d] = append(blockMap[d], listName)
				addedAny = true
			}
		}
	}
	return addedAny
}

func startBackgroundUpdater(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updateBlocklist(nil, true)
		}
	}
}

var (
	metadataCache = make(map[string]List)
	metadataMu    sync.RWMutex
)

// startMetadataUpdater periodically refreshes metadata for all lists and presets.
// Uses a 24h ticker for full refresh and a 1h ticker for missing information retries.
func startMetadataUpdater(ctx context.Context) {
	fullTicker := time.NewTicker(24 * time.Hour)
	missingTicker := time.NewTicker(1 * time.Hour)
	defer fullTicker.Stop()
	defer missingTicker.Stop()

	go func() {
		// Initial wait to let main startup finish
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}

		// Run once on startup
		refreshAllMetadata(false)

		for {
			select {
			case <-ctx.Done():
				return
			case <-fullTicker.C:
				refreshAllMetadata(false) // Full refresh
			case <-missingTicker.C:
				refreshAllMetadata(true) // Only missing metadata
			}
		}
	}()
}

func refreshAllMetadata(onlyMissing bool) {
	mode := "Full"
	if onlyMissing {
		mode = "Missing-Only"
	}
	slog.Info("Starting background metadata refresh", "mode", mode)

	configLock.RLock()
	allLists := append([]List{}, config.Lists...)
	allLists = append(allLists, config.Allowlists...)
	configLock.RUnlock()

	// Also include all presets
	allLists = append(allLists, DefaultPresets...)
	allLists = append(allLists, DefaultAllowlists...)

	// Deduplicate by URL
	uniqueURLs := make(map[string]List)
	for _, l := range allLists {
		uniqueURLs[l.URL] = l
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Concurrency limit

	for _, l := range uniqueURLs {
		// If onlyMissing is requested, skip lists that already have metadata
		if onlyMissing {
			metadataMu.RLock()
			cached, ok := metadataCache[l.URL]
			metadataMu.RUnlock()
			if ok && cached.Entries > 0 && !cached.RemoteUpdatedAt.IsZero() {
				continue
			}
		}

		wg.Add(1)
		go func(list List) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Local fallback check for official ShieldDNS lists
			useLocal := false
			var localPath string
			if strings.Contains(list.URL, "raw.githubusercontent.com/FaserF/ShieldDNS/") {
				parts := strings.Split(list.URL, "/official/")
				if len(parts) == 2 {
					localPath = filepath.Join("official", parts[1])
					if rel, err := filepath.Rel("official", localPath); err == nil && !strings.HasPrefix(rel, "..") && rel != ".." {
						if _, err := os.Stat(localPath); err == nil {
							useLocal = true
						}
					}
				}
			}

			if useLocal {
				file, err := os.Open(localPath)
				if err == nil {
					defer file.Close()
					list.RemoteUpdatedAt = time.Now()
					if info, err := file.Stat(); err == nil {
						list.RemoteUpdatedAt = info.ModTime()
					}

					scanner := bufio.NewScanner(file)
					count := 0
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") {
							count++
						}
					}
					list.Entries = count

					metadataMu.Lock()
					metadataCache[list.URL] = list
					metadataMu.Unlock()
					return
				}
			}

			if !isValidListURL(list.URL) {
				slog.Warn("Metadata fetch skipped: not a safe remote URL", "url", list.URL)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			req, _ := http.NewRequestWithContext(ctx, "GET", list.URL, nil)
			req.Header.Set("User-Agent", fmt.Sprintf("ShieldDNS/%s (MetadataFetcher)", FullVersion))
			req.Header.Set("Range", "bytes=0-102400") // Fetch first 100KB to estimate entries if needed

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
				list.RemoteUpdatedAt = getRemoteUpdateTime(list.URL, resp.Header)

				// Quick entry estimate if entries are 0
				if list.Entries == 0 {
					scanner := bufio.NewScanner(resp.Body)
					count := 0
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") {
							count++
						}
					}
					list.Entries = count
				}

				metadataMu.Lock()
				metadataCache[list.URL] = list
				metadataMu.Unlock()
			}
		}(l)
	}
	wg.Wait()
	slog.Info("Background metadata refresh completed", "count", len(uniqueURLs))
}

// getRemoteUpdateTime attempts to find the best possible modification timestamp for a remote file.
func getRemoteUpdateTime(rawURL string, headers http.Header) time.Time {
	// 1. Standard HTTP header (static files)
	if lm := headers.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			return t
		}
	}

	// 2. Fallback to Date header - DISABLED
	// The Date header is just when the server sent the response, not when the file changed.
	// Returning empty time is better than a false "now" timestamp.
	/*
		if d := headers.Get("Date"); d != "" {
			if t, err := http.ParseTime(d); err == nil {
				return t
			}
		}
	*/

	// 3. Specialized support for GitHub Raw Content
	// raw.githubusercontent.com does not send Last-Modified, so we check the Commit API
	if strings.Contains(rawURL, "raw.githubusercontent.com") {
		// URL: https://raw.githubusercontent.com/user/repo/branch/folder/file.txt
		parts := strings.Split(strings.TrimPrefix(rawURL, "https://"), "/")
		if len(parts) >= 5 {
			user := parts[1]
			repo := parts[2]
			branch := parts[3]
			path := strings.Join(parts[4:], "/")

			apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/commits?path=%s&sha=%s&per_page=1", user, repo, path, branch)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			req, _ := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
			req.Header.Set("User-Agent", "ShieldDNS-Update-Tracker")

			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var commitInfo []struct {
						Commit struct {
							Committer struct {
								Date time.Time `json:"date"`
							} `json:"committer"`
						} `json:"commit"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&commitInfo); err == nil && len(commitInfo) > 0 {
						return commitInfo[0].Commit.Committer.Date
					}
				} else if resp.StatusCode == http.StatusForbidden {
					slog.Debug("GitHub API rate limited while fetching list metadata", "url", rawURL)
				}
			}
		}
	}

	// 4. Specialized support for GitLab Raw Content
	// gitlab.com does not send Last-Modified, so we check the Commits API
	if strings.Contains(rawURL, "gitlab.com") && (strings.Contains(rawURL, "/raw/") || strings.Contains(rawURL, "/-/raw/")) {
		// Example: https://gitlab.com/curben/urlhaus-filter/raw/master/urlhaus-filter-hosts.txt
		// or https://gitlab.com/group/project/-/raw/ref/path/file.txt

		separator := "/raw/"
		if strings.Contains(rawURL, "/-/raw/") {
			separator = "/-/raw/"
		}

		parts := strings.Split(rawURL, separator)
		if len(parts) == 2 {
			// Extract project path (e.g. curben/urlhaus-filter)
			// Remove domain and any leading slashes
			projectPath := parts[0]
			for _, prefix := range []string{"https://gitlab.com/", "http://gitlab.com/", "gitlab.com/"} {
				projectPath = strings.TrimPrefix(projectPath, prefix)
			}
			projectPath = strings.Trim(projectPath, "/")

			refPath := parts[1]
			refParts := strings.Split(refPath, "/")
			if len(refParts) >= 2 {
				ref := refParts[0]
				filePath := strings.Join(refParts[1:], "/")

				// GitLab Project ID is the URL-encoded path
				projectID := url.PathEscape(projectPath)
				committedURL := fmt.Sprintf("https://gitlab.com/api/v4/projects/%s/repository/commits?path=%s&ref_name=%s&per_page=1",
					projectID, url.PathEscape(filePath), url.PathEscape(ref))

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()

				req, _ := http.NewRequestWithContext(ctx, "GET", committedURL, nil)
				req.Header.Set("User-Agent", "ShieldDNS-Update-Tracker")

				resp, err := http.DefaultClient.Do(req)
				if err == nil {
					defer resp.Body.Close()
					if resp.StatusCode == http.StatusOK {
						var commitInfo []struct {
							CreatedAt time.Time `json:"created_at"`
						}
						if err := json.NewDecoder(resp.Body).Decode(&commitInfo); err == nil && len(commitInfo) > 0 {
							return commitInfo[0].CreatedAt
						}
					}
				}
			}
		}
	}

	return time.Time{}
}
