package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func initPaths() {
	if dd := os.Getenv("DATA_DIR"); dd != "" {
		DataDir = dd
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
		AbuseDetectionEnabled:      true,
		CustomMappings:             map[string]string{"fritz.box": "192.168.178.1", "openwrt.lan": "192.168.1.1", "router.miwifi.com": "192.168.31.1"},
	}

	// 2. Load from file if exists
	file, err := os.ReadFile(ConfigPath)
	if err == nil {
		// This will overwrite defaults with values from file
		// If a key is missing in JSON, the default value from above remains
		json.Unmarshal(file, &config)
	} else {
		log.Printf("Creating default config at %s", ConfigPath)
		saveConfigNoLock()
	}

	// 3. Check environment variables for overrides
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

func saveConfig() {
	configLock.Lock()
	defer configLock.Unlock()
	saveConfigNoLock()
}

func saveConfigNoLock() {
	debugModeEnabled.Store(config.DebugMode)
	data, _ := json.MarshalIndent(config, "", "  ")
	os.MkdirAll(filepath.Dir(ConfigPath), 0755)
	if err := os.WriteFile(ConfigPath, data, 0644); err != nil {
		log.Printf("⚠️ ERROR: Failed to save config to %s: %v", ConfigPath, err)
	} else {
		DebugLog(fmt.Sprintf("Disk: Config saved to %s", ConfigPath))
	}
}

func updateBlocklist(cfg *Config) {
	if cfg == nil {
		configLock.RLock()
		cfg = config.Clone()
		configLock.RUnlock()
	}
	log.Println("Updating blocklists...")

	blocklists := cfg.Lists
	allowlists := cfg.Allowlists
	customBlocked := cfg.CustomBlocked
	customAllowed := cfg.CustomAllowed
	customMappings := cfg.CustomMappings
	blockPageIP := cfg.BlockPageIP

	newBlockAttribution := make(map[string][]string)
	allowDomains := make(map[string]struct{})

	for i := range blocklists {
		list := &blocklists[i]
		if !list.Enabled {
			continue
		}
		AddSystemLog("⏬ Downloading blocklist: " + list.Name)
		processList(list, newBlockAttribution, allowDomains)
		AddSystemLog("✅ Processed blocklist: " + list.Name)
	}

	for i := range allowlists {
		list := &allowlists[i]
		if !list.Enabled {
			continue
		}
		AddSystemLog("⏬ Downloading allowlist: " + list.Name)
		processList(list, nil, allowDomains) // Allowlists only populate allowDomains
		AddSystemLog("✅ Processed allowlist: " + list.Name)
	}

	// Update the config lists with the new metadata (Entries and UpdatedAt)
	configLock.Lock()
	for _, l := range blocklists {
		for j, cl := range config.Lists {
			if cl.URL == l.URL {
				config.Lists[j].Entries = l.Entries
				config.Lists[j].UpdatedAt = l.UpdatedAt
				break
			}
		}
	}
	for _, l := range allowlists {
		for j, cl := range config.Allowlists {
			if cl.URL == l.URL {
				config.Allowlists[j].Entries = l.Entries
				config.Allowlists[j].UpdatedAt = l.UpdatedAt
				break
			}
		}
	}
	configLock.Unlock()

	// Add Custom Rules
	for _, d := range customBlocked {
		newBlockAttribution[d] = append(newBlockAttribution[d], "Custom Blocklist")
	}
	for _, d := range customAllowed {
		allowDomains[d] = struct{}{}
	}

	saveConfig()
	applyCurrentRules(newBlockAttribution, allowDomains, customMappings, blockPageIP)
}

func applyCurrentRules(attribution map[string][]string, allowSet map[string]struct{}, mappings map[string]string, blockIP string) {
	// Remove allowlisted domains from attribution and populate blockDomains for .hosts file
	blockDomains := make(map[string]struct{})
	for d := range allowSet {
		delete(attribution, d)
	}

	// Always enforce blocking for the built-in test domain regardless of allowlists
	attribution["shielddns-maleware.test"] = []string{"ShieldDNS Built-in Test Domain"}

	for d := range attribution {
		blockDomains[d] = struct{}{}
	}

	// Update global attribution map
	blockAttributionLock.Lock()
	blockAttribution = attribution
	blockAttributionLock.Unlock()

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
	os.WriteFile(CombinedHostsPath, []byte(combinedBuilder.String()), 0644)
	os.WriteFile(BlocklistPath, []byte(combinedBuilder.String()), 0644)

	// Write Allowlist for tracking
	var allowBuilder strings.Builder
	for domain := range allowSet {
		allowBuilder.WriteString(fmt.Sprintf("127.0.0.1 %s\n", domain))
	}
	os.WriteFile(AllowlistPath, []byte(allowBuilder.String()), 0644)

	// Write Custom Mappings separately too
	var mappingsBuilder strings.Builder
	for domain, ip := range mappings {
		mappingsBuilder.WriteString(fmt.Sprintf("%s %s\n", ip, domain))
	}
	os.WriteFile(MappingsPath, []byte(mappingsBuilder.String()), 0644)

	log.Printf("Rules updated. Combined hosts written to %s. Restarting CoreDNS...", CombinedHostsPath)
	restartCoreDNS()
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
		go updateBlocklist(cfg)
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
	// RE-APPLY CURRENT CUSTOM RULES
	for _, d := range cfg.CustomBlocked {
		newAttribution[d] = append(newAttribution[d], "Custom Blocklist")
	}
	for _, d := range cfg.CustomAllowed {
		allowDomains[d] = struct{}{}
	}

	applyCurrentRules(newAttribution, allowDomains, cfg.CustomMappings, cfg.BlockPageIP)
}

func processList(list *List, blockMap map[string][]string, allowMap map[string]struct{}) {
	var reader io.Reader

	if strings.HasPrefix(list.URL, "file://") {
		path := strings.TrimPrefix(list.URL, "file://")
		file, err := os.Open(path)
		if err != nil {
			log.Printf("⚠️  WARNING: Could not open %s: %v. Skipping...", list.Name, err)
			return
		}
		defer file.Close()
		reader = file
	} else {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(list.URL)
		if err != nil {
			log.Printf("⚠️  WARNING: Could not fetch %s (%s): %v. Skipping...", list.Name, list.URL, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("⚠️  WARNING: %s returned status %d. Skipping...", list.Name, resp.StatusCode)
			return
		}
		reader = resp.Body
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

		isAllowlist := false
		if strings.HasPrefix(line, "@@") {
			isAllowlist = true
			line = line[2:]
		}

		domain := ""
		// AdGuard / AdBlock: ||domain^
		if strings.HasPrefix(line, "||") {
			domain = strings.Split(strings.TrimPrefix(line, "||"), "^")[0]
		} else if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") || strings.HasPrefix(line, "::1 ") {
			// Hosts: 0.0.0.0 domain
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain = parts[1]
			}
		} else if strings.HasPrefix(line, "address=/") {
			// Dnsmasq: address=/domain/0.0.0.0
			parts := strings.Split(line, "/")
			if len(parts) >= 3 {
				domain = parts[1]
			}
		} else if !strings.Contains(line, "/") && !strings.Contains(line, " ") && strings.Contains(line, ".") {
			// Raw domain
			domain = line
		}

		if domain != "" {
			domain = strings.Trim(domain, ".") // Some lists have trailing dots
			count++
			if isAllowlist {
				allowMap[domain] = struct{}{}
			} else if blockMap != nil {
				// Avoid duplicates in the same list attribution
				alreadyPresent := false
				for _, name := range blockMap[domain] {
					if name == list.Name {
						alreadyPresent = true
						break
					}
				}
				if !alreadyPresent {
					blockMap[domain] = append(blockMap[domain], list.Name)
				}
			}
		}
	}

	list.Entries = count
	list.UpdatedAt = time.Now()

	if err := scanner.Err(); err != nil {
		log.Printf("⚠️  WARNING: Error reading lines for %s: %v", list.Name, err)
	}
}

func startBackgroundUpdater() {
	ticker := time.NewTicker(24 * time.Hour)
	for range ticker.C {
		go updateBlocklist(nil)
	}
}
