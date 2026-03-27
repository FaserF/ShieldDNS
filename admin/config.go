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
	DBPath = filepath.Join(DataDir, "queries.db")

	if cp := os.Getenv("COREFILE_PATH"); cp != "" {
		CorefilePath = cp
	}
}

func loadConfig() {
	configLock.Lock()
	defer configLock.Unlock()

	// 1. Initialize with current defaults
	config = Config{
		Upstreams:           []string{"86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"},
		UpstreamDoT:          []string{"unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"},
		PreferEncrypted:      true,
		FilteringEnabled:    true,
		AdminDomain:         "shielddns.local",
		BlockPageIP:         "127.0.0.1",
		Lists:               DefaultPresets,
		Allowlists:          DefaultAllowlists,
		LatencyTestInterval: 10,
		SmartSelectionPolicy: "fastest",
		DiagnosticsRefreshInterval: 30, // Default to 30s
		ServeStale:          true,
		DNSSECEnabled:       true,
		SignMobileConfig:    true,
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
	if len(config.Upstreams) > 5 { config.Upstreams = config.Upstreams[:5] }
	if len(config.UpstreamDoT) > 5 { config.UpstreamDoT = config.UpstreamDoT[:5] }

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
			Name: "ShieldDNS Official Blocklist", 
			URL: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/blocklists/default.txt", 
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
			Name: "ShieldDNS Official Allowlist", 
			URL: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/allowlists/default.txt", 
			Enabled: true,
		}}, config.Allowlists...)
	}
}

func saveConfigNoLock() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.MkdirAll(filepath.Dir(ConfigPath), 0755)
	if err := os.WriteFile(ConfigPath, data, 0644); err != nil {
		log.Printf("⚠️ ERROR: Failed to save config to %s: %v", ConfigPath, err)
	} else {
		log.Printf("Disk: Config saved to %s", ConfigPath)
	}
}

func updateBlocklist() {
	log.Println("Updating blocklists...")
	configLock.RLock()
	blocklists := config.Lists
	allowlists := config.Allowlists
	customBlocked := config.CustomBlocked
	customAllowed := config.CustomAllowed
	blockPageIP := config.BlockPageIP
	configLock.RUnlock()

	newBlockAttribution := make(map[string][]string)
	blockDomains := make(map[string]struct{})
	allowDomains := make(map[string]struct{})

	for _, list := range blocklists {
		if !list.Enabled { continue }
		AddSystemLog("⏬ Downloading blocklist: " + list.Name)
		processList(list, newBlockAttribution, allowDomains)
		AddSystemLog("✅ Processed blocklist: " + list.Name)
	}

	for _, list := range allowlists {
		if !list.Enabled { continue }
		AddSystemLog("⏬ Downloading allowlist: " + list.Name)
		processList(list, nil, allowDomains) // Allowlists only populate allowDomains
		AddSystemLog("✅ Processed allowlist: " + list.Name)
	}

	// Add Custom Rules
	for _, d := range customBlocked {
		newBlockAttribution[d] = append(newBlockAttribution[d], "Custom Blocklist")
	}
	for _, d := range customAllowed {
		allowDomains[d] = struct{}{}
	}

	// Remove allowlisted domains from attribution and populate blockDomains for .hosts file
	for d := range allowDomains {
		delete(newBlockAttribution, d)
	}

	// Always enforce blocking for the built-in test domain regardless of allowlists
	newBlockAttribution["shielddns-maleware.test"] = []string{"ShieldDNS Built-in Test Domain"}

	for d := range newBlockAttribution {
		blockDomains[d] = struct{}{}
	}

	// Update global attribution map
	blockAttributionLock.Lock()
	blockAttribution = newBlockAttribution
	blockAttributionLock.Unlock()

	// Write Blocklist
	var combined strings.Builder
	ip := blockPageIP
	if ip == "" { ip = "0.0.0.0" }
	
	for domain := range blockDomains {
		combined.WriteString(fmt.Sprintf("%s %s\n", ip, domain))
	}
	os.MkdirAll(filepath.Dir(BlocklistPath), 0755)
	os.WriteFile(BlocklistPath, []byte(combined.String()), 0644)
	log.Printf("Blocklist updated with %d domains", len(blockDomains))

	// Write Allowlist for CoreDNS explicitly (optional but good for tracking)
	var allowBuilder strings.Builder
	for domain := range allowDomains {
		allowBuilder.WriteString(fmt.Sprintf("127.0.0.1 %s\n", domain)) // Or just track it
	}
	os.WriteFile(AllowlistPath, []byte(allowBuilder.String()), 0644)
}

func processList(list List, blockMap map[string][]string, allowMap map[string]struct{}) {
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

	if err := scanner.Err(); err != nil {
		log.Printf("⚠️  WARNING: Error reading lines for %s: %v", list.Name, err)
	}
}

func startBackgroundUpdater() {
	updateBlocklist() // Initial update
	ticker := time.NewTicker(6 * time.Hour)
	for range ticker.C {
		updateBlocklist()
	}
}
