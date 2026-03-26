package main

import (
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

	file, err := os.ReadFile(ConfigPath)
	if err != nil {
		log.Printf("Creating default config")
		config = Config{
			Upstreams:       []string{"86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"},
			UpstreamDoT:     []string{"unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"},
			PreferEncrypted: true,
			Lists: []List{
				{Name: "ShieldDNS Official Blocklist", URL: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/blocklists/default.txt", Enabled: true},
				{Name: "HaGeZi Multi Pro", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", Enabled: true},
				{Name: "AdGuard DNS Filter", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Enabled: true},
				{Name: "Steven Black Unified", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Enabled: false},
				{Name: "AdAway Default", URL: "https://adaway.org/hosts.txt", Enabled: false},
				{Name: "OISD Pro", URL: "https://big.oisd.nl", Enabled: false},
			},
			Allowlists: []List{
				{Name: "ShieldDNS Official Allowlist", URL: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/allowlists/default.txt", Enabled: true},
			},
		}
		saveConfigNoLock()
		return
	}
	json.Unmarshal(file, &config)
	
	// Prepend official lists if missing
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

	// Ensure defaults if fields are empty
	if len(config.Upstreams) == 0 {
		config.Upstreams = []string{"86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"}
	}
	// Limit to max 5
	if len(config.Upstreams) > 5 { config.Upstreams = config.Upstreams[:5] }
	if len(config.UpstreamDoT) > 5 { config.UpstreamDoT = config.UpstreamDoT[:5] }
}

func saveConfigNoLock() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.MkdirAll(filepath.Dir(ConfigPath), 0755)
	os.WriteFile(ConfigPath, data, 0644)
}

func updateBlocklist() {
	log.Println("Updating blocklists...")
	configLock.RLock()
	blocklists := config.Lists
	allowlists := config.Allowlists
	customBlocked := config.CustomBlocked
	customAllowed := config.CustomAllowed
	configLock.RUnlock()

	newBlockAttribution := make(map[string][]string)
	blockDomains := make(map[string]struct{})
	allowDomains := make(map[string]struct{})

	for _, list := range blocklists {
		if !list.Enabled { continue }
		processList(list, newBlockAttribution, allowDomains)
	}

	for _, list := range allowlists {
		if !list.Enabled { continue }
		processList(list, nil, allowDomains) // Allowlists only populate allowDomains
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

	for d := range newBlockAttribution {
		blockDomains[d] = struct{}{}
	}

	// Update global attribution map
	blockAttributionLock.Lock()
	blockAttribution = newBlockAttribution
	blockAttributionLock.Unlock()

	// Write Blocklist
	var combined strings.Builder
	for domain := range blockDomains {
		combined.WriteString(fmt.Sprintf("0.0.0.0 %s\n", domain))
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
	var body []byte
	var err error

	if strings.HasPrefix(list.URL, "file://") {
		path := strings.TrimPrefix(list.URL, "file://")
		body, err = os.ReadFile(path)
	} else {
		resp, err := http.Get(list.URL)
		if err != nil {
			log.Printf("⚠️  WARNING: Could not fetch %s (%s): %v. Skipping...", list.Name, list.URL, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("⚠️  WARNING: %s returned status %d. Skipping...", list.Name, resp.StatusCode)
			return
		}
		body, err = io.ReadAll(resp.Body)
	}

	if err != nil {
		log.Printf("⚠️  WARNING: Error reading %s: %v. Skipping...", list.Name, err)
		return
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
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
}

func startBackgroundUpdater() {
	updateBlocklist() // Initial update
	ticker := time.NewTicker(6 * time.Hour)
	for range ticker.C {
		updateBlocklist()
	}
}
