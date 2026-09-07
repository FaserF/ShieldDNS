package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

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
		var file *os.File
		var err error
		if strings.Contains(list.URL, "raw.githubusercontent.com/FaserF/ShieldDNS/") {
			parts := strings.Split(list.URL, "/official/")
			if len(parts) == 2 {
				switch parts[1] {
				case "allowlists/default.txt":
					file, err = os.Open("official/allowlists/default.txt")
					useLocal = true
				case "blocklists/default.txt":
					file, err = os.Open("official/blocklists/default.txt")
					useLocal = true
				case "blocklists/search-ads-hybrid.txt":
					file, err = os.Open("official/blocklists/search-ads-hybrid.txt")
					useLocal = true
				}
			}
		}

		if useLocal && err == nil {
			defer file.Close()
			list.RemoteUpdatedAt = time.Now()
			if info, err := file.Stat(); err == nil {
				list.RemoteUpdatedAt = info.ModTime()
			}
			reader = file
		} else {
			if useLocal && err != nil {
				slog.Warn("Could not open local official list fallback file, falling back to remote", "name", list.Name, "error", err)
			}
			if !testMode && !isValidListURL(list.URL) {
				// Give a specific message when the URL uses plain HTTP
				if strings.HasPrefix(strings.ToLower(list.URL), "http://") {
					slog.Warn("Blocklist URL rejected: only HTTPS is allowed, plain HTTP is insecure – skipping list", "name", list.Name, "url", list.URL)
				} else {
					slog.Warn("Blocklist URL rejected: not a safe remote URL", "name", list.Name, "url", list.URL)
				}
				return
			}
			ua := fmt.Sprintf("ShieldDNS/%s (https://github.com/FaserF/ShieldDNS)", FullVersion)
			resp, err := fetchBlocklistURL(list.URL, ua, map[string]string{"Accept": "text/plain, */*"}, 30)
			if err != nil {
				slog.Warn("Could not fetch remote list", "name", list.Name, "url", list.URL, "error", err)
				return
			}
			// Capture remote update time with specialized GitHub support
			list.RemoteUpdatedAt = getRemoteUpdateTime(list.URL, resp.Header)

			reader = resp.Body
			defer resp.Body.Close()
		}
	}

	listIsAllowlist := blockMap == nil
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

		isAllowlist := listIsAllowlist
		if strings.HasPrefix(line, "@@") {
			isAllowlist = true
			line = line[2:]
		}

		// 3. Handle AdGuard / AdBlock Plus syntax (||domain^, @@||domain^, $modifiers)
		if parsedRule := ParseAdblockRule(line); parsedRule != nil && parsedRule.Domain != "" {
			if isAllowlist {
				parsedRule.IsAllowlist = true
			}
			// Skip badfilter if requested
			hasBadFilter := false
			for _, m := range parsedRule.Modifiers {
				if m == "badfilter" {
					hasBadFilter = true
					break
				}
			}
			if !hasBadFilter {
				if added := addDomain(parsedRule.Domain, parsedRule.IsAllowlist, list.Name, true, blockMap, allowMap, allowAttr); added {
					count++
				}
				continue
			}
		}

		// 4. Handle Hosts: 0.0.0.0 domain1 domain2 ...
		if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") || strings.HasPrefix(line, "::1 ") || strings.HasPrefix(line, ":: ") {
			parts := strings.Fields(line)
			for i := 1; i < len(parts); i++ {
				d := NormalizeDomain(parts[i])
				if d != "" {
					if added := addDomain(d, isAllowlist, list.Name, true, blockMap, allowMap, allowAttr); added {
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
					if added := addDomain(d, isAllowlist, list.Name, true, blockMap, allowMap, allowAttr); added {
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

