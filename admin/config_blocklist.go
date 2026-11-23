package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
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

	blockAttributionLock.RLock()
	prevCap := len(blockAttribution)
	blockAttributionLock.RUnlock()

	newBlockAttribution := make(map[string][]string, prevCap)
	newAllowAttribution := make(map[string][]string)
	allowDomains := make(map[string]struct{})
	importantBlocks := make(map[string]struct{})
	customAllowedSet := make(map[string]struct{})

	for i := range blocklists {
		list := &blocklists[i]
		if !list.Enabled || list.EmergencySuspended {
			if list.EmergencySuspended {
				slog.Info("Skipping blocklist due to emergency RAM shedding", "name", list.Name)
			}
			continue
		}
		slog.Info("Processing blocklist", "name", list.Name)
		processList(list, newBlockAttribution, allowDomains, nil, importantBlocks)
	}

	for i := range allowlists {
		list := &allowlists[i]
		if !list.Enabled {
			continue
		}
		slog.Info("Processing allowlist", "name", list.Name)
		processList(list, nil, allowDomains, newAllowAttribution, nil) // Allowlists populate allowDomains and allowAttribution
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
		customAllowedSet[d] = struct{}{}
		newAllowAttribution[d] = append(newAllowAttribution[d], "Custom Allowlist")
		if !strings.HasPrefix(d, "*.") {
			allowDomains["*."+d] = struct{}{}
			customAllowedSet["*."+d] = struct{}{}
			newAllowAttribution["*."+d] = append(newAllowAttribution["*."+d], "Custom Allowlist")
		}
	}

	// Add Blocked Services Catalog Rules
	for domain, attr := range GetBlockedServiceDomains(cfg) {
		newBlockAttribution[domain] = append(newBlockAttribution[domain], attr)
	}

	// Merge SafeSearch VIP mappings with explicit CustomMappings (explicit mappings win)
	effectiveMappings := GetSafeSearchMappings(cfg)
	for k, v := range customMappings {
		effectiveMappings[k] = v
	}

	applyCurrentRules(newBlockAttribution, newAllowAttribution, allowDomains, importantBlocks, customAllowedSet, effectiveMappings, blockPageIP, restartCore)
}

func applyCurrentRules(attribution map[string][]string, allowAttr map[string][]string, allowSet map[string]struct{}, importantSet map[string]struct{}, customAllowedSet map[string]struct{}, mappings map[string]string, blockIP string, restartCore bool) {
	if importantSet == nil {
		importantSet = make(map[string]struct{})
	}
	if customAllowedSet == nil {
		customAllowedSet = make(map[string]struct{})
	}

	// Defense-in-depth: Never allow trusted infrastructure domains to remain in blocked attribution
	for ad := range attribution {
		if isTrustedInfrastructureDomain(ad) {
			delete(attribution, ad)
		}
	}

	// Remove allowlisted domains (and their subdomains) from attribution in O(N) time
	for ad := range attribution {
		// If domain is marked $important, standard allowlists cannot unblock it.
		// Only explicit user custom allowed rules can unblock an $important rule.
		if _, isImp := importantSet[ad]; isImp {
			if _, inCustom := customAllowedSet[ad]; !inCustom {
				continue
			}
		}

		// Exact match
		if _, ok := allowSet[ad]; ok {
			delete(attribution, ad)
			continue
		}

		// Subdomain match: only user custom allowed rules or explicit wildcard allow rules
		// can unblock a subdomain that was explicitly flagged by a blocklist.
		// Standard general allowlists (e.g. for apex domains like "google.com" or "spiegel.de")
		// must NOT blanket-unblock ad/tracking subdomains (like "adservice.google.com" or "ad.spiegel.de").
		// Walk dot boundaries in-place to avoid allocating []string + joined strings for 3M+ domains.
		isWWW := strings.HasPrefix(ad, "www.")
		rest := ad
		firstStep := true
		for {
			dot := strings.IndexByte(rest, '.')
			if dot < 0 || dot+1 >= len(rest) {
				break
			}
			parentDomain := rest[dot+1:]
			if _, inCustom := customAllowedSet[parentDomain]; inCustom {
				delete(attribution, ad)
				break
			}
			if _, inCustomWild := customAllowedSet["*."+parentDomain]; inCustomWild {
				delete(attribution, ad)
				break
			}
			if firstStep && isWWW {
				if _, inAllow := allowSet[parentDomain]; inAllow {
					delete(attribution, ad)
					break
				}
			}
			firstStep = false
			rest = parentDomain
		}
	}

	// Subdomain exception handling:
	// If a specific subdomain is allowlisted (e.g. "mydealz.digidip.net"),
	// any broader parent wildcard block in attribution (e.g. "*.digidip.net")
	// will match and block that subdomain in CoreDNS hosts plugin.
	// We delete conflicting parent wildcards from attribution so the allowlisted subdomain can resolve.
	for allowed := range allowSet {
		rest := strings.TrimPrefix(allowed, "*.")
		for {
			dot := strings.IndexByte(rest, '.')
			if dot < 0 || dot+1 >= len(rest) {
				break
			}
			parent := rest[dot+1:]
			parentWildcard := "*." + parent
			if _, isImp := importantSet[parentWildcard]; isImp {
				if _, inCustom := customAllowedSet[allowed]; !inCustom {
					rest = parent
					continue
				}
			}
			delete(attribution, parentWildcard)
			rest = parent
		}
	}

	// Always enforce blocking for the built-in test domain regardless of allowlists
	attribution["shielddns-maleware.test"] = []string{"ShieldDNS Built-in Test Domain"}

	// Update global attribution map
	blockAttributionLock.Lock()
	blockAttribution = attribution
	slog.Info("Blocklist attribution updated", "total_blocked_domains", len(blockAttribution))
	blockAttributionLock.Unlock()

	// Update global important attribution map
	importantAttributionLock.Lock()
	importantAttribution = importantSet
	importantAttributionLock.Unlock()

	// Update global allow attribution map
	allowAttributionLock.Lock()
	allowAttribution = allowAttr
	allowAttributionLock.Unlock()

	if blockIP == "" {
		blockIP = "0.0.0.0"
	}
	isIPv4 := false
	if parsed := net.ParseIP(blockIP); parsed != nil && parsed.To4() != nil {
		isIPv4 = true
	}

	// Stream Combined Hosts File for CoreDNS directly to disk without building a 100MB+ string in RAM
	os.MkdirAll(filepath.Dir(CombinedHostsPath), 0755)
	if err := writeCombinedHostsStreaming(CombinedHostsPath, mappings, attribution, blockIP, isIPv4); err != nil {
		slog.Error("Failed to stream CombinedHostsPath", "error", err)
	}
	if BlocklistPath != "" && BlocklistPath != CombinedHostsPath {
		if err := copyFileAtomic(CombinedHostsPath, BlocklistPath); err != nil {
			slog.Error("Failed to copy CombinedHostsPath to BlocklistPath", "error", err)
		}
	}

	// Stream Allowlist for tracking
	if AllowlistPath != "" {
		if err := writeAllowlistStreaming(AllowlistPath, allowSet); err != nil {
			slog.Error("Failed to stream AllowlistPath", "error", err)
		}
	}

	// Write Custom Mappings separately too
	writeMappingsFile(mappings)

	slog.Info("Rules updated", "host_file", CombinedHostsPath, "count", len(attribution))
	if restartCore {
		restartCoreDNS()
	}

	// Return dead temporary parsing/building heap pages back to the OS immediately
	debug.FreeOSMemory()
}

func writeMappingsFile(mappings map[string]string) {
	if MappingsPath == "" {
		return
	}
	var mappingsBuilder strings.Builder
	for domain, ip := range mappings {
		mappingsBuilder.WriteString(ip)
		mappingsBuilder.WriteByte(' ')
		mappingsBuilder.WriteString(domain)
		mappingsBuilder.WriteByte('\n')
	}
	_ = os.WriteFile(MappingsPath, []byte(mappingsBuilder.String()), 0644)
}

func writeCombinedHostsStreaming(targetPath string, mappings map[string]string, attribution map[string][]string, blockIP string, isIPv4 bool) error {
	tmpFile, err := os.CreateTemp(filepath.Dir(targetPath), ".shielddns_hosts_*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	bw := bufio.NewWriterSize(tmpFile, 64*1024)

	_, _ = bw.WriteString("# ShieldDNS Combined Hosts File\n# Generated at ")
	_, _ = bw.WriteString(time.Now().Format(time.RFC3339))
	_, _ = bw.WriteString("\n\n# RFC 6761 Loopback Entries\n127.0.0.1 localhost\n::1 localhost\n\n# Custom Mappings\n")

	for domain, ip := range mappings {
		_, _ = bw.WriteString(ip)
		_ = bw.WriteByte(' ')
		_, _ = bw.WriteString(domain)
		_ = bw.WriteByte('\n')
	}

	_, _ = bw.WriteString("\n# Blocked Domains\n")
	for domain := range attribution {
		_, _ = bw.WriteString(blockIP)
		_ = bw.WriteByte(' ')
		_, _ = bw.WriteString(domain)
		_ = bw.WriteByte('\n')
		if isIPv4 {
			// Synthesize IPv6 unspecified address (::) for IPv4 block IPs so dual-stack clients
			// querying AAAA records do not fall through to upstream public DNS.
			_, _ = bw.WriteString(":: ")
			_, _ = bw.WriteString(domain)
			_ = bw.WriteByte('\n')
		}
	}

	if err := bw.Flush(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	_ = os.Chmod(tmpPath, 0644)
	return os.Rename(tmpPath, targetPath)
}

func writeAllowlistStreaming(targetPath string, allowSet map[string]struct{}) error {
	os.MkdirAll(filepath.Dir(targetPath), 0755)
	tmpFile, err := os.CreateTemp(filepath.Dir(targetPath), ".shielddns_allow_*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	bw := bufio.NewWriterSize(tmpFile, 32*1024)
	for domain := range allowSet {
		_, _ = bw.WriteString("127.0.0.1 ")
		_, _ = bw.WriteString(domain)
		_ = bw.WriteByte('\n')
	}
	if err := bw.Flush(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	_ = os.Chmod(tmpPath, 0644)
	return os.Rename(tmpPath, targetPath)
}

func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	os.MkdirAll(filepath.Dir(dst), 0755)
	tmpFile, err := os.CreateTemp(filepath.Dir(dst), ".shielddns_copy_*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := io.Copy(tmpFile, in); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	_ = os.Chmod(tmpPath, 0644)
	return os.Rename(tmpPath, dst)
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

	// Build set of suspended list names for emergency relief
	suspendedListNames := make(map[string]struct{})
	for _, l := range cfg.Lists {
		if l.EmergencySuspended {
			suspendedListNames[l.Name] = struct{}{}
		}
	}

	// Filter out existing "Custom Blocklist" entries and any emergency suspended lists
	newAttribution := make(map[string][]string)
	for d, lists := range blockAttribution {
		var filtered []string
		for _, l := range lists {
			if _, isSuspended := suspendedListNames[l]; isSuspended {
				continue
			}
			if l != "Custom Blocklist" && l != "ShieldDNS Built-in Test Domain" && !strings.HasPrefix(l, "Blocked Service: ") {
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
	customAllowedSet := make(map[string]struct{})

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
		customAllowedSet[d] = struct{}{}
		newAllowAttribution[d] = append(newAllowAttribution[d], "Custom Allowlist")
		// For allowlists, we don't strictly need to add *.d because applyCurrentRules
		// already handles subdomain allowance by checking parent domains.
		// However, adding it explicitly doesn't hurt and makes attribution clearer.
		if !strings.HasPrefix(d, "*.") {
			allowDomains["*."+d] = struct{}{}
			customAllowedSet["*."+d] = struct{}{}
			newAllowAttribution["*."+d] = append(newAllowAttribution["*."+d], "Custom Allowlist")
		}
	}

	// RE-APPLY BLOCKED SERVICES CATALOG
	for domain, attr := range GetBlockedServiceDomains(cfg) {
		newAttribution[domain] = append(newAttribution[domain], attr)
	}

	importantAttributionLock.RLock()
	importantCopy := make(map[string]struct{}, len(importantAttribution))
	for k := range importantAttribution {
		importantCopy[k] = struct{}{}
	}
	importantAttributionLock.RUnlock()

	effectiveMappings := GetSafeSearchMappings(cfg)
	for k, v := range cfg.CustomMappings {
		effectiveMappings[k] = v
	}

	applyCurrentRules(newAttribution, newAllowAttribution, allowDomains, importantCopy, customAllowedSet, effectiveMappings, cfg.BlockPageIP, true)
}

func processList(list *List, blockMap map[string][]string, allowMap map[string]struct{}, allowAttr map[string][]string, importantMap map[string]struct{}) {
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
				case "allowlists/default.txt", "blocklists/default.txt", "blocklists/anti-adblock.txt", "blocklists/search-ads-hybrid.txt":
					file, err = openLocalOfficialFile(parts[1])
					if err == nil {
						useLocal = true
					}
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
			if !useLocal && err != nil {
				slog.Debug("Local official list fallback not present, downloading remote", "name", list.Name)
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
			resp, err := fetchBlocklistURL(list.URL, ua, map[string]string{"Accept": "text/plain, */*"}, 60)
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
		if strings.Contains(line, "##") || strings.Contains(line, "#@#") ||
			strings.Contains(line, "#?#") || strings.Contains(line, "#$#") ||
			strings.Contains(line, "#@$#") || strings.Contains(line, "#%#") ||
			strings.Contains(line, "#@%#") || strings.Contains(line, "$$") {
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
					if parsedRule.IsImportant && !parsedRule.IsAllowlist && importantMap != nil {
						importantMap[parsedRule.Domain] = struct{}{}
						if !strings.HasPrefix(parsedRule.Domain, "*.") {
							importantMap["*."+parsedRule.Domain] = struct{}{}
						}
					}
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
		// In hosts/domain files, comments after a domain must be preceded by whitespace (e.g. "domain.com # comment").
		// Any inline '#' or '!' without leading whitespace indicates a cosmetic selector or invalid syntax.
		if idx := strings.Index(line, "#"); idx != -1 {
			if idx > 0 && (line[idx-1] == ' ' || line[idx-1] == '\t') {
				line = strings.TrimSpace(line[:idx])
			} else {
				continue
			}
		}
		if idx := strings.Index(line, "!"); idx != -1 {
			if idx > 0 && (line[idx-1] == ' ' || line[idx-1] == '\t') {
				line = strings.TrimSpace(line[:idx])
			} else {
				continue
			}
		}
		if line == "" || strings.ContainsAny(line, "/?=&:$*") {
			continue
		}
		parts := strings.Fields(line)
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

