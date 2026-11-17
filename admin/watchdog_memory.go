package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	memoryWatchdogMu      sync.Mutex
	consecutiveStableRAM  int
	peerOffloadMu         sync.RWMutex
	activePeerOffloadAddr string
	primarySheddingActive bool
	primaryDNSTarget      string
)

// normalizeListPriorities ensures every list has an intelligent priority assigned
func normalizeListPriorities(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	modified := false

	// Build map from DefaultPresets for reference
	presetPrios := make(map[string]string)
	for _, p := range DefaultPresets {
		if p.Priority != "" {
			presetPrios[strings.ToLower(strings.TrimSpace(p.URL))] = p.Priority
			presetPrios[strings.ToLower(strings.TrimSpace(p.Name))] = p.Priority
		}
	}

	for i := range cfg.Lists {
		l := &cfg.Lists[i]
		if l.Priority == "" {
			urlKey := strings.ToLower(strings.TrimSpace(l.URL))
			nameKey := strings.ToLower(strings.TrimSpace(l.Name))
			if prio, ok := presetPrios[urlKey]; ok {
				l.Priority = prio
			} else if prio, ok := presetPrios[nameKey]; ok {
				l.Priority = prio
			} else if l.Category == "Security & Malware" || l.Category == "Official" {
				l.Priority = "high"
			} else if l.Entries > 200000 {
				l.Priority = "low"
			} else {
				l.Priority = "normal"
			}
			modified = true
		}
	}

	for i := range cfg.Allowlists {
		l := &cfg.Allowlists[i]
		if l.Priority == "" {
			l.Priority = "high"
			modified = true
		}
	}

	return modified
}

// startMemoryWatchdog periodically monitors host and container RAM to prevent OOM freeze
func startMemoryWatchdog(ctx context.Context) {
	if testMode {
		return
	}

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	slog.Info("ShieldDNS Autonomous Memory & Load-Shedding Watchdog started")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			evaluateMemoryHealth()
		}
	}
}

func evaluateMemoryHealth() {
	memoryWatchdogMu.Lock()
	defer memoryWatchdogMu.Unlock()

	sysStats := make(map[string]interface{})
	fillRAMStats(sysStats)

	var totalKB, usedKB, availKB int64
	if ram, ok := sysStats["ram"]; ok {
		if ramMap, ok := ram.(map[string]interface{}); ok {
			if v, ok := ramMap["total"].(int64); ok {
				totalKB = v
			}
			if v, ok := ramMap["used"].(int64); ok {
				usedKB = v
			}
			if v, ok := ramMap["available"].(int64); ok {
				availKB = v
			}
		}
	}

	if totalKB <= 0 {
		return
	}

	totalMB := float64(totalKB) / 1024.0
	usedMB := float64(usedKB) / 1024.0
	availMB := float64(availKB) / 1024.0

	configLock.RLock()
	ramProtEnabled := config.RAMProtectionEnabled
	maxBudget := config.MaxRAMBudgetMB
	safetyBuffer := config.RAMSafetyBufferMB
	sheddingActive := config.EmergencySheddingActive
	configLock.RUnlock()

	if !ramProtEnabled {
		return
	}

	if safetyBuffer <= 0 {
		safetyBuffer = int(totalMB * 0.20)
		if safetyBuffer < 256 {
			safetyBuffer = 256
		}
	}

	effectiveBudget := float64(maxBudget)
	if effectiveBudget <= 0 {
		effectiveBudget = totalMB - float64(safetyBuffer)
		if effectiveBudget < 256.0 {
			effectiveBudget = 256.0
		}
	}

	// Calculate estimated ShieldDNS memory
	blockAttributionLock.RLock()
	domainCount := len(blockAttribution)
	blockAttributionLock.RUnlock()
	estimatedShieldMB := float64(domainCount) * 1.3 / 1024.0

	// Check Critical Memory Conditions:
	// 1. Available RAM less than 200 MB, OR
	// 2. Available RAM less than 12% of total, OR
	// 3. ShieldDNS memory significantly exceeds the configured max budget
	isUnderCriticalPressure := availMB < 200.0 || (totalMB > 0 && availMB < totalMB*0.12) || (maxBudget > 0 && estimatedShieldMB > effectiveBudget)

	if isUnderCriticalPressure {
		consecutiveStableRAM = 0
		triggerEmergencyLoadShedding(availMB, totalMB, estimatedShieldMB, effectiveBudget)
		return
	}

	// Check if stable recovery is ongoing & re-verify peer offload health
	if sheddingActive {
		go evaluatePeerOffload()
		// If available RAM is now comfortably above safety margin (> 25% available and > 500 MB)
		if availMB > 500.0 && (availMB/totalMB) > 0.25 && usedMB/totalMB < 0.75 {
			consecutiveStableRAM++
			if consecutiveStableRAM == 4 { // Log once after 60 seconds of stable RAM
				slog.Info("Memory pressure relieved stably; system ready for list recovery",
					"available_mb", fmt.Sprintf("%.1f", availMB),
					"used_mb", fmt.Sprintf("%.1f", usedMB),
					"total_mb", fmt.Sprintf("%.1f", totalMB))
			} else if consecutiveStableRAM >= 20 { // Automatically restore shed lists after 5 min (20 * 15s) of sustained healthy RAM
				consecutiveStableRAM = 0
				restoreShedListsInternal("automatic_watchdog")
			}
		} else {
			consecutiveStableRAM = 0
		}
	}
}

func triggerEmergencyLoadShedding(availMB, totalMB, estimatedShieldMB, budgetMB float64) {
	configLock.Lock()
	defer configLock.Unlock()

	// Find all enabled, non-suspended blocklists
	type candidate struct {
		Index    int
		Name     string
		URL      string
		Priority string
		PrioRank int // 1 = low, 2 = normal, 3 = high
		Entries  int
	}

	var candidates []candidate
	for i, l := range config.Lists {
		if !l.Enabled || l.EmergencySuspended {
			continue
		}
		rank := 2
		switch strings.ToLower(strings.TrimSpace(l.Priority)) {
		case "low":
			rank = 1
		case "high":
			rank = 3
		default:
			rank = 2
		}
		candidates = append(candidates, candidate{
			Index:    i,
			Name:     l.Name,
			URL:      l.URL,
			Priority: l.Priority,
			PrioRank: rank,
			Entries:  l.Entries,
		})
	}

	if len(candidates) == 0 {
		slog.Warn("Emergency RAM shedding needed but no active blocklists available to shed",
			"avail_mb", availMB, "total_mb", totalMB)
		return
	}

	// Sort candidates:
	// 1. Priority rank ASC (low priority rank 1 shed first!)
	// 2. Entries DESC (highest number of entries shed first within priority)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].PrioRank != candidates[j].PrioRank {
			return candidates[i].PrioRank < candidates[j].PrioRank
		}
		return candidates[i].Entries > candidates[j].Entries
	})

	// Shed the top offending candidate
	topCandidate := candidates[0]
	config.Lists[topCandidate.Index].EmergencySuspended = true
	config.EmergencySheddingActive = true

	// Track in EmergencyShedLists if not already present
	found := false
	for _, u := range config.EmergencyShedLists {
		if u == topCandidate.URL {
			found = true
			break
		}
	}
	if !found {
		config.EmergencyShedLists = append(config.EmergencyShedLists, topCandidate.URL)
	}

	freedMB := float64(topCandidate.Entries) * 1.3 / 1024.0
	slog.Warn("EMERGENCY LOAD SHEDDING ACTIVATED: List temporarily suspended to prevent system freeze",
		"list", topCandidate.Name,
		"priority", topCandidate.Priority,
		"entries", topCandidate.Entries,
		"estimated_freed_mb", fmt.Sprintf("%.1f", freedMB),
		"avail_mb", fmt.Sprintf("%.1f", availMB),
		"total_mb", fmt.Sprintf("%.1f", totalMB))

	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config during emergency load shedding", "error", err)
	}

	// Immediately reload rules fast to dump memory in CoreDNS
	if !testMode {
		cfgClone := config.Clone()
		go func() {
			reloadRulesFastNoLock(cfgClone)
			evaluatePeerOffload()
			if cfgClone.ClusterRole == "replica" && cfgClone.ClusterPrimaryURL != "" && cfgClone.ClusterPrimaryToken != "" {
				_ = performReplicaSync(cfgClone.ClusterPrimaryURL, cfgClone.ClusterPrimaryToken, cfgClone.ClusterInstanceType, cfgClone.ClusterFailoverMode)
			}
		}()
	}
}

// restoreShedListsInternal restores all suspended lists and persists the configuration.
// Trigger can be "manual_api" or "automatic_watchdog".
func restoreShedListsInternal(trigger string) int {
	configLock.Lock()
	countRestored := 0
	for i := range config.Lists {
		if config.Lists[i].EmergencySuspended {
			config.Lists[i].EmergencySuspended = false
			countRestored++
		}
	}
	config.EmergencySheddingActive = false
	config.EmergencyShedLists = nil

	if err := saveConfigNoLock(); err != nil {
		configLock.Unlock()
		slog.Error("Failed to save config during shed lists restoration", "trigger", trigger, "error", err)
		return 0
	}
	cfgClone := config.Clone()
	configLock.Unlock()

	slog.Info("Emergency shed lists restored", "trigger", trigger, "count", countRestored)
	if !testMode {
		go func() {
			evaluatePeerOffload()
			updateBlocklist(nil, true)
			if cfgClone.ClusterRole == "replica" && cfgClone.ClusterPrimaryURL != "" && cfgClone.ClusterPrimaryToken != "" {
				_ = performReplicaSync(cfgClone.ClusterPrimaryURL, cfgClone.ClusterPrimaryToken, cfgClone.ClusterInstanceType, cfgClone.ClusterFailoverMode)
			}
		}()
	}
	return countRestored
}

// handleRestoreShedLists manually or automatically restores all suspended lists
func handleRestoreShedLists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	countRestored := restoreShedListsInternal("manual_api")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"restored": countRestored,
		"message":  fmt.Sprintf("Restored %d lists from emergency suspension.", countRestored),
	})
}

// handleSetListPriority allows setting priority for a specific list
func handleSetListPriority(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL      string `json:"url"`
		Priority string `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	prio := strings.ToLower(strings.TrimSpace(req.Priority))
	if prio != "low" && prio != "normal" && prio != "high" {
		http.Error(w, "Priority must be 'low', 'normal', or 'high'", http.StatusBadRequest)
		return
	}

	targetURL := strings.ToLower(strings.TrimSpace(req.URL))
	configLock.Lock()
	found := false
	for i := range config.Lists {
		if strings.ToLower(strings.TrimSpace(config.Lists[i].URL)) == targetURL {
			config.Lists[i].Priority = prio
			found = true
			break
		}
	}
	if !found {
		for i := range config.Allowlists {
			if strings.ToLower(strings.TrimSpace(config.Allowlists[i].URL)) == targetURL {
				config.Allowlists[i].Priority = prio
				found = true
				break
			}
		}
	}

	if !found {
		configLock.Unlock()
		http.Error(w, "List not found", http.StatusNotFound)
		return
	}

	if err := saveConfigNoLock(); err != nil {
		configLock.Unlock()
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	configLock.Unlock()

	slog.Info("List priority updated", "url", req.URL, "priority", prio)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"priority": prio,
	})
}

// handleMemoryCapacity provides real-time memory capacity metrics for UI meter
func handleMemoryCapacity(w http.ResponseWriter, r *http.Request) {
	sysStats := make(map[string]interface{})
	fillRAMStats(sysStats)

	var totalKB, usedKB, availKB int64
	if ram, ok := sysStats["ram"]; ok {
		if ramMap, ok := ram.(map[string]interface{}); ok {
			if v, ok := ramMap["total"].(int64); ok {
				totalKB = v
			}
			if v, ok := ramMap["used"].(int64); ok {
				usedKB = v
			}
			if v, ok := ramMap["available"].(int64); ok {
				availKB = v
			}
		}
	}

	totalMB := float64(totalKB) / 1024.0
	usedMB := float64(usedKB) / 1024.0
	availMB := float64(availKB) / 1024.0

	blockAttributionLock.RLock()
	domainCount := len(blockAttribution)
	blockAttributionLock.RUnlock()

	coreDNSEstimatedMB := float64(domainCount) * 1.3 / 1024.0

	configLock.RLock()
	maxBudget := config.MaxRAMBudgetMB
	safetyBuffer := config.RAMSafetyBufferMB
	sheddingActive := config.EmergencySheddingActive
	shedLists := append([]string{}, config.EmergencyShedLists...)
	configLock.RUnlock()

	if safetyBuffer <= 0 {
		safetyBuffer = int(totalMB * 0.20)
		if safetyBuffer < 256 {
			safetyBuffer = 256
		}
	}

	budgetMB := float64(maxBudget)
	if budgetMB <= 0 {
		budgetMB = totalMB - float64(safetyBuffer)
		if budgetMB < 256.0 {
			budgetMB = 256.0
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_mb":                  totalMB,
		"used_mb":                   usedMB,
		"available_mb":              availMB,
		"budget_mb":                 budgetMB,
		"safety_buffer_mb":          float64(safetyBuffer),
		"coredns_estimated_mb":      coreDNSEstimatedMB,
		"domain_count":              domainCount,
		"emergency_shedding_active": sheddingActive,
		"emergency_shed_lists":      shedLists,
		"peer_offload_target":       getActivePeerOffloadAddr(),
	})
}

func getActivePeerOffloadAddr() string {
	peerOffloadMu.RLock()
	defer peerOffloadMu.RUnlock()
	return activePeerOffloadAddr
}

func setPrimaryPeerStatus(shedding bool, dnsTarget string) {
	peerOffloadMu.Lock()
	primarySheddingActive = shedding
	if dnsTarget != "" {
		primaryDNSTarget = dnsTarget
	}
	peerOffloadMu.Unlock()
}

// resolvePeerDNSTarget extracts a host:53 target from a URL or host[:port] string.
func resolvePeerDNSTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			return net.JoinHostPort(u.Hostname(), "53")
		}
		return ""
	}
	if _, _, err := net.SplitHostPort(raw); err == nil {
		return raw
	}
	return net.JoinHostPort(raw, "53")
}

// selectPeerOffloadCandidate returns a healthy, non-shedding peer DNS target when the local node
// is in emergency RAM shedding, preventing forwarding loops by never offloading to a shedding peer.
func selectPeerOffloadCandidate(cfg *Config, primShedding bool, primDNS string) string {
	if cfg == nil || !cfg.EmergencySheddingActive || !cfg.ClusterPeerOffloadEnabled {
		return ""
	}
	if cfg.ClusterRole == "replica" {
		if primShedding {
			return ""
		}
		if cfg.ClusterPeerDNSTarget != "" {
			return resolvePeerDNSTarget(cfg.ClusterPeerDNSTarget)
		}
		if primDNS != "" {
			return resolvePeerDNSTarget(primDNS)
		}
		return resolvePeerDNSTarget(cfg.ClusterPrimaryURL)
	}
	if cfg.ClusterRole == "primary" {
		if cfg.ClusterPeerDNSTarget != "" {
			return resolvePeerDNSTarget(cfg.ClusterPeerDNSTarget)
		}
		now := time.Now().UTC()
		for _, rep := range cfg.ClusterReplicas {
			if rep.EmergencyShedding {
				continue
			}
			if !rep.LastSeen.IsZero() && now.Sub(rep.LastSeen) > 15*time.Minute {
				continue
			}
			if rep.DNSTarget != "" {
				return resolvePeerDNSTarget(rep.DNSTarget)
			}
			if t := resolvePeerDNSTarget(rep.URL); t != "" {
				return t
			}
		}
	}
	return ""
}

// evaluatePeerOffload checks whether this node should offload DNS queries to a healthy cluster peer
// and updates CoreDNS Corefile if the active offload target changes.
func evaluatePeerOffload() {
	configLock.RLock()
	cfg := config.Clone()
	configLock.RUnlock()

	peerOffloadMu.RLock()
	primShed := primarySheddingActive
	primDNS := primaryDNSTarget
	peerOffloadMu.RUnlock()

	candidate := selectPeerOffloadCandidate(cfg, primShed, primDNS)
	resolvedTarget := ""

	peerOffloadMu.RLock()
	hadPrev := activePeerOffloadAddr != ""
	peerOffloadMu.RUnlock()

	if candidate != "" && !testMode {
		host, port, err := net.SplitHostPort(candidate)
		if err == nil {
			conn, dialErr := net.DialTimeout("tcp", candidate, 2*time.Second)
			if dialErr == nil {
				_ = conn.Close()
				ip := resolveHost(host)
				resolvedTarget = net.JoinHostPort(ip, port)
			} else if hadPrev {
				// Only log when transitioning from reachable to unreachable to prevent log spam every 15s
				slog.Warn("Cluster peer DNS target unreachable for offload; falling back to normal upstreams",
					"target", candidate, "error", dialErr)
			}
		}
	} else if candidate != "" && testMode {
		resolvedTarget = candidate
	}

	peerOffloadMu.Lock()
	prev := activePeerOffloadAddr
	activePeerOffloadAddr = resolvedTarget
	peerOffloadMu.Unlock()

	if prev != resolvedTarget {
		if resolvedTarget != "" {
			slog.Info("Cluster peer offload activated: Forwarding unblocked DNS queries to healthy peer while local node is in emergency RAM shedding",
				"peer", resolvedTarget, "role", cfg.ClusterRole)
		} else if prev != "" {
			slog.Info("Cluster peer offload deactivated; resuming normal upstreams", "previous_peer", prev)
		}
		if !testMode {
			updateCorefile()
		}
	}
}
