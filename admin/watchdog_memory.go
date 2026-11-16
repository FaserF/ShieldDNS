package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	memoryWatchdogMu      sync.Mutex
	consecutiveStableRAM int
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

	// Check if stable recovery is ongoing
	if sheddingActive {
		// If available RAM is now comfortably above safety margin (> 30% available and > 500 MB)
		if availMB > 500.0 && (availMB/totalMB) > 0.25 && usedMB/totalMB < 0.75 {
			consecutiveStableRAM++
			if consecutiveStableRAM >= 4 { // 60 seconds of stable RAM
				slog.Info("Memory pressure relieved stably; system ready for list recovery",
					"available_mb", fmt.Sprintf("%.1f", availMB),
					"used_mb", fmt.Sprintf("%.1f", usedMB),
					"total_mb", fmt.Sprintf("%.1f", totalMB))
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
	cfgClone := config.Clone()
	go func() {
		reloadRulesFastNoLock(cfgClone)
	}()
}

// handleRestoreShedLists manually or automatically restores all suspended lists
func handleRestoreShedLists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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
		slog.Error("Failed to save config during shed lists restoration", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	configLock.Unlock()

	slog.Info("All emergency shed lists restored by administrator", "count", countRestored)
	go updateBlocklist(nil, true)

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
	})
}
