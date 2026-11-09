package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// handleRoutingRules handles GET (list), POST (add/update), and DELETE for routing rules
func handleRoutingRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configLock.RLock()
		rules := append([]RoutingRule{}, config.RoutingRules...)
		wgGateway := config.WireGuardGateway
		ytEnabled := config.YouTubeAdblockEnabled
		vpnProvider := config.VPNProvider
		vpnCountry := config.VPNDefaultCountry
		vpnProxy := config.VPNProxyURL
		geoProxyIP := config.GeoProxyIP
		nextProfile := config.NextDNSProfileID
		nextYT := config.NextDNSYouTube
		nextReddit := config.NextDNSReddit
		nextLimit := GetNextDNSMonthlyLimit(&config)
		nextExceeded := isNextDNSQuotaExceeded(&config)
		nextQueries := GetNextDNSMonthlyQueries(&config)
		configLock.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"rules":                   rules,
			"wireguard_gateway":       wgGateway,
			"youtube_adblock_enabled": ytEnabled,
			"vpn_provider":            vpnProvider,
			"vpn_default_country":     vpnCountry,
			"vpn_proxy_url":           vpnProxy,
			"geo_proxy_ip":            geoProxyIP,
			"nextdns_profile_id":      nextProfile,
			"nextdns_youtube":         nextYT,
			"nextdns_reddit":          nextReddit,
			"nextdns_monthly_limit":   nextLimit,
			"nextdns_monthly_queries": nextQueries,
			"nextdns_quota_exceeded":  nextExceeded,
		})

	case http.MethodPost:
		configLock.RLock()
		if config.ClusterRole == "replica" {
			configLock.RUnlock()
			sendJSONError(w, "Routing rules are centrally managed by Cluster Master and cannot be modified on a replica node.", http.StatusForbidden)
			return
		}
		configLock.RUnlock()

		var req struct {
			ID               string `json:"id"`
			Name             string `json:"name"`
			Match            string `json:"match"`
			MatchType        string `json:"match_type"` // "domain" or "client_ip"
			Target           string `json:"target"`     // "default", "host", "wireguard", "vpn", "geo_proxy"
			HostTarget       string `json:"host_target"`
			WireGuardConfig  string `json:"wireguard_config"`
			WireGuardGateway string `json:"wireguard_gateway"`
			Country          string `json:"country"`
			ProxyURL         string `json:"proxy_url"`
			Enabled          *bool  `json:"enabled"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, "Invalid request payload: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Optional gateway update
		if req.WireGuardGateway != "" {
			configLock.Lock()
			config.WireGuardGateway = strings.TrimSpace(req.WireGuardGateway)
			_ = saveConfigNoLock()
			configLock.Unlock()
		}

		match := strings.TrimSpace(req.Match)
		if match == "" {
			sendJSONError(w, "Match criteria is required", http.StatusUnprocessableEntity)
			return
		}

		matchType := strings.ToLower(strings.TrimSpace(req.MatchType))
		if matchType == "" {
			if net.ParseIP(match) != nil || strings.Contains(match, "/") {
				matchType = "client_ip"
			} else {
				matchType = "domain"
			}
		}

		if matchType != "domain" && matchType != "client_ip" {
			sendJSONError(w, "match_type must be 'domain' or 'client_ip'", http.StatusBadRequest)
			return
		}

		if matchType == "domain" {
			match = NormalizeDomain(match)
			if match == "" || !isValidDomain(match) {
				sendJSONError(w, "Invalid domain match format", http.StatusBadRequest)
				return
			}
		} else {
			// Validate IP or CIDR
			if strings.Contains(match, "/") {
				if _, _, err := net.ParseCIDR(match); err != nil {
					sendJSONError(w, "Invalid CIDR IP match format", http.StatusBadRequest)
					return
				}
			} else {
				if net.ParseIP(match) == nil {
					sendJSONError(w, "Invalid client IP match format", http.StatusBadRequest)
					return
				}
			}
		}

		target := strings.ToLower(strings.TrimSpace(req.Target))
		if target == "" {
			target = "default"
		}
		if target != "default" && target != "host" && target != "wireguard" && target != "vpn" && target != "geo_proxy" && target != "nextdns" {
			sendJSONError(w, "target must be 'default', 'host', 'wireguard', 'vpn', 'geo_proxy', or 'nextdns'", http.StatusBadRequest)
			return
		}

		if target == "host" && strings.TrimSpace(req.HostTarget) == "" {
			sendJSONError(w, "host_target is required when target is 'host'", http.StatusBadRequest)
			return
		}

		if target == "nextdns" && strings.TrimSpace(req.HostTarget) == "" {
			configLock.RLock()
			globalProfile := strings.TrimSpace(config.NextDNSProfileID)
			configLock.RUnlock()
			if globalProfile == "" {
				sendJSONError(w, "NextDNS Profile ID is required (configure globally in Settings or specify in host_target)", http.StatusBadRequest)
				return
			}
		}

		enabled := true
		if req.Enabled != nil {
			enabled = *req.Enabled
		}

		ruleID := strings.TrimSpace(req.ID)
		if ruleID == "" {
			ruleID = uuid.New().String()
		}

		rule := RoutingRule{
			ID:              ruleID,
			Name:            strings.TrimSpace(req.Name),
			Match:           match,
			MatchType:       matchType,
			Target:          target,
			HostTarget:      strings.TrimSpace(req.HostTarget),
			WireGuardConfig: strings.TrimSpace(req.WireGuardConfig),
			Country:         strings.ToUpper(strings.TrimSpace(req.Country)),
			ProxyURL:        strings.TrimSpace(req.ProxyURL),
			Enabled:         enabled,
			CreatedAt:       time.Now().UTC(),
		}

		configLock.Lock()
		updated := false
		for i, r := range config.RoutingRules {
			if r.ID == ruleID {
				rule.CreatedAt = r.CreatedAt
				config.RoutingRules[i] = rule
				updated = true
				break
			}
		}
		if !updated {
			config.RoutingRules = append(config.RoutingRules, rule)
		}

		if err := saveConfigNoLock(); err != nil {
			configLock.Unlock()
			slog.Error("Failed to save routing rule", "error", err)
			sendJSONError(w, "Failed to save configuration", http.StatusInternalServerError)
			return
		}
		configLock.Unlock()

		updateCorefile()
		restartCoreDNS()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"rule":    rule,
			"message": fmt.Sprintf("Routing rule saved for %s", match),
		})

	case http.MethodDelete:
		configLock.RLock()
		if config.ClusterRole == "replica" {
			configLock.RUnlock()
			sendJSONError(w, "Routing rules are centrally managed by Cluster Master and cannot be deleted on a replica node.", http.StatusForbidden)
			return
		}
		configLock.RUnlock()

		id := r.URL.Query().Get("id")
		match := r.URL.Query().Get("match")
		if id == "" && match == "" {
			sendJSONError(w, "Query parameter 'id' or 'match' is required", http.StatusBadRequest)
			return
		}

		configLock.Lock()
		var filtered []RoutingRule
		found := false
		for _, r := range config.RoutingRules {
			if (id != "" && r.ID == id) || (match != "" && strings.EqualFold(r.Match, match)) {
				found = true
				continue
			}
			filtered = append(filtered, r)
		}

		if !found {
			configLock.Unlock()
			sendJSONError(w, "Routing rule not found", http.StatusNotFound)
			return
		}

		config.RoutingRules = filtered
		if err := saveConfigNoLock(); err != nil {
			configLock.Unlock()
			sendJSONError(w, "Failed to save configuration", http.StatusInternalServerError)
			return
		}
		configLock.Unlock()

		updateCorefile()
		restartCoreDNS()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"success": true})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

var (
	cachedNextDNSQueries   int64
	cachedNextDNSMonth     time.Month
	cachedNextDNSYear      int
	lastNextDNSQueryCheck  time.Time
	cachedNextDNSExceeded  atomic.Bool
	nextDNSCacheMu         sync.Mutex
)

// GetNextDNSMonthlyLimit returns the configured monthly limit, defaulting to 300,000 queries.
func GetNextDNSMonthlyLimit(cfg *Config) int64 {
	if cfg == nil || cfg.NextDNSMonthlyLimit <= 0 {
		return 300000
	}
	return int64(cfg.NextDNSMonthlyLimit)
}

// getNextDNSDomainPatterns returns all domain patterns currently routed via NextDNS.
func getNextDNSDomainPatterns(cfg *Config) []string {
	if cfg == nil {
		return nil
	}
	seen := make(map[string]bool)
	var patterns []string
	addDom := func(d string) {
		d = strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
		d = strings.TrimPrefix(d, "*.")
		if d != "" && isValidDomain(d) && !seen[d] {
			seen[d] = true
			patterns = append(patterns, d)
		}
	}
	if cfg.NextDNSYouTube {
		for _, d := range defaultYouTubeGeoDomains {
			addDom(d)
		}
	}
	if cfg.NextDNSReddit {
		for _, d := range defaultRedditGeoDomains {
			addDom(d)
		}
		addDom("reddit.com")
		addDom("redd.it")
	}
	for _, r := range cfg.RoutingRules {
		if r.Enabled && r.Target == "nextdns" && r.MatchType != "client_ip" {
			addDom(r.Match)
		}
	}
	return patterns
}

// IsNextDNSActiveDomain checks if a given domain matches an active NextDNS routing target.
func IsNextDNSActiveDomain(cfg *Config, domain string) bool {
	if cfg == nil || strings.TrimSpace(cfg.NextDNSProfileID) == "" {
		return false
	}
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if domain == "" {
		return false
	}
	patterns := getNextDNSDomainPatterns(cfg)
	for _, p := range patterns {
		if domain == p || strings.HasSuffix(domain, "."+p) {
			return true
		}
	}
	return false
}

// queryNextDNSMonthlyCount queries the database for total queries matching NextDNS domains in the current calendar month.
func queryNextDNSMonthlyCount(cfg *Config) int64 {
	if cfg == nil {
		return 0
	}
	patterns := getNextDNSDomainPatterns(cfg)
	if len(patterns) == 0 {
		return 0
	}
	now := time.Now().UTC()
	startOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02 15:04:05")

	var conds []string
	var args []interface{}
	args = append(args, startOfMonth)

	for _, p := range patterns {
		conds = append(conds, "(domain = ? OR domain LIKE ?)")
		args = append(args, p, "%."+p)
	}

	q := fmt.Sprintf("SELECT COUNT(id) FROM queries WHERE timestamp >= ? AND (%s)", strings.Join(conds, " OR "))
	var count int64
	row := dbQueryRow(q, args...)
	if row != nil {
		if err := row.Scan(&count); err == nil {
			return count
		}
	}
	return 0
}

// GetNextDNSMonthlyQueries returns the total count of NextDNS-routed queries for the current month.
func GetNextDNSMonthlyQueries(cfg *Config) int64 {
	nextDNSCacheMu.Lock()
	defer nextDNSCacheMu.Unlock()

	now := time.Now().UTC()
	curMonth := now.Month()
	curYear := now.Year()

	// If calendar month rolled over or cache is expired (>2m) or uninitialized, refresh from DB
	if curMonth != cachedNextDNSMonth || curYear != cachedNextDNSYear || time.Since(lastNextDNSQueryCheck) > 2*time.Minute {
		count := queryNextDNSMonthlyCount(cfg)
		cachedNextDNSQueries = count
		cachedNextDNSMonth = curMonth
		cachedNextDNSYear = curYear
		lastNextDNSQueryCheck = now
		limit := GetNextDNSMonthlyLimit(cfg)
		cachedNextDNSExceeded.Store(count >= limit)
	}

	return cachedNextDNSQueries
}

// isNextDNSQuotaExceeded checks whether NextDNS has exceeded its configured monthly limit.
func isNextDNSQuotaExceeded(cfg *Config) bool {
	if cfg == nil || strings.TrimSpace(cfg.NextDNSProfileID) == "" {
		return false
	}
	if !cfg.NextDNSYouTube && !cfg.NextDNSReddit {
		hasRule := false
		for _, r := range cfg.RoutingRules {
			if r.Enabled && r.Target == "nextdns" {
				hasRule = true
				break
			}
		}
		if !hasRule {
			return false
		}
	}
	queries := GetNextDNSMonthlyQueries(cfg)
	limit := GetNextDNSMonthlyLimit(cfg)
	exceeded := queries >= limit
	cachedNextDNSExceeded.Store(exceeded)
	return exceeded
}

// TrackNextDNSQuery atomically increments the NextDNS query counter and initiates fallback if quota is hit.
func TrackNextDNSQuery(domain string) {
	configLock.RLock()
	cfg := config
	configLock.RUnlock()

	if !IsNextDNSActiveDomain(&cfg, domain) {
		return
	}

	newCount := atomic.AddInt64(&cachedNextDNSQueries, 1)
	limit := GetNextDNSMonthlyLimit(&cfg)
	if newCount >= limit && !cachedNextDNSExceeded.Load() {
		cachedNextDNSExceeded.Store(true)
		slog.Warn("NextDNS monthly query limit reached. Automatically switching fallback to standard ShieldDNS / Geo-Proxy routing until month reset.", "queries", newCount, "limit", limit)
		updateCorefile()
	}
}

// CheckNextDNSQuotaTransition checks for quota state changes (e.g. monthly reset or limit update) and triggers CoreDNS reload if needed.
func CheckNextDNSQuotaTransition() {
	configLock.RLock()
	cfg := config
	configLock.RUnlock()

	if strings.TrimSpace(cfg.NextDNSProfileID) == "" {
		return
	}

	prevExceeded := cachedNextDNSExceeded.Load()
	nowExceeded := isNextDNSQuotaExceeded(&cfg)

	if prevExceeded != nowExceeded {
		if nowExceeded {
			slog.Warn("NextDNS monthly quota exceeded; fallback to standard routing activated", "limit", GetNextDNSMonthlyLimit(&cfg))
		} else {
			slog.Info("NextDNS monthly quota reset or limit increased; resuming NextDNS routing", "queries", GetNextDNSMonthlyQueries(&cfg), "limit", GetNextDNSMonthlyLimit(&cfg))
		}
		updateCorefile()
	}
}

// handleNextDNSStatus returns real-time quota, routing status, and month reset details.
func handleNextDNSStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.RLock()
	cfg := config
	configLock.RUnlock()

	profileID := strings.TrimSpace(cfg.NextDNSProfileID)
	enabled := profileID != "" && (cfg.NextDNSYouTube || cfg.NextDNSReddit)
	limit := GetNextDNSMonthlyLimit(&cfg)
	queries := GetNextDNSMonthlyQueries(&cfg)
	exceeded := isNextDNSQuotaExceeded(&cfg)

	now := time.Now().UTC()
	nextMonth := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)

	percentUsed := 0.0
	if limit > 0 {
		percentUsed = float64(queries) / float64(limit) * 100.0
	}

	currentRouting := "nextdns"
	if !enabled {
		currentRouting = "disabled"
	} else if exceeded {
		currentRouting = "fallback_standard"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":          enabled,
		"profile_id":       profileID,
		"monthly_limit":    limit,
		"monthly_queries":  queries,
		"quota_exceeded":   exceeded,
		"percentage_used":  percentUsed,
		"reset_date":       nextMonth.Format(time.RFC3339),
		"current_routing":  currentRouting,
		"youtube_enabled":  cfg.NextDNSYouTube,
		"reddit_enabled":   cfg.NextDNSReddit,
	})
}
