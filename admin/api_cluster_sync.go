package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

func listsEqual(a, b []List) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.TrimSpace(a[i].URL) != strings.TrimSpace(b[i].URL) || a[i].Enabled != b[i].Enabled {
			return false
		}
	}
	return true
}

// performReplicaSync performs an HTTP GET to retrieve latest exported configuration from Primary
func performReplicaSync(primaryURL, apiToken, instType string, failover bool) error {
	clusterSyncMu.Lock()
	defer clusterSyncMu.Unlock()

	if !isValidRedirectUrl(primaryURL) {
		return fmt.Errorf("invalid or disallowed primary URL: %s", primaryURL)
	}

	parsedURL, err := url.Parse(primaryURL)
	if err != nil {
		return fmt.Errorf("failed to parse primary URL: %w", err)
	}
	if err := isSafeClusterTarget(parsedURL); err != nil {
		return fmt.Errorf("invalid host in primary URL: %w", err)
	}

	endpoint := (&url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   "/api/cluster/replicas/sync",
	}).String()

	if !isValidRedirectUrl(endpoint) {
		return fmt.Errorf("invalid cluster sync endpoint: %s", endpoint)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}

	req.Header.Set("X-API-Key", apiToken)
	req.Header.Set("X-Shield-Request", "true")

	configLock.RLock()
	verifyTLS := config.VerifyUpstreamTLS
	localNodeName := config.ClusterNodeName
	localShedding := config.EmergencySheddingActive
	configLock.RUnlock()

	if strings.TrimSpace(localNodeName) != "" {
		req.Header.Set("X-Cluster-Node-Name", strings.TrimSpace(localNodeName))
	}
	if localShedding {
		req.Header.Set("X-Cluster-Shedding", "true")
	} else {
		req.Header.Set("X-Cluster-Shedding", "false")
	}

	client := newClusterHTTPClient(7*time.Second, verifyTLS)

	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "context deadline exceeded") {
			slog.Debug("Network error contacting primary (cluster sync)", "error", err)
		} else {
			slog.Error("Network error contacting primary", "error", err)
		}
		return fmt.Errorf("network error contacting primary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return fmt.Errorf("primary returned HTTP %d: %s", resp.StatusCode, string(b))
	}

	var exp ClusterConfigExport
	if err := json.NewDecoder(resp.Body).Decode(&exp); err != nil {
		return fmt.Errorf("failed to decode primary config: %w", err)
	}

	if err := applyClusterExport(exp, primaryURL, apiToken, instType, failover); err != nil {
		return err
	}

	setPrimaryPeerStatus(exp.PrimaryEmergencyShedding, exp.PrimaryDNSTarget)
	go evaluatePeerOffload()

	// Trigger log synchronization exclusively during regular cluster sync
	go func() {
		if err := SyncClusterLogs(); err != nil {
			slog.Warn("Cluster log sync failed", "error", err)
		}
	}()

	return nil
}

// applyClusterExport updates local configuration with exported values
func applyClusterExport(exp ClusterConfigExport, primaryURL, apiToken, instType string, failover bool) error {
	configLock.Lock()

	mergedMappings := make(map[string]string, len(exp.CustomMappings)+len(config.ClusterLocalMappings))
	for k, v := range exp.CustomMappings {
		mergedMappings[k] = v
	}
	for _, excluded := range config.ClusterExcludedMappings {
		exNorm := strings.ToLower(strings.TrimSpace(excluded))
		delete(mergedMappings, exNorm)
		for k := range mergedMappings {
			if strings.ToLower(strings.TrimSpace(k)) == exNorm {
				delete(mergedMappings, k)
			}
		}
	}
	for k, v := range config.ClusterLocalMappings {
		mergedMappings[k] = v
	}

	listsChanged := !listsEqual(config.Lists, exp.Lists) || !listsEqual(config.Allowlists, exp.Allowlists)
	customRulesChanged := config.FilteringEnabled != exp.FilteringEnabled ||
		!slices.Equal(config.CustomBlocked, exp.CustomBlocked) ||
		!slices.Equal(config.CustomAllowed, exp.CustomAllowed) ||
		!slices.Equal(config.BlockedServices, exp.BlockedServices) ||
		config.SafeSearchEnabled != exp.SafeSearchEnabled ||
		config.YouTubeRestriction != exp.YouTubeRestriction ||
		!maps.Equal(config.CustomMappings, mergedMappings)
	maliciousNewlyEnabled := exp.MaliciousIPBlockingEnabled && !config.MaliciousIPBlockingEnabled

	config.ClusterRole = "replica"
	config.ClusterPrimaryURL = primaryURL
	config.ClusterPrimaryToken = apiToken
	config.ClusterInstanceType = instType
	config.ClusterFailoverMode = failover
	config.ClusterLastSync = time.Now().UTC()
	if exp.ClusterLogSharingMode != "" {
		config.ClusterLogSharingMode = exp.ClusterLogSharingMode
	}
	config.ClusterWorkerDomain = exp.ClusterWorkerDomain

	// Password fallback: sync hash if provided
	if exp.AdminPasswordHashed != "" {
		config.AdminPasswordHashed = exp.AdminPasswordHashed
		config.SetupDone = true
	}

	// Overwrite filtering and rule settings from Primary (Always Primary Wins)
	config.FilteringEnabled = exp.FilteringEnabled

	// Preserve local emergency shedding state on replica to protect local node RAM
	suspendedMap := make(map[string]bool)
	hasSuspended := false
	for _, l := range config.Lists {
		if l.EmergencySuspended {
			suspendedMap[strings.ToLower(strings.TrimSpace(l.URL))] = true
			hasSuspended = true
		}
	}
	config.Lists = exp.Lists
	for i := range config.Lists {
		if suspendedMap[strings.ToLower(strings.TrimSpace(config.Lists[i].URL))] {
			config.Lists[i].EmergencySuspended = true
		}
	}
	config.EmergencySheddingActive = hasSuspended
	if !hasSuspended {
		config.EmergencyShedLists = nil
	}
	config.Allowlists = exp.Allowlists
	normalizeListPriorities(&config)
	config.CustomBlocked = exp.CustomBlocked
	config.CustomAllowed = exp.CustomAllowed
	config.CustomMappings = mergedMappings
	config.AutoblockWhitelist = exp.AutoblockWhitelist
	config.BlockedCountries = exp.BlockedCountries
	config.SmartSelectionPolicy = exp.SmartSelectionPolicy
	config.ServeStale = exp.ServeStale
	config.DNSSECEnabled = exp.DNSSECEnabled
	config.AbuseDetectionEnabled = exp.AbuseDetectionEnabled
	config.AbuseDGAThreshold = exp.AbuseDGAThreshold
	config.AbuseDGAMinLen = exp.AbuseDGAMinLen
	config.MaliciousIPBlockingEnabled = exp.MaliciousIPBlockingEnabled
	config.MaliciousIPInterval = exp.MaliciousIPInterval
	config.VerifyUpstreamTLS = exp.VerifyUpstreamTLS
	config.PreferEncrypted = exp.PreferEncrypted
	config.DoH3Enabled = exp.DoH3Enabled
	config.RateLimitRate = exp.RateLimitRate
	config.RateLimitBurst = exp.RateLimitBurst
	config.ECHOptimizationEnabled = exp.ECHOptimizationEnabled
	config.DNSRebindingProtection = exp.DNSRebindingProtection
	config.StripECS = exp.StripECS
	if exp.RoutingRules != nil {
		config.RoutingRules = exp.RoutingRules
	}
	if exp.WireGuardGateway != "" {
		config.WireGuardGateway = exp.WireGuardGateway
	}
	config.YouTubeAdblockEnabled = exp.YouTubeAdblockEnabled
	config.TwitchAdblockEnabled = exp.TwitchAdblockEnabled
	config.RedditAdblockEnabled = exp.RedditAdblockEnabled
	config.SpotifyAdblockEnabled = exp.SpotifyAdblockEnabled
	config.SocialAdblockEnabled = exp.SocialAdblockEnabled
	config.SmartTVAdblockEnabled = exp.SmartTVAdblockEnabled
	if exp.BlockedServices != nil {
		config.BlockedServices = exp.BlockedServices
	}
	config.SafeSearchEnabled = exp.SafeSearchEnabled
	if exp.YouTubeRestriction != "" {
		config.YouTubeRestriction = exp.YouTubeRestriction
	}
	if exp.VPNCountryProxies != nil {
		config.VPNCountryProxies = exp.VPNCountryProxies
	}
	if exp.VPNProvider != "" {
		config.VPNProvider = exp.VPNProvider
	}
	if exp.VPNMode != "" {
		config.VPNMode = exp.VPNMode
	}
	if exp.VPNDefaultCountry != "" {
		config.VPNDefaultCountry = exp.VPNDefaultCountry
	}
	if exp.VPNProxyURL != "" {
		config.VPNProxyURL = exp.VPNProxyURL
	}
	if exp.VPNInterface != "" {
		config.VPNInterface = exp.VPNInterface
	}
	if exp.VPNConfigContent != "" {
		config.VPNConfigContent = exp.VPNConfigContent
	}
	if exp.VPNUsername != "" {
		config.VPNUsername = exp.VPNUsername
	}
	if exp.VPNPassword != "" {
		config.VPNPassword = exp.VPNPassword
	}
	if exp.VPNDNSUpstream != "" {
		config.VPNDNSUpstream = exp.VPNDNSUpstream
	}
	if exp.GeoProxyIP != "" {
		config.GeoProxyIP = exp.GeoProxyIP
	}
	if exp.NextDNSProfileID != "" {
		config.NextDNSProfileID = exp.NextDNSProfileID
	}
	if exp.NextDNSAPIKey != "" {
		config.NextDNSAPIKey = exp.NextDNSAPIKey
	}
	if exp.NextDNSMonthlyLimit > 0 {
		config.NextDNSMonthlyLimit = exp.NextDNSMonthlyLimit
	}
	config.NextDNSYouTube = exp.NextDNSYouTube
	config.NextDNSReddit = exp.NextDNSReddit
	if exp.SNIProxyPort > 0 {
		config.SNIProxyPort = exp.SNIProxyPort
	}
	if exp.BlockedClients != nil {
		config.BlockedClients = exp.BlockedClients
	}
	if exp.BlockedClientsInfo != nil {
		config.BlockedClientsInfo = exp.BlockedClientsInfo
	}
	if exp.ClientRules != nil {
		config.ClientRules = exp.ClientRules
	}
	if exp.ClientAliases != nil {
		config.ClientAliases = exp.ClientAliases
	}
	config.MCPServerEnabled = exp.MCPServerEnabled
	if exp.APIKeys != nil {
		config.APIKeys = exp.APIKeys
	}
	if exp.Groups != nil {
		config.Groups = exp.Groups
	}
	if exp.Schedules != nil {
		config.Schedules = exp.Schedules
	}
	if exp.QuickRules != nil {
		config.QuickRules = exp.QuickRules
	}
	if exp.LocalRecords != nil {
		config.LocalRecords = exp.LocalRecords
	}
	if exp.LocalPTRUpstreams != nil {
		config.LocalPTRUpstreams = exp.LocalPTRUpstreams
	}
	config.AutoPTR = exp.AutoPTR
	config.CNAMECloakingEnabled = exp.CNAMECloakingEnabled
	config.FilterAAAA = exp.FilterAAAA
	if exp.FilterAAAADomains != nil {
		config.FilterAAAADomains = exp.FilterAAAADomains
	}
	if exp.TrustedHostDomains != nil {
		config.TrustedHostDomains = exp.TrustedHostDomains
	}
	if exp.AdminDomain != "" {
		config.AdminDomain = exp.AdminDomain
		setAtomicAdminDomain(config.AdminDomain)
	}
	if exp.AIRules != nil {
		if config.AIRules == nil {
			config.AIRules = make(map[string]AIRuleMetadata, len(exp.AIRules))
		}
		for k, v := range exp.AIRules {
			config.AIRules[k] = v
		}
	}
	config.AIEnabled = exp.AIEnabled
	if exp.AIBaseURL != "" {
		config.AIBaseURL = rewriteLoopbackAIURL(exp.AIBaseURL, primaryURL)
	}
	if exp.AIModel != "" {
		config.AIModel = exp.AIModel
	}
	if exp.AIAPIKey != "" {
		config.AIAPIKey = exp.AIAPIKey
	}
	if exp.AITimeoutSeconds > 0 {
		config.AITimeoutSeconds = exp.AITimeoutSeconds
	}
	config.AIAutoBlockThreats = exp.AIAutoBlockThreats
	config.AIAutoBlockAds = exp.AIAutoBlockAds
	config.AIAutoFlagFalsePositives = exp.AIAutoFlagFalsePositives
	if exp.AIConfidenceThreshold > 0 {
		config.AIConfidenceThreshold = exp.AIConfidenceThreshold
	}
	if exp.AIAuditIntervalMinutes > 0 {
		config.AIAuditIntervalMinutes = exp.AIAuditIntervalMinutes
	}

	// Configure DNS Upstream: if failover mode is set, use Primary as first upstream!
	if failover && primaryURL != "" {
		u, err := url.Parse(primaryURL)
		if err == nil {
			primaryHost := u.Hostname()
			if net.ParseIP(primaryHost) != nil {
				// Put Primary as topmost upstream
				config.Upstreams = append([]string{primaryHost}, exp.Upstreams...)
			} else {
				config.Upstreams = exp.Upstreams
			}
		} else {
			config.Upstreams = exp.Upstreams
		}
	} else {
		config.Upstreams = exp.Upstreams
	}
	config.UpstreamDoT = exp.UpstreamDoT

	if err := saveConfigNoLock(); err != nil {
		configLock.Unlock()
		return err
	}
	cfgClone := config.Clone()
	configLock.Unlock()
	ReloadPolicySnapshot()

	blockAttributionLock.RLock()
	attributionEmpty := len(blockAttribution) == 0
	blockAttributionLock.RUnlock()

	if !testMode {
		go func(countries []string, maliciousEnabled, maliciousTrigger bool) {
			for _, c := range countries {
				cc := strings.ToLower(strings.TrimSpace(c))
				if len(cc) != 2 || cc[0] < 'a' || cc[0] > 'z' || cc[1] < 'a' || cc[1] > 'z' {
					continue
				}
				zonePath := filepath.Join(geoCacheDir, cc+".zone")
				if _, err := os.Stat(zonePath); os.IsNotExist(err) {
					_ = syncCountryIPs(cc)
				}
			}
			maliciousMu.RLock()
			maliciousEmpty := len(maliciousIPList) == 0
			maliciousMu.RUnlock()
			if maliciousEnabled && (maliciousTrigger || maliciousEmpty) {
				_ = syncMaliciousIPs(false)
			}
			corefileChanged := updateCorefile()
			dnsCmdLock.Lock()
			coreDNSRunning := dnsCmd != nil && dnsCmd.Process != nil
			dnsCmdLock.Unlock()
			if corefileChanged || !coreDNSRunning {
				restartCoreDNS()
			}
		}(exp.BlockedCountries, exp.MaliciousIPBlockingEnabled, maliciousNewlyEnabled)

		if listsChanged || attributionEmpty {
			go updateBlocklist(nil, true)
		} else if customRulesChanged {
			go reloadRulesFastNoLock(cfgClone)
		}
	}

	return nil
}

// handleClusterIngestLogs receives a batch of query logs from another cluster node
func handleClusterIngestLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rawToken := r.Header.Get("X-API-Key")
	if rawToken == "" {
		authHdr := r.Header.Get("Authorization")
		if strings.HasPrefix(authHdr, "Bearer ") {
			rawToken = strings.TrimPrefix(authHdr, "Bearer ")
		}
	}
	if rawToken == "" {
		http.Error(w, "Missing authentication token", http.StatusUnauthorized)
		return
	}
	tokenHashed := hashToken(rawToken)

	configLock.RLock()
	var authorized = false
	for _, rep := range config.ClusterReplicas {
		if rep.TokenHash == tokenHashed {
			authorized = true
			break
		}
	}
	if !authorized {
		for _, k := range config.APIKeys {
			if k.TokenHash == tokenHashed && hasPermission(&k, "cluster:sync") {
				authorized = true
				break
			}
		}
	}
	needPromote := authorized && config.ClusterRole != "primary"
	configLock.RUnlock()

	if !authorized {
		http.Error(w, "Forbidden: Invalid token or missing 'cluster:sync' permission", http.StatusForbidden)
		return
	}

	if needPromote {
		configLock.Lock()
		if config.ClusterRole != "primary" {
			config.ClusterRole = "primary"
			slog.Info("Auto-promoted node to primary on replica log ingest")
			_ = saveConfigNoLock()
		}
		configLock.Unlock()
	}

	var payload struct {
		NodeName string  `json:"node_name"`
		Queries  []Query `json:"queries"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(payload.Queries) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "count": 0})
		return
	}

	for i := range payload.Queries {
		if payload.Queries[i].NodeName == "" {
			payload.Queries[i].NodeName = payload.NodeName
		}
	}

	flushLogs(payload.Queries)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"count":   len(payload.Queries),
	})
}

var (
	lastSyncQueryID          int64
	lastSyncQueryInitialized bool
	lastSyncQueryMu          sync.Mutex
)

// rewriteLoopbackAIURL rewrites loopback AI base URLs (127.0.0.1/localhost/::1) exported by Primary
// to the Primary's reachable hostname so replicas do not hit their own loopback interface.
func rewriteLoopbackAIURL(rawAIURL, primaryURL string) string {
	aiURL := strings.TrimSpace(rawAIURL)
	if aiURL == "" || strings.TrimSpace(primaryURL) == "" {
		return aiURL
	}
	parsedAI, err := url.Parse(aiURL)
	if err != nil {
		return aiURL
	}
	aiHost := parsedAI.Hostname()
	if aiHost != "127.0.0.1" && !strings.EqualFold(aiHost, "localhost") && aiHost != "::1" {
		return aiURL
	}
	parsedPrimary, err := url.Parse(strings.TrimSpace(primaryURL))
	if err != nil {
		return aiURL
	}
	pHost := parsedPrimary.Hostname()
	if pHost == "" || pHost == "127.0.0.1" || strings.EqualFold(pHost, "localhost") || pHost == "::1" {
		return aiURL
	}
	if port := parsedAI.Port(); port != "" {
		parsedAI.Host = net.JoinHostPort(pHost, port)
	} else {
		parsedAI.Host = pHost
	}
	return parsedAI.String()
}

func readLocalClusterSyncBatch(minID int64, nodeName string, limit int) ([]Query, int64, error) {
	rows, err := dbQuery(`
		SELECT id, timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms, country_code, node_name
		FROM queries
		WHERE id > ? AND (node_name IS NULL OR node_name = '' OR node_name = ?)
		ORDER BY id ASC LIMIT ?
	`, minID, nodeName, limit)
	if err != nil {
		return nil, minID, fmt.Errorf("failed to read local queries for cluster sync: %w", err)
	}
	defer rows.Close()

	var queriesToPush []Query
	maxSeenID := minID
	for rows.Next() {
		var q Query
		var ts string
		var rawNode *string
		if err := rows.Scan(&q.ID, &ts, &q.Domain, &q.Type, &q.Status, &q.ClientIP, &q.IsCacheHit, &q.DurationMs, &q.CountryCode, &rawNode); err != nil {
			continue
		}
		q.Time, _ = ParseFlexibleTime(ts)
		if rawNode != nil && *rawNode != "" {
			q.NodeName = *rawNode
		} else {
			q.NodeName = nodeName
		}
		if q.ID > maxSeenID {
			maxSeenID = q.ID
		}
		queriesToPush = append(queriesToPush, q)
	}
	if err := rows.Err(); err != nil {
		return queriesToPush, maxSeenID, err
	}
	return queriesToPush, maxSeenID, nil
}

// SyncClusterLogs forwards recent query logs to the primary (or replica) if configured
func SyncClusterLogs() error {
	configLock.RLock()
	role := config.ClusterRole
	logMode := config.ClusterLogSharingMode
	primaryURL := config.ClusterPrimaryURL
	apiToken := config.ClusterPrimaryToken
	nodeName := config.ClusterNodeName
	verifyTLS := config.VerifyUpstreamTLS
	configLock.RUnlock()

	if logMode == "" || logMode == "local_only" {
		return nil
	}

	if role != "replica" || primaryURL == "" || apiToken == "" {
		return nil
	}

	if nodeName == "" {
		nodeName = "ShieldDNS Replica"
	}

	if !isValidRedirectUrl(primaryURL) {
		return fmt.Errorf("invalid or disallowed primary URL: %s", primaryURL)
	}

	parsedURL, err := url.Parse(primaryURL)
	if err != nil {
		return fmt.Errorf("invalid primary URL: %s: %w", primaryURL, err)
	}
	if err := isSafeClusterTarget(parsedURL); err != nil {
		return fmt.Errorf("invalid host in primary URL: %w", err)
	}

	endpoint := (&url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   "/api/cluster/logs/ingest",
	}).String()

	if !isValidRedirectUrl(endpoint) {
		return fmt.Errorf("invalid cluster log ingest endpoint: %s", endpoint)
	}

	lastSyncQueryMu.Lock()
	if !lastSyncQueryInitialized {
		if lastSyncQueryID == 0 {
			var initID sql.NullInt64
			cutoff := time.Now().UTC().Add(-10 * time.Minute)
			if row := dbQueryRow("SELECT COALESCE(MAX(id), 0) FROM queries WHERE timestamp < ?", cutoff); row != nil {
				_ = row.Scan(&initID)
			}
			if initID.Valid && initID.Int64 > lastSyncQueryID {
				lastSyncQueryID = initID.Int64
			}
		}
		lastSyncQueryInitialized = true
	}
	minID := lastSyncQueryID
	lastSyncQueryMu.Unlock()

	const batchSize = 500
	const maxBatches = 5
	client := newClusterHTTPClient(10*time.Second, verifyTLS)

	for batchIdx := 0; batchIdx < maxBatches; batchIdx++ {
		queriesToPush, maxSeenID, err := readLocalClusterSyncBatch(minID, nodeName, batchSize)
		if err != nil {
			return err
		}
		if len(queriesToPush) == 0 {
			break
		}

		payloadData, err := json.Marshal(map[string]interface{}{
			"node_name": nodeName,
			"queries":   queriesToPush,
		})
		if err != nil {
			return fmt.Errorf("failed to encode queries payload: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payloadData))
		if err != nil {
			cancel()
			return err
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("X-API-Key", apiToken)
		httpReq.Header.Set("X-Shield-Request", "true")

		resp, err := client.Do(httpReq)
		if err != nil {
			cancel()
			return fmt.Errorf("error pushing query logs to primary: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body.Close()
			cancel()
			return fmt.Errorf("primary returned HTTP %d on log ingest: %s", resp.StatusCode, string(b))
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		cancel()

		lastSyncQueryMu.Lock()
		if maxSeenID > lastSyncQueryID {
			lastSyncQueryID = maxSeenID
		}
		minID = lastSyncQueryID
		lastSyncQueryMu.Unlock()

		if len(queriesToPush) < batchSize {
			break
		}
	}

	return nil
}

