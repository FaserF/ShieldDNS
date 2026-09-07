package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// performReplicaSync performs an HTTP GET to retrieve latest exported configuration from Primary
func performReplicaSync(primaryURL, apiToken, instType string, failover bool) error {
	clusterSyncMu.Lock()
	defer clusterSyncMu.Unlock()

	parsedURL, err := url.Parse(primaryURL)
	host := parsedURL.Hostname()
	if !isValidDomain(host) {
		return fmt.Errorf("invalid host in primary URL: %s", host)
	}

	endpoint := (&url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   "/api/cluster/replicas/sync",
	}).String()
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
	configLock.RUnlock()

	client := &http.Client{
		Timeout: 7 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("network error contacting primary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("primary returned HTTP %d: %s", resp.StatusCode, string(b))
	}

	var exp ClusterConfigExport
	if err := json.NewDecoder(resp.Body).Decode(&exp); err != nil {
		return fmt.Errorf("failed to decode primary config: %w", err)
	}

	if err := applyClusterExport(exp, primaryURL, apiToken, instType, failover); err != nil {
		return err
	}

	// Trigger log synchronization exclusively during regular cluster sync
	go func() {
		_ = SyncClusterLogs()
	}()

	return nil
}

// applyClusterExport updates local configuration with exported values
func applyClusterExport(exp ClusterConfigExport, primaryURL, apiToken, instType string, failover bool) error {
	configLock.Lock()
	defer configLock.Unlock()

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
	config.Lists = exp.Lists
	config.Allowlists = exp.Allowlists
	config.CustomBlocked = exp.CustomBlocked
	config.CustomAllowed = exp.CustomAllowed
	config.CustomMappings = exp.CustomMappings
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
		return err
	}

	go updateCorefile()
	go updateBlocklist(nil, true)

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
	configLock.RUnlock()

	if !authorized {
		http.Error(w, "Forbidden: Invalid token or missing 'cluster:sync' permission", http.StatusForbidden)
		return
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

var lastSyncQueryID int64
var lastSyncQueryMu sync.Mutex

// SyncClusterLogs forwards recent query logs to the primary (or replica) if configured
func SyncClusterLogs() error {
	configLock.RLock()
	role := config.ClusterRole
	logMode := config.ClusterLogSharingMode
	primaryURL := config.ClusterPrimaryURL
	apiToken := config.ClusterPrimaryToken
	nodeName := config.ClusterNodeName
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

	lastSyncQueryMu.Lock()
	minID := lastSyncQueryID
	lastSyncQueryMu.Unlock()

	// Select queries created since last sync that originated from this node (prevent echo loops)
	rows, err := db.Query(`
		SELECT id, timestamp, domain, type, status, client_ip, is_cache_hit, duration_ms, country_code, node_name
		FROM queries
		WHERE id > ? AND (node_name = '' OR node_name = ?)
		ORDER BY id ASC LIMIT 500
	`, minID, nodeName)
	if err != nil {
		return fmt.Errorf("failed to read local queries for cluster sync: %w", err)
	}
	defer rows.Close()

	var queriesToPush []Query
	var maxSeenID int64 = minID

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

	if len(queriesToPush) == 0 {
		return nil
	}

	payloadData, err := json.Marshal(map[string]interface{}{
		"node_name": nodeName,
		"queries":   queriesToPush,
	})
	if err != nil {
		return fmt.Errorf("failed to encode queries payload: %w", err)
	}

	parsedURL, err := url.Parse(primaryURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Hostname() == "" {
		return fmt.Errorf("invalid primary URL: %s", primaryURL)
	}

	host := parsedURL.Hostname()
	if !isValidDomain(host) {
		return fmt.Errorf("invalid host in primary URL: %s", host)
	}

	endpoint := (&url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   "/api/cluster/logs/ingest",
	}).String()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payloadData))
	if err != nil {
		return err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Key", apiToken)
	httpReq.Header.Set("X-Shield-Request", "true")

	configLock.RLock()
	verifyTLS := config.VerifyUpstreamTLS
	configLock.RUnlock()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS},
		},
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("error pushing query logs to primary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("primary returned HTTP %d on log ingest: %s", resp.StatusCode, string(b))
	}

	lastSyncQueryMu.Lock()
	if maxSeenID > lastSyncQueryID {
		lastSyncQueryID = maxSeenID
	}
	lastSyncQueryMu.Unlock()

	return nil
}

