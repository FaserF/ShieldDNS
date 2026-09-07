package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	clusterConnLost      int32 // atomic: 1 = lost, 0 = healthy
	clusterLastSyncError string
	clusterSyncMu        sync.Mutex
)

// handleClusterStatus returns current cluster topology & status
func handleClusterStatus(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	role := config.ClusterRole
	instanceType := config.ClusterInstanceType
	nodeName := config.ClusterNodeName
	logSharingMode := config.ClusterLogSharingMode
	if logSharingMode == "" {
		logSharingMode = "local_only"
	}
	primaryURL := config.ClusterPrimaryURL
	syncInterval := config.ClusterSyncInterval
	failoverMode := config.ClusterFailoverMode
	lastSync := config.ClusterLastSync
	replicas := append([]ClusterReplica{}, config.ClusterReplicas...)
	configLock.RUnlock()

	connLost := atomic.LoadInt32(&clusterConnLost) == 1

	type ReplicaInfo struct {
		ID           string    `json:"id"`
		Name         string    `json:"name"`
		URL          string    `json:"url"`
		InstanceType string    `json:"instance_type"`
		CreatedAt    time.Time `json:"created_at"`
		LastSeen     time.Time `json:"last_seen"`
		LastSync     time.Time `json:"last_sync"`
	}

	sanitizedReplicas := make([]ReplicaInfo, len(replicas))
	for i, rep := range replicas {
		sanitizedReplicas[i] = ReplicaInfo{
			ID:           rep.ID,
			Name:         rep.Name,
			URL:          rep.URL,
			InstanceType: rep.InstanceType,
			CreatedAt:    rep.CreatedAt,
			LastSeen:     rep.LastSeen,
			LastSync:     rep.LastSync,
		}
	}

	res := map[string]interface{}{
		"role":             role,
		"instance_type":    instanceType,
		"node_name":        nodeName,
		"log_sharing_mode": logSharingMode,
		"primary_url":      primaryURL,
		"sync_interval":    syncInterval,
		"failover_mode":    failoverMode,
		"last_sync":        lastSync,
		"worker_domain":    config.ClusterWorkerDomain,
		"connection_lost":  connLost,
		"last_sync_error":  clusterLastSyncError,
		"replicas":         sanitizedReplicas,
		"replica_count":    len(replicas),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

// handleClusterConnectionStatus is a lightweight public endpoint to check if replica has connection to primary
func handleClusterConnectionStatus(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	role := config.ClusterRole
	primaryURL := config.ClusterPrimaryURL
	lastSync := config.ClusterLastSync
	configLock.RUnlock()

	connLost := atomic.LoadInt32(&clusterConnLost) == 1

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"role":            role,
		"primary_url":     primaryURL,
		"connection_lost": connLost,
		"last_sync":       lastSync,
		"last_error":      clusterLastSyncError,
	})
}

// handleClusterRegisterReplica is called ON PRIMARY by a new or existing replica via API Token
func handleClusterRegisterReplica(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name         string `json:"name"`
		URL          string `json:"url"`
		InstanceType string `json:"instance_type"`
		FailoverMode bool   `json:"failover_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.InstanceType != "public" && req.InstanceType != "private" && req.InstanceType != "hybrid" {
		req.InstanceType = "private"
	}
	if req.Name == "" {
		req.Name = "ShieldDNS Replica"
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
	var matchedKey *APIKey

	configLock.Lock()
	for _, k := range config.APIKeys {
		if k.TokenHash == tokenHashed {
			matchedKey = &k
			break
		}
	}

	if matchedKey == nil || !hasPermission(matchedKey, "cluster:sync") {
		configLock.Unlock()
		http.Error(w, "Forbidden: Invalid token or missing 'cluster:sync' / 'admin:all' permission", http.StatusForbidden)
		return
	}

	if config.ClusterRole != "primary" {
		config.ClusterRole = "primary" // Auto-promote to primary if accepting replicas
	}

	replicaID := fmt.Sprintf("rep-%d", time.Now().UnixNano())
	now := time.Now().UTC()

	// Check if this token was already used by a replica
	foundIdx := -1
	for i, rep := range config.ClusterReplicas {
		if rep.TokenHash == tokenHashed {
			foundIdx = i
			replicaID = rep.ID
			break
		}
	}

	newRep := ClusterReplica{
		ID:           replicaID,
		Name:         req.Name,
		URL:          req.URL,
		TokenHash:    tokenHashed,
		InstanceType: req.InstanceType,
		CreatedAt:    now,
		LastSeen:     now,
		LastSync:     now,
	}

	if foundIdx >= 0 {
		newRep.CreatedAt = config.ClusterReplicas[foundIdx].CreatedAt
		config.ClusterReplicas[foundIdx] = newRep
	} else {
		config.ClusterReplicas = append(config.ClusterReplicas, newRep)
	}

	primaryDomain := config.AdminDomain
	if primaryDomain == "" {
		primaryDomain = r.Host
	}
	primaryURL := "https://" + primaryDomain

	if err := saveConfigNoLock(); err != nil {
		configLock.Unlock()
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	configLock.Unlock()

	// Export tailored config for this replica
	exported := buildClusterConfigExport(req.InstanceType, primaryURL, req.FailoverMode)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"replica_id": replicaID,
		"config":     exported,
	})
}

// handleClusterGetReplicaConfig is called ON PRIMARY by a replica during periodic or manual sync
func handleClusterGetReplicaConfig(w http.ResponseWriter, r *http.Request) {
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

	configLock.Lock()
	var repType = "private"
	var found = false
	now := time.Now().UTC()
	for i, rep := range config.ClusterReplicas {
		if rep.TokenHash == tokenHashed {
			config.ClusterReplicas[i].LastSeen = now
			config.ClusterReplicas[i].LastSync = now
			repType = rep.InstanceType
			found = true
			break
		}
	}
	if found {
		_ = saveConfigNoLock()
	}
	primaryDomain := config.AdminDomain
	if primaryDomain == "" {
		primaryDomain = r.Host
	}
	primaryURL := "https://" + primaryDomain
	configLock.Unlock()

	if !found {
		http.Error(w, "Replica not registered or token revoked", http.StatusForbidden)
		return
	}

	exported := buildClusterConfigExport(repType, primaryURL, false)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exported)
}

// handleClusterRevokeReplica is called ON PRIMARY by Admin to disconnect a replica
func handleClusterRevokeReplica(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "Missing replica id", http.StatusBadRequest)
		return
	}

	configLock.Lock()
	filtered := make([]ClusterReplica, 0, len(config.ClusterReplicas))
	for _, rep := range config.ClusterReplicas {
		if rep.ID != id {
			filtered = append(filtered, rep)
		}
	}
	config.ClusterReplicas = filtered
	if err := saveConfigNoLock(); err != nil {
		configLock.Unlock()
		http.Error(w, "Failed to update config", http.StatusInternalServerError)
		return
	}
	configLock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleClusterJoin is called on an unconfigured or configured REPLICA to connect to a primary
func handleClusterJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PrimaryURL   string `json:"primary_url"`
		APIToken     string `json:"api_token"`
		Name         string `json:"name"`
		InstanceType string `json:"instance_type"`
		FailoverMode bool   `json:"failover_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	req.PrimaryURL = strings.TrimRight(strings.TrimSpace(req.PrimaryURL), "/")
	if req.PrimaryURL == "" || req.APIToken == "" {
		http.Error(w, "Primary URL and API Token are required", http.StatusBadRequest)
		return
	}

	if !strings.HasPrefix(req.PrimaryURL, "http://") && !strings.HasPrefix(req.PrimaryURL, "https://") {
		req.PrimaryURL = "https://" + req.PrimaryURL
	}

	parsedURL, err := url.Parse(req.PrimaryURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Hostname() == "" {
		http.Error(w, "Invalid Primary URL", http.StatusBadRequest)
		return
	}

	if req.InstanceType != "public" && req.InstanceType != "private" && req.InstanceType != "hybrid" {
		req.InstanceType = "private"
	}
	if req.Name == "" {
		req.Name = "ShieldDNS Secondary Node"
	}

	// Register with Primary node
	registerPayload, _ := json.Marshal(map[string]interface{}{
		"name":          req.Name,
		"instance_type": req.InstanceType,
		"failover_mode": req.FailoverMode,
	})

	// Ensure host is valid domain or IP and construct target URL from parsed components
	host := parsedURL.Hostname()
	if !isValidDomain(host) {
		http.Error(w, "Invalid Primary URL host", http.StatusBadRequest)
		return
	}

	primaryEndpoint := (&url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
		Path:   "/api/cluster/replicas/register",
	}).String()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, primaryEndpoint, bytes.NewReader(registerPayload))
	if err != nil {
		http.Error(w, "Failed to create request: "+err.Error(), http.StatusInternalServerError)
		return
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Key", req.APIToken)
	httpReq.Header.Set("X-Shield-Request", "true")

	configLock.RLock()
	verifyTLS := config.VerifyUpstreamTLS
	configLock.RUnlock()

	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !verifyTLS},
		},
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		slog.Error("Cluster join connection failed", "url", primaryEndpoint, "error", err)
		http.Error(w, fmt.Sprintf("Could not connect to Primary ShieldDNS at %s: %v", req.PrimaryURL, err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		http.Error(w, fmt.Sprintf("Primary rejected registration (Status %d): %s", resp.StatusCode, string(body)), resp.StatusCode)
		return
	}

	var regResult struct {
		Success   bool                `json:"success"`
		ReplicaID string              `json:"replica_id"`
		Config    ClusterConfigExport `json:"config"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&regResult); err != nil {
		http.Error(w, "Failed to parse Primary response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply exported config onto this replica
	if err := applyClusterExport(regResult.Config, req.PrimaryURL, req.APIToken, req.InstanceType, req.FailoverMode); err != nil {
		http.Error(w, "Failed to apply synced configuration: "+err.Error(), http.StatusInternalServerError)
		return
	}

	atomic.StoreInt32(&clusterConnLost, 0)
	clusterLastSyncError = ""

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"replica_id":    regResult.ReplicaID,
		"instance_type": req.InstanceType,
		"message":       "Successfully joined cluster as Replica.",
	})
}

// handleClusterSync triggers an immediate manual pull from the Primary node
func handleClusterSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.RLock()
	role := config.ClusterRole
	primaryURL := config.ClusterPrimaryURL
	apiToken := config.ClusterPrimaryToken
	instType := config.ClusterInstanceType
	failover := config.ClusterFailoverMode
	configLock.RUnlock()

	if role != "replica" || primaryURL == "" || apiToken == "" {
		http.Error(w, "This node is not configured as a cluster replica", http.StatusBadRequest)
		return
	}

	err := performReplicaSync(primaryURL, apiToken, instType, failover)
	if err != nil {
		atomic.StoreInt32(&clusterConnLost, 1)
		clusterLastSyncError = err.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
			"message": "Connection to Primary node lost. Cached settings and fallback password remain active.",
		})
		return
	}

	atomic.StoreInt32(&clusterConnLost, 0)
	clusterLastSyncError = ""

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Configuration successfully synced from Primary node.",
	})
}

// handleClusterLeave turns this node back into a standalone instance
func handleClusterLeave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.Lock()
	config.ClusterRole = "standalone"
	config.ClusterPrimaryURL = ""
	config.ClusterPrimaryToken = ""
	config.ClusterFailoverMode = false
	if err := saveConfigNoLock(); err != nil {
		configLock.Unlock()
		http.Error(w, "Failed to update configuration", http.StatusInternalServerError)
		return
	}
	configLock.Unlock()

	atomic.StoreInt32(&clusterConnLost, 0)
	clusterLastSyncError = ""

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

// handleClusterUpdateSettings allows updating cluster options like sync interval or instance type
func handleClusterUpdateSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Role           string `json:"role"`
		InstanceType   string `json:"instance_type"`
		NodeName       string `json:"node_name"`
		LogSharingMode string  `json:"log_sharing_mode"`
		WorkerDomain   *string `json:"worker_domain"`
		FailoverMode   *bool   `json:"failover_mode"`
		SyncInterval   *int    `json:"sync_interval"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	configLock.Lock()
	if req.Role != "" {
		config.ClusterRole = req.Role
	}
	if req.InstanceType == "public" || req.InstanceType == "private" || req.InstanceType == "hybrid" {
		config.ClusterInstanceType = req.InstanceType
	}
	if req.NodeName != "" {
		config.ClusterNodeName = strings.TrimSpace(req.NodeName)
	}
	if req.WorkerDomain != nil {
		config.ClusterWorkerDomain = strings.TrimSpace(strings.ToLower(*req.WorkerDomain))
	}
	if req.LogSharingMode == "local_only" || req.LogSharingMode == "push_to_primary" || req.LogSharingMode == "full_sync" {
		config.ClusterLogSharingMode = req.LogSharingMode
	}
	if req.FailoverMode != nil {
		config.ClusterFailoverMode = *req.FailoverMode
	}
	if req.SyncInterval != nil && *req.SyncInterval >= 0 {
		config.ClusterSyncInterval = *req.SyncInterval
	}
	if err := saveConfigNoLock(); err != nil {
		configLock.Unlock()
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	configLock.Unlock()

	go updateCorefile()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

