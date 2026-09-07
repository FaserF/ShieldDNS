package main

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

var mcpClusterTools = []mcpToolDefinition{
	// 11. Cluster & Multi-Node Federation Management
	{
		tool: mcpTool{
			Name:        "get_cluster_status",
			Description: "Get complete multi-node cluster topology, role (primary, replica, standalone), environment profile (private, public, hybrid), node name, log sharing mode, failover status, connected replicas, and synchronization health.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
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

			return map[string]interface{}{
				"role":             role,
				"instance_type":    instanceType,
				"node_name":        nodeName,
				"log_sharing_mode": logSharingMode,
				"primary_url":      primaryURL,
				"sync_interval":    syncInterval,
				"failover_mode":    failoverMode,
				"last_sync":        lastSync,
				"connection_lost":  connLost,
				"last_sync_error":  clusterLastSyncError,
				"replicas":         sanitizedReplicas,
				"replica_count":    len(replicas),
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "trigger_cluster_sync",
			Description: "Immediately synchronize configuration and query logs from Primary node (if configured as replica).",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "write:maintenance",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.RLock()
			role := config.ClusterRole
			primaryURL := config.ClusterPrimaryURL
			apiToken := config.ClusterPrimaryToken
			instType := config.ClusterInstanceType
			failover := config.ClusterFailoverMode
			configLock.RUnlock()

			if role != "replica" || primaryURL == "" || apiToken == "" {
				return nil, fmt.Errorf("this node is not configured as a cluster replica")
			}

			err := performReplicaSync(primaryURL, apiToken, instType, failover)
			if err != nil {
				atomic.StoreInt32(&clusterConnLost, 1)
				clusterLastSyncError = err.Error()
				return nil, fmt.Errorf("sync failed: %w", err)
			}

			atomic.StoreInt32(&clusterConnLost, 0)
			clusterLastSyncError = ""

			return map[string]interface{}{
				"success": true,
				"message": "Configuration and query logs successfully synchronized from Primary node.",
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "update_cluster_settings",
			Description: "Configure cluster role, environment profile (private, public, hybrid), node name, log sharing mode, upstream failover, and sync interval.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"role":             map[string]interface{}{"type": "string", "enum": []string{"standalone", "primary", "replica"}, "description": "Cluster role"},
					"instance_type":    map[string]interface{}{"type": "string", "enum": []string{"private", "public", "hybrid"}, "description": "Environment profile"},
					"node_name":        map[string]interface{}{"type": "string", "description": "Human-readable label for this server node"},
					"log_sharing_mode": map[string]interface{}{"type": "string", "enum": []string{"local_only", "push_to_primary", "full_sync"}, "description": "Query log replication mode across cluster"},
					"failover_mode":    map[string]interface{}{"type": "boolean", "description": "Use Primary node as upstream resolver for failover"},
					"sync_interval":    map[string]interface{}{"type": "integer", "description": "Sync interval in minutes (0 = manual only)"},
				},
			},
		},
		requiredPerm: "write:config",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.Lock()
			if r, ok := args["role"].(string); ok && (r == "standalone" || r == "primary" || r == "replica") {
				config.ClusterRole = r
			}
			if it, ok := args["instance_type"].(string); ok && (it == "private" || it == "public" || it == "hybrid") {
				config.ClusterInstanceType = it
			}
			if nn, ok := args["node_name"].(string); ok {
				config.ClusterNodeName = strings.TrimSpace(nn)
			}
			if lsm, ok := args["log_sharing_mode"].(string); ok && (lsm == "local_only" || lsm == "push_to_primary" || lsm == "full_sync") {
				config.ClusterLogSharingMode = lsm
			}
			if fm, ok := args["failover_mode"].(bool); ok {
				config.ClusterFailoverMode = fm
			}
			if si, ok := args["sync_interval"].(float64); ok && int(si) >= 0 {
				config.ClusterSyncInterval = int(si)
			}
			if err := saveConfigNoLock(); err != nil {
				configLock.Unlock()
				return nil, fmt.Errorf("failed to save config: %w", err)
			}
			configLock.Unlock()

			go updateCorefile()

			return map[string]interface{}{
				"success": true,
				"message": "Cluster settings updated successfully",
			}, nil
		},
	},
	{
		tool: mcpTool{
			Name:        "diagnose_cluster",
			Description: "Analyze and debug cluster configuration, profile constraints (private vs hybrid vs public), DNS rebinding settings, mobile configuration restrictions, replica connectivity, and log replication health.",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		requiredPerm: "read:diagnostics",
		actionHandler: func(apiKey *APIKey, args map[string]interface{}) (interface{}, error) {
			configLock.RLock()
			role := config.ClusterRole
			instType := config.ClusterInstanceType
			nodeName := config.ClusterNodeName
			logMode := config.ClusterLogSharingMode
			primaryURL := config.ClusterPrimaryURL
			failover := config.ClusterFailoverMode
			rebinding := config.DNSRebindingProtection
			signMobile := config.SignMobileConfig
			dohLimit := config.DoHRateLimit
			replicas := append([]ClusterReplica{}, config.ClusterReplicas...)
			configLock.RUnlock()

			var issues []string
			var suggestions []string

			// Check environment constraints
			if instType == "private" {
				if signMobile {
					issues = append(issues, "Private instance cannot sign .mobileconfig profiles because public CA verification requires a public domain.")
					suggestions = append(suggestions, "Disable mobileconfig signing or switch profile to 'hybrid' if this node has a public domain.")
				}
				if !rebinding {
					suggestions = append(suggestions, "Consider enabling DNS rebinding protection for private LAN security.")
				}
			} else if instType == "public" {
				if dohLimit > 120 {
					suggestions = append(suggestions, "High DoH rate limit on public node. Recommended limit is <= 60 requests/minute.")
				}
				if rebinding {
					suggestions = append(suggestions, "DNS rebinding protection is active on a public resolver; this may cause false-positive blocks on private IP answers.")
				}
			} else if instType == "hybrid" {
				suggestions = append(suggestions, "Hybrid profile active: suitable for external DoH/DoT with local failover resolution.")
			}

			// Check replica status
			connLost := atomic.LoadInt32(&clusterConnLost) == 1
			if role == "replica" {
				if connLost {
					issues = append(issues, fmt.Sprintf("Replica disconnected from Primary (%s): %s", primaryURL, clusterLastSyncError))
					suggestions = append(suggestions, "Verify network route to Primary, check API token validity, and use trigger_cluster_sync to retry.")
				}
				if failover && primaryURL == "" {
					issues = append(issues, "Failover enabled but no Primary URL is configured.")
				}
			}

			return map[string]interface{}{
				"status":           map[string]interface{}{
					"role":             role,
					"instance_type":    instType,
					"node_name":        nodeName,
					"log_sharing_mode": logMode,
					"connection_lost":  connLost,
					"last_sync_error":  clusterLastSyncError,
					"replica_count":    len(replicas),
				},
				"profile_analysis": map[string]interface{}{
					"instance_type":              instType,
					"dns_rebinding_protection":   rebinding,
					"mobileconfig_sign_allowed":  instType != "private",
					"doh_rate_limit":             dohLimit,
					"upstream_failover_enabled":  failover,
				},
				"issues":      issues,
				"suggestions": suggestions,
				"healthy":     len(issues) == 0,
			}, nil
		},
	},
}
