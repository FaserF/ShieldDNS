package main

import (
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

// NodeComparisonMetrics holds per-node metrics for side-by-side cluster comparison.
type NodeComparisonMetrics struct {
	NodeName      string  `json:"node_name"`
	Role          string  `json:"role"`
	TotalQueries  int64   `json:"total_queries"`
	BlockedPct    float64 `json:"blocked_pct"`
	CacheHitPct   float64 `json:"cache_hit_pct"`
	AvgLatencyMs  float64 `json:"avg_latency_ms"`
	Maintenance   bool    `json:"maintenance"`
	Online        bool    `json:"online"`
	Outlier       bool    `json:"outlier"`
	OutlierReason string  `json:"outlier_reason,omitempty"`
}

func handleClusterMaintenance(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configLock.RLock()
		enabled := config.MaintenanceMode
		reason := config.MaintenanceReason
		configLock.RUnlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"maintenance_mode":   enabled,
			"maintenance_reason": reason,
		})

	case http.MethodPost:
		var body struct {
			Enabled bool   `json:"enabled"`
			Reason  string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		configLock.Lock()
		config.MaintenanceMode = body.Enabled
		config.MaintenanceReason = strings.TrimSpace(body.Reason)
		saveConfigNoLock()
		configLock.Unlock()

		state := "disabled"
		if body.Enabled {
			state = "enabled"
		}
		RecordAuditEvent(r, "cluster.maintenance", state, body.Reason)
		RecordAnnotation("cluster.maintenance", "admin", "Maintenance mode "+state+": "+body.Reason)

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":             "ok",
			"maintenance_mode":   body.Enabled,
			"maintenance_reason": body.Reason,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleClusterCompare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.RLock()
	nodeName := config.ClusterNodeName
	if nodeName == "" {
		nodeName = "local"
	}
	role := config.ClusterRole
	if role == "" {
		role = "standalone"
	}
	maint := config.MaintenanceMode
	replicas := append([]ClusterReplica(nil), config.ClusterReplicas...)
	configLock.RUnlock()

	statsLock.RLock()
	tot := stats.TotalQueries
	blk := stats.BlockedQueries
	hits := stats.CacheHits
	avgLat := stats.AverageLatency
	statsLock.RUnlock()

	var nodes []NodeComparisonMetrics
	local := NodeComparisonMetrics{
		NodeName:     nodeName,
		Role:         role,
		TotalQueries: tot,
		AvgLatencyMs: avgLat,
		Maintenance:  maint,
		Online:       true,
	}
	if tot > 0 {
		local.BlockedPct = (float64(blk) / float64(tot)) * 100.0
		local.CacheHitPct = (float64(hits) / float64(tot)) * 100.0
	}
	nodes = append(nodes, local)

	// Include known cluster replicas with their DB-persisted query counts if available
	now := time.Now()
	for _, rep := range replicas {
		m := NodeComparisonMetrics{
			NodeName: rep.Name,
			Role:     "replica",
			Online:   !rep.LastSeen.IsZero() && now.Sub(rep.LastSeen) < 10*time.Minute,
		}
		if db != nil {
			var rTot, rBlk, rHit int64
			var rLat float64
			row := dbQueryRow(
				"SELECT COUNT(*), COALESCE(SUM(CASE WHEN status LIKE 'Blocked%' THEN 1 ELSE 0 END), 0), COALESCE(SUM(CASE WHEN is_cache_hit IS TRUE THEN 1 ELSE 0 END), 0), COALESCE(AVG(duration_ms), 0) FROM queries WHERE node_name = ?",
				rep.Name,
			)
			if row != nil {
				if err := row.Scan(&rTot, &rBlk, &rHit, &rLat); err == nil && rTot > 0 {
					m.TotalQueries = rTot
					m.BlockedPct = (float64(rBlk) / float64(rTot)) * 100.0
					m.CacheHitPct = (float64(rHit) / float64(rTot)) * 100.0
					m.AvgLatencyMs = rLat
				}
			}
		}
		nodes = append(nodes, m)
	}

	// MAD outlier detection on AvgLatencyMs when >= 3 nodes
	if len(nodes) >= 3 {
		lats := make([]float64, len(nodes))
		for i, n := range nodes {
			lats[i] = n.AvgLatencyMs
		}
		med := medianFloat64(lats)
		devs := make([]float64, len(lats))
		for i, v := range lats {
			devs[i] = math.Abs(v - med)
		}
		mad := medianFloat64(devs)
		for i := range nodes {
			if mad > 0 && math.Abs(nodes[i].AvgLatencyMs-med) > 3.5*mad {
				nodes[i].Outlier = true
				nodes[i].OutlierReason = "latency_mad_outlier"
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"nodes": nodes,
	})
}

func medianFloat64(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	cp := append([]float64(nil), vals...)
	sort.Float64s(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 0 {
		return (cp[mid-1] + cp[mid]) / 2.0
	}
	return cp[mid]
}
