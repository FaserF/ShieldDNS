package main

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Latency bucket upper bounds in milliseconds (17 log-spaced buckets).
var latencyBucketBoundsMs = []float64{
	0.25, 0.5, 1, 2, 4, 8, 15, 30, 50, 100, 200, 400, 750, 1000, 1500, 2000,
}

var latencyBucketLabels = []string{
	"<0.25ms", "0.5ms", "1ms", "2ms", "4ms", "8ms", "15ms", "30ms",
	"50ms", "100ms", "200ms", "400ms", "750ms", "1s", "1.5s", "2s", ">2s",
}

type flowEdgeKey struct {
	Source string
	Target string
	Stage  string // "group_decision", "decision_upstream", "upstream_rcode"
}

type latencyMinuteBucket struct {
	Minute time.Time
	Counts [17]int64
	Total  int64
	Errors int64
	Slow   int64
}

var (
	obsLock          sync.RWMutex
	flowEdges        = make(map[flowEdgeKey]int64)
	latencyHistory   []latencyMinuteBucket
	sloTotalQueries  int64
	sloErrorQueries  int64
	sloSlowQueries   int64
	sloOffenderIPs   = make(map[string]int64)
	sloOffenderNames = make(map[string]int64)
)

// RecordFlowAndSLO records a query outcome into Flow edges, Latency Heatmap buckets, and SLO counters.
func RecordFlowAndSLO(groupID, decision, upstream, rcode string, durationMs float64) {
	if groupID == "" {
		groupID = "default"
	}
	if decision == "" {
		decision = "allowed"
	}
	if upstream == "" {
		upstream = "local"
	}
	if rcode == "" {
		rcode = "NOERROR"
	}

	bIdx := latencyBucketIndex(durationMs)
	nowMin := time.Now().Truncate(time.Minute)

	configLock.RLock()
	sloLatMs := config.SLOTargetLatencyMs
	configLock.RUnlock()
	if sloLatMs <= 0 {
		sloLatMs = 50.0
	}

	isErr := strings.EqualFold(rcode, "SERVFAIL") || strings.EqualFold(decision, "error")
	isSlow := durationMs > sloLatMs

	obsLock.Lock()
	defer obsLock.Unlock()

	flowEdges[flowEdgeKey{Source: "group:" + groupID, Target: "decision:" + decision, Stage: "group_decision"}]++
	flowEdges[flowEdgeKey{Source: "decision:" + decision, Target: "upstream:" + upstream, Stage: "decision_upstream"}]++
	flowEdges[flowEdgeKey{Source: "upstream:" + upstream, Target: "rcode:" + rcode, Stage: "upstream_rcode"}]++

	// Update minute bucket
	n := len(latencyHistory)
	if n == 0 || !latencyHistory[n-1].Minute.Equal(nowMin) {
		latencyHistory = append(latencyHistory, latencyMinuteBucket{Minute: nowMin})
		if len(latencyHistory) > 120 {
			latencyHistory = latencyHistory[len(latencyHistory)-120:]
		}
		n = len(latencyHistory)
	}
	latencyHistory[n-1].Counts[bIdx]++
	latencyHistory[n-1].Total++
	if isErr {
		latencyHistory[n-1].Errors++
	}
	if isSlow {
		latencyHistory[n-1].Slow++
	}

	sloTotalQueries++
	if isErr {
		sloErrorQueries++
	}
	if isSlow {
		sloSlowQueries++
	}
}

// RecordSLOOffender attributes an error or slow query to a client/domain for SLO budget attribution.
func RecordSLOOffender(clientIP, domain string) {
	obsLock.Lock()
	defer obsLock.Unlock()
	if clientIP != "" {
		sloOffenderIPs[clientIP]++
	}
	if domain != "" {
		sloOffenderNames[domain]++
	}
}

func latencyBucketIndex(ms float64) int {
	for i, bound := range latencyBucketBoundsMs {
		if ms <= bound {
			return i
		}
	}
	return len(latencyBucketBoundsMs)
}

func handleStatsFlow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type flowLink struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Stage  string `json:"stage"`
		Value  int64  `json:"value"`
	}

	obsLock.RLock()
	links := make([]flowLink, 0, len(flowEdges))
	nodeSet := make(map[string]struct{})
	for k, v := range flowEdges {
		if v <= 0 {
			continue
		}
		links = append(links, flowLink{Source: k.Source, Target: k.Target, Stage: k.Stage, Value: v})
		nodeSet[k.Source] = struct{}{}
		nodeSet[k.Target] = struct{}{}
	}
	obsLock.RUnlock()

	sort.Slice(links, func(i, j int) bool { return links[i].Value > links[j].Value })
	nodes := make([]string, 0, len(nodeSet))
	for n := range nodeSet {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"nodes": nodes,
		"links": links,
	})
}

func handleStatsHeatmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clientFilter := strings.TrimSpace(r.URL.Query().Get("client"))
	domainFilter := strings.TrimSpace(r.URL.Query().Get("domain"))

	// 7 days (0=Sun..6=Sat) x 24 hours matrix
	var total [7][24]int64
	var blocked [7][24]int64

	if db != nil {
		query := "SELECT timestamp, status FROM queries WHERE timestamp >= datetime('now', '-7 days')"
		var args []interface{}
		if clientFilter != "" {
			query += " AND client_ip = ?"
			args = append(args, clientFilter)
		}
		if domainFilter != "" {
			query += " AND domain = ?"
			args = append(args, domainFilter)
		}
		rows, err := dbQuery(query, args...)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var tsStr, status string
				if err := rows.Scan(&tsStr, &status); err == nil {
					if t, err := ParseFlexibleTime(tsStr); err == nil {
						wd := int(t.Weekday())
						hr := t.Hour()
						total[wd][hr]++
						if strings.Contains(strings.ToLower(status), "blocked") {
							blocked[wd][hr]++
						}
					}
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"days":    []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"},
		"total":   total,
		"blocked": blocked,
	})
}

func handleStatsLatencyHeatmap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type bucketRow struct {
		Time   string    `json:"time"`
		Counts [17]int64 `json:"counts"`
		Total  int64     `json:"total"`
	}

	obsLock.RLock()
	rows := make([]bucketRow, 0, len(latencyHistory))
	for _, b := range latencyHistory {
		rows = append(rows, bucketRow{
			Time:   b.Minute.Format(time.RFC3339),
			Counts: b.Counts,
			Total:  b.Total,
		})
	}
	obsLock.RUnlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"buckets": latencyBucketLabels,
		"series":  rows,
	})
}

func handleStatsSLO(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.RLock()
	targetAvail := config.SLOTargetAvailability
	targetLatMs := config.SLOTargetLatencyMs
	configLock.RUnlock()
	if targetAvail <= 0 || targetAvail >= 100 {
		targetAvail = 99.9
	}
	if targetLatMs <= 0 {
		targetLatMs = 50.0
	}

	obsLock.RLock()
	tot := sloTotalQueries
	errs := sloErrorQueries
	slow := sloSlowQueries

	type offender struct {
		Name  string `json:"name"`
		Count int64  `json:"count"`
	}
	topClients := make([]offender, 0, len(sloOffenderIPs))
	for k, v := range sloOffenderIPs {
		topClients = append(topClients, offender{Name: k, Count: v})
	}
	topDomains := make([]offender, 0, len(sloOffenderNames))
	for k, v := range sloOffenderNames {
		topDomains = append(topDomains, offender{Name: k, Count: v})
	}
	obsLock.RUnlock()

	sort.Slice(topClients, func(i, j int) bool { return topClients[i].Count > topClients[j].Count })
	sort.Slice(topDomains, func(i, j int) bool { return topDomains[i].Count > topDomains[j].Count })
	if len(topClients) > 5 {
		topClients = topClients[:5]
	}
	if len(topDomains) > 5 {
		topDomains = topDomains[:5]
	}

	availPct := 100.0
	if tot > 0 {
		availPct = (float64(tot-errs) / float64(tot)) * 100.0
	}
	allowedErrBudget := (100.0 - targetAvail) / 100.0
	actualErrRate := 0.0
	if tot > 0 {
		actualErrRate = float64(errs) / float64(tot)
	}
	burnRate := 0.0
	if allowedErrBudget > 0 {
		burnRate = actualErrRate / allowedErrBudget
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"target_availability_pct": targetAvail,
		"actual_availability_pct": availPct,
		"target_latency_ms":       targetLatMs,
		"total_queries":           tot,
		"error_queries":           errs,
		"slow_queries":            slow,
		"burn_rate":               burnRate,
		"top_offender_clients":    topClients,
		"top_offender_domains":    topDomains,
	})
}

func handleClientTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	clientIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	if clientIP == "" {
		http.Error(w, "Missing ip", http.StatusBadRequest)
		return
	}

	var hourlyTotal [24]int64
	var hourlyBlocked [24]int64
	if db != nil {
		rows, err := dbQuery(
			"SELECT timestamp, status FROM queries WHERE client_ip = ? AND timestamp >= datetime('now', '-24 hours')",
			clientIP,
		)
		if err == nil {
			defer rows.Close()
			now := time.Now()
			for rows.Next() {
				var tsStr, status string
				if err := rows.Scan(&tsStr, &status); err == nil {
					if t, err := ParseFlexibleTime(tsStr); err == nil {
						hrsAgo := int(now.Sub(t).Hours())
						if hrsAgo >= 0 && hrsAgo < 24 {
							idx := 23 - hrsAgo
							hourlyTotal[idx]++
							if strings.Contains(strings.ToLower(status), "blocked") {
								hourlyBlocked[idx]++
							}
						}
					}
				}
			}
		}
	}

	labels := make([]string, 24)
	now := time.Now()
	for i := 0; i < 24; i++ {
		labels[i] = fmt.Sprintf("%02d:00", now.Add(time.Duration(i-23)*time.Hour).Hour())
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ip":      clientIP,
		"labels":  labels,
		"total":   hourlyTotal,
		"blocked": hourlyBlocked,
	})
}
