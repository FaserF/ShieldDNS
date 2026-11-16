package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AnomalyFinding represents a deterministic behavioral anomaly observed in query logs.
type AnomalyFinding struct {
	ID                  string    `json:"id"`
	Kind                string    `json:"kind"` // "periodic_beacon", "chatty_loop", "dga_entropy", "block_storm"
	ClientIP            string    `json:"client_ip"`
	ClientAlias         string    `json:"client_alias,omitempty"`
	Domain              string    `json:"domain,omitempty"`
	Severity            string    `json:"severity"` // "high", "medium", "info"
	Summary             string    `json:"summary"`
	Evidence            string    `json:"evidence"`
	DominantIntervalSec int       `json:"dominant_interval_sec,omitempty"`
	DetectedAt          time.Time `json:"detected_at"`
	Acknowledged        bool      `json:"acknowledged"`
	Muted               bool      `json:"muted"`
}

type anomalyStateStore struct {
	Acknowledged map[string]bool `json:"acknowledged"`
	Muted        map[string]bool `json:"muted"` // key: clientIP + "|" + kind
}

var (
	anomalyStateMu     sync.RWMutex
	anomalyState       = anomalyStateStore{Acknowledged: make(map[string]bool), Muted: make(map[string]bool)}
	anomalyStateLoaded bool
)

func anomalyStatePath() string {
	return filepath.Join(DataDir, "anomalies_state.json")
}

func loadAnomalyStateLocked() {
	if anomalyStateLoaded {
		return
	}
	anomalyStateLoaded = true
	b, err := os.ReadFile(anomalyStatePath())
	if err != nil {
		return
	}
	var st anomalyStateStore
	if err := json.Unmarshal(b, &st); err == nil {
		if st.Acknowledged != nil {
			anomalyState.Acknowledged = st.Acknowledged
		}
		if st.Muted != nil {
			anomalyState.Muted = st.Muted
		}
	}
}

func saveAnomalyStateLocked() {
	b, err := json.MarshalIndent(anomalyState, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(anomalyStatePath()), 0755)
	_ = atomicWriteFile(anomalyStatePath(), b)
}

func resetAnomalyStateForTest() {
	anomalyStateMu.Lock()
	defer anomalyStateMu.Unlock()
	anomalyState = anomalyStateStore{
		Acknowledged: make(map[string]bool),
		Muted:        make(map[string]bool),
	}
	anomalyStateLoaded = true
}

func makeAnomalyID(kind, clientIP, domain string) string {
	sum := sha256.Sum256([]byte(kind + "|" + clientIP + "|" + domain))
	return hex.EncodeToString(sum[:8])
}

// DetectAnomalies analyzes recent query history for periodic beaconing, chatty loops,
// high-entropy DGA domains, and excessive client blocking storms.
func DetectAnomalies() ([]AnomalyFinding, error) {
	if db == nil {
		return []AnomalyFinding{}, nil
	}

	configLock.RLock()
	dgaThreshold := config.AbuseDGAThreshold
	if dgaThreshold <= 0 {
		dgaThreshold = 3.8
	}
	dgaMinLen := config.AbuseDGAMinLen
	if dgaMinLen <= 0 {
		dgaMinLen = 8
	}
	aliases := make(map[string]string, len(config.ClientAliases))
	for k, v := range config.ClientAliases {
		aliases[k] = v
	}
	configLock.RUnlock()

	cutoff := time.Now().UTC().Add(-3 * time.Hour).Format("2006-01-02 15:04:05")
	rows, err := dbQuery(`
		SELECT client_ip, domain, status, timestamp
		FROM queries
		WHERE timestamp >= ?
		ORDER BY client_ip, domain, timestamp ASC
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("anomaly scan query failed: %w", err)
	}
	defer rows.Close()

	type pairKey struct {
		clientIP string
		domain   string
	}
	type clientAgg struct {
		total   int
		blocked int
	}

	pairTimes := make(map[pairKey][]time.Time)
	clientCounts := make(map[string]*clientAgg)
	distinctDomains := make(map[string]string) // domain -> sample clientIP

	for rows.Next() {
		var cip, dom, status, tsStr string
		if err := rows.Scan(&cip, &dom, &status, &tsStr); err != nil {
			continue
		}
		if cip == "" || dom == "" {
			continue
		}
		ts, err := ParseFlexibleTime(tsStr)
		if err != nil {
			continue
		}
		normDom := NormalizeDomain(dom)
		if normDom == "" {
			continue
		}

		pk := pairKey{clientIP: cip, domain: normDom}
		pairTimes[pk] = append(pairTimes[pk], ts)

		agg := clientCounts[cip]
		if agg == nil {
			agg = &clientAgg{}
			clientCounts[cip] = agg
		}
		agg.total++
		if strings.HasPrefix(status, "Blocked") {
			agg.blocked++
		}
		if _, exists := distinctDomains[normDom]; !exists {
			distinctDomains[normDom] = cip
		}
	}

	var findings []AnomalyFinding
	now := time.Now().UTC()

	// 1. Periodic Beaconing & Chatty Loop detection
	for pk, times := range pairTimes {
		if len(times) < 10 {
			continue
		}
		sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })

		var deltas []float64
		for i := 1; i < len(times); i++ {
			diff := times[i].Sub(times[i-1]).Seconds()
			if diff > 0 {
				deltas = append(deltas, diff)
			}
		}
		if len(deltas) < 8 {
			continue
		}

		sortedDeltas := append([]float64{}, deltas...)
		sort.Float64s(sortedDeltas)
		med := sortedDeltas[len(sortedDeltas)/2]
		if med < 5 || med > 1800 {
			continue
		}

		inBand := 0
		tol := med * 0.20
		if tol < 2 {
			tol = 2
		}
		for _, d := range deltas {
			if d >= med-tol && d <= med+tol {
				inBand++
			}
		}
		regularity := float64(inBand) / float64(len(deltas))
		if regularity >= 0.70 {
			kind := "periodic_beacon"
			sev := "medium"
			summary := fmt.Sprintf("Periodic DNS queries every ~%ds to %s", int(med+0.5), pk.domain)
			if med < 30 && len(times) >= 20 {
				kind = "chatty_loop"
				sev = "info"
				summary = fmt.Sprintf("High-frequency chatty loop every ~%ds to %s", int(med+0.5), pk.domain)
			}
			findings = append(findings, AnomalyFinding{
				ID:                  makeAnomalyID(kind, pk.clientIP, pk.domain),
				Kind:                kind,
				ClientIP:            pk.clientIP,
				ClientAlias:         aliases[pk.clientIP],
				Domain:              pk.domain,
				Severity:            sev,
				Summary:             summary,
				Evidence:            fmt.Sprintf("%d queries, %.0f%% intervals within ±20%% of %.1fs median", len(times), regularity*100, med),
				DominantIntervalSec: int(med + 0.5),
				DetectedAt:          now,
			})
		}
	}

	// 2. High-Entropy / DGA Domain Detection
	for dom, cip := range distinctDomains {
		if isInfrastructureDomain(dom) {
			continue
		}
		parts := strings.Split(dom, ".")
		label := parts[0]
		if len(label) >= dgaMinLen {
			ent := CalculateEntropy(label)
			if ent > dgaThreshold {
				findings = append(findings, AnomalyFinding{
					ID:          makeAnomalyID("dga_entropy", cip, dom),
					Kind:        "dga_entropy",
					ClientIP:    cip,
					ClientAlias: aliases[cip],
					Domain:      dom,
					Severity:    "high",
					Summary:     fmt.Sprintf("High-entropy / DGA-like domain queried: %s", dom),
					Evidence:    fmt.Sprintf("Label %q (len=%d) Shannon entropy %.2f exceeds threshold %.2f", label, len(label), ent, dgaThreshold),
					DetectedAt:  now,
				})
			}
		}
	}

	// 3. Block / Overblocking Storm Detection
	for cip, agg := range clientCounts {
		if agg.blocked >= 50 {
			ratio := float64(agg.blocked) / float64(agg.total)
			if ratio >= 0.50 {
				findings = append(findings, AnomalyFinding{
					ID:          makeAnomalyID("block_storm", cip, ""),
					Kind:        "block_storm",
					ClientIP:    cip,
					ClientAlias: aliases[cip],
					Severity:    "medium",
					Summary:     fmt.Sprintf("Client experiencing high block rate (%.0f%% blocked)", ratio*100),
					Evidence:    fmt.Sprintf("%d of %d queries blocked in the last 3 hours", agg.blocked, agg.total),
					DetectedAt:  now,
				})
			}
		}
	}

	// Apply acknowledgment & mute status
	anomalyStateMu.Lock()
	loadAnomalyStateLocked()
	for i := range findings {
		findings[i].Acknowledged = anomalyState.Acknowledged[findings[i].ID]
		muteKey := findings[i].ClientIP + "|" + findings[i].Kind
		if anomalyState.Muted[muteKey] || anomalyState.Muted["*|"+findings[i].Kind] {
			findings[i].Muted = true
		}
	}
	anomalyStateMu.Unlock()

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
		}
		return findings[i].ID < findings[j].ID
	})

	return findings, nil
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

// SetAnomalyAcknowledge marks or unmarks a finding ID as acknowledged.
func SetAnomalyAcknowledge(id string, undo bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	anomalyStateMu.Lock()
	defer anomalyStateMu.Unlock()
	loadAnomalyStateLocked()
	if undo {
		delete(anomalyState.Acknowledged, id)
	} else {
		anomalyState.Acknowledged[id] = true
	}
	saveAnomalyStateLocked()
}

// SetAnomalyMute mutes or unmutes an anomaly kind for a specific client IP (or "*").
func SetAnomalyMute(clientIP, kind string, unmute bool) {
	clientIP = strings.TrimSpace(clientIP)
	kind = strings.TrimSpace(kind)
	if clientIP == "" || kind == "" {
		return
	}
	key := clientIP + "|" + kind
	anomalyStateMu.Lock()
	defer anomalyStateMu.Unlock()
	loadAnomalyStateLocked()
	if unmute {
		delete(anomalyState.Muted, key)
	} else {
		anomalyState.Muted[key] = true
	}
	saveAnomalyStateLocked()
}

func handleGetAnomalies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	findings, err := DetectAnomalies()
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	includeMuted := strings.EqualFold(r.URL.Query().Get("include_muted"), "true")
	var filtered []AnomalyFinding
	unackedCount := 0
	for _, f := range findings {
		if f.Muted && !includeMuted {
			continue
		}
		if !f.Acknowledged && !f.Muted && f.Kind != "chatty_loop" {
			unackedCount++
		}
		filtered = append(filtered, f)
	}
	if filtered == nil {
		filtered = []AnomalyFinding{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"anomalies":         filtered,
		"unacknowledged":    unackedCount,
		"total_detected":    len(findings),
	})
}

func handleAcknowledgeAnomaly(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ID   string `json:"id"`
		Undo bool   `json:"undo"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ID) == "" {
		sendJSONError(w, "id is required", http.StatusBadRequest)
		return
	}
	SetAnomalyAcknowledge(req.ID, req.Undo)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "id": req.ID, "acknowledged": !req.Undo})
}

func handleMuteAnomaly(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		ClientIP string `json:"client_ip"`
		Kind     string `json:"kind"`
		Unmute   bool   `json:"unmute"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.ClientIP) == "" || strings.TrimSpace(req.Kind) == "" {
		sendJSONError(w, "client_ip and kind are required", http.StatusBadRequest)
		return
	}
	SetAnomalyMute(req.ClientIP, req.Kind, req.Unmute)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "client_ip": req.ClientIP, "kind": req.Kind, "muted": !req.Unmute})
}
