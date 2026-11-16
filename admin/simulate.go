package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// SimulationRequest defines a candidate rule or service change to replay against recent query logs.
type SimulationRequest struct {
	Action      string `json:"action"` // "block_domain", "allow_domain", "toggle_service"
	Domain      string `json:"domain,omitempty"`
	ServiceID   string `json:"service_id,omitempty"`
	ClientIP    string `json:"client_ip,omitempty"`
	WindowHours int    `json:"window_hours,omitempty"`
	AskAI       bool   `json:"ask_ai,omitempty"`
}

// SimulationResult summarizes the predicted blast radius of a candidate rule change.
type SimulationResult struct {
	WindowHours        int              `json:"window_hours"`
	QueriesAnalyzed    int64            `json:"queries_analyzed"`
	NewlyBlocked       int64            `json:"newly_blocked"`
	NewlyAllowed       int64            `json:"newly_allowed"`
	AffectedClients    map[string]int64 `json:"affected_clients"`
	TopAffectedDomains []DomainCount    `json:"top_affected_domains"`
	SummarySentence    string           `json:"summary_sentence"`
	AIBlastAssessment  string           `json:"ai_blast_assessment,omitempty"`
}

// SimulateChange replays a candidate rule or service toggle against historical queries in the database.
func SimulateChange(req SimulationRequest) (*SimulationResult, error) {
	window := req.WindowHours
	if window <= 0 {
		window = 24
	}
	if window > 24*30 {
		window = 24 * 30
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	var targetDomains []string
	switch action {
	case "block_domain", "allow_domain":
		d := NormalizeDomain(strings.TrimPrefix(strings.TrimSpace(req.Domain), "*."))
		if d == "" || !isValidDomain(d) {
			return nil, fmt.Errorf("valid domain is required for action %s", action)
		}
		targetDomains = []string{d}
	case "toggle_service":
		svc, ok := GetServicePresetByID(req.ServiceID)
		if !ok {
			return nil, fmt.Errorf("unknown service_id: %q", req.ServiceID)
		}
		targetDomains = append(targetDomains, svc.Domains...)
	default:
		return nil, fmt.Errorf("unsupported simulation action: %q", req.Action)
	}

	res := &SimulationResult{
		WindowHours:        window,
		AffectedClients:    make(map[string]int64),
		TopAffectedDomains: []DomainCount{},
	}

	if db == nil {
		res.SummarySentence = "Query database is not initialized; 0 historical queries available to simulate."
		return res, nil
	}

	configLock.RLock()
	aliases := make(map[string]string, len(config.ClientAliases))
	for k, v := range config.ClientAliases {
		aliases[k] = v
	}
	aiEnabled := config.AIEnabled
	configLock.RUnlock()

	clientFilter := strings.TrimSpace(req.ClientIP)
	cutoffStr := time.Now().UTC().Add(-time.Duration(window) * time.Hour).Format("2006-01-02 15:04:05")

	// Query matching records over the window. Filter domain matching in SQLite/Postgres via LIKE or exact,
	// and perform exact subdomain boundary verification in Go for correctness across DB engines.
	var whereClauses []string
	var queryArgs []interface{}
	whereClauses = append(whereClauses, "timestamp >= ?")
	queryArgs = append(queryArgs, cutoffStr)

	if clientFilter != "" {
		whereClauses = append(whereClauses, "client_ip = ?")
		queryArgs = append(queryArgs, clientFilter)
	}

	var domainLikes []string
	for _, td := range targetDomains {
		domainLikes = append(domainLikes, "(domain = ? OR domain LIKE ?)")
		queryArgs = append(queryArgs, td, "%."+td)
	}
	if len(domainLikes) > 0 {
		whereClauses = append(whereClauses, "("+strings.Join(domainLikes, " OR ")+")")
	}

	sqlStr := fmt.Sprintf(
		"SELECT domain, client_ip, status, COUNT(*) FROM queries WHERE %s GROUP BY domain, client_ip, status",
		strings.Join(whereClauses, " AND "),
	)

	rows, err := dbQuery(sqlStr, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("simulation query failed: %w", err)
	}
	defer rows.Close()

	domainHits := make(map[string]int64)
	for rows.Next() {
		var dom, cip, status string
		var cnt int64
		if err := rows.Scan(&dom, &cip, &status, &cnt); err != nil {
			continue
		}
		normDom := NormalizeDomain(dom)
		matched := false
		for _, td := range targetDomains {
			if normDom == td || strings.HasSuffix(normDom, "."+td) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		res.QueriesAnalyzed += cnt
		isCurrentlyBlocked := strings.HasPrefix(status, "Blocked")

		impacted := false
		if action == "allow_domain" {
			if isCurrentlyBlocked {
				res.NewlyAllowed += cnt
				impacted = true
			}
		} else {
			// block_domain or toggle_service
			if !isCurrentlyBlocked {
				res.NewlyBlocked += cnt
				impacted = true
			}
		}

		if impacted {
			clientLabel := cip
			if alias, ok := aliases[cip]; ok && alias != "" {
				clientLabel = fmt.Sprintf("%s (%s)", alias, cip)
			}
			res.AffectedClients[clientLabel] += cnt
			domainHits[normDom] += cnt
		}
	}

	// Build sorted top affected domains (up to 10)
	for d, c := range domainHits {
		res.TopAffectedDomains = append(res.TopAffectedDomains, DomainCount{Domain: d, Count: c})
	}
	sort.Slice(res.TopAffectedDomains, func(i, j int) bool {
		if res.TopAffectedDomains[i].Count != res.TopAffectedDomains[j].Count {
			return res.TopAffectedDomains[i].Count > res.TopAffectedDomains[j].Count
		}
		return res.TopAffectedDomains[i].Domain < res.TopAffectedDomains[j].Domain
	})
	if len(res.TopAffectedDomains) > 10 {
		res.TopAffectedDomains = res.TopAffectedDomains[:10]
	}

	clientCount := len(res.AffectedClients)
	if action == "allow_domain" {
		res.SummarySentence = fmt.Sprintf("Would allow %d previously blocked queries across %d devices over the last %dh.", res.NewlyAllowed, clientCount, window)
	} else {
		res.SummarySentence = fmt.Sprintf("Would newly block %d queries across %d devices over the last %dh.", res.NewlyBlocked, clientCount, window)
	}

	if req.AskAI && aiEnabled {
		res.AIBlastAssessment = fetchAIBlastAssessment(req, res)
	}

	return res, nil
}

func fetchAIBlastAssessment(req SimulationRequest, res *SimulationResult) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var topDoms []string
	for _, td := range res.TopAffectedDomains {
		topDoms = append(topDoms, fmt.Sprintf("%s (%d)", td.Domain, td.Count))
	}
	target := req.Domain
	if req.ServiceID != "" {
		target = "service:" + req.ServiceID
	}

	messages := []OpenAIChatMessage{
		{
			Role:    "system",
			Content: "You are ShieldDNS AI Guardian. Give a concise 1-sentence plain-English assessment of potential side effects or false-positive risk for this simulated DNS rule change. No markdown.",
		},
		{
			Role: "user",
			Content: fmt.Sprintf("Action: %s, Target: %s, Window: %dh, NewlyBlocked: %d, NewlyAllowed: %d, AffectedClients: %d, TopDomains: [%s].",
				req.Action, target, res.WindowHours, res.NewlyBlocked, res.NewlyAllowed, len(res.AffectedClients), strings.Join(topDoms, ", ")),
		},
	}

	out, err := CallOpenAIChatCompletion(ctx, messages)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// handleSimulateChange handles POST /api/rules/simulate.
func handleSimulateChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SimulationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid simulation payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	res, err := SimulateChange(req)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}
