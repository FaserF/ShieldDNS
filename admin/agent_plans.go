package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// AgentPlan represents a staged DNS configuration mutation proposed by an AI agent or operator.
type AgentPlan struct {
	ID         string            `json:"id"`
	CreatedAt  time.Time         `json:"created_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	AgentName  string            `json:"agent_name"`
	Reason     string            `json:"reason"`
	Action     string            `json:"action"` // "block_domain", "allow_domain", "toggle_service"
	Target     string            `json:"target"`
	ClientIP   string            `json:"client_ip,omitempty"`
	Status     string            `json:"status"` // "pending", "applied", "rejected", "expired"
	Simulation *SimulationResult `json:"simulation,omitempty"`
}

const maxStoredPlans = 100

var (
	agentPlansMu     sync.Mutex
	agentPlansStore  []AgentPlan
	agentPlansLoaded bool
)

func agentPlansFilePath() string {
	return filepath.Join(DataDir, "agent_plans.json")
}

func loadAgentPlansLocked() {
	if agentPlansLoaded {
		return
	}
	agentPlansLoaded = true
	b, err := os.ReadFile(agentPlansFilePath())
	if err != nil {
		return
	}
	var plans []AgentPlan
	if err := json.Unmarshal(b, &plans); err == nil {
		agentPlansStore = plans
	}
}

func saveAgentPlansLocked() {
	if DataDir == "" {
		return
	}
	b, err := json.MarshalIndent(agentPlansStore, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(agentPlansFilePath()), 0755)
	_ = atomicWriteFile(agentPlansFilePath(), b)
}

func resetAgentPlansForTest() {
	agentPlansMu.Lock()
	defer agentPlansMu.Unlock()
	agentPlansStore = nil
	agentPlansLoaded = true
}

// CreateAgentPlan stages a proposed rule/service change and automatically computes its 24h impact simulation.
func CreateAgentPlan(agentName, action, target, clientIP, reason string) (*AgentPlan, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	target = strings.TrimSpace(target)
	clientIP = strings.TrimSpace(clientIP)
	reason = strings.TrimSpace(reason)
	if agentName == "" {
		agentName = "mcp-agent"
	}
	if reason == "" {
		reason = "Automated agent proposal"
	}

	var simReq SimulationRequest
	switch action {
	case "block_domain", "allow_domain":
		norm := NormalizeDomain(strings.TrimPrefix(target, "*."))
		if norm == "" || !isValidDomain(norm) {
			return nil, fmt.Errorf("invalid domain target: %q", target)
		}
		target = norm
		simReq = SimulationRequest{
			Action:      action,
			Domain:      norm,
			ClientIP:    clientIP,
			WindowHours: 24,
		}
	case "toggle_service":
		svc, ok := GetServicePresetByID(target)
		if !ok {
			return nil, fmt.Errorf("unknown service preset: %q", target)
		}
		target = svc.ID
		simReq = SimulationRequest{
			Action:      "toggle_service",
			ServiceID:   svc.ID,
			WindowHours: 24,
		}
	default:
		return nil, fmt.Errorf("unsupported plan action %q", action)
	}

	sim, _ := SimulateChange(simReq)

	now := time.Now().UTC()
	plan := AgentPlan{
		ID:         fmt.Sprintf("plan_%d", now.UnixNano()),
		CreatedAt:  now,
		ExpiresAt:  now.Add(30 * time.Minute),
		AgentName:  agentName,
		Reason:     reason,
		Action:     action,
		Target:     target,
		ClientIP:   clientIP,
		Status:     "pending",
		Simulation: sim,
	}

	agentPlansMu.Lock()
	defer agentPlansMu.Unlock()
	loadAgentPlansLocked()
	agentPlansStore = append(agentPlansStore, plan)
	if len(agentPlansStore) > maxStoredPlans {
		agentPlansStore = agentPlansStore[len(agentPlansStore)-maxStoredPlans:]
	}
	saveAgentPlansLocked()

	pCopy := plan
	return &pCopy, nil
}

// ListAgentPlans returns all plans in reverse chronological order, marking expired pending plans.
func ListAgentPlans() []AgentPlan {
	agentPlansMu.Lock()
	defer agentPlansMu.Unlock()
	loadAgentPlansLocked()

	now := time.Now().UTC()
	changed := false
	for i := range agentPlansStore {
		if agentPlansStore[i].Status == "pending" && now.After(agentPlansStore[i].ExpiresAt) {
			agentPlansStore[i].Status = "expired"
			changed = true
		}
	}
	if changed {
		saveAgentPlansLocked()
	}

	out := make([]AgentPlan, 0, len(agentPlansStore))
	for i := len(agentPlansStore) - 1; i >= 0; i-- {
		out = append(out, agentPlansStore[i])
	}
	return out
}

// ApplyAgentPlan executes a pending staged plan against live ShieldDNS configuration.
func ApplyAgentPlan(planID string) (*AgentPlan, error) {
	agentPlansMu.Lock()
	loadAgentPlansLocked()

	idx := -1
	now := time.Now().UTC()
	for i := range agentPlansStore {
		if agentPlansStore[i].ID == planID {
			idx = i
			break
		}
	}
	if idx == -1 {
		agentPlansMu.Unlock()
		return nil, fmt.Errorf("plan %q not found", planID)
	}
	plan := agentPlansStore[idx]
	if plan.Status != "pending" {
		agentPlansMu.Unlock()
		return nil, fmt.Errorf("plan %q is %s, not pending", planID, plan.Status)
	}
	if now.After(plan.ExpiresAt) {
		agentPlansStore[idx].Status = "expired"
		saveAgentPlansLocked()
		agentPlansMu.Unlock()
		return nil, fmt.Errorf("plan %q has expired", planID)
	}
	agentPlansMu.Unlock()

	configLock.Lock()
	if config.ClusterRole == "replica" {
		configLock.Unlock()
		return nil, fmt.Errorf("cannot apply plans on a cluster replica; apply on Primary instead")
	}

	switch plan.Action {
	case "block_domain", "allow_domain":
		isAllow := plan.Action == "allow_domain"
		if plan.ClientIP != "" {
			var clean []ClientRule
			for _, cr := range config.ClientRules {
				if !(strings.EqualFold(cr.Domain, plan.Target) && cr.ClientIP == plan.ClientIP) {
					clean = append(clean, cr)
				}
			}
			clean = append(clean, ClientRule{Domain: plan.Target, ClientIP: plan.ClientIP, IsAllowlist: isAllow})
			config.ClientRules = clean
		} else if isAllow {
			config.CustomAllowed = appendUniqueString(config.CustomAllowed, plan.Target)
			config.CustomBlocked = removeString(config.CustomBlocked, plan.Target)
		} else {
			config.CustomBlocked = appendUniqueString(config.CustomBlocked, plan.Target)
			config.CustomAllowed = removeString(config.CustomAllowed, plan.Target)
		}
	case "toggle_service":
		found := false
		for _, id := range config.BlockedServices {
			if id == plan.Target {
				found = true
				break
			}
		}
		if found {
			config.BlockedServices = removeString(config.BlockedServices, plan.Target)
		} else {
			config.BlockedServices = append(config.BlockedServices, plan.Target)
		}
	}

	if err := saveConfigNoLock(); err != nil {
		configLock.Unlock()
		return nil, fmt.Errorf("failed to save config: %w", err)
	}
	cfgClone := config.Clone()
	configLock.Unlock()

	reloadRulesFastNoLock(cfgClone)
	RecordAnnotation("agent_plan", plan.AgentName, fmt.Sprintf("Applied %s (%s): %s", plan.Action, plan.Target, plan.Reason))

	agentPlansMu.Lock()
	defer agentPlansMu.Unlock()
	for i := range agentPlansStore {
		if agentPlansStore[i].ID == planID {
			agentPlansStore[i].Status = "applied"
			saveAgentPlansLocked()
			pCopy := agentPlansStore[i]
			return &pCopy, nil
		}
	}
	return &plan, nil
}

// DiscardAgentPlan marks a pending plan as rejected.
func DiscardAgentPlan(planID string) (*AgentPlan, error) {
	agentPlansMu.Lock()
	defer agentPlansMu.Unlock()
	loadAgentPlansLocked()

	for i := range agentPlansStore {
		if agentPlansStore[i].ID == planID {
			if agentPlansStore[i].Status != "pending" {
				return nil, fmt.Errorf("plan %q is already %s", planID, agentPlansStore[i].Status)
			}
			agentPlansStore[i].Status = "rejected"
			saveAgentPlansLocked()
			pCopy := agentPlansStore[i]
			return &pCopy, nil
		}
	}
	return nil, fmt.Errorf("plan %q not found", planID)
}

func removeString(slice []string, item string) []string {
	var out []string
	for _, s := range slice {
		if !strings.EqualFold(s, item) {
			out = append(out, s)
		}
	}
	return out
}

func handleListAgentPlans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	plans := ListAgentPlans()
	pending := 0
	for _, p := range plans {
		if p.Status == "pending" {
			pending++
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"plans":         plans,
		"pending_count": pending,
	})
}

func handleCreateAgentPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		AgentName string `json:"agent_name"`
		Action    string `json:"action"`
		Target    string `json:"target"`
		ClientIP  string `json:"client_ip"`
		Reason    string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	plan, err := CreateAgentPlan(req.AgentName, req.Action, req.Target, req.ClientIP, req.Reason)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plan)
}

func handleApplyAgentPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.PlanID) == "" {
		sendJSONError(w, "plan_id is required", http.StatusBadRequest)
		return
	}
	plan, err := ApplyAgentPlan(req.PlanID)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plan)
}

func handleDiscardAgentPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.PlanID) == "" {
		sendJSONError(w, "plan_id is required", http.StatusBadRequest)
		return
	}
	plan, err := DiscardAgentPlan(req.PlanID)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(plan)
}
