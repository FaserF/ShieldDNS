package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

func handleGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configLock.RLock()
		groups := append([]ClientGroup(nil), config.Groups...)
		configLock.RUnlock()
		if groups == nil {
			groups = []ClientGroup{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"groups": groups})

	case http.MethodPost:
		var req ClientGroup
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" {
			http.Error(w, "Group name is required", http.StatusBadRequest)
			return
		}
		if req.ID == "" {
			req.ID = uuid.NewString()
		}

		configLock.Lock()
		updated := false
		for i, g := range config.Groups {
			if g.ID == req.ID {
				config.Groups[i] = req
				updated = true
				break
			}
		}
		if !updated {
			config.Groups = append(config.Groups, req)
		}
		saveConfigNoLock()
		configLock.Unlock()

		ReloadPolicySnapshot()
		RecordAuditEvent(r, "group.upsert", req.ID, req.Name)
		RecordAnnotation("group.updated", "admin", "Group updated: "+req.Name)
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "group": req})

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "Missing id", http.StatusBadRequest)
			return
		}
		configLock.Lock()
		filtered := make([]ClientGroup, 0, len(config.Groups))
		for _, g := range config.Groups {
			if g.ID != id {
				filtered = append(filtered, g)
			}
		}
		config.Groups = filtered
		saveConfigNoLock()
		configLock.Unlock()

		ReloadPolicySnapshot()
		RecordAuditEvent(r, "group.delete", id, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleSchedules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configLock.RLock()
		schedules := append([]ScheduleRule(nil), config.Schedules...)
		configLock.RUnlock()
		if schedules == nil {
			schedules = []ScheduleRule{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"schedules": schedules})

	case http.MethodPost:
		var req ScheduleRule
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		if req.Name == "" || req.StartTime == "" || req.EndTime == "" {
			http.Error(w, "Name, start_time, and end_time are required", http.StatusBadRequest)
			return
		}
		if req.Action == "" {
			req.Action = "block_all"
		}
		if req.ID == "" {
			req.ID = uuid.NewString()
		}

		configLock.Lock()
		updated := false
		for i, s := range config.Schedules {
			if s.ID == req.ID {
				config.Schedules[i] = req
				updated = true
				break
			}
		}
		if !updated {
			config.Schedules = append(config.Schedules, req)
		}
		saveConfigNoLock()
		configLock.Unlock()

		ReloadPolicySnapshot()
		RecordAuditEvent(r, "schedule.upsert", req.ID, req.Name)
		RecordAnnotation("schedule.updated", "admin", "Schedule updated: "+req.Name)
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "schedule": req})

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "Missing id", http.StatusBadRequest)
			return
		}
		configLock.Lock()
		filtered := make([]ScheduleRule, 0, len(config.Schedules))
		for _, s := range config.Schedules {
			if s.ID != id {
				filtered = append(filtered, s)
			}
		}
		config.Schedules = filtered
		saveConfigNoLock()
		configLock.Unlock()

		ReloadPolicySnapshot()
		RecordAuditEvent(r, "schedule.delete", id, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleLocalRecords(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		configLock.RLock()
		recs := append([]LocalRecord(nil), config.LocalRecords...)
		autoPTR := config.AutoPTR
		configLock.RUnlock()
		if recs == nil {
			recs = []LocalRecord{}
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"records": recs, "auto_ptr": autoPTR})

	case http.MethodPost:
		var req LocalRecord
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
		req.Type = strings.ToUpper(strings.TrimSpace(req.Type))
		req.Value = strings.TrimSpace(req.Value)
		if req.Domain == "" || req.Type == "" || req.Value == "" {
			http.Error(w, "Domain, type, and value are required", http.StatusBadRequest)
			return
		}
		switch req.Type {
		case "A", "AAAA", "CNAME", "TXT", "MX", "SRV", "PTR":
		default:
			http.Error(w, "Unsupported record type", http.StatusBadRequest)
			return
		}
		if req.ID == "" {
			req.ID = uuid.NewString()
		}

		configLock.Lock()
		updated := false
		for i, rec := range config.LocalRecords {
			if rec.ID == req.ID {
				config.LocalRecords[i] = req
				updated = true
				break
			}
		}
		if !updated {
			config.LocalRecords = append(config.LocalRecords, req)
		}
		saveConfigNoLock()
		configLock.Unlock()

		ReloadPolicySnapshot()
		RecordAuditEvent(r, "local_record.upsert", req.Domain, req.Type+" -> "+req.Value)
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "record": req})

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "Missing id", http.StatusBadRequest)
			return
		}
		configLock.Lock()
		filtered := make([]LocalRecord, 0, len(config.LocalRecords))
		for _, rec := range config.LocalRecords {
			if rec.ID != id {
				filtered = append(filtered, rec)
			}
		}
		config.LocalRecords = filtered
		saveConfigNoLock()
		configLock.Unlock()

		ReloadPolicySnapshot()
		RecordAuditEvent(r, "local_record.delete", id, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleQuickRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		now := time.Now()
		configLock.RLock()
		active := make([]QuickRule, 0, len(config.QuickRules))
		for _, qr := range config.QuickRules {
			if qr.ExpiresAt == nil || now.Before(*qr.ExpiresAt) {
				active = append(active, qr)
			}
		}
		configLock.RUnlock()
		writeJSON(w, http.StatusOK, map[string]interface{}{"rules": active})

	case http.MethodPost:
		var body struct {
			Domain      string `json:"domain"`
			IsAllowlist bool   `json:"is_allowlist"`
			GroupID     string `json:"group_id"`
			ClientIP    string `json:"client_ip"`
			TTLMinutes  int    `json:"ttl_minutes"`
			Reason      string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		body.Domain = strings.TrimSpace(body.Domain)
		if body.Domain == "" {
			http.Error(w, "Domain or /regex/ is required", http.StatusBadRequest)
			return
		}
		now := time.Now()
		qr := QuickRule{
			ID:          uuid.NewString(),
			Domain:      body.Domain,
			IsAllowlist: body.IsAllowlist,
			GroupID:     body.GroupID,
			ClientIP:    body.ClientIP,
			Reason:      body.Reason,
			CreatedAt:   now,
		}
		if body.TTLMinutes > 0 {
			exp := now.Add(time.Duration(body.TTLMinutes) * time.Minute)
			qr.ExpiresAt = &exp
		}

		configLock.Lock()
		config.QuickRules = append(config.QuickRules, qr)
		saveConfigNoLock()
		configLock.Unlock()

		ReloadPolicySnapshot()
		RecordAuditEvent(r, "quick_rule.add", qr.Domain, qr.Reason)
		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "rule": qr})

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, "Missing id", http.StatusBadRequest)
			return
		}
		configLock.Lock()
		filtered := make([]QuickRule, 0, len(config.QuickRules))
		for _, qr := range config.QuickRules {
			if qr.ID != id {
				filtered = append(filtered, qr)
			}
		}
		config.QuickRules = filtered
		saveConfigNoLock()
		configLock.Unlock()

		ReloadPolicySnapshot()
		RecordAuditEvent(r, "quick_rule.delete", id, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
