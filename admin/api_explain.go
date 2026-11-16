package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// handleExplainDecision handles GET /api/explain?domain=...&client_ip=...&qtype=...&ask_ai=...
func handleExplainDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	clientIP := r.URL.Query().Get("client_ip")
	qtype := r.URL.Query().Get("qtype")
	askAI := strings.EqualFold(r.URL.Query().Get("ask_ai"), "true") || r.URL.Query().Get("ask_ai") == "1"

	exp, err := ExplainResolution(domain, clientIP, qtype, askAI)
	if err != nil {
		sendJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exp)
}
