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

// ChangeAnnotation marks a significant configuration, list, filtering, or operator event on timeline charts.
type ChangeAnnotation struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Kind      string    `json:"kind"` // "config", "blocklist", "filtering", "restart", "ai_audit", "rule", "note"
	Actor     string    `json:"actor"`
	Summary   string    `json:"summary"`
}

const maxChangeAnnotations = 200

var (
	annotationsMu     sync.RWMutex
	annotationsStore  []ChangeAnnotation
	annotationsLoaded bool
)

func annotationsFilePath() string {
	return filepath.Join(DataDir, "annotations.json")
}

func loadAnnotationsLocked() {
	if annotationsLoaded {
		return
	}
	annotationsLoaded = true
	b, err := os.ReadFile(annotationsFilePath())
	if err != nil {
		return
	}
	var list []ChangeAnnotation
	if err := json.Unmarshal(b, &list); err == nil {
		annotationsStore = list
	}
}

func saveAnnotationsLocked() {
	if DataDir == "" {
		return
	}
	b, err := json.MarshalIndent(annotationsStore, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(annotationsFilePath()), 0755)
	_ = atomicWriteFile(annotationsFilePath(), b)
}

// RecordAnnotation appends a new change marker and trims the ring buffer to maxChangeAnnotations.
func RecordAnnotation(kind, actor, summary string) ChangeAnnotation {
	summary = strings.TrimSpace(summary)
	if len(summary) > 200 {
		summary = summary[:200]
	}
	if actor == "" {
		actor = "system"
	}
	if kind == "" {
		kind = "note"
	}

	now := time.Now().UTC()
	entry := ChangeAnnotation{
		ID:        fmt.Sprintf("ann_%d", now.UnixNano()),
		Timestamp: now,
		Kind:      kind,
		Actor:     actor,
		Summary:   summary,
	}

	annotationsMu.Lock()
	defer annotationsMu.Unlock()
	loadAnnotationsLocked()
	annotationsStore = append(annotationsStore, entry)
	if len(annotationsStore) > maxChangeAnnotations {
		annotationsStore = annotationsStore[len(annotationsStore)-maxChangeAnnotations:]
	}
	saveAnnotationsLocked()
	return entry
}

// GetAnnotations returns recent change markers in reverse chronological order.
func GetAnnotations(limit int) []ChangeAnnotation {
	if limit <= 0 || limit > maxChangeAnnotations {
		limit = 100
	}
	annotationsMu.Lock()
	loadAnnotationsLocked()
	n := len(annotationsStore)
	if n == 0 {
		annotationsMu.Unlock()
		return []ChangeAnnotation{}
	}
	start := n - limit
	if start < 0 {
		start = 0
	}
	out := make([]ChangeAnnotation, 0, n-start)
	for i := n - 1; i >= start; i-- {
		out = append(out, annotationsStore[i])
	}
	annotationsMu.Unlock()
	return out
}

func resetAnnotationsForTest() {
	annotationsMu.Lock()
	defer annotationsMu.Unlock()
	annotationsStore = nil
	annotationsLoaded = true
}

func handleAnnotations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"annotations": GetAnnotations(100),
		})
	case http.MethodPost:
		var req struct {
			Kind    string `json:"kind"`
			Actor   string `json:"actor"`
			Summary string `json:"summary"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Summary) == "" {
			sendJSONError(w, "summary is required", http.StatusBadRequest)
			return
		}
		if req.Kind == "" {
			req.Kind = "note"
		}
		if req.Actor == "" {
			req.Actor = "admin"
		}
		entry := RecordAnnotation(req.Kind, req.Actor, req.Summary)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entry)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
