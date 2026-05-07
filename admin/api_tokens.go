package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

func handleGetTokens(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	defer configLock.RUnlock()

	// Strip hashes before sending to UI
	type TokenInfo struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		Permissions []string  `json:"permissions"`
		CreatedAt   time.Time `json:"created_at"`
		LastUsed    time.Time `json:"last_used"`
	}

	tokens := make([]TokenInfo, len(config.APIKeys))
	for i, k := range config.APIKeys {
		tokens[i] = TokenInfo{
			ID:          k.ID,
			Name:        k.Name,
			Permissions: k.Permissions,
			CreatedAt:   k.CreatedAt,
			LastUsed:    k.LastUsed,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rawToken := generateToken()
	newToken := APIKey{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Name:        req.Name,
		TokenHash:   hashToken(rawToken),
		Permissions: req.Permissions,
		CreatedAt:   time.Now(),
	}

	configLock.Lock()
	config.APIKeys = append(config.APIKeys, newToken)
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleCreateToken", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		configLock.Unlock()
		return
	}
	configLock.Unlock()

	slog.Info("New API token created", "name", req.Name, "id", newToken.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": rawToken,
		"id":    newToken.ID,
	})
}

func handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	newKeys := make([]APIKey, 0)
	for _, k := range config.APIKeys {
		if k.ID != id {
			newKeys = append(newKeys, k)
		}
	}
	config.APIKeys = newKeys
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleDeleteToken", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	slog.Info("API token deleted", "id", id)
	w.WriteHeader(http.StatusOK)
}

func handleUpdateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	for i := range config.APIKeys {
		if config.APIKeys[i].ID == req.ID {
			config.APIKeys[i].Name = req.Name
			config.APIKeys[i].Permissions = req.Permissions
			if err := saveConfigNoLock(); err != nil {
				slog.Error("Failed to save config in handleUpdateToken", "error", err)
				http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
				return
			}
			slog.Info("API token updated", "id", req.ID, "name", req.Name)
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	http.Error(w, "Token not found", http.StatusNotFound)
}
