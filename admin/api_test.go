package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware(t *testing.T) {
	// Initialize minimal config
	config = Config{
		APIKeys: []APIKey{
			{
				ID: "test-1",
				Name: "Read Only",
				TokenHash: hashToken("test-token-read"),
				Permissions: []string{"read:stats"},
			},
			{
				ID: "test-2",
				Name: "Full Access",
				TokenHash: hashToken("test-token-full"),
				Permissions: []string{"read:all"},
			},
		},
		AdminPasswordHashed: "dummy-hash",
	}

	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name       string
		token      string
		path       string
		method     string
		wantStatus int
	}{
		{"No Token", "", "/api/stats", "GET", http.StatusUnauthorized},
		{"Valid Read Token", "test-token-read", "/api/stats", "GET", http.StatusOK},
		{"Forbidden Write", "test-token-read", "/api/filtering/toggle", "POST", http.StatusForbidden},
		{"Valid Full Token Write", "test-token-full", "/api/filtering/toggle", "POST", http.StatusOK},
		{"Invalid Token", "bad-token", "/api/stats", "GET", http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.token != "" {
				req.Header.Set("X-API-Key", tt.token)
			}
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("got status %v, want %v", rr.Code, tt.wantStatus)
			}
		})
	}
}

func TestNoAPIKeysRejectsAll(t *testing.T) {
	config = Config{ APIKeys: []APIKey{} }
	
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("X-API-Key", "any-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("got status %v, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestToggleFiltering(t *testing.T) {
	config = Config{ FilteringEnabled: true }
	
	reqBody, _ := json.Marshal(map[string]bool{"enabled": false})
	req := httptest.NewRequest("POST", "/api/filtering/toggle", bytes.NewBuffer(reqBody))
	rr := httptest.NewRecorder()
	
	handleToggleFiltering(rr, req)
	
	if rr.Code != http.StatusOK {
		t.Errorf("got status %v, want %d", rr.Code, http.StatusOK)
	}
	
	if config.FilteringEnabled != false {
		t.Error("FilteringEnabled should be false")
	}
}
