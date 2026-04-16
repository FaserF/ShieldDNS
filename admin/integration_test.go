package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFullSystemLifecycle(t *testing.T) {
	// 1. Initial State: Need Setup
	req, _ := http.NewRequest("GET", "/api/auth-status", nil)
	rr := httptest.NewRecorder()
	http.HandlerFunc(handleAuthStatus).ServeHTTP(rr, req)

	var status map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &status)
	if status["need_setup"] != true {
		t.Errorf("Expected need_setup=true, got %v", status["need_setup"])
	}

	// 2. Perform Setup
	setupBody, _ := json.Marshal(map[string]string{"password": "testpassword123"})
	req, _ = http.NewRequest("POST", "/api/setup", bytes.NewBuffer(setupBody))
	req.Header.Set("Content-Type", "application/json")
	// Note: Setup doesn't require CSRF header yet as per current implementation,
	// but we applied csrfMiddleware in main.go. For tests, we'll bypass middleware
	// or use the unified handler.

	rr = httptest.NewRecorder()
	http.HandlerFunc(handleSetup).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Setup failed: %v", rr.Body.String())
	}

	// 3. Login
	loginBody, _ := json.Marshal(map[string]string{"password": "testpassword123"})
	req, _ = http.NewRequest("POST", "/api/login", bytes.NewBuffer(loginBody))
	rr = httptest.NewRecorder()
	http.HandlerFunc(handleLogin).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Login failed: %v", rr.Body.String())
	}

	cookie := rr.Result().Header.Get("Set-Cookie")
	if cookie == "" {
		t.Fatal("No session cookie set")
	}
	sessionCookie := strings.Split(strings.Split(cookie, ";")[0], "=")[1]

	// 4. Test CSRF Protection (Mutating request without header should fail)
	ruleBody, _ := json.Marshal(map[string]string{
		"domain": "blocked-by-test.com",
		"type":   "block",
	})
	req, _ = http.NewRequest("POST", "/api/rules/add", bytes.NewBuffer(ruleBody))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sessionCookie})

	rr = httptest.NewRecorder()
	// Use the middleware-wrapped handler
	handler := authMiddleware(http.HandlerFunc(handleRuleAdd))
	csrfHandler := csrfMiddleware(handler)
	csrfHandler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for missing CSRF header, got %v", rr.Code)
	}

	// 5. Successful Mutation (With Header)
	req, _ = http.NewRequest("POST", "/api/rules/add", bytes.NewBuffer(ruleBody))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sessionCookie})
	req.Header.Set("X-Shield-Request", "true")

	rr = httptest.NewRecorder()
	csrfHandler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("Rule add failed with CSRF header: %v", rr.Body.String())
	}

	// 6. Verify Search
	req, _ = http.NewRequest("GET", "/api/search?q=blocked-by-test.com", nil)
	rr = httptest.NewRecorder()
	http.HandlerFunc(handleSearch).ServeHTTP(rr, req)

	var searchResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &searchResp)
	if searchResp["blocked"] != true {
		t.Errorf("Search failed: domain not blocked")
	}
}
