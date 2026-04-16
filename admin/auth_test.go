package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHandleLoginRateLimit(t *testing.T) {
	// Reset failures for this test
	failureLock.Lock()
	loginFailures = make(map[string]int)
	failureLock.Unlock()

	// Mock password in config
	password := "testpassword123"
	hashed, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	configLock.Lock()
	config.AdminPasswordHashed = string(hashed)
	configLock.Unlock()

	handler := http.HandlerFunc(handleLogin)

	// 1. Test failed attempts (up to 10)
	for i := 1; i <= 10; i++ {
		req, _ := http.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"wrong"}`))
		req.RemoteAddr = "1.2.3.4:1234"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Attempt %d: expected 401, got %d", i, rr.Code)
		}
	}

	// 2. 11th attempt should be blocked (429)
	req, _ := http.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"wrong"}`))
	req.RemoteAddr = "1.2.3.4:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("11th attempt: expected 429, got %d", rr.Code)
	}

	// 3. Different IP should still be allowed to try
	req, _ = http.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"wrong"}`))
	req.RemoteAddr = "5.6.7.8:1234"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Attempt from other IP: expected 401, got %d", rr.Code)
	}

	// 4. Test success resets failures
	// First, simulate some failures for a new IP
	failureLock.Lock()
	loginFailures["9.9.9.9"] = 5
	failureLock.Unlock()

	req, _ = http.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"`+password+`"}`))
	req.RemoteAddr = "9.9.9.9:1234"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Correct login: expected 200, got %d", rr.Code)
	}

	failureLock.Lock()
	if loginFailures["9.9.9.9"] != 0 {
		t.Errorf("Expected failures to be reset to 0, got %d", loginFailures["9.9.9.9"])
	}
	failureLock.Unlock()
}

func TestCSRFProtection(t *testing.T) {
	// Handler with csrfMiddleware
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := csrfMiddleware(inner)

	// 1. POST without header should fail with 403 Forbidden
	req, _ := http.NewRequest("POST", "/api/rules", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("POST without X-Shield-Request: expected 403, got %d", rr.Code)
	}

	// 2. POST with header 'true' should succeed
	req, _ = http.NewRequest("POST", "/api/rules", nil)
	req.Header.Set("X-Shield-Request", "true")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("POST with X-Shield-Request=true: expected 200, got %d", rr.Code)
	}

	// 3. POST with API Key should skip CSRF check
	req, _ = http.NewRequest("POST", "/api/rules", nil)
	req.Header.Set("X-API-Key", "dummy")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("POST with API Key: expected 200, got %d", rr.Code)
	}

	// 4. GET should not require header
	req, _ = http.NewRequest("GET", "/api/stats", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET without header: expected 200, got %d", rr.Code)
	}
}
