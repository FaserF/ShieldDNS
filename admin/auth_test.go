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
