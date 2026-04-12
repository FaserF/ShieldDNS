package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestSessionManagement(t *testing.T) {
	// Setup
	configLock.Lock()
	pwd := "test-password-123"
	hash, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	config = Config{
		AdminPasswordHashed: string(hash),
	}
	configLock.Unlock()

	// 1. Test Login generates session
	loginBody, _ := json.Marshal(map[string]string{"password": pwd})
	req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(loginBody))
	rr := httptest.NewRecorder()
	handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Login failed: %v", rr.Code)
	}

	cookie := rr.Result().Cookies()[0]
	if cookie.Name != CookieName {
		t.Errorf("Expected cookie name %s, got %s", CookieName, cookie.Name)
	}

	token := cookie.Value
	if _, found := sessionStore.Load(token); !found {
		t.Error("Session not found in sessionStore after login")
	}

	// 2. Test Auth Middleware with session
	handler := authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqAuth := httptest.NewRequest("GET", "/api/stats", nil)
	reqAuth.AddCookie(cookie)
	rrAuth := httptest.NewRecorder()
	handler.ServeHTTP(rrAuth, reqAuth)

	if rrAuth.Code != http.StatusOK {
		t.Errorf("Auth middleware rejected valid session: %v", rrAuth.Code)
	}

	// 3. Test Logout
	reqLogout := httptest.NewRequest("POST", "/api/logout", nil)
	reqLogout.AddCookie(cookie)
	rrLogout := httptest.NewRecorder()
	handleLogout(rrLogout, reqLogout)

	if _, found := sessionStore.Load(token); found {
		t.Error("Session still found in sessionStore after logout")
	}

	// 4. Test Expired Session
	expiredToken := "expired-token"
	sessionStore.Store(expiredToken, Session{
		Token:     expiredToken,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	})

	reqExp := httptest.NewRequest("GET", "/api/stats", nil)
	reqExp.AddCookie(&http.Cookie{Name: CookieName, Value: expiredToken})
	rrExp := httptest.NewRecorder()
	handler.ServeHTTP(rrExp, reqExp)

	if rrExp.Code != http.StatusUnauthorized {
		t.Errorf("Expected unauthorized for expired session, got %v", rrExp.Code)
	}
}

func TestLoginThrottling(t *testing.T) {
	configLock.Lock()
	config = Config{AdminPasswordHashed: "some-hash"}
	configLock.Unlock()

	ip := "1.2.3.4"
	failureLock.Lock()
	loginFailures[ip] = 10
	failureLock.Unlock()

	loginBody, _ := json.Marshal(map[string]string{"password": "wrong"})
	req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(loginBody))
	req.RemoteAddr = ip + ":1234"
	rr := httptest.NewRecorder()
	handleLogin(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 for throttled login, got %v", rr.Code)
	}

	// Test cleanup
	cleanupLoginFailures()
	failureLock.Lock()
	count := loginFailures[ip]
	failureLock.Unlock()
	if count != 9 {
		t.Errorf("Expected failure count to decay to 9, got %d", count)
	}
}
