package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"sync"
)

var (
	apiLastWrite sync.Map // tokenHash -> time.Time
	apiRateLimit sync.Map // tokenHash -> *apiKeyQuota
)

type apiKeyQuota struct {
	Count int
	Reset time.Time
	uMu   sync.Mutex
}

const SessionDuration = 24 * time.Hour

func startAuthWorkers() {
	// Periodic cleanup for login failures and sessions
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			cleanupLoginFailures()
			cleanupSessions()
		}
	}()
}

func cleanupLoginFailures() {
	failureLock.Lock()
	defer failureLock.Unlock()
	for ip, count := range loginFailures {
		if count > 0 {
			loginFailures[ip]--
			if loginFailures[ip] == 0 {
				delete(loginFailures, ip)
			}
		}
	}
}

func cleanupSessions() {
	now := time.Now()
	sessionStore.Range(func(key, value interface{}) bool {
		sess := value.(Session)
		if now.After(sess.ExpiresAt) {
			sessionStore.Delete(key)
		}
		return true
	})
}

func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mutating methods must have the custom header if using session cookies
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			// Skip CSRF check for API Key / Bearer requests
			hasApiKey := r.Header.Get("X-API-Key") != "" || strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !hasApiKey && r.Header.Get("X-Shield-Request") != "true" {
				http.Error(w, "Invalid request: Missing security header", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Try API Token Authentication first
		token := r.Header.Get("X-API-Key")
		if token == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				token = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if token != "" {
			hashed := hashToken(token)

			// 1a. Rate Limiting
			quotaVal, _ := apiRateLimit.LoadOrStore(hashed, &apiKeyQuota{Reset: time.Now().Add(1 * time.Minute)})
			quota := quotaVal.(*apiKeyQuota)

			quota.uMu.Lock()
			if time.Now().After(quota.Reset) {
				quota.Count = 0
				quota.Reset = time.Now().Add(1 * time.Minute)
			}
			quota.Count++
			currentCount := quota.Count
			quota.uMu.Unlock()

			if currentCount > 100 {
				http.Error(w, "API Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			// 1b. Validate & Update LastUsed
			var matchedKey APIKey
			found := false

			configLock.RLock()
			for _, k := range config.APIKeys {
				if k.TokenHash == hashed {
					matchedKey = k
					found = true
					break
				}
			}
			configLock.RUnlock()

			if found {
				required := getRequiredPermission(r)
				if hasPermission(&matchedKey, required) {
					// Throttled LastUsed update
					now := time.Now()
					lastWriteVal, _ := apiLastWrite.LoadOrStore(hashed, time.Time{})
					lastWrite := lastWriteVal.(time.Time)

					if now.Sub(lastWrite) > 1*time.Hour {
						configLock.Lock()
						for i, k := range config.APIKeys {
							if k.TokenHash == hashed {
								config.APIKeys[i].LastUsed = now
								saveConfigNoLock()
								apiLastWrite.Store(hashed, now)
								break
							}
						}
						configLock.Unlock()
					}

					next.ServeHTTP(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "Forbidden: Insufficient permissions", "code": "FORBIDDEN"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized: Invalid token", "code": "UNAUTHORIZED"})
			return
		}

		// 2. Try Session Cookie Authentication
		configLock.RLock()
		hasPwd := config.AdminPasswordHashed != ""
		configLock.RUnlock()

		if !hasPwd {
			renderError(w, "Setup required", "SETUP_REQUIRED", http.StatusForbidden)
			return
		}

		cookie, err := r.Cookie(CookieName)
		if err != nil {
			renderError(w, "Unauthorized", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}

		val, found := sessionStore.Load(cookie.Value)
		if !found {
			renderError(w, "Unauthorized", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}
		sess := val.(Session)
		if time.Now().After(sess.ExpiresAt) {
			sessionStore.Delete(cookie.Value)
			renderError(w, "Unauthorized", "UNAUTHORIZED", http.StatusUnauthorized)
			return
		}

		// 3. API Authorization check
		required := getRequiredPermission(r)
		// (Session user has all permissions essentially, but we could add role checks here)
		_ = required 

		next.ServeHTTP(w, r)
	})
}

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	hasPwd := config.AdminPasswordHashed != ""
	configLock.RUnlock()

	loggedIn := false
	if cookie, err := r.Cookie(CookieName); err == nil {
		if val, found := sessionStore.Load(cookie.Value); found {
			sess := val.(Session)
			if time.Now().Before(sess.ExpiresAt) {
				loggedIn = true
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"need_setup": !hasPwd,
		"logged_in":  loggedIn,
	})
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	configLock.Lock()
	defer configLock.Unlock()

	if config.AdminPasswordHashed != "" {
		http.Error(w, "Already setup", http.StatusConflict)
		return
	}

	var req struct{ Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 12 {
		http.Error(w, "Password too short", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error secure hashing", http.StatusInternalServerError)
		return
	}
	config.AdminPasswordHashed = string(hash)
	saveConfigNoLock()
	slog.Info("Admin setup completed", "ip", strings.Split(r.RemoteAddr, ":")[0])
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := strings.Split(r.RemoteAddr, ":")[0]

	failureLock.Lock()
	if loginFailures[ip] >= 10 {
		failureLock.Unlock()
		slog.Warn("Login blocked due to too many failures", "ip", ip)
		http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
		return
	}
	failureLock.Unlock()

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	configLock.RLock()
	hashed := config.AdminPasswordHashed
	configLock.RUnlock()

	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(req.Password))
	if err != nil {
		failureLock.Lock()
		loginFailures[ip]++
		failureLock.Unlock()

		slog.Warn("Failed login attempt", "ip", ip)
		renderError(w, "Invalid password", "INVALID_PASSWORD", http.StatusUnauthorized)
		return
	}

	// Success - Reset failures
	failureLock.Lock()
	delete(loginFailures, ip)
	failureLock.Unlock()

	// Generate session
	token := generateToken()
	sess := Session{
		Token:     token,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(SessionDuration),
	}
	sessionStore.Store(token, sess)

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   int(SessionDuration.Seconds()),
		SameSite: http.SameSiteLaxMode,
	})

	// Record last login: shift current LastLogin to PreviousLogin, then update
	configLock.Lock()
	if !config.LastLogin.IsZero() {
		config.PreviousLogin = config.LastLogin
	}
	config.LastLogin = time.Now()
	saveConfigNoLock()
	configLock.Unlock()

	slog.Info("Admin logged in", "ip", ip)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(CookieName); err == nil {
		sessionStore.Delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   CookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	w.WriteHeader(http.StatusOK)
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	if err := bcrypt.CompareHashAndPassword([]byte(config.AdminPasswordHashed), []byte(req.Current)); err != nil {
		http.Error(w, "Current password incorrect", http.StatusUnauthorized)
		return
	}

	if len(req.New) < 12 {
		http.Error(w, "New password too short", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error secure hashing", http.StatusInternalServerError)
		return
	}
	config.AdminPasswordHashed = string(hash)
	saveConfigNoLock()

	// Clear all sessions on pwd change
	sessionStore.Range(func(key, value interface{}) bool {
		sessionStore.Delete(key)
		return true
	})

	slog.Info("Admin password changed", "ip", strings.Split(r.RemoteAddr, ":")[0])
	w.WriteHeader(http.StatusOK)
}

func renderError(w http.ResponseWriter, message, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
}

func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func generateToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback for very rare cases if rand.Read fails
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

func hasPermission(key *APIKey, perm string) bool {
	for _, p := range key.Permissions {
		if p == "read:all" || p == perm {
			return true
		}
	}
	return false
}

func getRequiredPermission(r *http.Request) string {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/api/stats"), strings.HasPrefix(path, "/api/history"), strings.HasPrefix(path, "/api/health"):
		return "read:stats"
	case strings.HasPrefix(path, "/api/metrics"):
		return "read:metrics"
	case strings.HasPrefix(path, "/api/queries"), strings.HasPrefix(path, "/api/top-blocked"), strings.HasPrefix(path, "/api/top-clients"), strings.HasPrefix(path, "/api/search"), strings.HasPrefix(path, "/api/export"), strings.HasPrefix(path, "/api/ip-history"):
		return "read:logs"
	case strings.HasPrefix(path, "/api/system-logs"), strings.HasPrefix(path, "/api/diagnostics"), strings.HasPrefix(path, "/api/backup"), strings.HasPrefix(path, "/api/events"):
		return "read:system"
	case strings.HasPrefix(path, "/api/filtering"), strings.HasPrefix(path, "/api/rules"), strings.HasPrefix(path, "/api/full-reload"), strings.HasPrefix(path, "/api/restore"), strings.HasPrefix(path, "/api/reset"), strings.HasPrefix(path, "/api/restart-dns"):
		return "write:filtering"
	case strings.HasPrefix(path, "/api/tokens"), strings.HasPrefix(path, "/api/keys"):
		return "write:system"
	case strings.HasPrefix(path, "/api/config"):
		if r.Method == http.MethodGet {
			return "read:system"
		}
		return "write:filtering"
	}
	return "read:all"
}
