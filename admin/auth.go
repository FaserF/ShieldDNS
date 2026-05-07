package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
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
			cleanupRateLimits()
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

func cleanupRateLimits() {
	now := time.Now()
	// Cleanup API rate limit quotas that haven't been reset in over 1 hour
	apiRateLimit.Range(func(key, value interface{}) bool {
		quota := value.(*apiKeyQuota)
		if now.After(quota.Reset.Add(1 * time.Hour)) {
			apiRateLimit.Delete(key)
		}
		return true
	})

	// Cleanup API last write timestamps older than 24h
	apiLastWrite.Range(func(key, value interface{}) bool {
		lastUpdate := value.(time.Time)
		if now.Sub(lastUpdate) > 24*time.Hour {
			apiLastWrite.Delete(key)
		}
		return true
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Strict Transport Security (HSTS)
		// Only set if served over HTTPS or if we know it's a secure environment
		// max-age is 1 year
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// 2. Prevent MIME-Type Sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// 3. Clickjacking Protection
		// SAMEORIGIN allows the page to be displayed in a frame on the same origin as the page itself.
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")

		// 4. XSS Protection (Legacy but still useful for some browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// 5. Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// 6. Content Security Policy (CSP)
		// Dynamically discover configured Admin domain for whitelisting
		configLock.RLock()
		adminDomain := config.AdminDomain
		configLock.RUnlock()

		dynamicHosts := ""
		if adminDomain != "" {
			dynamicHosts = " https://" + adminDomain
			if net.ParseIP(adminDomain) == nil {
				dynamicHosts += " https://*." + adminDomain
			}
		}

		// Allows self-hosted assets, Google Fonts, and verified CDNs
		// script-src: 'self', 'unsafe-inline' (for templates)
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net" + dynamicHosts + "; " +
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://use.fontawesome.com https://cdnjs.cloudflare.com; " +
			"font-src 'self' https://fonts.gstatic.com https://use.fontawesome.com https://cdnjs.cloudflare.com; " +
			"img-src 'self' data: https://flagcdn.com https://raw.githubusercontent.com" + dynamicHosts + "; " +
			"connect-src 'self' https://api.github.com https://fonts.googleapis.com https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://flagcdn.com https://raw.githubusercontent.com" + dynamicHosts + "; " +
			"worker-src 'self'; " +
			"manifest-src 'self'; " +
			"frame-ancestors 'self'" + dynamicHosts + "; " +
			"base-uri 'none';"

		w.Header().Set("Content-Security-Policy", csp)

		// 7. Permissions Policy (Disable unneeded browser features)
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), xr-spatial-tracking=()")

		next.ServeHTTP(w, r)
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

		// Security: Bind session to IP and User-Agent
		clientIP := getClientIP(r)

		if sess.RemoteIP != clientIP || sess.UserAgent != r.UserAgent() {
			slog.Warn("Session identity mismatch: possibly hijaked or changed connection",
				"expected_ip", sess.RemoteIP, "actual_ip", clientIP,
				"expected_ua", sess.UserAgent, "actual_ua", r.UserAgent())
			sessionStore.Delete(cookie.Value)
			renderError(w, "Session invalid: connection changed", "SESSION_MISMATCH", http.StatusUnauthorized)
			return
		}

		// 4. MFA Enforcement
		configLock.RLock()
		mfaEnabled := config.MFAEnabled
		configLock.RUnlock()

		if mfaEnabled && !sess.MFAVerified {
			renderError(w, "MFA required", "MFA_REQUIRED", http.StatusForbidden)
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
			if time.Now().Before(sess.ExpiresAt) && sess.MFAVerified {
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
	ip := getClientIP(r)

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
		count := loginFailures[ip]
		loginFailures[ip]++
		failureLock.Unlock()

		slog.Warn("Failed login attempt", "ip", ip, "failure_count", count+1)

		// Brute-force cooling: Artificial delay for repeated failures
		if count >= 3 && !testMode {
			time.Sleep(2 * time.Second)
		}

		renderError(w, "Invalid password", "INVALID_PASSWORD", http.StatusUnauthorized)
		return
	}

	// Success - Reset failures
	failureLock.Lock()
	delete(loginFailures, ip)
	failureLock.Unlock()

	// Generate session
	token := generateToken()

	configLock.RLock()
	mfaEnabled := config.MFAEnabled
	configLock.RUnlock()

	sess := Session{
		Token:       token,
		RemoteIP:    ip,
		UserAgent:   r.UserAgent(),
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(SessionDuration),
		MFAVerified: !mfaEnabled, // Will be false if MFA is enabled
	}
	sessionStore.Store(token, sess)

	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
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
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"mfa_required": mfaEnabled,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(CookieName); err == nil {
		sessionStore.Delete(cookie.Value)
	}
	isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		MaxAge:   -1,
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

func getClientIP(r *http.Request) string {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	// Handle X-Forwarded-For if behind a proxy like HA Ingress
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain a list of IPs, take the first one
		clientIP = strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	return clientIP
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
		// Master permission or exact match
		if p == "admin:all" || p == "read:all" || p == perm {
			return true
		}
		// Hierarchical shortcuts
		if (perm == "read:health") && (p == "read:stats" || p == "read:system" || p == "read:diagnostics" || p == "read:config") {
			return true
		}
	}
	return false
}

func getRequiredPermission(r *http.Request) string {
	path := r.URL.Path
	method := r.Method

	switch {
	case strings.HasPrefix(path, "/api/health"):
		return "read:health"
	case strings.HasPrefix(path, "/api/stats"), strings.HasPrefix(path, "/api/history"), strings.HasPrefix(path, "/api/metrics"), strings.HasPrefix(path, "/api/clients"):
		return "read:stats"
	case strings.HasPrefix(path, "/api/queries"), strings.HasPrefix(path, "/api/top-"), strings.HasPrefix(path, "/api/search"), strings.HasPrefix(path, "/api/export"), strings.HasPrefix(path, "/api/ip-history"), strings.HasPrefix(path, "/api/domain/"):
		return "read:logs"
	case strings.HasPrefix(path, "/api/diagnostics"):
		if method == http.MethodPost {
			return "write:maintenance"
		}
		return "read:diagnostics"
	case strings.HasPrefix(path, "/api/system-logs"), strings.HasPrefix(path, "/api/events"):
		return "read:system"
	case strings.HasPrefix(path, "/api/config"):
		if method == http.MethodGet {
			return "read:config"
		}
		return "write:config"
	case strings.HasPrefix(path, "/api/rules"), strings.HasPrefix(path, "/api/toggle"), strings.HasPrefix(path, "/api/client/"), strings.HasPrefix(path, "/api/filtering"):
		if method == http.MethodGet {
			return "read:rules"
		}
		return "write:rules"
	case strings.HasPrefix(path, "/api/refresh"), strings.HasPrefix(path, "/api/logs/clear"), strings.HasPrefix(path, "/api/system/full-reload"), strings.HasPrefix(path, "/api/restore"), strings.HasPrefix(path, "/api/reset"), strings.HasPrefix(path, "/api/restart-dns"), strings.HasPrefix(path, "/api/backup"):
		return "write:maintenance"
	case strings.HasPrefix(path, "/api/tokens"), strings.HasPrefix(path, "/api/keys"):
		return "write:system"
	}
	return "admin:all"
}
