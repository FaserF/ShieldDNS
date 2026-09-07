package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
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

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	hasPwd := config.AdminPasswordHashed != ""
	hasPasskey := len(config.WebAuthnCredentials) > 0
	configLock.RUnlock()

	loggedIn := false
	mfaRequired := false
	if cookie, err := r.Cookie(CookieName); err == nil {
		if val, found := sessionStore.Load(cookie.Value); found {
			sess := val.(Session)
			if time.Now().Before(sess.ExpiresAt) {
				if sess.MFAVerified {
					loggedIn = true
				} else {
					mfaRequired = true
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"need_setup":   !hasPwd,
		"logged_in":    loggedIn,
		"mfa_required": mfaRequired,
		"has_passkey":  hasPasskey,
	})
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	configLock.Lock()
	defer configLock.Unlock()

	if config.AdminPasswordHashed != "" {
		http.Error(w, "Already setup", http.StatusConflict)
		return
	}

	var req struct {
		Mode         string `json:"mode"` // "standalone", "primary", "replica"
		Password     string `json:"password"`
		InstanceType string `json:"instance_type"` // "private" or "public"
		PrimaryURL   string `json:"primary_url"`
		APIToken     string `json:"api_token"`
		FailoverMode bool   `json:"failover_mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.InstanceType != "public" && req.InstanceType != "private" && req.InstanceType != "hybrid" {
		req.InstanceType = "private"
	}
	config.ClusterInstanceType = req.InstanceType

	if req.Mode == "replica" {
		if req.PrimaryURL == "" || req.APIToken == "" {
			http.Error(w, "Primary URL and API Token are required for replica setup", http.StatusBadRequest)
			return
		}
		// Temporarily unlock configLock to call join logic
		configLock.Unlock()
		joinReq, _ := json.Marshal(map[string]interface{}{
			"primary_url":   req.PrimaryURL,
			"api_token":     req.APIToken,
			"instance_type": req.InstanceType,
			"failover_mode": req.FailoverMode,
			"name":          "Secondary Node",
		})
		joinHTTPReq, _ := http.NewRequest(http.MethodPost, "/api/cluster/join", bytes.NewReader(joinReq))
		joinHTTPReq.RemoteAddr = r.RemoteAddr
		joinRec := &bufferedResponseWriter{header: make(http.Header), body: new(bytes.Buffer)}
		handleClusterJoin(joinRec, joinHTTPReq)
		configLock.Lock()

		if joinRec.code != 0 && joinRec.code != http.StatusOK {
			http.Error(w, "Failed to connect to Primary: "+joinRec.body.String(), joinRec.code)
			return
		}

		slog.Info("Cluster replica setup completed", "primary", req.PrimaryURL)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"mode":    "replica",
			"message": "Connected to Primary node. You can log in using your Primary admin password.",
		})
		return
	}

	// Standalone or Primary mode requires password
	if len(req.Password) < 12 {
		http.Error(w, "Password too short (minimum 12 characters)", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error secure hashing", http.StatusInternalServerError)
		return
	}
	config.AdminPasswordHashed = string(hash)
	config.SetupDone = true
	if req.Mode == "primary" {
		config.ClusterRole = "primary"
	} else {
		config.ClusterRole = "standalone"
	}

	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleSetup", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	slog.Info("Admin setup completed", "ip", strings.Split(r.RemoteAddr, ":")[0], "role", config.ClusterRole, "instance_type", config.ClusterInstanceType)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

type bufferedResponseWriter struct {
	header http.Header
	body   *bytes.Buffer
	code   int
}

func (b *bufferedResponseWriter) Header() http.Header         { return b.header }
func (b *bufferedResponseWriter) Write(p []byte) (int, error) { return b.body.Write(p) }
func (b *bufferedResponseWriter) WriteHeader(statusCode int)  { b.code = statusCode }

func handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)

	failureLock.Lock()
	if loginFailures[ip] >= 10 {
		failureLock.Unlock()
		if !testMode {
			slog.Warn("Login blocked due to too many failures", "ip", ip)
		}
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

		if !testMode {
			slog.Warn("Failed login attempt", "ip", ip, "failure_count", count+1)
		}

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
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleLogin (update session)", "error", err)
	}
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

	if config.ClusterRole == "replica" {
		http.Error(w, "Forbidden: Password changes are managed centrally on the Primary node", http.StatusForbidden)
		return
	}

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
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleTokenLogin", "error", err)
	}

	// Clear all sessions on pwd change
	sessionStore.Range(func(key, value interface{}) bool {
		sessionStore.Delete(key)
		return true
	})

	slog.Info("Admin password changed", "ip", strings.Split(r.RemoteAddr, ":")[0])
	w.WriteHeader(http.StatusOK)
}

