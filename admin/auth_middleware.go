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
)

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Strict Transport Security (HSTS)
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		// 2. Prevent MIME-Type Sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// 3. Clickjacking Protection
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")

		// 4. XSS Protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// 5. Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// 6. Content Security Policy (CSP)
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

		// 7. Permissions Policy
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), xr-spatial-tracking=()")

		next.ServeHTTP(w, r)
	})
}

func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			hasApiKey := r.Header.Get("X-API-Key") != "" || strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || r.URL.Query().Get("token") != "" || strings.HasPrefix(r.URL.Path, "/api/mcp")
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
		if token == "" {
			token = r.URL.Query().Get("token")
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
					now := time.Now()
					lastWriteVal, _ := apiLastWrite.LoadOrStore(hashed, time.Time{})
					lastWrite := lastWriteVal.(time.Time)

					if now.Sub(lastWrite) > 1*time.Hour {
						configLock.Lock()
						for i, k := range config.APIKeys {
							if k.TokenHash == hashed {
								config.APIKeys[i].LastUsed = now
								if err := saveConfigNoLock(); err != nil {
									slog.Error("Failed to save config in authMiddleware", "error", err)
								}
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

		if mfaEnabled && !sess.MFAVerified && !isMFAEndpoint(r.URL.Path) {
			renderError(w, "MFA required", "MFA_REQUIRED", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func renderError(w http.ResponseWriter, message, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
}

func getClientIP(r *http.Request) string {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
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
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

func hasPermission(key *APIKey, perm string) bool {
	for _, p := range key.Permissions {
		if p == "admin:all" || p == "read:all" || p == perm {
			return true
		}
		if perm == "read:config" && (p == "cluster:sync" || p == "write:config") {
			return true
		}
		if perm == "read:health" && p == "proxy:worker" {
			return true
		}
		if (perm == "read:health") && (p == "read:stats" || p == "read:system" || p == "read:diagnostics" || p == "read:config" || p == "cluster:sync") {
			return true
		}
	}
	return false
}

func getRequiredPermission(r *http.Request) string {
	path := r.URL.Path
	method := r.Method

	switch {
	case strings.HasPrefix(path, "/api/cluster/replicas/"):
		return "cluster:sync"
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
	case strings.HasPrefix(path, "/api/mcp"):
		return "exec:mcp"
	}
	return "admin:all"
}

func isMFAEndpoint(path string) bool {
	return strings.HasPrefix(path, "/api/mfa/totp/verify") ||
		strings.HasPrefix(path, "/api/mfa/webauthn/login") ||
		path == "/api/mfa/status"
}
