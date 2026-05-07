package main

import (
	"context"
	"crypto/tls"
	"html/template"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var (
	Version        = "v1.11.0"
	Subversion = "0"
	CommitID   = ""
)

var (
	FullVersion  string
	CacheVersion string
	appCtx       context.Context
	appCancel    context.CancelFunc
	testMode     = false
)

func init() {
	// Construct version strings
	vBase := strings.TrimPrefix(Version, "v")
	FullVersion = Version
	CacheVersion = vBase

	if Subversion != "0" && Subversion != "" {
		FullVersion += "." + Subversion
		CacheVersion += "." + Subversion
	}

	if CommitID != "" {
		FullVersion += " (" + CommitID + ")"
	}

	appCtx, appCancel = context.WithCancel(context.Background())
}

func main() {
	initLogging()
	slog.Info("ShieldDNS Backend starting", "version", FullVersion)

	initServices()
	startWorkers()

	// Ensure Corefile is generated with correct settings before starting CoreDNS
	updateCorefile()
	initWebAuthn()

	mux := setupRouter()

	// Apply Ingress Middleware to strip X-Ingress-Path from HA
	finalHandler := ingressMiddleware(securityHeadersMiddleware(csrfMiddleware(mux)))

	// Base server configuration
	adminPort := os.Getenv("ADMIN_PORT")
	if adminPort == "" {
		adminPort = "443"
	}

	ingressPort := os.Getenv("INGRESS_PORT")

	// Capture cert paths for primary server
	certFile := os.Getenv("CERT_FILE")
	if certFile == "" {
		certFile = "/ssl/fullchain.pem"
	}
	keyFile := os.Getenv("KEY_FILE")
	if keyFile == "" {
		keyFile = "/ssl/privkey.pem"
	}

	// 1. Primary Server (Admin UI + DoH)
	primaryServer := &http.Server{
		Addr:         ":" + adminPort,
		Handler:      finalHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // Disable timeout for SSE support
		IdleTimeout:  120 * time.Second,
		ErrorLog:     log.New(&LogWriter{}, "", 0),
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
		},
	}

	go func() {
		if adminPort != "443" {
			slog.Info("Primary Admin server starting", "port", adminPort, "mode", "HTTP")
			if err := primaryServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Primary server stopped", "error", err)
			}
		} else {
			slog.Info("Primary Admin server starting", "port", "443", "mode", "HTTPS")
			if err := primaryServer.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				slog.Error("Primary server stopped", "error", err)
			}
		}
	}()

	// 2. Optional Ingress Server (Home Assistant internal access)
	var auxiliaryServer *http.Server
	if ingressPort != "" && ingressPort != adminPort {
		auxiliaryServer = &http.Server{
			Addr:         ":" + ingressPort,
			Handler:      finalHandler, // Shared handler for both ports
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 0, // Disable timeout for SSE support
			IdleTimeout:  120 * time.Second,
		}
		go func() {
			slog.Info("Ingress secondary server starting", "port", ingressPort)
			if err := auxiliaryServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("Ingress server stopped", "error", err)
			}
		}()
	}

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	slog.Info("Shutting down ShieldDNS...")

	// Cancel context to stop workers
	appCancel()

	// Give servers time to shut down
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := primaryServer.Shutdown(shutdownCtx); err != nil {
		slog.Error("Primary server shutdown error", "error", err)
	}
	if auxiliaryServer != nil {
		if err := auxiliaryServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("Ingress server shutdown error", "error", err)
		}
	}

	// Final log flush
	bufferLock.Lock()
	if len(logBuffer) > 0 {
		flushLogs(logBuffer)
	}
	bufferLock.Unlock()

	if db != nil {
		db.Close()
	}
	slog.Info("Goodbye!")
}

func initLogging() {
	handlerOpts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	if os.Getenv("DEBUG") == "true" {
		handlerOpts.Level = slog.LevelDebug
		debugModeEnabled.Store(true)
	}

	uiHandler := NewSlogUIHandler(os.Stdout, handlerOpts)
	slog.SetDefault(slog.New(uiHandler))

	// Bridge legacy standard log usage into slog
	log.SetOutput(&LogWriter{})
	log.SetFlags(0)
}

func initServices() {
	stats.QueryTypes = make(map[string]int64)
	stats.CoreDNSAlive = true
	initPaths()
	loadConfig()
	initGeo()
	initMalicious()

	// Initialize SQLite
	initDB()
	initializeStatsFromDB()
	initMetrics()

	// Ensure hosts file exists before CoreDNS starts to prevent listener failures
	if _, err := os.Stat(CombinedHostsPath); os.IsNotExist(err) {
		slog.Info("Creating initial empty hosts file")
		os.MkdirAll(filepath.Dir(CombinedHostsPath), 0755)
		os.WriteFile(CombinedHostsPath, []byte("# Initial ShieldDNS hosts file\n"), 0644)
	}
}

func startWorkers() {
	// Start background updater tickers
	go startBackgroundUpdater(appCtx)
	go startMaliciousUpdater(appCtx)
	go startMetadataUpdater(appCtx)
	go StartQPSWorker(appCtx)

	// Trigger initial blocklist and malicious updates in background
	// Sequential execution prevents multiple concurrent CoreDNS restarts
	go func() {
		updateBlocklist(nil, false)
		syncMaliciousIPs(true)
		slog.Info("ShieldDNS Ready: Blocklists and Threat Intelligence loaded")

		// Initial CoreDNS start after everything is ready
		go startCoreDNS(appCtx)
	}()

	// Start health and monitoring
	go startHealthChecker(appCtx)
	go startDNSWatchdog(appCtx)
	go detectServerCountry()

	startAuthWorkers()
	startDNSWorkers(appCtx)
	go startDBWorker(appCtx)
	go startLogWorker(appCtx)
	go startAbuseCleanup(appCtx)
}

func setupRouter() *http.ServeMux {
	mux := http.NewServeMux()

	// Internal DNS-over-HTTPS (DoH) Proxy to CoreDNS
	mux.Handle("/dns-query", DoHRateLimitMiddleware(newDoHProxy()))

	// Auth API (Public but CSRF protected mutations)
	mux.HandleFunc("/api/auth-status", handleAuthStatus)
	mux.HandleFunc("/api/setup", handleSetup)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/mobileconfig", handleMobileConfig)
	mux.HandleFunc("/api/qr", handleQR)

	// Protected API (Authenticated + AuthZ + CSRF)
	mux.Handle("/api/stats", authMiddleware(http.HandlerFunc(handleStats)))
	mux.Handle("/api/stats/history", authMiddleware(http.HandlerFunc(handleStatsHistory)))
	mux.Handle("/api/system-logs", authMiddleware(http.HandlerFunc(handleSystemLogs)))
	mux.Handle("/api/events", authMiddleware(http.HandlerFunc(handleEvents)))
	mux.Handle("/api/diagnostics", authMiddleware(http.HandlerFunc(handleDiagnostics)))
	mux.Handle("/api/diagnostics/recheck", authMiddleware(http.HandlerFunc(handleRecheckUpstreams)))
	mux.Handle("/api/ip-info", authMiddleware(http.HandlerFunc(handleIPInfo)))
	mux.HandleFunc("/api/presets", handlePresets)
	mux.HandleFunc("/api/presets/allow", handlePresetAllowlists)
	mux.HandleFunc("/api/countries", handleGetCountries)
	mux.Handle("/api/system/high-risk-countries", authMiddleware(http.HandlerFunc(handleHighRiskCountries)))
	mux.Handle("/api/system/server-country", authMiddleware(http.HandlerFunc(handleServerCountry)))
	mux.Handle("/api/clients", authMiddleware(http.HandlerFunc(handleGetAllClients)))
	mux.Handle("/api/metrics", authMiddleware(http.HandlerFunc(handleMetrics)))

	mux.Handle("/api/config", authMiddleware(http.HandlerFunc(handleConfig)))
	mux.Handle("/api/refresh", authMiddleware(http.HandlerFunc(handleRefresh)))
	mux.Handle("/api/queries", authMiddleware(http.HandlerFunc(handleQueries)))
	mux.Handle("/api/system/full-reload", authMiddleware(http.HandlerFunc(handleFullReload)))
	mux.Handle("/api/history", authMiddleware(http.HandlerFunc(handleHistory)))
	mux.Handle("/api/search", authMiddleware(http.HandlerFunc(handleSearch)))
	mux.Handle("/api/top-blocked", authMiddleware(http.HandlerFunc(handleTopBlocked)))
	mux.Handle("/api/top-clients", authMiddleware(http.HandlerFunc(handleTopClients)))
	mux.Handle("/api/client/top-domains", authMiddleware(http.HandlerFunc(handleTopDomainsForClient)))
	mux.Handle("/api/client/top-blocked", authMiddleware(http.HandlerFunc(handleClientTopBlocked)))
	mux.Handle("/api/client/stats", authMiddleware(http.HandlerFunc(handleClientStats)))
	mux.Handle("/api/client/alias", authMiddleware(http.HandlerFunc(handleClientAlias)))
	mux.Handle("/api/client/block", authMiddleware(http.HandlerFunc(handleClientBlock)))
	mux.Handle("/api/export", authMiddleware(http.HandlerFunc(handleExport)))
	mux.Handle("/api/backup", authMiddleware(http.HandlerFunc(handleBackup)))
	mux.Handle("/api/restore", authMiddleware(http.HandlerFunc(handleRestore)))
	mux.Handle("/api/logs/clear", authMiddleware(http.HandlerFunc(handleClearLogs)))
	mux.Handle("/api/change-password", authMiddleware(http.HandlerFunc(handleChangePassword)))

	// MFA API
	mux.HandleFunc("/api/mfa/challenge", handleMFAChallenge)
	mux.Handle("/api/mfa/totp/setup", authMiddleware(http.HandlerFunc(handleTOTPSetup)))
	mux.HandleFunc("/api/mfa/totp/verify", handleTOTPVerify)
	mux.Handle("/api/mfa/disable", authMiddleware(http.HandlerFunc(handleMFADisable)))
	mux.Handle("/api/mfa/webauthn/register/start", authMiddleware(http.HandlerFunc(handleWebAuthnRegisterStart)))
	mux.Handle("/api/mfa/webauthn/register/finish", authMiddleware(http.HandlerFunc(handleWebAuthnRegisterFinish)))
	mux.HandleFunc("/api/mfa/webauthn/login/start", handleWebAuthnLoginStart)
	mux.HandleFunc("/api/mfa/webauthn/login/finish", handleWebAuthnLoginFinish)

	mux.Handle("/api/tokens", authMiddleware(http.HandlerFunc(handleGetTokens)))
	mux.Handle("/api/tokens/create", authMiddleware(http.HandlerFunc(handleCreateToken)))
	mux.Handle("/api/tokens/update", authMiddleware(http.HandlerFunc(handleUpdateToken)))
	mux.Handle("/api/tokens/delete", authMiddleware(http.HandlerFunc(handleDeleteToken)))

	mux.Handle("/api/domain/stats", authMiddleware(http.HandlerFunc(handleDomainStats)))
	mux.Handle("/api/domain/clients", authMiddleware(http.HandlerFunc(handleDomainClients)))

	mux.Handle("/api/filtering/toggle", authMiddleware(http.HandlerFunc(handleToggleFiltering)))
	mux.Handle("/api/filtering/status", authMiddleware(http.HandlerFunc(handleFilteringStatus)))
	mux.Handle("/api/rules/add", authMiddleware(http.HandlerFunc(handleRuleAdd)))
	mux.Handle("/api/rules/remove", authMiddleware(http.HandlerFunc(handleRuleRemove)))
	mux.Handle("/api/reset", authMiddleware(http.HandlerFunc(handleReset)))
	mux.Handle("/api/config/reset-lists", authMiddleware(http.HandlerFunc(handleResetLists)))

	// Public API
	mux.HandleFunc("/api/block-info", handleBlockInfo)

	// Health
	mux.HandleFunc("/api/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.Handle("/api/health", authMiddleware(http.HandlerFunc(handleHealth)))

	// Static Files from Embedded FS
	setupStaticHandlers(mux)

	return mux
}

// newDoHProxy creates a reverse proxy to forward /dns-query requests to the internal CoreDNS DoH port.
func newDoHProxy() http.Handler {
	internalPort := os.Getenv("INTERNAL_DOH_PORT")
	if internalPort == "" {
		internalPort = "5553"
	}
	target, _ := url.Parse("https://127.0.0.1:" + internalPort)

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Disable TLS verification for internal proxy to CoreDNS
	proxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		// Suppress error logging if it's just a temporary connection refusal (likely during restart)
		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "i/o timeout") {
			slog.Debug("DoH Proxy temporary unavailability", "error", err)
		} else {
			slog.Error("DoH Proxy Error", "target", target.String(), "error", err)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("ShieldDNS Error: DNS engine (CoreDNS) unreachable. Please check logs."))
	}

	return proxy
}

func setupStaticHandlers(mux *http.ServeMux) {
	// Root filesystem for everything under www/
	wwwFS, err := fs.Sub(WebAssets, "www")
	if err != nil {
		slog.Error("Failed to create sub-filesystem for web assets", "error", err)
		return
	}

	// Specialized filesystem for the admin subdirectory
	adminFS, err := fs.Sub(wwwFS, "admin")
	if err != nil {
		slog.Error("Failed to create sub-filesystem for admin assets", "error", err)
		// Fallback to searching manually if Sub fails, but it shouldn't
	}

	// 1. Admin Index & Assets Handler
	adminHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Header().Set("Location", "admin/")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		if r.URL.Path == "/admin/" || r.URL.Path == "/admin/index.html" {
			// Read from adminFS (which is rooted at www/admin)
			tmplBytes, err := fs.ReadFile(adminFS, "index.html")
			if err != nil {
				slog.Error("Failed to read admin index from embedded FS", "error", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			tmpl, err := template.New("index.html").Parse(string(tmplBytes))
			if err != nil {
				slog.Error("Failed to parse admin index template", "error", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tmpl.Execute(w, struct {
				FullVersion    string
				CacheVersion   string
				CoreDNSVersion string
				OSVersion      string
			}{
				FullVersion:    FullVersion,
				CacheVersion:   CacheVersion,
				CoreDNSVersion: getCoreDNSVersion(),
				OSVersion:      getOSVersion(),
			})
			return
		}

		// Use the specialized adminFS for all other requests under /admin/ (CSS, JS, etc.)
		http.StripPrefix("/admin/", http.FileServer(http.FS(adminFS))).ServeHTTP(w, r)
	}

	mux.HandleFunc("/admin", adminHandler)
	mux.HandleFunc("/admin/", adminHandler)

	// 2. Service Worker Handler
	mux.HandleFunc("/admin/sw.js", func(w http.ResponseWriter, r *http.Request) {
		tmplBytes, err := fs.ReadFile(adminFS, "sw.js")
		if err != nil {
			slog.Error("Failed to read sw.js from embedded FS", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		tmpl, err := template.New("sw.js").Parse(string(tmplBytes))
		if err != nil {
			slog.Error("Failed to parse service worker template", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		tmpl.Execute(w, struct{ CacheVersion string }{CacheVersion: CacheVersion})
	})

	// 2.5 icon.png fallback (HA Ingress looks for this)
	mux.HandleFunc("/icon.png", func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(wwwFS, "logo.png")
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(data)
	})

	// 3. Root landing page and public assets
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		configLock.RLock()
		adminDomain := config.AdminDomain
		isSetupMode := config.AdminPasswordHashed == ""
		configLock.RUnlock()

		// Case 1: Special block/stop pages
		if r.URL.Path == "/blocked" || r.URL.Path == "/stopped" {
			data, err := fs.ReadFile(wwwFS, "blocked.html")
			if err != nil {
				http.Error(w, "Error loading block page", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.Write(data)
			return
		}

		// Case 2: Redirection for blocked domains
		isInternal := strings.HasPrefix(r.URL.Path, "/api/") ||
			r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") ||
			strings.HasPrefix(r.URL.Path, "/favicon.ico") ||
			strings.HasPrefix(r.URL.Path, "/logo.png") ||
			strings.HasPrefix(r.URL.Path, "/icon.png") ||
			strings.HasSuffix(r.URL.Path, ".css") ||
			strings.HasSuffix(r.URL.Path, ".js") ||
			strings.HasSuffix(r.URL.Path, ".json") ||
			r.URL.Path == "/stopped" ||
			r.URL.Path == "/blocked"

		if !isInternal && !isSetupMode && adminDomain != "" && r.Host != adminDomain &&
			!strings.HasPrefix(r.Host, "127.0.0.1") && !strings.HasPrefix(r.Host, "localhost") {
			// Security: Use url.QueryEscape to prevent URI injection/Open Redirect via r.Host
			target := "https://" + adminDomain + "/stopped?domain=" + url.QueryEscape(r.Host)
			http.Redirect(w, r, target, http.StatusFound)
			return
		}

		// Case 3: Root landing page (Server-Side Rendered)
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			tmplBytes, err := fs.ReadFile(wwwFS, "index.html")
			if err != nil {
				http.Error(w, "Error loading landing page template", http.StatusInternalServerError)
				return
			}
			tmpl, err := template.New("index.html").Parse(string(tmplBytes))
			if err != nil {
				http.Error(w, "Error parsing landing page template", http.StatusInternalServerError)
				return
			}
			host := r.Host
			if strings.Contains(host, ":") {
				host = strings.Split(host, ":")[0]
			}
			configLock.RLock()
			signEnabled := config.SignMobileConfig
			configLock.RUnlock()
			w.Header().Set("Content-Type", "text/html")
			tmpl.Execute(w, struct {
				Host         string
				SignEnabled  bool
				FullVersion  string
				CacheVersion string
			}{
				Host:         host,
				SignEnabled:  signEnabled,
				FullVersion:  FullVersion,
				CacheVersion: CacheVersion,
			})
			return
		}

		// Case 4: Static assets
		http.FileServer(http.FS(wwwFS)).ServeHTTP(w, r)
	})
}

func ingressMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ingressPath := r.Header.Get("X-Ingress-Path")
		if ingressPath != "" {
			// Normalize ingressPath to not end with slash
			ingressPath = strings.TrimSuffix(ingressPath, "/")
			if strings.HasPrefix(r.URL.Path, ingressPath) {
				r.URL.Path = strings.TrimPrefix(r.URL.Path, ingressPath)
				if r.URL.Path == "" {
					r.URL.Path = "/"
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
