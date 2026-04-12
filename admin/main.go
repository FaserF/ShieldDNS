package main

import (
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	Version        = "v1.6.1-dev+91e88fd"
	Subversion = "0"
	CommitID   = ""
)

var (
	FullVersion  string
	CacheVersion string
)

func main() {
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

	// Initialize Structured Logging
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
	log.SetFlags(0) // slog handles timestamps

	slog.Info("ShieldDNS Backend starting", "version", Version)

	stats.QueryTypes = make(map[string]int64)
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

	// Start background updater ticker
	go startBackgroundUpdater()
	go startMaliciousUpdater()
	go startMetadataUpdater()

	// Trigger initial blocklist update in background
	go updateBlocklist(nil)
	go syncMaliciousIPs()

	// Start health checker
	go startHealthChecker()
	go startDNSWatchdog()
	
	// Server setup
	startAuthWorkers()
	startDNSWorkers()
	go startDBWorker()
	go startLogWorker()
	go startAbuseCleanup()

	// Ensure Corefile is generated with correct settings before starting CoreDNS
	updateCorefile()

	// Start CoreDNS management
	go startCoreDNS()

	// Setup Router
	mux := http.NewServeMux()

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

	// Public API (Truly public, no auth required)
	mux.HandleFunc("/api/block-info", handleBlockInfo)

	// Health
	mux.HandleFunc("/api/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	mux.Handle("/api/health", authMiddleware(http.HandlerFunc(handleHealth)))

	// Get cert/key paths
	certFile := os.Getenv("CERT_FILE")
	if certFile == "" {
		certFile = "/ssl/fullchain.pem"
	}
	keyFile := os.Getenv("KEY_FILE")
	if keyFile == "" {
		keyFile = "/ssl/privkey.pem"
	}

	webRoot := os.Getenv("WEB_ROOT")
	if webRoot == "" {
		webRoot = "/var/www/admin"
	}

	// Static Files: Admin UI
	// 1. Specialized handler for the main admin index (template-aware for version injection)
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		// Only handle exactly /admin/ or /admin/index.html as a template
		if r.URL.Path == "/admin/" || r.URL.Path == "/admin/index.html" {
			tmpl, err := template.ParseFiles(webRoot + "/admin/index.html")
			if err != nil {
				slog.Error("Failed to parse admin index template", "error", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			tmpl.Execute(w, struct {
				FullVersion  string
				CacheVersion string
			}{
				FullVersion:  FullVersion,
				CacheVersion: CacheVersion,
			})
			return
		}

		// Otherwise serve as static (js, css, icons)
		adminFs := http.FileServer(http.Dir(webRoot + "/admin"))
		http.StripPrefix("/admin/", adminFs).ServeHTTP(w, r)
	})

	// 2. Specialized handler for sw.js (template-aware for version injection)
	mux.HandleFunc("/admin/sw.js", func(w http.ResponseWriter, r *http.Request) {
		// We use text/template to avoid HTML escaping in JS
		tmpl, err := template.New("sw.js").ParseFiles(webRoot + "/admin/sw.js")
		if err != nil {
			slog.Error("Failed to parse service worker template", "error", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		tmpl.Execute(w, struct{ CacheVersion string }{CacheVersion: CacheVersion})
	})

	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	})

	// Catch-all for the public landing page (index.html in webRoot)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		configLock.RLock()
		adminDomain := config.AdminDomain
		isSetupMode := config.AdminPasswordHashed == ""
		configLock.RUnlock()

		// Case 1: Special block/stop page route (publicly accessible)
		if r.URL.Path == "/blocked" || r.URL.Path == "/stopped" {
			http.ServeFile(w, r, webRoot+"/blocked.html")
			return
		}

		// Case 2: Redirection for blocked domains
		isInternal := strings.HasPrefix(r.URL.Path, "/api/") ||
			strings.HasPrefix(r.URL.Path, "/admin/") ||
			strings.HasPrefix(r.URL.Path, "/favicon.ico") ||
			strings.HasPrefix(r.URL.Path, "/logo.png") ||
			r.URL.Path == "/stopped" ||
			r.URL.Path == "/blocked"

		if !isInternal && !isSetupMode && adminDomain != "" && r.Host != adminDomain &&
			!strings.HasPrefix(r.Host, "127.0.0.1") && !strings.HasPrefix(r.Host, "localhost") {
			target := "https://" + adminDomain + "/stopped?domain=" + r.Host
			http.Redirect(w, r, target, http.StatusFound)
			return
		}

		// Case 3: Root landing page (Server-Side Rendered)
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			tmpl, err := template.ParseFiles(webRoot + "/index.html")
			if err != nil {
				http.Error(w, "Error loading landing page", http.StatusInternalServerError)
				return
			}
			host := r.Host
			if strings.Contains(host, ":") {
				host = strings.Split(host, ":")[0]
			}
			configLock.RLock()
			signEnabled := config.SignMobileConfig
			configLock.RUnlock()
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
		if r.URL.Path == "/logo.png" {
			http.ServeFile(w, r, webRoot+"/logo.png")
			return
		}

		fs := http.FileServer(http.Dir(webRoot))
		fs.ServeHTTP(w, r)
	})

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	adminPort := os.Getenv("ADMIN_PORT")
	if adminPort == "" {
		adminPort = "443"
	}

	// Apply unified security middleware (Headers + CSRF)
	finalHandler := securityHeadersMiddleware(csrfMiddleware(mux))

	go func() {
		if adminPort != "443" {
			slog.Info("ShieldDNS Admin starting", "port", adminPort, "mode", "HTTP internal proxy")
			if err := http.ListenAndServe(":"+adminPort, finalHandler); err != nil {
				slog.Error("Admin UI server stopped", "error", err)
			}
		} else {
			slog.Info("ShieldDNS Admin starting", "port", "443", "mode", "HTTPS")
			if err := http.ListenAndServeTLS(":443", certFile, keyFile, finalHandler); err != nil {
				slog.Error("Admin UI server stopped", "error", err)
			}
		}
	}()

	<-stop
	log.Println("Shutting down ShieldDNS...")

	// Final log flush
	bufferLock.Lock()
	if len(logBuffer) > 0 {
		flushLogs(logBuffer)
	}
	bufferLock.Unlock()

	if db != nil {
		db.Close()
	}
	log.Println("Goodbye!")
}
