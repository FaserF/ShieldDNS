package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"html/template"
)

const Version        = "v1.2.0"

func main() {
	stats.QueryTypes = make(map[string]int64)
	initPaths()
	loadConfig()

	// Initialize SQLite
	initDB()

	// Start background updater
	go startBackgroundUpdater()

	// Start health checker
	go startHealthChecker()
	go startDBWorker()
	go startLogWorker()

	// Ensure Corefile is generated with correct settings before starting CoreDNS
	updateCorefile()

	// Start CoreDNS management
	go startCoreDNS()

	// Logging
	log.SetOutput(&LogWriter{})

	// Auth API
	http.HandleFunc("/api/auth-status", handleAuthStatus)
	http.HandleFunc("/api/setup", handleSetup)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/mobileconfig", handleMobileConfig)
	// Dashboard Data
	http.Handle("/api/stats", authMiddleware(http.HandlerFunc(handleStats)))
	http.Handle("/api/system-logs", authMiddleware(http.HandlerFunc(handleSystemLogs)))
	http.Handle("/api/events", authMiddleware(http.HandlerFunc(handleEvents)))
	http.Handle("/api/diagnostics", authMiddleware(http.HandlerFunc(handleDiagnostics)))
	http.Handle("/api/ip-info", authMiddleware(http.HandlerFunc(handleIPInfo)))
	http.Handle("/api/presets", authMiddleware(http.HandlerFunc(handlePresets)))
	http.Handle("/api/presets/allow", authMiddleware(http.HandlerFunc(handlePresetAllowlists)))

	// Protected API
	http.Handle("/api/config", authMiddleware(http.HandlerFunc(handleConfig)))
	http.Handle("/api/refresh", authMiddleware(http.HandlerFunc(handleRefresh)))
	http.Handle("/api/queries", authMiddleware(http.HandlerFunc(handleQueries)))
	http.Handle("/api/history", authMiddleware(http.HandlerFunc(handleHistory)))
	http.Handle("/api/search", authMiddleware(http.HandlerFunc(handleSearch)))
	http.Handle("/api/top-blocked", authMiddleware(http.HandlerFunc(handleTopBlocked)))
	http.Handle("/api/top-clients", authMiddleware(http.HandlerFunc(handleTopClients)))
	http.Handle("/api/export", authMiddleware(http.HandlerFunc(handleExport)))
	http.Handle("/api/backup", authMiddleware(http.HandlerFunc(handleBackup)))
	http.Handle("/api/restore", authMiddleware(http.HandlerFunc(handleRestore)))
	http.Handle("/api/change-password", authMiddleware(http.HandlerFunc(handleChangePassword)))
	
	// API Tokens
	http.Handle("/api/tokens", authMiddleware(http.HandlerFunc(handleGetTokens)))
	http.Handle("/api/tokens/create", authMiddleware(http.HandlerFunc(handleCreateToken)))
	http.Handle("/api/tokens/update", authMiddleware(http.HandlerFunc(handleUpdateToken)))
	http.Handle("/api/tokens/delete", authMiddleware(http.HandlerFunc(handleDeleteToken)))
	
	// Global Controls & Rules
	http.Handle("/api/filtering/toggle", authMiddleware(http.HandlerFunc(handleToggleFiltering)))
	http.Handle("/api/filtering/status", authMiddleware(http.HandlerFunc(handleFilteringStatus)))
	http.Handle("/api/rules/add", authMiddleware(http.HandlerFunc(handleRuleAdd)))
	http.Handle("/api/rules/remove", authMiddleware(http.HandlerFunc(handleRuleRemove)))
	http.Handle("/api/reset", authMiddleware(http.HandlerFunc(handleReset)))
	http.Handle("/api/config/reset-lists", authMiddleware(http.HandlerFunc(handleResetLists)))
	
	// Public API
	http.HandleFunc("/api/block-info", handleBlockInfo)
	
	// Health
	http.HandleFunc("/api/health/live", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	http.Handle("/api/health", authMiddleware(http.HandlerFunc(handleHealth)))

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

	// Static Files: Admin UI at /admin and Public Page at /
	adminFs := http.FileServer(http.Dir(webRoot + "/admin"))
	http.Handle("/admin/", http.StripPrefix("/admin/", adminFs))
	http.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusMovedPermanently)
	})

	// Catch-all for the public landing page (index.html in webRoot)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		configLock.RLock()
		adminDomain := config.AdminDomain
		configLock.RUnlock()

		// Case 1: Special block page route (publicly accessible)
		if r.URL.Path == "/blocked" {
			http.ServeFile(w, r, webRoot+"/blocked.html")
			return
		}

		// Case 2: Redirection for blocked domains
		// If the requested Host doesn't match our AdminDomain and isn't a local address, redirect to block page
		if adminDomain != "" && r.Host != adminDomain && !strings.HasPrefix(r.Host, "127.0.0.1") && !strings.HasPrefix(r.Host, "localhost") {
			// We redirect to the official HTTPS block page on the admin domain
			// This avoids SSL certificate errors for the landing page itself
			target := "https://" + adminDomain + "/blocked?domain=" + r.Host
			http.Redirect(w, r, target, http.StatusFound)
			return
		}

		// Case 3: Root landing page (Server-Side Rendered to inject Host)
		if r.URL.Path == "/" {
			tmpl, err := template.ParseFiles(webRoot + "/index.html")
			if err != nil {
				http.Error(w, "Error loading landing page", http.StatusInternalServerError)
				return
			}
			host := r.Host
			if strings.Contains(host, ":") {
				host = strings.Split(host, ":")[0]
			}
			tmpl.Execute(w, struct{ Host string }{Host: host})
			return
		}

		// Case 4: Static assets
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

	go func() {
		if adminPort != "443" {
			log.Printf("ShieldDNS Admin starting on :%s (HTTP internal proxy)", adminPort)
			if err := http.ListenAndServe(":"+adminPort, nil); err != nil {
				log.Printf("Admin UI server stopped: %v", err)
			}
		} else {
			log.Println("ShieldDNS Admin starting on :443 (HTTPS)")
			if err := http.ListenAndServeTLS(":443", certFile, keyFile, nil); err != nil {
				log.Printf("Admin UI server stopped: %v", err)
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
