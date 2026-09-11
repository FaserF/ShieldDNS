package main

import (
	"crypto/tls"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

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
	mux.Handle("/api/system/check-version", authMiddleware(http.HandlerFunc(handleCheckVersion)))
	mux.Handle("/api/system/update", authMiddleware(http.HandlerFunc(handleSystemUpdate)))
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
	mux.Handle("/api/mfa/delete", authMiddleware(http.HandlerFunc(handleMFADelete)))
	mux.Handle("/api/mfa/webauthn/register/start", authMiddleware(http.HandlerFunc(handleWebAuthnRegisterStart)))
	mux.Handle("/api/mfa/webauthn/register/finish", authMiddleware(http.HandlerFunc(handleWebAuthnRegisterFinish)))
	mux.HandleFunc("/api/mfa/webauthn/login/start", handleWebAuthnLoginStart)
	mux.HandleFunc("/api/mfa/webauthn/login/finish", handleWebAuthnLoginFinish)

	mux.Handle("/api/tokens", authMiddleware(http.HandlerFunc(handleGetTokens)))
	mux.Handle("/api/tokens/create", authMiddleware(http.HandlerFunc(handleCreateToken)))
	mux.Handle("/api/tokens/update", authMiddleware(http.HandlerFunc(handleUpdateToken)))
	mux.Handle("/api/tokens/delete", authMiddleware(http.HandlerFunc(handleDeleteToken)))

	// Cluster & Federation API
	mux.Handle("/api/cluster/status", authMiddleware(http.HandlerFunc(handleClusterStatus)))
	mux.HandleFunc("/api/cluster/connection-status", handleClusterConnectionStatus)
	mux.HandleFunc("/api/cluster/join", handleClusterJoin)
	mux.Handle("/api/cluster/sync", authMiddleware(http.HandlerFunc(handleClusterSync)))
	mux.Handle("/api/cluster/leave", authMiddleware(http.HandlerFunc(handleClusterLeave)))
	mux.Handle("/api/cluster/settings", authMiddleware(http.HandlerFunc(handleClusterUpdateSettings)))
	mux.HandleFunc("/api/cluster/replicas/register", handleClusterRegisterReplica)
	mux.HandleFunc("/api/cluster/replicas/sync", handleClusterGetReplicaConfig)
	mux.Handle("/api/cluster/replicas/revoke", authMiddleware(http.HandlerFunc(handleClusterRevokeReplica)))
	mux.HandleFunc("/api/cluster/logs/ingest", handleClusterIngestLogs)
	mux.Handle("/api/cluster/worker-script", authMiddleware(http.HandlerFunc(handleClusterWorkerScript)))

	// MCP (Model Context Protocol) API
	mux.HandleFunc("/api/mcp", handleMCP)

	mux.Handle("/api/domain/stats", authMiddleware(http.HandlerFunc(handleDomainStats)))
	mux.Handle("/api/domain/clients", authMiddleware(http.HandlerFunc(handleDomainClients)))

	mux.Handle("/api/filtering/toggle", authMiddleware(http.HandlerFunc(handleToggleFiltering)))
	mux.Handle("/api/filtering/status", authMiddleware(http.HandlerFunc(handleFilteringStatus)))
	mux.Handle("/api/rules/add", authMiddleware(http.HandlerFunc(handleRuleAdd)))
	mux.Handle("/api/rules/remove", authMiddleware(http.HandlerFunc(handleRuleRemove)))
	mux.Handle("/api/routing/rules", authMiddleware(http.HandlerFunc(handleRoutingRules)))
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

type retryTransport struct {
	transport  http.RoundTripper
	maxRetries int
	retryDelay time.Duration
}

func (r *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for i := 0; i <= r.maxRetries; i++ {
		resp, err = r.transport.RoundTrip(req)
		if err == nil {
			return resp, nil
		}

		if i < r.maxRetries {
			time.Sleep(r.retryDelay)
		}
	}
	return nil, err
}

// newDoHProxy creates a reverse proxy to forward /dns-query requests to the internal CoreDNS DoH port.
func newDoHProxy() http.Handler {
	internalPort := os.Getenv("INTERNAL_DOH_PORT")
	if internalPort == "" {
		internalPort = "5553"
	}
	target, _ := url.Parse("https://127.0.0.1:" + internalPort)

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Internal proxy to CoreDNS running on loopback 127.0.0.1:5553.
	// CoreDNS uses the public domain cert (e.g. dns.fabiseitz.de), so skip verification for loopback.
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	baseTransport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
	}

	proxy.Transport = &retryTransport{
		transport:  baseTransport,
		maxRetries: 3,
		retryDelay: 50 * time.Millisecond,
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

	// Pre-parse the admin templates once at startup for high performance
	adminTmpl, tmplErr := template.ParseFS(adminFS, "index.html", "views/*.html", "partials/*.html")
	if tmplErr != nil {
		slog.Error("Failed to pre-parse admin index templates", "error", tmplErr)
	}

	// 1. Admin Index & Assets Handler
	adminHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Header().Set("Location", "admin/")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		if r.URL.Path == "/admin/" || r.URL.Path == "/admin/index.html" {
			tmpl := adminTmpl
			if tmpl == nil {
				var err error
				tmpl, err = template.ParseFS(adminFS, "index.html", "views/*.html", "partials/*.html")
				if err != nil {
					slog.Error("Failed to parse admin index templates", "error", err)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
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
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
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

	// 2.6 manifest.json route (for root/PWA requests)
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(adminFS, "manifest.json")
		if err != nil {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/manifest+json")
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

		// Shortcut redirections: /master, /primary, /slave, /replica
		pathLower := strings.TrimRight(strings.ToLower(r.URL.Path), "/")
		if pathLower == "/master" || pathLower == "/primary" {
			configLock.RLock()
			target := "/admin/"
			if config.ClusterRole == "replica" && config.ClusterPrimaryURL != "" {
				target = strings.TrimRight(config.ClusterPrimaryURL, "/") + "/admin/"
			}
			configLock.RUnlock()
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
			return
		}
		if pathLower == "/slave" || pathLower == "/replica" {
			configLock.RLock()
			target := "/admin/"
			if config.ClusterRole == "primary" && len(config.ClusterReplicas) > 0 {
				for _, rep := range config.ClusterReplicas {
					if rep.URL != "" {
						target = strings.TrimRight(rep.URL, "/") + "/admin/"
						break
					}
				}
			}
			configLock.RUnlock()
			http.Redirect(w, r, target, http.StatusTemporaryRedirect)
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
			retentionDays := config.RetentionDays
			anonymizeIPs := config.AnonymizeClientIPs
			preferEncrypted := config.PreferEncrypted
			stripECS := config.StripECS
			dnsRebinding := config.DNSRebindingProtection
			filteringEnabled := config.FilteringEnabled
			clusterRole := config.ClusterRole
			clusterInstType := config.ClusterInstanceType
			clusterPrimaryURL := config.ClusterPrimaryURL
			workerDomain := config.ClusterWorkerDomain
			configLock.RUnlock()

			// Trust worker: If ClusterWorkerDomain is set and Host matches or request passed through worker
			effectiveHost := host
			if workerDomain != "" {
				// Display the worker domain for DoH/DoT endpoints
				effectiveHost = workerDomain
			}

			isPrivate := clusterInstType == "private"
			isHybrid := clusterInstType == "hybrid"
			isReplica := clusterRole == "replica"

			w.Header().Set("Content-Type", "text/html")
			tmpl.Execute(w, struct {
				Host              string
				SignEnabled       bool
				FullVersion       string
				CacheVersion      string
				RetentionDays     int
				AnonymizeIPs      bool
				PreferEncrypted   bool
				StripECS          bool
				DNSRebinding      bool
				FilteringEnabled  bool
				ClusterRole       string
				InstanceType      string
				IsPrivate         bool
				IsHybrid          bool
				IsReplica         bool
				PrimaryURL        string
				WorkerDomain      string
			}{
				Host:              effectiveHost,
				SignEnabled:       signEnabled && !isPrivate,
				FullVersion:       FullVersion,
				CacheVersion:      CacheVersion,
				RetentionDays:     retentionDays,
				AnonymizeIPs:      anonymizeIPs,
				PreferEncrypted:   preferEncrypted,
				StripECS:          stripECS,
				DNSRebinding:      dnsRebinding,
				FilteringEnabled:  filteringEnabled,
				ClusterRole:       clusterRole,
				InstanceType:      clusterInstType,
				IsPrivate:         isPrivate,
				IsHybrid:          isHybrid,
				IsReplica:         isReplica,
				PrimaryURL:        clusterPrimaryURL,
				WorkerDomain:      workerDomain,
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
