package main

import (
	"context"
	"crypto/tls"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
)

var (
	Version        = "v1.11.0"
	Subversion = "1"
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

	// If configured as replica with sync interval or on startup, trigger initial sync in background
	go func() {
		time.Sleep(3 * time.Second) // wait for local server to be ready
		configLock.RLock()
		role := config.ClusterRole
		pURL := config.ClusterPrimaryURL
		pTok := config.ClusterPrimaryToken
		iType := config.ClusterInstanceType
		failover := config.ClusterFailoverMode
		interval := config.ClusterSyncInterval
		configLock.RUnlock()

		if role == "replica" && pURL != "" && pTok != "" {
			slog.Info("Cluster replica: starting background sync with Primary", "primary", pURL)
			if err := performReplicaSync(pURL, pTok, iType, failover); err != nil {
				atomic.StoreInt32(&clusterConnLost, 1)
				clusterLastSyncError = err.Error()
				slog.Warn("Cluster replica initial sync failed: continuing with cached configuration", "error", err)
			} else {
				atomic.StoreInt32(&clusterConnLost, 0)
				clusterLastSyncError = ""
				slog.Info("Cluster replica initial sync succeeded")
			}

			// Periodic sync if interval configured (> 0 minutes)
			if interval > 0 {
				ticker := time.NewTicker(time.Duration(interval) * time.Minute)
				for range ticker.C {
					configLock.RLock()
					currRole := config.ClusterRole
					currPURL := config.ClusterPrimaryURL
					currPTok := config.ClusterPrimaryToken
					currIType := config.ClusterInstanceType
					currFailover := config.ClusterFailoverMode
					configLock.RUnlock()

					if currRole != "replica" || currPURL == "" {
						break
					}
					if err := performReplicaSync(currPURL, currPTok, currIType, currFailover); err != nil {
						atomic.StoreInt32(&clusterConnLost, 1)
						clusterLastSyncError = err.Error()
						slog.Warn("Cluster periodic sync failed", "error", err)
					} else {
						atomic.StoreInt32(&clusterConnLost, 0)
						clusterLastSyncError = ""
					}
				}
			}
		}
	}()

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
		},
	}

	// 2. HTTP/3 Server (DoH3 on port 443 UDP, alongside HTTP/2 on TCP)
	var h3Server *http3.Server
	configLock.RLock()
	doh3Active := config.DoH3Enabled
	configLock.RUnlock()

	if doh3Active && adminPort == "443" && certFile != "" && keyFile != "" {
		h3Server = &http3.Server{
			Addr:    ":443",
			Handler: finalHandler,
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		}
		// Wrap handler to advertise HTTP/3 support via Alt-Svc header
		primaryServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := h3Server.SetQUICHeaders(w.Header()); err != nil {
				slog.Debug("Failed to set QUIC headers", "error", err)
			}
			finalHandler.ServeHTTP(w, r)
		})
		go func() {
			slog.Info("HTTP/3 DoH server starting", "port", "443", "mode", "QUIC/UDP")
			if err := h3Server.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP/3 server stopped", "error", err)
			}
		}()
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
	if h3Server != nil {
		if err := h3Server.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP/3 server shutdown error", "error", err)
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
	go startAutoUpdateWorker(appCtx)
}

