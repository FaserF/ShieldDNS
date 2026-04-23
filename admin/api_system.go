package main

import (
	"archive/zip"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var activeSSEClients atomic.Int32

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "version": Version})
}

func AddSystemLog(line string) {
	// Add timestamp for UI display if not present
	if !strings.HasPrefix(line, "[") {
		line = fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line)
	}

	systemLogLock.Lock()
	systemLogBuffer = append(systemLogBuffer, line)
	if len(systemLogBuffer) > 500 {
		systemLogBuffer = systemLogBuffer[1:]
	}
	// Notify clients
	clients := make([]chan string, 0, len(systemLogClients))
	for ch := range systemLogClients {
		clients = append(clients, ch)
	}
	systemLogLock.Unlock()

	for _, ch := range clients {
		select {
		case ch <- line:
		default:
		}
	}
}

var debugModeEnabled atomic.Bool

func DebugLog(msg string) {
	if debugModeEnabled.Load() {
		slog.Debug(msg)
	}
}

// SlogUIHandler is a custom slog.Handler that writes JSON to a writer
// and plain text to the ShieldDNS UI system log buffer.
type SlogUIHandler struct {
	jsonHandler slog.Handler
}

func NewSlogUIHandler(w io.Writer, opts *slog.HandlerOptions) *SlogUIHandler {
	return &SlogUIHandler{
		jsonHandler: slog.NewJSONHandler(w, opts),
	}
}

func (h *SlogUIHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.jsonHandler.Enabled(ctx, level)
}

func (h *SlogUIHandler) Handle(ctx context.Context, r slog.Record) error {
	// 1. Send to System UI Log (Human Readable)
	levelStr := ""
	if r.Level != slog.LevelInfo {
		levelStr = "[" + r.Level.String() + "] "
	}

	// Extract attributes for UI log
	attrs := ""
	r.Attrs(func(a slog.Attr) bool {
		attrs += fmt.Sprintf(" %s=%v", a.Key, a.Value.Any())
		return true
	})

	AddSystemLog(levelStr + r.Message + attrs)

	// 2. Pass to JSON Handler (Machine Readable)
	return h.jsonHandler.Handle(ctx, r)
}

func (h *SlogUIHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SlogUIHandler{jsonHandler: h.jsonHandler.WithAttrs(attrs)}
}

func (h *SlogUIHandler) WithGroup(name string) slog.Handler {
	return &SlogUIHandler{jsonHandler: h.jsonHandler.WithGroup(name)}
}

var noiseLogTracker sync.Map // IP -> lastLogTime

type LogWriter struct{}

func (w *LogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg == "" {
		return len(p), nil
	}

	// Suppress noisy TLS and HTTP/2 handshake errors (e.g. from probes, bots, or premature client disconnects)
	// These are handled by the standard library but logged to the error log, creating unnecessary noise.
	isTLS := strings.Contains(msg, "http: TLS handshake error")
	isHTTP2 := strings.Contains(msg, "http2: server: error reading preface")

	if isTLS || isHTTP2 {
		noisePatterns := []string{
			"EOF",
			"i/o timeout",
			"connection reset by peer",
			"unknown certificate",
			"bad certificate",
			"bad record MAC",
			"remote error",
			"broken pipe",
		}

		isNoise := isHTTP2
		if !isNoise {
			for _, pattern := range noisePatterns {
				if strings.Contains(msg, pattern) {
					isNoise = true
					break
				}
			}
		}

		if isNoise {
			// Extract IP from log message to allow automated blocking
			ip := extractIPFromLog(msg)

			if ip != "" {
				// Suppression: Only log once every 5 minutes per IP to avoid "log-flooding" by bots
				now := time.Now()
				if last, ok := noiseLogTracker.Load(ip); ok {
					if now.Sub(last.(time.Time)) < 5*time.Minute {
						// still allow auto-block check below, but skip the Info log
						goto blockCheck
					}
				}
				noiseLogTracker.Store(ip, now)

				// Log as Info with an English explanation as requested by the user
				slog.Info("[Bot/Scanner Activity] " + msg + " -- Note: This message is typically caused by automated scanners, bots, or interrupted connections. It does not indicate a problem with ShieldDNS.")
			}

		blockCheck:
			// Auto-block if Abuse Detection is enabled and it's not a critical IP
			if ip != "" {
				configLock.RLock()
				abuseEnabled := config.AbuseDetectionEnabled
				configLock.RUnlock()
				if abuseEnabled {
					go blockClientAuto(ip, "threat:bot_scanner")
				}
			}
			return len(p), nil
		}
	}

	slog.Info(msg)
	return len(p), nil
}

func handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	if activeSSEClients.Load() >= 50 {
		http.Error(w, "Server busy: too many active streams", http.StatusServiceUnavailable)
		return
	}
	activeSSEClients.Add(1)
	defer activeSSEClients.Add(-1)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan string, 50)
	systemLogLock.Lock()
	systemLogClients[ch] = struct{}{}
	// Send existing history
	for _, line := range systemLogBuffer {
		fmt.Fprintf(w, "data: %s\n\n", line)
	}
	systemLogLock.Unlock()

	defer func() {
		systemLogLock.Lock()
		delete(systemLogClients, ch)
		systemLogLock.Unlock()
	}()

	flusher, _ := w.(http.Flusher)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case line := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		case <-ticker.C:
			// Heartbeat comment to keep connection alive
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
func handleEvents(w http.ResponseWriter, r *http.Request) {
	if activeSSEClients.Load() >= 50 {
		http.Error(w, "Server busy: too many active streams", http.StatusServiceUnavailable)
		return
	}
	activeSSEClients.Add(1)
	defer activeSSEClients.Add(-1)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := make(chan Query, 500) // Increased buffer for high query volume
	sseLock.Lock()
	sseClients[ch] = struct{}{}
	sseLock.Unlock()

	defer func() {
		sseLock.Lock()
		delete(sseClients, ch)
		sseLock.Unlock()
		DebugLog("SSE client disconnected")
	}()

	flusher, _ := w.(http.Flusher)
	flusher.Flush()
	DebugLog("SSE client connected")

	// Send initial ping to keep connection alive
	fmt.Fprintf(w, "data: {\"type\":\"ping\"}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case q := <-ch:
			data, _ := json.Marshal(q)
			fmt.Fprintf(w, "data: %s\n\n", string(data))
			flusher.Flush()
		case <-ticker.C:
			// Heartbeat comment to keep connection alive
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func getSystemStats() map[string]interface{} {
	stats := make(map[string]interface{})

	fillCPUStats(stats)
	fillRAMStats(stats)
	fillUptimeStats(stats)
	fillDiskStats(stats)
	fillShieldStats(stats)

	return stats
}

func handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	certFile := os.Getenv("CERT_FILE")
	if certFile == "" {
		certFile = "/ssl/fullchain.pem"
	}

	data, err := os.ReadFile(certFile)
	if err != nil {
		http.Error(w, "Could not read cert file", http.StatusNotFound)
		return
	}

	block, _ := pem.Decode(data)
	if block == nil {
		http.Error(w, "Failed to decode PEM", http.StatusInternalServerError)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		// Fallback for self-signed if default fails or file missing
		fallbackPath := filepath.Join(DataDir, "ssl", "selfsigned.crt")
		if data, err = os.ReadFile(fallbackPath); err == nil {
			block, _ = pem.Decode(data)
			if block != nil {
				cert, err = x509.ParseCertificate(block.Bytes)
			}
		}
	}

	if cert == nil || err != nil {
		http.Error(w, "Failed to parse certificate", http.StatusInternalServerError)
		return
	}

	latencyLock.RLock()
	lats := make(map[string]string)
	latsRaw := make(map[string]time.Duration)
	for k, v := range latencyMap {
		lats[k] = v.String()
		latsRaw[k] = v
	}
	latencyLock.RUnlock()

	healthLock.RLock()
	hUp := make(map[string]bool)
	for _, u := range healthyUpstreams {
		hUp[u] = true
	}
	hDoT := make(map[string]bool)
	for _, u := range healthyDoT {
		hDoT[u] = true
	}
	healthLock.RUnlock()

	configLock.RLock()
	allUpstreams := config.Upstreams
	allDoT := config.UpstreamDoT
	preferEncrypted := config.PreferEncrypted
	smartSelection := config.UseFastestUpstream
	configLock.RUnlock()

	healthLock.RLock()
	var preferredServer string
	if preferEncrypted && len(healthyDoT) > 0 {
		preferredServer = "tls://" + healthyDoT[0]
	} else if len(healthyUpstreams) > 0 {
		preferredServer = healthyUpstreams[0]
	}
	healthLock.RUnlock()

	type UpstreamHealth struct {
		Server      string  `json:"server"`
		Status      string  `json:"status"`
		LatencyMs   float64 `json:"latency_ms"`
		IsPreferred bool    `json:"is_preferred"`
	}

	var upstreamHealth []UpstreamHealth
	for _, u := range allUpstreams {
		status := "down"
		healthLock.RLock()
		for _, hu := range healthyUpstreams {
			if hu == u {
				status = "up"
				break
			}
		}
		healthLock.RUnlock()

		latMs := 0.0
		latencyLock.RLock()
		if d, ok := latencyMap[u]; ok {
			latMs = float64(d.Microseconds()) / 1000.0
		}
		latencyLock.RUnlock()

		upstreamHealth = append(upstreamHealth, UpstreamHealth{
			Server:      u,
			Status:      status,
			LatencyMs:   latMs,
			IsPreferred: u == preferredServer,
		})
	}
	for _, u := range allDoT {
		fullUrl := "tls://" + u
		status := "down"
		healthLock.RLock()
		for _, hu := range healthyDoT {
			if hu == u {
				status = "up"
				break
			}
		}
		healthLock.RUnlock()

		latMs := 0.0
		latencyLock.RLock()
		if d, ok := latencyMap[u]; ok {
			latMs = float64(d.Microseconds()) / 1000.0
		}
		latencyLock.RUnlock()

		upstreamHealth = append(upstreamHealth, UpstreamHealth{
			Server:      fullUrl,
			Status:      status,
			LatencyMs:   latMs,
			IsPreferred: fullUrl == preferredServer,
		})
	}
	if upstreamHealth == nil {
		upstreamHealth = []UpstreamHealth{}
	}

	selectionMode := "Manual"
	if smartSelection {
		if config.SmartSelectionPolicy == "random" {
			selectionMode = "Smart Selection (Random Load Balancing)"
		} else {
			selectionMode = "Smart Selection (Lowest Latency)"
		}
	}

	info := map[string]interface{}{
		"certificate": map[string]interface{}{
			"issuer":      cert.Issuer.String(),
			"subject":     cert.Subject.String(),
			"not_after":   cert.NotAfter.Format(time.RFC3339),
			"not_before":  cert.NotBefore.Format(time.RFC3339),
			"dns_names":   cert.DNSNames,
			"valid":       !time.Now().After(cert.NotAfter),
			"self_signed": cert.Issuer.String() == cert.Subject.String(),
		},
		"selection_mode":  selectionMode,
		"upstream_health": upstreamHealth,
	}

	// Merge system stats into info (flatten)
	systemStats := getSystemStats()
	for k, v := range systemStats {
		info[k] = v
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func handleBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=shielddns-backup.zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	// 1. Snapshot the database consistently to a temporary file
	tmpDB := filepath.Join(os.TempDir(), fmt.Sprintf("shielddns-backup-%d.db", time.Now().UnixNano()))
	dbConsistent := false
	if db != nil {
		if _, err := db.Exec("VACUUM INTO ?", tmpDB); err == nil {
			dbConsistent = true
			defer os.Remove(tmpDB)
		} else {
			slog.Error("Failed to create DB snapshot for backup", "error", err)
			tmpDB = DBPath // fallback to live file
		}
	} else {
		tmpDB = DBPath
	}

	// 2. Prepare files to include
	type backupFile struct {
		Path     string
		Target   string
		WithLock bool
	}
	files := []backupFile{
		{Path: ConfigPath, Target: "config.json", WithLock: true},
		{Path: tmpDB, Target: "shielddns.db", WithLock: false},
		{Path: BlocklistPath, Target: "shielddns.hosts", WithLock: false},
		{Path: AllowlistPath, Target: "allow.hosts", WithLock: false},
	}

	for _, bf := range files {
		var fReader io.ReadCloser
		var err error

		if bf.WithLock {
			configLock.RLock()
			content, err := os.ReadFile(bf.Path)
			configLock.RUnlock()
			if err == nil {
				f, err := zw.Create(bf.Target)
				if err == nil {
					f.Write(content)
				}
			}
			continue
		} else {
			fReader, err = os.Open(bf.Path)
			if err != nil {
				continue
			}
		}

		f, err := zw.Create(bf.Target)
		if err == nil {
			io.Copy(f, fReader)
		}
		fReader.Close()
	}

	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	slog.Info("System backup downloaded", "ip", ip, "consistent_db", dbConsistent)
}

func handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(50 << 20) // Allow up to 50MB for ZIP backups
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("config")
	if err != nil {
		http.Error(w, "Restore file field 'config' required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Check if it's a ZIP file
	isZip := strings.HasSuffix(strings.ToLower(header.Filename), ".zip")

	if isZip {
		// Temporary buffer for the zip file
		tmpZip, err := os.CreateTemp("", "shielddns-restore-*.zip")
		if err != nil {
			http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
			return
		}
		defer os.Remove(tmpZip.Name())
		defer tmpZip.Close()

		if _, err := io.Copy(tmpZip, file); err != nil {
			http.Error(w, "Failed to save uploaded ZIP", http.StatusInternalServerError)
			return
		}

		zr, err := zip.OpenReader(tmpZip.Name())
		if err != nil {
			http.Error(w, "Corrupt ZIP file", http.StatusBadRequest)
			return
		}
		defer zr.Close()

		var newCfg *Config
		restoreDBPath := ""

		for _, f := range zr.File {
			// Security: Prevent path traversal
			if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") {
				continue
			}

			// Security: Prevention of ZIP bomb/Resource exhaustion
			// Skip files larger than 100MB
			if f.UncompressedSize64 > 100*1024*1024 {
				slog.Warn("Restore: Skipping oversized file in ZIP", "name", f.Name, "size", f.UncompressedSize64)
				continue
			}

			rc, err := f.Open()
			if err != nil {
				continue
			}
			defer rc.Close()

			if f.Name == "config.json" {
				// We can read config.json into memory as it's small
				lr := io.LimitReader(rc, 1*1024*1024) // 1MB limit for config
				content, _ := io.ReadAll(lr)
				var c Config
				if err := json.Unmarshal(content, &c); err == nil {
					newCfg = &c
				}
			} else if f.Name == "shielddns.db" {
				// Stream DB to temp file
				tmpDB, err := os.CreateTemp("", "shielddns-restore-db-*.db")
				if err == nil {
					lr := io.LimitReader(rc, 100*1024*1024) // 100MB limit for DB
					if _, err := io.Copy(tmpDB, lr); err == nil {
						restoreDBPath = tmpDB.Name()
					}
					tmpDB.Close()
				}
			}
		}

		if newCfg == nil {
			if restoreDBPath != "" {
				os.Remove(restoreDBPath)
			}
			http.Error(w, "ZIP missing config.json or it was truncated due to size limits", http.StatusBadRequest)
			return
		}

		// Apply Config
		configLock.Lock()
		if newCfg.AdminPasswordHashed == "" {
			newCfg.AdminPasswordHashed = config.AdminPasswordHashed
		}
		config = *newCfg
		saveConfigNoLock()
		configLock.Unlock()

		// Apply Database if present
		if restoreDBPath != "" {
			defer os.Remove(restoreDBPath)
			closeDB()

			// Move the temp DB into place
			if err := os.Rename(restoreDBPath, DBPath); err != nil {
				// Fallback to atomicWrite if rename fails (e.g. cross-device)
				data, _ := os.ReadFile(restoreDBPath)
				atomicWriteFile(DBPath, data)
			}
			initDB()
		}

		updateCorefile()
		go updateBlocklist(nil)

		ip := r.Header.Get("X-Real-IP")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
		slog.Info("System Full Restore Completed from ZIP", "ip", ip)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Fallback to legacy JSON restore
	var newConfig Config
	if err := json.NewDecoder(file).Decode(&newConfig); err != nil {
		http.Error(w, "Invalid JSON format: "+err.Error(), http.StatusBadRequest)
		return
	}

	configLock.Lock()
	if newConfig.AdminPasswordHashed == "" {
		newConfig.AdminPasswordHashed = config.AdminPasswordHashed
	}
	config = newConfig
	saveConfigNoLock()
	configLock.Unlock()

	updateCorefile()
	go updateBlocklist(nil)

	slog.Info("System Configuration Restored from JSON")
	w.WriteHeader(http.StatusOK)
}

func handleRecheckUpstreams(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	slog.Info("Manual upstream latency check triggered")
	go checkAll()

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"triggered"}`)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		configLock.Lock()
		// Preserve fields that might not be sent in a partial update
		if len(newConfig.BlockedCountries) == 0 && len(config.BlockedCountries) > 0 {
			newConfig.BlockedCountries = config.BlockedCountries
		}
		if len(newConfig.BlockedClients) == 0 && len(config.BlockedClients) > 0 {
			newConfig.BlockedClients = config.BlockedClients
		}

		// Security: Prevent blocking the server's host country
		if detectedServerCountry != "" || newConfig.ServerCountry != "" {
			for _, bc := range newConfig.BlockedCountries {
				if (detectedServerCountry != "" && strings.EqualFold(bc, detectedServerCountry)) ||
					(newConfig.ServerCountry != "" && strings.EqualFold(bc, newConfig.ServerCountry)) {
					http.Error(w, fmt.Sprintf("Cannot block the country where ShieldDNS is running (%s). This country is protected to ensure system accessibility.", bc), http.StatusBadRequest)
					configLock.Unlock()
					return
				}
			}
		}

		// Validate that critical clients are not being blocked manually via config
		for _, bip := range newConfig.BlockedClients {
			if bip == "DoH Proxy" || bip == "127.0.0.1" || bip == "::1" || bip == "localhost" {
				http.Error(w, "Cannot block critical internal clients (DoH Proxy, localhost, loopback). Please remove these entries from the Blocked Clients list.", http.StatusBadRequest)
				configLock.Unlock()
				return
			}
		}
		if newConfig.BlockedClientsInfo == nil && config.BlockedClientsInfo != nil {
			newConfig.BlockedClientsInfo = config.BlockedClientsInfo
		}
		if newConfig.ClientAliases == nil && config.ClientAliases != nil {
			newConfig.ClientAliases = config.ClientAliases
		}
		if newConfig.APIKeys == nil && config.APIKeys != nil {
			newConfig.APIKeys = config.APIKeys
		}
		if len(newConfig.Lists) == 0 && len(config.Lists) > 0 {
			newConfig.Lists = config.Lists
		}
		if len(newConfig.Allowlists) == 0 && len(config.Allowlists) > 0 {
			newConfig.Allowlists = config.Allowlists
		}
		if newConfig.AdminPasswordHashed == "" {
			newConfig.AdminPasswordHashed = config.AdminPasswordHashed
		}
		if newConfig.LastLogin.IsZero() {
			newConfig.LastLogin = config.LastLogin
		}
		if newConfig.PreviousLogin.IsZero() {
			newConfig.PreviousLogin = config.PreviousLogin
		}
		if !newConfig.SetupDone && config.SetupDone {
			newConfig.SetupDone = config.SetupDone
		}
		if newConfig.DoHRateLimit == 0 && config.DoHRateLimit != 0 {
			newConfig.DoHRateLimit = config.DoHRateLimit
		}

		// Security: Validate Upstreams and UpstreamDoT for malicious injections
		validatedUpstreams := make([]string, 0, len(newConfig.Upstreams))
		for _, u := range newConfig.Upstreams {
			u = strings.TrimSpace(u)
			if isValidUpstream(u) {
				validatedUpstreams = append(validatedUpstreams, u)
			} else if u != "" {
				http.Error(w, "Invalid Upstream DNS format detected: "+u, http.StatusBadRequest)
				configLock.Unlock()
				return
			}
		}
		newConfig.Upstreams = validatedUpstreams

		validatedDoT := make([]string, 0, len(newConfig.UpstreamDoT))
		for _, u := range newConfig.UpstreamDoT {
			u = strings.TrimSpace(u)
			if isValidUpstream(u) {
				validatedDoT = append(validatedDoT, u)
			} else if u != "" {
				http.Error(w, "Invalid Upstream DoT format detected: "+u, http.StatusBadRequest)
				configLock.Unlock()
				return
			}
		}
		newConfig.UpstreamDoT = validatedDoT

		var cleanBlocked []string
		for _, b := range newConfig.CustomBlocked {
			if s := NormalizeDomain(b); s != "" && isValidDomain(s) {
				cleanBlocked = append(cleanBlocked, s)
			}
		}
		newConfig.CustomBlocked = cleanBlocked

		var cleanAllowed []string
		for _, a := range newConfig.CustomAllowed {
			if s := NormalizeDomain(a); s != "" && isValidDomain(s) {
				cleanAllowed = append(cleanAllowed, s)
			}
		}
		newConfig.CustomAllowed = cleanAllowed

		configHold := config
		config = newConfig
		saveConfigNoLock()
		configLock.Unlock()

		// If malicious settings changed, restart the background worker
		if config.MaliciousIPInterval != configHold.MaliciousIPInterval ||
			config.MaliciousIPBlockingEnabled != configHold.MaliciousIPBlockingEnabled {
			restartMaliciousUpdater()
			// If it was just enabled, trigger an immediate sync
			if config.MaliciousIPBlockingEnabled && !configHold.MaliciousIPBlockingEnabled {
				go syncMaliciousIPs()
			}
		}

		updateCorefile()
		restartCoreDNS() // Ensure Corefile changes (ACL) are applied

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
		return
	}

	configLock.Lock() // Use write lock to allow retrofit
	defer configLock.Unlock()
	
	changed := RetrofitBlockedClientsInfo()
	if changed {
		saveConfigNoLock()
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func handleFullReload(w http.ResponseWriter, r *http.Request) {
	slog.Info("Full system refresh initiated by user")

	// We run this in a goroutine because blacklists update can take a while,
	// and we don't want the frontend to timeout.
	go func() {
		// 1. Reload all blocklists (Synchronously within this goroutine)
		updateBlocklist(nil)

		// 2. Ensure Corefile is up to date with any newly fetched dynamic content/config
		updateCorefile()

		// 3. Restart CoreDNS to flush cache and apply everything
		restartCoreDNS()

		slog.Info("Full system refresh completed successfully")
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	slog.Warn("SYSTEM RESET TRIGGERED")

	// 1. Close DB
	if db != nil {
		db.Close()
		db = nil
	}

	// 2. Delete files
	files := []string{ConfigPath, DBPath, DBPath + "-wal", DBPath + "-shm", BlocklistPath, AllowlistPath}
	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			slog.Error("Failed to remove file during reset", "path", f, "error", err)
		}
	}

	// 3. Clear sessions
	sessionStore.Range(func(key, value interface{}) bool {
		sessionStore.Delete(key)
		return true
	})

	statsLock.Lock()
	stats = Stats{Version: Version}
	statsLock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reset", "message": "Success. System is restarting."})

	// Graceful exit after response
	go func() {
		time.Sleep(1 * time.Second)
		slog.Warn("System Reset complete. Exiting for restart.")
		os.Exit(0)
	}()
}
func fillShieldStats(stats map[string]interface{}) {
	dbSize := int64(0)
	if fi, err := os.Stat(DBPath); err == nil {
		dbSize = fi.Size()
	}

	dataSize := int64(0)
	filepath.Walk(DataDir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			dataSize += info.Size()
		}
		return nil
	})

	stats["shield_data"] = map[string]interface{}{
		"db_size":    dbSize,
		"total_size": dataSize,
	}
}
