package main

import (
	"archive/zip"
	"bytes"
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
	health := map[string]interface{}{
		"status":  "healthy",
		"version": Version,
		"time":    time.Now().Format(time.RFC3339),
	}

	// Check DB connection and writability
	if db != nil {
		// Try a dummy write test to detect read-only or full-disk issues
		_, err := db.Exec("CREATE TABLE IF NOT EXISTS _health_check (id INTEGER PRIMARY KEY); INSERT INTO _health_check (id) VALUES (1) ON CONFLICT(id) DO UPDATE SET id=1;")
		if err != nil {
			health["status"] = "unhealthy"
			health["database"] = "error: " + err.Error()
			slog.Error("Health check: Database write test failed", "error", err)
		} else {
			health["database"] = "ok"
		}
	} else {
		health["status"] = "unhealthy"
		health["database"] = "not connected"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
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
			// Additional specific handshake noise patterns
			if !isNoise && isTLS {
				extraNoise := []string{
					"client sent an HTTP request to an HTTPS server",
					"first record does not look like a TLS handshake",
					"unsupported SSLv2 handshake received",
					"client offered only unsupported versions",
					"client requested unsupported application protocols",
					"no cipher suite supported by both client and server",
				}
				for _, pattern := range extraNoise {
					if strings.Contains(msg, pattern) {
						isNoise = true
						break
					}
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

var configKeyCategories = map[string]string{
	"upstreams":                     "dns",
	"upstream_dot":                  "dns",
	"prefer_encrypted":              "dns",
	"use_fastest_upstream":          "dns",
	"smart_selection_policy":        "dns",
	"dnssec_enabled":                 "dns",
	"serve_stale":                    "dns",
	"filtering_enabled":              "filtering",
	"custom_blocked":                 "filtering",
	"custom_allowed":                 "filtering",
	"custom_mappings":                "filtering",
	"lists":                         "lists",
	"allowlists":                    "lists",
	"blocked_countries":              "lists",
	"blocked_clients":                "clients",
	"blocked_clients_info":            "clients",
	"client_aliases":                 "clients",
	"autoblock_whitelist":            "clients",
	"abuse_detection_enabled":        "abuse",
	"abuse_dga_threshold":            "abuse",
	"abuse_dga_min_len":              "abuse",
	"malicious_ip_blocking_enabled":  "abuse",
	"malicious_ip_interval":          "abuse",
	"retention_days":                 "system",
	"admin_domain":                   "system",
	"block_page_ip":                  "system",
	"latency_test_interval":          "system",
	"diagnostics_refresh_interval":   "system",
	"sign_mobileconfig":              "system",
	"verify_upstream_tls":            "system",
	"doh_rate_limit":                 "system",
	"debug_mode":                     "system",
	"server_country":                 "system",
	"admin_password_hashed":          "auth",
	"mfa_enabled":                    "auth",
	"totp_configs":                   "auth",
	"webauthn_credentials":           "auth",
	"api_keys":                       "auth",
}

func getLenOrDesc(val interface{}) interface{} {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case []interface{}:
		return len(v)
	case map[string]interface{}:
		return len(v)
	default:
		return 1
	}
}

func jsonEquals(a, b interface{}) bool {
	aBytes, _ := json.Marshal(a)
	bBytes, _ := json.Marshal(b)
	return bytes.Equal(aBytes, bBytes)
}

func applyBackupConfig(current *Config, backup *Config, selectedCategories []string) {
	cats := make(map[string]bool)
	for _, c := range selectedCategories {
		cats[c] = true
	}

	if cats["dns"] {
		current.Upstreams = backup.Upstreams
		current.UpstreamDoT = backup.UpstreamDoT
		current.PreferEncrypted = backup.PreferEncrypted
		current.UseFastestUpstream = backup.UseFastestUpstream
		current.SmartSelectionPolicy = backup.SmartSelectionPolicy
		current.DNSSECEnabled = backup.DNSSECEnabled
		current.ServeStale = backup.ServeStale
	}
	if cats["filtering"] {
		current.FilteringEnabled = backup.FilteringEnabled
		current.CustomBlocked = backup.CustomBlocked
		current.CustomAllowed = backup.CustomAllowed
		current.CustomMappings = backup.CustomMappings
	}
	if cats["lists"] {
		current.Lists = backup.Lists
		current.Allowlists = backup.Allowlists
		current.BlockedCountries = backup.BlockedCountries
	}
	if cats["clients"] {
		current.BlockedClients = backup.BlockedClients
		current.BlockedClientsInfo = backup.BlockedClientsInfo
		current.ClientAliases = backup.ClientAliases
		current.AutoblockWhitelist = backup.AutoblockWhitelist
	}
	if cats["abuse"] {
		current.AbuseDetectionEnabled = backup.AbuseDetectionEnabled
		current.AbuseDGAThreshold = backup.AbuseDGAThreshold
		current.AbuseDGAMinLen = backup.AbuseDGAMinLen
		current.MaliciousIPBlockingEnabled = backup.MaliciousIPBlockingEnabled
		current.MaliciousIPInterval = backup.MaliciousIPInterval
	}
	if cats["system"] {
		current.RetentionDays = backup.RetentionDays
		current.AdminDomain = backup.AdminDomain
		current.BlockPageIP = backup.BlockPageIP
		current.LatencyTestInterval = backup.LatencyTestInterval
		current.DiagnosticsRefreshInterval = backup.DiagnosticsRefreshInterval
		current.SignMobileConfig = backup.SignMobileConfig
		current.VerifyUpstreamTLS = backup.VerifyUpstreamTLS
		current.DoHRateLimit = backup.DoHRateLimit
		current.DebugMode = backup.DebugMode
		current.ServerCountry = backup.ServerCountry
	}
	if cats["auth"] {
		if backup.AdminPasswordHashed != "" && backup.AdminPasswordHashed != "********" {
			current.AdminPasswordHashed = backup.AdminPasswordHashed
		}
		current.MFAEnabled = backup.MFAEnabled
		current.TOTPConfigs = backup.TOTPConfigs
		current.WebAuthnCredentials = backup.WebAuthnCredentials
		current.APIKeys = backup.APIKeys
	}
}

func GenerateBackupZIP(includeData bool) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	type backupFile struct {
		Path     string
		Target   string
		WithLock bool
	}
	var files []backupFile
	files = append(files, backupFile{Path: ConfigPath, Target: "config.json", WithLock: true})

	if _, err := os.Stat(BlocklistPath); err == nil {
		files = append(files, backupFile{Path: BlocklistPath, Target: "shielddns.hosts", WithLock: false})
	}
	if _, err := os.Stat(AllowlistPath); err == nil {
		files = append(files, backupFile{Path: AllowlistPath, Target: "allow.hosts", WithLock: false})
	}

	var tmpDB string
	if includeData {
		tmpDB = filepath.Join(os.TempDir(), fmt.Sprintf("shielddns-backup-%d.db", time.Now().UnixNano()))
		if db != nil {
			if _, err := db.Exec("VACUUM INTO ?", tmpDB); err == nil {
				defer os.Remove(tmpDB)
				files = append(files, backupFile{Path: tmpDB, Target: "shielddns.db", WithLock: false})
			} else {
				slog.Error("Failed to create DB snapshot for backup", "error", err)
				tmpDB = DBPath // fallback to live file
				files = append(files, backupFile{Path: tmpDB, Target: "shielddns.db", WithLock: false})
			}
		} else {
			files = append(files, backupFile{Path: DBPath, Target: "shielddns.db", WithLock: false})
		}
	}

	for _, bf := range files {
		var fReader io.ReadCloser
		var err error

		if bf.WithLock {
			configLock.RLock()
			var content []byte
			content, err = os.ReadFile(bf.Path)
			configLock.RUnlock()
			if err == nil {
				var f io.Writer
				f, err = zw.Create(bf.Target)
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

	zw.Close()
	return buf.Bytes(), nil
}

func handleBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=shielddns-backup.zip")

	backupType := r.URL.Query().Get("type")
	includeData := backupType == "full" || backupType == ""

	backupData, err := GenerateBackupZIP(includeData)
	if err != nil {
		http.Error(w, "Failed to generate backup ZIP: "+err.Error(), http.StatusInternalServerError)
		return
	}

	password := r.URL.Query().Get("password")
	if password != "" {
		backupData, err = EncryptBackup(backupData, password)
		if err != nil {
			http.Error(w, "Failed to encrypt backup: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Write(backupData)

	ip := r.Header.Get("X-Real-IP")
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	slog.Info("System backup downloaded", "ip", ip, "type", backupType, "encrypted", password != "")
}

func handleCheckVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	latest := checkVersionsNow()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(latest)
}

func handleSystemUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.RLock()
	channel := config.UpdateChannel
	configLock.RUnlock()

	// 1. Force a backup on the server before updating
	err := createAutoBackup()
	if err != nil {
		slog.Error("Pre-update backup failed, aborting update", "error", err)
		http.Error(w, "Pre-update backup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 2. Trigger self-update
	err = triggerUpdate(channel)
	if err != nil {
		slog.Error("Self-update trigger failed", "error", err)
		http.Error(w, "Self-update failed to initiate: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "Update initiated successfully. Container is recreating..."})
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

	file, _, err := r.FormFile("config")
	if err != nil {
		http.Error(w, "Restore file field 'config' required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	action := r.FormValue("action")
	password := r.FormValue("password")

	encrypted := IsBackupEncrypted(data)
	var rawZipBytes []byte

	if encrypted {
		if password == "" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"encrypted": true,
				"error":     "password_required",
			})
			return
		}
		rawZipBytes, err = DecryptBackup(data, password)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"encrypted": true,
				"error":     "invalid_password",
			})
			return
		}
	} else {
		rawZipBytes = data
	}

	isJson := len(rawZipBytes) > 0 && rawZipBytes[0] == '{'

	if action == "" {
		if isJson {
			action = "apply"
		} else {
			action = "preview"
		}
	}

	var backupCfg *Config
	hasData := false
	var blocklistData []byte
	var allowlistData []byte
	var dbFileInZip *zip.File

	if isJson {
		var c Config
		if err := json.Unmarshal(rawZipBytes, &c); err != nil {
			http.Error(w, "Invalid JSON format: "+err.Error(), http.StatusBadRequest)
			return
		}
		backupCfg = &c
	} else {
		if len(rawZipBytes) < 4 || string(rawZipBytes[:4]) != "PK\x03\x04" {
			http.Error(w, "Invalid backup format: Must be ZIP or JSON", http.StatusBadRequest)
			return
		}

		zr, err := zip.NewReader(bytes.NewReader(rawZipBytes), int64(len(rawZipBytes)))
		if err != nil {
			http.Error(w, "Corrupt ZIP file", http.StatusBadRequest)
			return
		}

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

			if f.Name == "config.json" {
				rc, err := f.Open()
				if err == nil {
					lr := io.LimitReader(rc, 2*1024*1024) // 2MB limit for config
					content, _ := io.ReadAll(lr)
					rc.Close()
					var c Config
					if err := json.Unmarshal(content, &c); err == nil {
						backupCfg = &c
					}
				}
			} else if f.Name == "shielddns.db" {
				hasData = true
				dbFileInZip = f
			} else if f.Name == "shielddns.hosts" {
				rc, err := f.Open()
				if err == nil {
					blocklistData, _ = io.ReadAll(rc)
					rc.Close()
				}
			} else if f.Name == "allow.hosts" {
				rc, err := f.Open()
				if err == nil {
					allowlistData, _ = io.ReadAll(rc)
					rc.Close()
				}
			}
		}
	}

	if backupCfg == nil {
		http.Error(w, "Backup missing config.json", http.StatusBadRequest)
		return
	}

	if action == "preview" {
		currentBytes, _ := json.Marshal(config)
		var currentMap map[string]interface{}
		json.Unmarshal(currentBytes, &currentMap)

		backupBytes, _ := json.Marshal(backupCfg)
		var backupMap map[string]interface{}
		json.Unmarshal(backupBytes, &backupMap)

		type ValueCompare struct {
			Current  interface{} `json:"current"`
			Backup   interface{} `json:"backup"`
			Category string      `json:"category"`
			Changed  bool        `json:"changed"`
		}

		previewData := make(map[string]ValueCompare)

		for k, cat := range configKeyCategories {
			curVal := currentMap[k]
			bakVal := backupMap[k]

			if cat == "auth" {
				if k == "admin_password_hashed" {
					curVal = "********"
					if bakVal != nil && bakVal != "" {
						bakVal = "********"
					} else {
						bakVal = ""
					}
				} else if k == "api_keys" || k == "totp_configs" || k == "webauthn_credentials" {
					curVal = getLenOrDesc(curVal)
					bakVal = getLenOrDesc(bakVal)
				}
			}

			changed := !jsonEquals(curVal, bakVal)

			previewData[k] = ValueCompare{
				Current:  curVal,
				Backup:   bakVal,
				Category: cat,
				Changed:  changed,
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"encrypted": false,
			"has_data":  hasData,
			"preview":   previewData,
		})
		return
	}

	if action == "apply" {
		var selectedCategories []string
		selCatsRaw := r.FormValue("selected_categories")
		if selCatsRaw != "" {
			json.Unmarshal([]byte(selCatsRaw), &selectedCategories)
		} else {
			selectedCategories = []string{"dns", "filtering", "lists", "clients", "abuse", "system", "auth"}
		}

		restoreData := false
		for _, cat := range selectedCategories {
			if cat == "data" {
				restoreData = true
				break
			}
		}

		configLock.Lock()
		applyBackupConfig(&config, backupCfg, selectedCategories)
		if err := saveConfigNoLock(); err != nil {
			slog.Error("Failed to save config in backup restore", "error", err)
			http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
			configLock.Unlock()
			return
		}
		configLock.Unlock()

		for _, cat := range selectedCategories {
			if cat == "lists" {
				if len(blocklistData) > 0 {
					atomicWriteFile(BlocklistPath, blocklistData)
				}
				if len(allowlistData) > 0 {
					atomicWriteFile(AllowlistPath, allowlistData)
				}
			}
		}

		if restoreData && dbFileInZip != nil {
			closeDB()
			tmpDB, err := os.CreateTemp("", "shielddns-restore-db-*.db")
			if err == nil {
				rc, err := dbFileInZip.Open()
				if err == nil {
					lr := io.LimitReader(rc, 100*1024*1024) // 100MB limit for DB
					io.Copy(tmpDB, lr)
					rc.Close()
				}
				tmpDB.Close()

				// Move the temp DB into place
				if err := os.Rename(tmpDB.Name(), DBPath); err != nil {
					// Fallback to atomicWrite if rename fails
					data, _ := os.ReadFile(tmpDB.Name())
					atomicWriteFile(DBPath, data)
				}
				os.Remove(tmpDB.Name())
			}
			initDB()
		}

		updateCorefile()
		go updateBlocklist(nil, true)

		ip := r.Header.Get("X-Real-IP")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
		slog.Info("Selective System Restore Completed", "ip", ip, "categories", selectedCategories)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "success"})
		return
	}

	http.Error(w, "Invalid action", http.StatusBadRequest)
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
		if len(newConfig.AutoblockWhitelist) == 0 && len(config.AutoblockWhitelist) > 0 {
			newConfig.AutoblockWhitelist = config.AutoblockWhitelist
		}
		if len(newConfig.CustomBlocked) == 0 && len(config.CustomBlocked) > 0 {
			newConfig.CustomBlocked = config.CustomBlocked
		}
		if len(newConfig.CustomAllowed) == 0 && len(config.CustomAllowed) > 0 {
			newConfig.CustomAllowed = config.CustomAllowed
		}
		if newConfig.CustomMappings == nil && config.CustomMappings != nil {
			newConfig.CustomMappings = config.CustomMappings
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
		} else if newConfig.APIKeys != nil && config.APIKeys != nil {
			// Restore masked token hashes
			for i, newKey := range newConfig.APIKeys {
				if newKey.TokenHash == "********" {
					for _, oldKey := range config.APIKeys {
						if oldKey.ID == newKey.ID {
							newConfig.APIKeys[i].TokenHash = oldKey.TokenHash
							break
						}
					}
				}
			}
		}
		if len(newConfig.Lists) == 0 && len(config.Lists) > 0 {
			newConfig.Lists = config.Lists
		}
		if len(newConfig.Allowlists) == 0 && len(config.Allowlists) > 0 {
			newConfig.Allowlists = config.Allowlists
		}
		if newConfig.AdminPasswordHashed == "" || newConfig.AdminPasswordHashed == "********" {
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
		if newConfig.RetentionDays == 0 && config.RetentionDays != 0 {
			newConfig.RetentionDays = config.RetentionDays
		}
		if !newConfig.MFAEnabled && config.MFAEnabled {
			newConfig.MFAEnabled = config.MFAEnabled
		}
		if len(newConfig.TOTPConfigs) > 0 {
			for i, nt := range newConfig.TOTPConfigs {
				if nt.Secret == "********" {
					// Find original secret by ID
					for _, ot := range config.TOTPConfigs {
						if ot.ID == nt.ID {
							newConfig.TOTPConfigs[i].Secret = ot.Secret
							break
						}
					}
				}
			}
		} else if config.TOTPConfigs != nil {
			newConfig.TOTPConfigs = config.TOTPConfigs
		}
		if newConfig.WebAuthnCredentials == nil && config.WebAuthnCredentials != nil {
			newConfig.WebAuthnCredentials = config.WebAuthnCredentials
		}
		if newConfig.UpdateChannel == "" {
			newConfig.UpdateChannel = config.UpdateChannel
		}
		if newConfig.AutoUpdateHour < 0 || newConfig.AutoUpdateHour > 23 {
			newConfig.AutoUpdateHour = config.AutoUpdateHour
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
		if err := saveConfigNoLock(); err != nil {
			slog.Error("Failed to save config in handleConfig", "error", err)
			config = configHold
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to save configuration: %v", err)})
			configLock.Unlock()
			return
		}
		configLock.Unlock()

		// If malicious settings changed, restart the background worker
		if config.MaliciousIPInterval != configHold.MaliciousIPInterval ||
			config.MaliciousIPBlockingEnabled != configHold.MaliciousIPBlockingEnabled {
			restartMaliciousUpdater()
			// If it was just enabled, trigger an immediate sync
			if config.MaliciousIPBlockingEnabled && !configHold.MaliciousIPBlockingEnabled {
				go syncMaliciousIPs(true)
			}
		}

		updateCorefile()
		restartCoreDNS() // Ensure Corefile changes (ACL) are applied
		initWebAuthn()   // Update WebAuthn RPID if domain changed

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config.SanitizedCopy())
		return
	}

	configLock.Lock() // Use write lock to allow retrofit
	defer configLock.Unlock()

	changed := RetrofitBlockedClientsInfo()
	if changed {
		if err := saveConfigNoLock(); err != nil {
			slog.Error("Failed to save config in handleConfig (retrofit)", "error", err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config.SanitizedCopy())
}

func handleFullReload(w http.ResponseWriter, r *http.Request) {
	slog.Info("Full system refresh initiated by user")

	// We run this in a goroutine because blacklists update can take a while,
	// and we don't want the frontend to timeout.
	go func() {
		// 1. Reload all blocklists (Synchronously within this goroutine)
		updateBlocklist(nil, true)

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
