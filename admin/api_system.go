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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

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
	AddSystemLog(levelStr + r.Message)

	// 2. Pass to JSON Handler (Machine Readable)
	return h.jsonHandler.Handle(ctx, r)
}

func (h *SlogUIHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SlogUIHandler{jsonHandler: h.jsonHandler.WithAttrs(attrs)}
}

func (h *SlogUIHandler) WithGroup(name string) slog.Handler {
	return &SlogUIHandler{jsonHandler: h.jsonHandler.WithGroup(name)}
}

type LogWriter struct{}

func (w *LogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		slog.Info(msg)
	}
	return len(p), nil
}

func handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
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

	for {
		select {
		case line := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
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

	for {
		select {
		case q := <-ch:
			data, _ := json.Marshal(q)
			fmt.Fprintf(w, "data: %s\n\n", string(data))
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
		var content []byte
		var err error

		if bf.WithLock {
			configLock.RLock()
			content, err = os.ReadFile(bf.Path)
			configLock.RUnlock()
		} else {
			content, err = os.ReadFile(bf.Path)
		}

		if err != nil {
			continue
		}

		f, err := zw.Create(bf.Target)
		if err != nil {
			continue
		}
		f.Write(content)
	}

	slog.Info("System backup downloaded", "consistent_db", dbConsistent)
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
		var dbData []byte

		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			defer rc.Close()

			content, _ := io.ReadAll(rc)
			if f.Name == "config.json" {
				var c Config
				if err := json.Unmarshal(content, &c); err == nil {
					newCfg = &c
				}
			} else if f.Name == "shielddns.db" {
				dbData = content
			}
		}

		if newCfg == nil {
			http.Error(w, "ZIP missing config.json", http.StatusBadRequest)
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
		if len(dbData) > 0 {
			closeDB()
			if err := atomicWriteFile(DBPath, dbData); err != nil {
				slog.Error("Failed to restore DB file", "error", err)
			}
			initDB()
		}

		updateCorefile()
		go updateBlocklist(nil)
		slog.Info("System Full Restore Completed from ZIP")
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

		config = newConfig
		saveConfigNoLock()
		configLock.Unlock()
		updateCorefile()
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
		return
	}

	configLock.RLock()
	defer configLock.RUnlock()
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
