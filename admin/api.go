package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	systemLogBuffer []string
	systemLogLock   sync.RWMutex
	systemLogClients = make(map[chan string]struct{})
)

func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func hasPermission(key *APIKey, perm string) bool {
	for _, p := range key.Permissions {
		if p == "read:all" || p == perm {
			return true
		}
	}
	return false
}

func getRequiredPermission(r *http.Request) string {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/api/stats"), strings.HasPrefix(path, "/api/history"), strings.HasPrefix(path, "/api/health"):
		return "read:stats"
	case strings.HasPrefix(path, "/api/queries"), strings.HasPrefix(path, "/api/top-blocked"), strings.HasPrefix(path, "/api/top-clients"), strings.HasPrefix(path, "/api/search"), strings.HasPrefix(path, "/api/export"):
		return "read:logs"
	case strings.HasPrefix(path, "/api/system-logs"), strings.HasPrefix(path, "/api/diagnostics"), strings.HasPrefix(path, "/api/backup"):
		return "read:system"
	case strings.HasPrefix(path, "/api/filtering"), strings.HasPrefix(path, "/api/rules"):
		if r.Method == http.MethodGet {
			return "read:stats"
		}
		return "write:filtering"
	case strings.HasPrefix(path, "/api/config"):
		if r.Method == http.MethodPost {
			return "write:config" // Not exposed via tokens usually, but for RBAC safety
		}
		return "read:stats"
	default:
		return "read:stats"
	}
}

func handleGetTokens(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	defer configLock.RUnlock()
	
	// Strip hashes before sending to UI
	type TokenInfo struct {
		ID          string    `json:"id"`
		Name        string    `json:"name"`
		Permissions []string  `json:"permissions"`
		CreatedAt   time.Time `json:"created_at"`
		LastUsed    time.Time `json:"last_used"`
	}
	
	tokens := make([]TokenInfo, len(config.APIKeys))
	for i, k := range config.APIKeys {
		tokens[i] = TokenInfo{
			ID:          k.ID,
			Name:        k.Name,
			Permissions: k.Permissions,
			CreatedAt:   k.CreatedAt,
			LastUsed:    k.LastUsed,
		}
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rawToken := generateToken()
	newToken := APIKey{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		Name:        req.Name,
		TokenHash:   hashToken(rawToken),
		Permissions: req.Permissions,
		CreatedAt:   time.Now(),
	}

	configLock.Lock()
	config.APIKeys = append(config.APIKeys, newToken)
	saveConfigNoLock()
	configLock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": rawToken,
		"id":    newToken.ID,
	})
}

func handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()
	
	newKeys := make([]APIKey, 0)
	for _, k := range config.APIKeys {
		if k.ID != id {
			newKeys = append(newKeys, k)
		}
	}
	config.APIKeys = newKeys
	saveConfigNoLock()
	w.WriteHeader(http.StatusOK)
}

func handleUpdateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()
	
	for i := range config.APIKeys {
		if config.APIKeys[i].ID == req.ID {
			config.APIKeys[i].Name = req.Name
			config.APIKeys[i].Permissions = req.Permissions
			saveConfigNoLock()
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	http.Error(w, "Token not found", http.StatusNotFound)
}

func handleToggleFiltering(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	configLock.Lock()
	config.FilteringEnabled = req.Enabled
	saveConfigNoLock()
	configLock.Unlock()

	updateCorefile()
	
	status := "Disabled"
	if req.Enabled { status = "Enabled" }
	AddSystemLog("Global protection " + status)

	w.WriteHeader(http.StatusOK)
}

func handleFilteringStatus(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	enabled := config.FilteringEnabled
	configLock.RUnlock()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": enabled})
}

func handleRuleAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Domain string `json:"domain"`
		Type   string `json:"type"` // "block" or "allow"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}
	
	configLock.Lock()
	defer configLock.Unlock()
	
	if req.Type == "block" {
		// Remove from allowed if present
		var clean []string
		for _, d := range config.CustomAllowed {
			if d != domain { clean = append(clean, d) }
		}
		config.CustomAllowed = clean
		
		// Add to blocked if not present
		exists := false
		for _, d := range config.CustomBlocked {
			if d == domain { exists = true; break }
		}
		if !exists {
			config.CustomBlocked = append(config.CustomBlocked, domain)
		}
	} else if req.Type == "allow" {
		// Remove from blocked if present
		var clean []string
		for _, d := range config.CustomBlocked {
			if d != domain { clean = append(clean, d) }
		}
		config.CustomBlocked = clean
		
		// Add to allowed if not present
		exists := false
		for _, d := range config.CustomAllowed {
			if d == domain { exists = true; break }
		}
		if !exists {
			config.CustomAllowed = append(config.CustomAllowed, domain)
		}
	} else {
		http.Error(w, "Type must be 'block' or 'allow'", http.StatusBadRequest)
		return
	}
	
	saveConfigNoLock()
	go updateBlocklist() // Process rule changes asynchronously
	
	w.WriteHeader(http.StatusOK)
}

func handleRuleRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	
	domain := strings.TrimSpace(req.Domain)
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}
	
	configLock.Lock()
	defer configLock.Unlock()
	
	var cleanBlocked []string
	for _, d := range config.CustomBlocked {
		if d != domain { cleanBlocked = append(cleanBlocked, d) }
	}
	config.CustomBlocked = cleanBlocked
	
	var cleanAllowed []string
	for _, d := range config.CustomAllowed {
		if d != domain { cleanAllowed = append(cleanAllowed, d) }
	}
	config.CustomAllowed = cleanAllowed
	
	saveConfigNoLock()
	go updateBlocklist() // Process rule changes asynchronously
	
	w.WriteHeader(http.StatusOK)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	// Simple health check for monitoring
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "version": Version})
}

func AddSystemLog(line string) {
	line = fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line)
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

type LogWriter struct{}

func (w *LogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		AddSystemLog(msg)
	}
	return os.Stdout.Write(p)
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

	ch := make(chan Query, 100)
	sseLock.Lock()
	sseClients[ch] = struct{}{}
	sseLock.Unlock()

	defer func() {
		sseLock.Lock()
		delete(sseClients, ch)
		sseLock.Unlock()
	}()

	flusher, _ := w.(http.Flusher)
	flusher.Flush()

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
		fallbackPath := "/etc/shielddns/ssl/selfsigned.crt"
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
	configLock.RUnlock()

	type UpstreamHealth struct {
		Server    string  `json:"server"`
		Status    string  `json:"status"`
		LatencyMs float64 `json:"latency_ms"`
	}

	var upstreamHealth []UpstreamHealth
	for _, u := range allUpstreams {
		key := u
		if strings.Contains(u, ":") {
			key = u
		}
		status := "down"
		if hUp[key] {
			status = "up"
		}
		latMs := 0.0
		if d, ok := latsRaw[key]; ok {
			latMs = float64(d.Microseconds()) / 1000.0
		}
		upstreamHealth = append(upstreamHealth, UpstreamHealth{Server: u, Status: status, LatencyMs: latMs})
	}
	for _, u := range allDoT {
		key := u
		status := "down"
		if hDoT[key] {
			status = "up"
		}
		latMs := 0.0
		if d, ok := latsRaw[key]; ok {
			latMs = float64(d.Microseconds()) / 1000.0
		}
		upstreamHealth = append(upstreamHealth, UpstreamHealth{Server: "tls://" + u, Status: status, LatencyMs: latMs})
	}
	if upstreamHealth == nil {
		upstreamHealth = []UpstreamHealth{}
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
		"latencies":        lats,
		"upstream_health":  upstreamHealth,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}


func handleBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=shielddns-backup.zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	files := []string{ConfigPath, DBPath, BlocklistPath, AllowlistPath}
	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			continue
		}
		
		info, err := file.Stat()
		if err != nil {
			file.Close()
			continue
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			file.Close()
			continue
		}
		header.Name = filepath.Base(f)
		header.Method = zip.Deflate

		writer, err := zw.CreateHeader(header)
		if err != nil {
			file.Close()
			continue
		}

		io.Copy(writer, file)
		file.Close()
	}
}

func handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("config")
	if err != nil {
		http.Error(w, "Config file 'config' field required", http.StatusBadRequest)
		return
	}
	defer file.Close()

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
	go updateBlocklist()

	AddSystemLog("System Configuration Restored from uploaded file.")
	w.WriteHeader(http.StatusOK)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	statsLock.RLock()
	s := stats
	statsLock.RUnlock()

	// Query unique clients in the last 24 hours from DB
	var uniqueClients int
	row := db.QueryRow("SELECT COUNT(DISTINCT client_ip) FROM queries WHERE timestamp > datetime('now', '-24 hours')")
	if err := row.Scan(&uniqueClients); err == nil {
		s.UniqueClients = uniqueClients
	}

	s.Version = Version
	s.CoreDNSVersion = "v1.14.2" // Match Dockerfile
	
	// Try to read Alpine version
	alpineVer := "3.23"
	if b, err := os.ReadFile("/etc/alpine-release"); err == nil {
		alpineVer = strings.TrimSpace(string(b))
	}
	s.AlpineVersion = alpineVer

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func handleBlockInfo(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}

	blockAttributionLock.RLock()
	lists := blockAttribution[domain]
	blockAttributionLock.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"domain": domain,
		"lists":  lists,
	})
}

func handleMobileConfig(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}

	// Read configured upstreams for ServerAddresses fallback
	configLock.RLock()
	upstreams := config.Upstreams
	configLock.RUnlock()

	// Build ServerAddresses XML array from configured upstream IPs
	serverAddrsXML := ""
	for _, ip := range upstreams {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			serverAddrsXML += fmt.Sprintf("\t\t\t\t<string>%s</string>\n", ip)
		}
	}
	if serverAddrsXML == "" {
		serverAddrsXML = "\t\t\t\t<string>1.1.1.1</string>\n\t\t\t\t<string>8.8.8.8</string>\n"
	}

	// Generate unique UUIDs per download to avoid profile conflicts
	payloadUUID := fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		time.Now().UnixNano()&0xFFFFFFFF, time.Now().UnixNano()>>32&0xFFFF,
		0x4000|(time.Now().UnixNano()>>48&0x0FFF), 0x8000|(time.Now().UnixNano()>>60&0x3FFF),
		time.Now().UnixNano()&0xFFFFFFFFFFFF)
	profileUUID := fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		(time.Now().UnixNano()+1)&0xFFFFFFFF, (time.Now().UnixNano()+1)>>32&0xFFFF,
		0x4000|((time.Now().UnixNano()+1)>>48&0x0FFF), 0x8000|((time.Now().UnixNano()+1)>>60&0x3FFF),
		(time.Now().UnixNano()+1)&0xFFFFFFFFFFFF)

	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=shielddns_%s.mobileconfig", host))

	mobileConfig := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				<key>DNSProtocol</key>
				<string>TLS</string>
				<key>ServerName</key>
				<string>%s</string>
				<key>ServerAddresses</key>
				<array>
%s				</array>
			</dict>
			<key>OnDemandRules</key>
			<array>
				<dict>
					<key>Action</key>
					<string>Connect</string>
				</dict>
			</array>
			<key>ProhibitDisablement</key>
			<false/>
			<key>PayloadDescription</key>
			<string>Configures encrypted DNS-over-TLS (DoT) to route all DNS queries through ShieldDNS on %s. This protects your browsing from tracking and blocks malicious domains.</string>
			<key>PayloadDisplayName</key>
			<string>ShieldDNS DNS Settings</string>
			<key>PayloadIdentifier</key>
			<string>com.shielddns.dns.%s</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>ShieldDNS Encrypted DNS</string>
	<key>PayloadDescription</key>
	<string>This profile enables encrypted DNS-over-TLS (DoT) via ShieldDNS. All DNS queries from this device will be routed through your private ShieldDNS server at %s, providing ad-blocking, tracking protection, and malware filtering.</string>
	<key>PayloadIdentifier</key>
	<string>com.shielddns.profile.%s</string>
	<key>PayloadOrganization</key>
	<string>ShieldDNS</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>ConsentText</key>
	<dict>
		<key>default</key>
		<string>This profile will configure your device to use ShieldDNS (%s) as your encrypted DNS server (DNS-over-TLS). All DNS queries will be routed through this server for ad-blocking and privacy protection. You can remove this profile at any time in Settings > General > VPN &amp; Device Management.</string>
	</dict>
</dict>
</plist>`, host, serverAddrsXML, host, host, payloadUUID, host, host, profileUUID, host)

	w.Write([]byte(mobileConfig))
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		configLock.Lock()
		if newConfig.AdminPasswordHashed == "" {
			newConfig.AdminPasswordHashed = config.AdminPasswordHashed
		}

		// Sanitize Custom Rules
		sanitizeRule := func(r string) string {
			r = strings.TrimSpace(r)
			r = strings.TrimPrefix(r, "http://")
			r = strings.TrimPrefix(r, "https://")
			if idx := strings.Index(r, "/"); idx != -1 {
				r = r[:idx]
			}
			return r
		}

		var cleanBlocked []string
		for _, b := range newConfig.CustomBlocked {
			if s := sanitizeRule(b); s != "" {
				cleanBlocked = append(cleanBlocked, s)
			}
		}
		newConfig.CustomBlocked = cleanBlocked

		var cleanAllowed []string
		for _, a := range newConfig.CustomAllowed {
			if s := sanitizeRule(a); s != "" {
				cleanAllowed = append(cleanAllowed, s)
			}
		}
		newConfig.CustomAllowed = cleanAllowed

		config = newConfig
		saveConfigNoLock()
		configLock.Unlock()
		updateCorefile()
		w.WriteHeader(http.StatusOK)
		return
	}

	configLock.RLock()
	defer configLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	go updateBlocklist()
	w.WriteHeader(http.StatusAccepted)
}

func handlePresets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DefaultPresets)
}

func handlePresetAllowlists(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DefaultAllowlists)
}

func handleQueries(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	statusFilter := r.URL.Query().Get("status")

	query := "SELECT timestamp, domain, type, status, client_ip FROM queries WHERE 1=1"
	var args []interface{}

	if search != "" {
		query += " AND domain LIKE ?"
		args = append(args, "%"+search+"%")
	}
	if statusFilter != "" {
		query += " AND status = ?"
		args = append(args, statusFilter)
	}

	query += " ORDER BY timestamp DESC LIMIT 100"

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("Error querying queries: %v", err)
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	queries := make([]Query, 0)
	for rows.Next() {
		var q Query
		var ts string
		rows.Scan(&ts, &q.Domain, &q.Type, &q.Status, &q.ClientIP)
		q.Time, _ = time.Parse(time.RFC3339, ts)
		queries = append(queries, q)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(queries)
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	rows, err := db.Query("SELECT timestamp, domain, type, status, client_ip FROM queries ORDER BY timestamp DESC")
	if err != nil {
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment;filename=shielddns_export.csv")
		fmt.Fprintln(w, "Timestamp,Domain,Type,Status,ClientIP")
		for rows.Next() {
			var ts, domain, qtype, status, ip string
			rows.Scan(&ts, &domain, &qtype, &status, &ip)
			fmt.Fprintf(w, "%s,%s,%s,%s,%s\n", ts, domain, qtype, status, ip)
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment;filename=shielddns_export.json")
		var queries []map[string]string
		for rows.Next() {
			var ts, domain, qtype, status, ip string
			rows.Scan(&ts, &domain, &qtype, &status, &ip)
			queries = append(queries, map[string]string{
				"timestamp": ts,
				"domain":    domain,
				"type":      qtype,
				"status":    status,
				"client_ip": ip,
			})
		}
		json.NewEncoder(w).Encode(queries)
	}
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT 
			strftime('%H', timestamp) as hr,
			COUNT(*) as total,
			SUM(CASE WHEN status = 'Blocked' THEN 1 ELSE 0 END) as blocked
		FROM queries
		WHERE timestamp > datetime('now', '-24 hours')
		GROUP BY hr
		ORDER BY timestamp ASC
	`)
	if err != nil {
		http.Error(w, "Error querying history", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var result [24]HourStats
	for rows.Next() {
		var hr int
		var total, blocked int64
		rows.Scan(&hr, &total, &blocked)
		if hr >= 0 && hr < 24 {
			result[hr] = HourStats{Total: total, Blocked: blocked}
		}
	}

	currentHr := time.Now().Hour()
	var rotated [24]HourStats
	for i := 0; i < 24; i++ {
		rotated[i] = result[(currentHr+1+i)%24]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rotated)
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, "Query required", http.StatusBadRequest)
		return
	}

	// Standardize query (trim http://, paths, trailing dots)
	query = strings.TrimSpace(query)
	query = strings.TrimPrefix(query, "http://")
	query = strings.TrimPrefix(query, "https://")
	query = strings.Split(query, "/")[0]
	query = strings.TrimSuffix(query, ".")

	blockAttributionLock.RLock()
	lists, found := blockAttribution[query]
	blockAttributionLock.RUnlock()

	// If not found directly, check if the blocklist has even been loaded
	// We can check if the map is empty but the config has lists
	configLock.RLock()
	hasLists := len(config.Lists) > 0 || len(config.CustomBlocked) > 0
	configLock.RUnlock()

	if !found && hasLists && len(blockAttribution) == 0 {
		http.Error(w, "Blocklist still loading", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked": found,
		"lists":   lists,
	})
}

func handleTopBlocked(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT domain, COUNT(*) as count 
		FROM queries 
		WHERE status = 'Blocked' 
		GROUP BY domain 
		ORDER BY count DESC 
		LIMIT 10
	`)
	if err != nil {
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var domain string
		var count int
		rows.Scan(&domain, &count)
		result = append(result, map[string]interface{}{"domain": domain, "count": count})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleTopClients(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT client_ip, COUNT(*) as count 
		FROM queries 
		GROUP BY client_ip 
		ORDER BY count DESC 
		LIMIT 10
	`)
	if err != nil {
		http.Error(w, "Error querying database", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		var client_ip string
		var count int
		rows.Scan(&client_ip, &count)
		if client_ip == "" { client_ip = "Unknown" }
		result = append(result, map[string]interface{}{"client_ip": client_ip, "count": count})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	log.Println("!!! SYSTEM RESET TRIGGERED !!!")

	// 1. Close DB
	if db != nil {
		db.Close()
		db = nil
	}

	// 2. Delete files
	files := []string{ConfigPath, DBPath, BlocklistPath, AllowlistPath}
	for _, f := range files {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			log.Printf("Failed to remove %s: %v", f, err)
		}
	}

	// 3. Clear sessions
	sessionLock.Lock()
	sessionToken = "" // Invalidate current session
	sessionLock.Unlock()

	// 4. Reset in-memory stats
	statsLock.Lock()
	stats = Stats{Version: Version} 
	statsLock.Unlock()

	queryLock.Lock()
	recentQueries = nil
	queryLock.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))

	// Graceful exit after response
	go func() {
		time.Sleep(1 * time.Second)
		log.Println("System Reset complete. Exiting for restart.")
		os.Exit(0)
	}()
}

func handleResetLists(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.Lock()
	config.Lists = DefaultPresets
	config.Allowlists = DefaultAllowlists
	saveConfigNoLock()
	configLock.Unlock()

	// Trigger background update
	go updateBlocklist()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
