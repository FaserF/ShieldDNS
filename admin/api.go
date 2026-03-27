package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9-]{2,63}$`)

// isValidDomain checks if a string is a valid domain name or IP address.
func isValidDomain(s string) bool {
	if s == "" {
		return false
	}
	// Allow valid IP addresses
	if net.ParseIP(s) != nil {
		return true
	}
	// Check against domain regex
	if len(s) > 253 {
		return false
	}
	return domainRegex.MatchString(s)
}

var (
	systemLogBuffer []string
	systemLogLock   sync.RWMutex
	systemLogClients = make(map[chan string]struct{})

	// Cache for IP info to avoid redundant DNS and GeoIP lookups
	ipInfoCache sync.Map

	// Latest User-Agent per IP (populated from CoreDNS logs)
	ipToUA sync.Map
)

type IPInfo struct {
	IP           string    `json:"ip"`
	IsPrivate    bool      `json:"is_private"`
	Hostname     string    `json:"hostname"`
	Country      string    `json:"country"`
	CountryCode  string    `json:"country_code"`
	City         string    `json:"city"`
	ISP          string    `json:"isp"`
	MAC          string    `json:"mac,omitempty"`
	Manufacturer string    `json:"manufacturer,omitempty"`
	OS           string    `json:"os,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	ExpiresAt    time.Time `json:"-"`
}

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
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}
	if !isValidDomain(domain) {
		http.Error(w, "Invalid domain format", http.StatusBadRequest)
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
		"system":          getSystemStats(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func handleIPInfo(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	if val, ok := ipInfoCache.Load(ip); ok {
		info := val.(IPInfo)
		if time.Now().Before(info.ExpiresAt) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(info)
			return
		}
	}

	isPrivate := false
	if strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") || ip == "127.0.0.1" || ip == "::1" || strings.HasPrefix(ip, "fd") {
		isPrivate = true
	}

	info := IPInfo{
		IP:        ip,
		IsPrivate: isPrivate,
	}

	// Reverse DNS
	names, _ := net.LookupAddr(ip)
	if len(names) > 0 {
		info.Hostname = strings.TrimSuffix(names[0], ".")
	}

	// GeoIP for public IPs
	if !isPrivate {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://ip-api.com/json/" + ip)
		if err == nil {
			var geo struct {
				Country     string `json:"country"`
				CountryCode string `json:"countryCode"`
				City        string `json:"city"`
				Org         string `json:"org"`
			}
			json.NewDecoder(resp.Body).Decode(&geo)
			resp.Body.Close()
			info.Country = geo.Country
			info.CountryCode = geo.CountryCode
			info.City = geo.City
			info.ISP = geo.Org
		}
	}

	// MAC and Manufacturer for local IPs
	if isPrivate {
		mac := getMACByIP(ip)
		if mac != "" {
			info.MAC = mac
			info.Manufacturer = getManufacturerByMAC(mac)
		}
	}

	// Add User-Agent and OS info if available
	ua := ""
	if uaVal, ok := ipToUA.Load(ip); ok {
		ua = uaVal.(string)
	} else {
		// Fallback to database for persistence across restarts
		ua = getClientUA(ip)
		if ua != "" {
			ipToUA.Store(ip, ua) // Refresh memory cache
		}
	}

	if ua != "" && ua != "-" {
		info.UserAgent = ua
		info.OS = detectOS(ua)
		
		// If it's a mobile device, we can sometimes improve the manufacturer field
		if info.Manufacturer == "" || info.Manufacturer == "Unknown" {
			dev := detectDevice(ua)
			if dev != "" {
				info.Manufacturer = dev
			}
		}
	}

	// Set expiration
	if isPrivate {
		info.ExpiresAt = time.Now().Add(1 * time.Hour)
	} else {
		info.ExpiresAt = time.Now().Add(24 * time.Hour)
	}

	ipInfoCache.Store(ip, info)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func detectOS(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") || strings.Contains(ua, "ipod"):
		return "iOS"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "windows nt"):
		return "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os x"):
		return "macOS"
	case strings.Contains(ua, "linux") && !strings.Contains(ua, "android"):
		return "Linux"
	case strings.Contains(ua, "crkey"):
		return "Chromecast"
	case strings.Contains(ua, "tizen"):
		return "Tizen (Samsung TV)"
	case strings.Contains(ua, "playstation"):
		return "PlayStation"
	case strings.Contains(ua, "nintendo switch"):
		return "Nintendo Switch"
	}
	// DoH specific UAs
	if strings.Contains(ua, "dnssettings") {
		return "Apple Managed DNS"
	}
	return ""
}

func detectDevice(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "iphone"): return "iPhone"
	case strings.Contains(ua, "ipad"):   return "iPad"
	case strings.Contains(ua, "pixel"):  return "Google Pixel"
	case strings.Contains(ua, "samsung") || strings.Contains(ua, "sm-"): return "Samsung Device"
	}
	return ""
}

func getMACByIP(ip string) string {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == ip {
			return fields[3]
		}
	}
	return ""
}

func getManufacturerByMAC(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToUpper(strings.ReplaceAll(mac[:8], ":", ""))

	// Expanded OUI database
	ouis := map[string]string{
		"B4FB12": "Apple", "0017F2": "Apple", "D0034B": "Apple", "F01898": "Apple",
		"04D6B8": "Apple", "1499E2": "Apple", "341298": "Apple", "404D7F": "Apple",
		"600308": "Apple", "703560": "Apple", "8C8590": "Apple", "DC2BD4": "Apple",
		"00166B": "Samsung", "E470B8": "Samsung", "286B35": "Samsung", "382D23": "Samsung",
		"484377": "Samsung", "8C71F8": "Samsung", "90B686": "Samsung", "B40B44": "Samsung",
		"702C1F": "Google", "D824BD": "Google", "1CC035": "Google", "BCD074": "Google",
		"28D244": "Xiaomi", "649E33": "Xiaomi", "8CBEBE": "Xiaomi", "ACF7F3": "Xiaomi",
		"00000C": "Cisco", "000142": "Cisco", "000143": "Cisco",
		"0010FA": "Sony", "280D1C": "Sony", "3C0771": "Sony", "709E29": "Sony",
		"001422": "Dell", "000874": "Dell", "000AF7": "Dell",
		"001143": "HP", "000E7F": "HP", "001185": "HP",
		"001132": "Synology", "9009DF": "Synology", "0024A5": "Synology",
		"B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
		"000C29": "VMware", "080027": "VirtualBox",
		"000420": "Slim Devices (Logitech)",
		"00096B": "IBM",
		"001F3B": "Nintendo",
		"C0EEFB": "OnePlus",
		"000FB5": "Netgear",
		"0014BF": "Linksys",
		"0018E7": "TP-Link", "F4F26D": "TP-Link",
	}

	if m, ok := ouis[prefix]; ok {
		return m
	}
	return "Unknown"
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
	s.CoreDNSVersion = getCoreDNSVersion()

	// Try to read Alpine version
	alpineVer := "3.23"
	if b, err := os.ReadFile("/etc/alpine-release"); err == nil {
		alpineVer = strings.TrimSpace(string(b))
	}
	s.AlpineVersion = alpineVer

	// Get latest versions for update check
	latest := getLatestVersions()
	s.LatestVersion = latest.ShieldDNS
	s.LatestCoreDNSVersion = latest.CoreDNS
	s.LatestAlpineVersion = latest.Alpine

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
	configLock.RLock()
	adminDomain := config.AdminDomain
	blockPageIP := config.BlockPageIP
	signEnabled := config.SignMobileConfig
	configLock.RUnlock()

	host := adminDomain
	if host == "" {
		host = r.Host
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
	}

	// Build ServerAddresses XML block
	serverAddrsXML := ""
	if blockPageIP != "" && blockPageIP != "127.0.0.1" {
		serverAddrsXML = fmt.Sprintf(`
			<key>ServerAddresses</key>
			<array>
				<string>%s</string>
			</array>`, blockPageIP)
	}

	// Certificate handling - check if self-signed
	certFile := os.Getenv("CERT_FILE")
	if certFile == "" {
		certFile = "/ssl/fullchain.pem"
	}

	isSelfSigned := false
	var certBase64 string
	certData, err := os.ReadFile(certFile)
	if err != nil {
		certData, _ = os.ReadFile("/etc/shielddns/ssl/selfsigned.crt")
	}

	if certData != nil {
		block, _ := pem.Decode(certData)
		if block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				if cert.Issuer.String() == cert.Subject.String() {
					isSelfSigned = true
					certBase64 = base64.StdEncoding.EncodeToString(block.Bytes)
				}
			}
		}
	}

	// Generate unique UUIDs
	genUUID := func(offset int64) string {
		now := time.Now().UnixNano() + offset
		return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
			now&0xFFFFFFFF, now>>32&0xFFFF,
			0x4000|(now>>48&0x0FFF), 0x8000|(now>>60&0x3FFF),
			now&0xFFFFFFFFFFFF)
	}

	dohUUID := genUUID(0)
	profileUUID := genUUID(1)
	certPayloadUUID := genUUID(2)

	certPayloadXML := ""
	certReferenceXML := ""
	if isSelfSigned && certBase64 != "" {
		certPayloadXML = fmt.Sprintf(`
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>ShieldDNS.crt</string>
			<key>PayloadContent</key>
			<data>%s</data>
			<key>PayloadDescription</key>
			<string>Trusts the ShieldDNS self-signed root certificate.</string>
			<key>PayloadDisplayName</key>
			<string>ShieldDNS Root Certificate</string>
			<key>PayloadIdentifier</key>
			<string>com.shielddns.rootcert</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>%s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>`, certBase64, certPayloadUUID)

		certReferenceXML = fmt.Sprintf("\n\t\t\t<key>PayloadCertificateUUID</key>\n\t\t\t<string>%s</string>", certPayloadUUID)
	}

	// NOTE: iOS Configuration Profiles only support DNSProtocol values "TLS" and "HTTPS".
	// QUIC is NOT part of Apple's MDM specification and causes "internal error" on install.
	// DoQ is supported natively via third-party apps (DNSecure, AdGuard) but not via profiles.

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
				<string>HTTPS</string>
				<key>ServerURL</key>
				<string>https://%[1]s/dns-query</string>%[2]s
			</dict>
			<key>OnDemandRules</key>
			<array>
				<dict>
					<key>Action</key>
					<string>Connect</string>
				</dict>
			</array>
			<key>PayloadDescription</key>
			<string>Encrypted DNS-over-HTTPS (DoH) for ShieldDNS (%[1]s).</string>
			<key>PayloadDisplayName</key>
			<string>ShieldDNS DoH (%[1]s)</string>
			<key>PayloadIdentifier</key>
			<string>com.shielddns.doh.%[1]s</string>
			<key>PayloadType</key>
			<string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key>
			<string>%[3]s</string>
			<key>PayloadVersion</key>
			<integer>1</integer>%[5]s
		</dict>%[4]s
	</array>
	<key>PayloadDescription</key>
	<string>ShieldDNS Encryption Profile (%[1]s). Enables system-wide DNS encryption for improved privacy.</string>
	<key>PayloadDisplayName</key>
	<string>ShieldDNS Protection (%[1]s)</string>
	<key>PayloadIdentifier</key>
	<string>com.shielddns.profile.%[1]s</string>
	<key>PayloadOrganization</key>
	<string>ShieldDNS Project</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>%[6]s</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
	<key>ConsentText</key>
	<dict>
		<key>default</key>
		<string>SECURITY &amp; PRIVACY NOTICE:
This profile configures your device to use ShieldDNS (%[1]s) as its encrypted DNS provider.

WHAT THIS MEANS:
ShieldDNS will encrypt all DNS queries from this device, preventing ISPs and third parties from monitoring your web activity. It also leverages advanced blocklists to protect you from advertisements, trackers, and malicious content in real-time.

TECHNICAL DETAILS:
- Target Server: %[1]s
- Supported Protocol: DNS-over-HTTPS (DoH)
- Documentation: https://github.com/FaserF/ShieldDNS

By proceeding, you consent to all DNS traffic being routed through this server. No personal web traffic (HTTP/HTTPS content) is decrypted; only the destination addresses are processed for filtering. You can remove this profile at any time in Settings &gt; General &gt; VPN &amp; Device Management.</string>
	</dict>
</dict>
</plist>`, host, serverAddrsXML, dohUUID, certPayloadXML, certReferenceXML, profileUUID)

	finalContent := []byte(mobileConfig)
	if signEnabled {
		// Get cert and key files
		certFile := os.Getenv("CERT_FILE")
		if certFile == "" { certFile = "/ssl/fullchain.pem" }
		keyFile := os.Getenv("KEY_FILE")
		if keyFile == "" { keyFile = "/ssl/privkey.pem" }

		if _, err := os.Stat(certFile); err == nil {
			if signed, err := signProfile(finalContent, certFile, keyFile); err == nil {
				finalContent = signed
			} else {
				log.Printf("⚠️ Error signing profile: %v", err)
			}
		}
	}

	w.Write(finalContent)
}

func signProfile(content []byte, certFile, keyFile string) ([]byte, error) {
	// openssl smime -sign -signer cert.pem -inkey key.pem -certfile chain.pem -nodetach -outform der
	// Note: certFile (fullchain.pem) usually contains both the entity cert and the chain.
	cmd := exec.Command("openssl", "smime", "-sign",
		"-signer", certFile,
		"-inkey", keyFile,
		"-certfile", certFile,
		"-nodetach",
		"-outform", "der")

	cmd.Stdin = bytes.NewReader(content)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl error: %v, stderr: %s", err, stderr.String())
	}

	return out.Bytes(), nil
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

		// Sanitize & Validate Custom Rules
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
			if s := sanitizeRule(b); s != "" && isValidDomain(s) {
				cleanBlocked = append(cleanBlocked, s)
			}
		}
		newConfig.CustomBlocked = cleanBlocked

		var cleanAllowed []string
		for _, a := range newConfig.CustomAllowed {
			if s := sanitizeRule(a); s != "" && isValidDomain(s) {
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

func handleGetCountries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GetCountryList())
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
	clientIP := r.URL.Query().Get("client_ip")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := fmt.Sscanf(limitStr, "%d", &limit); err == nil && l > 0 {
			// limit already set
		}
	}

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
	if clientIP != "" {
		query += " AND client_ip = ?"
		args = append(args, clientIP)
	}

	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d", limit)

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

func handleTopDomainsForClient(w http.ResponseWriter, r *http.Request) {
	clientIP := r.URL.Query().Get("ip")
	if clientIP == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	rows, err := db.Query(`
		SELECT domain, COUNT(*) as count
		FROM queries
		WHERE client_ip = ?
		GROUP BY domain
		ORDER BY count DESC
		LIMIT 10
	`, clientIP)
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

func handleClientStats(w http.ResponseWriter, r *http.Request) {
	clientIP := r.URL.Query().Get("ip")
	if clientIP == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	cs, err := getClientStats(clientIP)
	if err != nil {
		log.Printf("Error fetching client stats: %v", err)
		http.Error(w, "Error fetching client stats", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cs)
}

func handleClientTopBlocked(w http.ResponseWriter, r *http.Request) {
	clientIP := r.URL.Query().Get("ip")
	if clientIP == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	limit := 10
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil {
			limit = l
		}
	}

	results, err := getClientTopBlocked(clientIP, limit)
	if err != nil {
		log.Printf("Error fetching top blocked: %v", err)
		http.Error(w, "Error fetching top blocked", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func handleClientAlias(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		configLock.RLock()
		defer configLock.RUnlock()

		if config.ClientAliases == nil {
			config.ClientAliases = make(map[string]string)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config.ClientAliases)
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			IP    string `json:"ip"`
			Alias string `json:"alias"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.IP == "" {
			http.Error(w, "IP required", http.StatusBadRequest)
			return
		}

		configLock.Lock()
		if config.ClientAliases == nil {
			config.ClientAliases = make(map[string]string)
		}
		if req.Alias == "" {
			delete(config.ClientAliases, req.IP)
		} else {
			config.ClientAliases[req.IP] = req.Alias
		}
		saveConfigNoLock()
		configLock.Unlock()

		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
