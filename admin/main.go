package main

import (
	"archive/zip"
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type Config struct {
	Upstreams           []string `json:"upstreams"`
	UpstreamDoT         []string `json:"upstream_dot"`
	PreferEncrypted     bool     `json:"prefer_encrypted"`
	UseFastestUpstream  bool     `json:"use_fastest_upstream"`
	RetentionDays       int      `json:"retention_days"`
	Lists               []List   `json:"lists"`
	Whitelists          []List   `json:"whitelists"`
	CustomBlocked       []string `json:"custom_blocked"`
	CustomAllowed       []string `json:"custom_allowed"`
	SetupDone           bool     `json:"setup_done"`
	AdminPasswordHashed string   `json:"admin_password_hashed"`
}

type List struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type Stats struct {
	TotalQueries   int64            `json:"total_queries"`
	BlockedQueries int64            `json:"blocked_queries"`
	CacheHits      int64            `json:"cache_hits"`
	QueryTypes     map[string]int64 `json:"query_types"`
	Version        string           `json:"version"`
}

type Query struct {
	Time     time.Time `json:"time"`
	Domain   string    `json:"domain"`
	Type     string    `json:"type"`
	Status   string    `json:"status"` // "Allowed" or "Blocked"
	ClientIP string    `json:"client_ip"`
}

type HourStats struct {
	Total   int64 `json:"total"`
	Blocked int64 `json:"blocked"`
}

var (
	config         Config
	configLock     sync.RWMutex
	stats          Stats
	statsLock      sync.RWMutex
	dnsCmd         *exec.Cmd
	sessionToken   string
	sessionLock    sync.RWMutex
	recentQueries  []Query
	queryLock      sync.RWMutex
	history        [24]HourStats
	historyLock    sync.RWMutex
	Version        = "v1.0.0"

	// Health monitoring
	healthyUpstreams []string
	healthyDoT       []string
	healthLock       sync.RWMutex

	// Log Buffering
	logBuffer  []Query
	bufferLock sync.Mutex

	// Login Throttling
	loginFailures = make(map[string]int)
	failureLock   sync.Mutex

	// SSE Logging
	sseClients = make(map[chan Query]struct{})
	sseLock    sync.Mutex

	// Latency Tracking
	latencyMap  = make(map[string]time.Duration)
	latencyLock sync.RWMutex
)

var (
	DataDir       = "/etc/shielddns"
	ConfigPath    = "/etc/shielddns/config.json"
	BlocklistPath = "/etc/shielddns/blocklist.hosts"
	WhitelistPath = "/etc/shielddns/whitelist.hosts"
	CorefilePath  = "/etc/Corefile"
	DBPath        = "/etc/shielddns/queries.db"
)

const CookieName = "shielddns_session"

func initPaths() {
	if dd := os.Getenv("DATA_DIR"); dd != "" {
		DataDir = dd
	}
	ConfigPath = filepath.Join(DataDir, "config.json")
	BlocklistPath = filepath.Join(DataDir, "blocklist.hosts")
	WhitelistPath = filepath.Join(DataDir, "whitelist.hosts")
	DBPath = filepath.Join(DataDir, "queries.db")

	if cp := os.Getenv("COREFILE_PATH"); cp != "" {
		CorefilePath = cp
	}
}

var db *sql.DB

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
	go startRetentionWorker()

	// Start CoreDNS management
	go startCoreDNS()

	// Auth API
	http.HandleFunc("/api/auth-status", handleAuthStatus)
	http.HandleFunc("/api/setup", handleSetup)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/presets", handlePresets)

	// Protected API
	http.Handle("/api/events", authMiddleware(http.HandlerFunc(handleEvents)))
	http.Handle("/api/stats", authMiddleware(http.HandlerFunc(handleStats)))
	http.Handle("/api/config", authMiddleware(http.HandlerFunc(handleConfig)))
	http.Handle("/api/refresh", authMiddleware(http.HandlerFunc(handleRefresh)))
	http.Handle("/api/queries", authMiddleware(http.HandlerFunc(handleQueries)))
	http.Handle("/api/history", authMiddleware(http.HandlerFunc(handleHistory)))
	http.Handle("/api/search", authMiddleware(http.HandlerFunc(handleSearch)))
	http.Handle("/api/top-blocked", authMiddleware(http.HandlerFunc(handleTopBlocked)))
	http.Handle("/api/top-clients", authMiddleware(http.HandlerFunc(handleTopClients)))
	http.Handle("/api/export", authMiddleware(http.HandlerFunc(handleExport)))
	http.Handle("/api/backup", authMiddleware(http.HandlerFunc(handleBackup)))
	http.Handle("/api/change-password", authMiddleware(http.HandlerFunc(handleChangePassword)))

	// Get cert/key paths
	certFile := os.Getenv("CERT_FILE")
	if certFile == "" { certFile = "/ssl/fullchain.pem" }
	keyFile := os.Getenv("KEY_FILE")
	if keyFile == "" { keyFile = "/ssl/privkey.pem" }

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Println("ShieldDNS Admin starting on :443 (HTTPS)")
		if err := http.ListenAndServeTLS(":443", certFile, keyFile, nil); err != nil {
			log.Printf("Admin UI server stopped: %v", err)
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

func handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ch := make(chan Query, 10)
	sseLock.Lock()
	sseClients[ch] = struct{}{}
	sseLock.Unlock()

	defer func() {
		sseLock.Lock()
		delete(sseClients, ch)
		sseLock.Unlock()
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "data: {\"type\":\"ping\"}\n\n")
	flusher.Flush()

	for {
		select {
		case q := <-ch:
			data, _ := json.Marshal(q)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func handleBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=shielddns-backup.zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	files := []string{ConfigPath, DBPath, BlocklistPath, WhitelistPath}
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

func startRetentionWorker() {
	ticker := time.NewTicker(12 * time.Hour)
	for range ticker.C {
		configLock.RLock()
		days := config.RetentionDays
		if days <= 0 {
			days = 30
		}
		configLock.RUnlock()

		if db != nil {
			_, err := db.Exec("DELETE FROM queries WHERE timestamp < datetime('now', ?)", fmt.Sprintf("-%d days", days))
			if err != nil {
				log.Printf("Error cleaning up old queries: %v", err)
			} else {
				log.Printf("Cleaned up queries older than %d days", days)
			}
		}
	}
}

func initDB() {
	var err error
	os.MkdirAll(filepath.Dir(DBPath), 0755)
	db, err = sql.Open("sqlite", DBPath)
	if err != nil {
		log.Fatalf("Fatal: Could not open database: %v", err)
	}

	_, err = db.Exec(`
		PRAGMA journal_mode=WAL;
		CREATE TABLE IF NOT EXISTS queries (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp DATETIME,
			domain TEXT,
			type TEXT,
			status TEXT,
			client_ip TEXT
		);
		CREATE INDEX IF NOT EXISTS idx_timestamp ON queries(timestamp);
		CREATE INDEX IF NOT EXISTS idx_status ON queries(status);
		CREATE INDEX IF NOT EXISTS idx_client ON queries(client_ip);
	`)
	if err != nil {
		log.Fatalf("Fatal: Could not initialize database schema: %v", err)
	}
}

func startDBWorker() {
	// Periodic cleanup of old queries (30 days)
	ticker := time.NewTicker(24 * time.Hour)
	cleanup := func() {
		_, err := db.Exec("DELETE FROM queries WHERE timestamp < datetime('now', '-30 days')")
		if err != nil {
			log.Printf("Error purging old queries: %v", err)
		} else {
			log.Println("Database maintenance: Old queries purged.")
		}
	}

	go cleanup() // Initial cleanup
	for range ticker.C {
		cleanup()
	}
}

func startLogWorker() {
	// Periodically flush buffered queries to SQLite
	ticker := time.NewTicker(5 * time.Second)
	for range ticker.C {
		bufferLock.Lock()
		if len(logBuffer) == 0 {
			bufferLock.Unlock()
			continue
		}
		toFlush := logBuffer
		logBuffer = nil
		bufferLock.Unlock()

		if db == nil {
			continue
		}
		flushLogs(toFlush)
	}
}

func flushLogs(toFlush []Query) {
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting log transaction: %v", err)
		return
	}

	stmt, err := tx.Prepare("INSERT INTO queries (timestamp, domain, type, status, client_ip) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		log.Printf("Error preparing log statement: %v", err)
		tx.Rollback()
		return
	}
	defer stmt.Close()

	for _, q := range toFlush {
		_, err = stmt.Exec(q.Time.Format(time.RFC3339), q.Domain, q.Type, q.Status, q.ClientIP)
		if err != nil {
			log.Printf("Error executing log statement: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing log transaction: %v", err)
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configLock.RLock()
		hasPwd := config.AdminPasswordHashed != "" // Changed from PasswordHash to AdminPasswordHashed
		configLock.RUnlock()

		if !hasPwd {
			http.Error(w, "Setup required", http.StatusForbidden)
			return
		}

		cookie, err := r.Cookie(CookieName)
		sessionLock.RLock()
		valid := err == nil && cookie.Value == sessionToken && sessionToken != ""
		sessionLock.RUnlock()

		if !valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	configLock.RLock()
	hasPwd := config.AdminPasswordHashed != "" // Changed from PasswordHash to AdminPasswordHashed
	configLock.RUnlock()

	cookie, err := r.Cookie(CookieName)
	sessionLock.RLock()
	loggedIn := err == nil && cookie.Value == sessionToken && sessionToken != ""
	sessionLock.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"need_setup": !hasPwd,
		"logged_in":  loggedIn,
	})
}

func handleSetup(w http.ResponseWriter, r *http.Request) {
	configLock.Lock()
	defer configLock.Unlock()

	if config.AdminPasswordHashed != "" { // Changed from PasswordHash to AdminPasswordHashed
		http.Error(w, "Already setup", http.StatusConflict)
		return
	}

	var req struct{ Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 12 {
		http.Error(w, "Password too short", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error secure hashing", http.StatusInternalServerError)
		return
	}
	config.AdminPasswordHashed = string(hash) // Changed from PasswordHash to AdminPasswordHashed
	saveConfigNoLock()
	w.WriteHeader(http.StatusOK)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	ip := strings.Split(r.RemoteAddr, ":")[0]
	failureLock.Lock()
	if loginFailures[ip] >= 5 {
		failureLock.Unlock()
		http.Error(w, "Too many login attempts. Please wait.", http.StatusTooManyRequests)
		return
	}
	failureLock.Unlock()

	configLock.RLock()
	err := bcrypt.CompareHashAndPassword([]byte(config.AdminPasswordHashed), []byte(req.Password)) // Changed from PasswordHash to AdminPasswordHashed
	configLock.RUnlock()

	if err != nil {
		failureLock.Lock()
		loginFailures[ip]++
		go func(ip string) {
			time.Sleep(1 * time.Minute)
			failureLock.Lock()
			loginFailures[ip]--
			failureLock.Unlock()
		}(ip)
		failureLock.Unlock()

		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Generate session
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	sessionLock.Lock()
	sessionToken = token
	sessionLock.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set to true in prod if TLS is handled here, but we often use proxy
		MaxAge:   86400,
	})
	w.WriteHeader(http.StatusOK)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionLock.Lock()
	sessionToken = ""
	sessionLock.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:   CookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	w.WriteHeader(http.StatusOK)
}

func handlePresets(w http.ResponseWriter, r *http.Request) {
	presets := []List{
		// --- Hagezi ---
		{Name: "Hagezi Multi (Light)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt", Enabled: true},
		{Name: "Hagezi Multi (Normal)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt", Enabled: true},
		{Name: "Hagezi Multi (Pro)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt", Enabled: true},
		{Name: "Hagezi Multi (Pro++)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.plus.txt", Enabled: true},
		{Name: "Hagezi Multi (Ultimate)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/ultimate.txt", Enabled: true},
		{Name: "Hagezi TIF (Threat Intelligence)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.txt", Enabled: true},
		{Name: "Hagezi Gambling", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/gambling.txt", Enabled: true},
		{Name: "Hagezi Fake (Fake Stores/Malware)", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/fake.txt", Enabled: true},
		// --- OISD ---
		{Name: "OISD Basic", URL: "https://big.oisd.nl", Enabled: true},
		{Name: "OISD Full", URL: "https://small.oisd.nl", Enabled: true},
		// --- AdGuard ---
		{Name: "AdGuard DNS Filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", Enabled: true},
		{Name: "AdGuard Tracking Protection", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt", Enabled: true},
		{Name: "AdGuard Social Media Filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt", Enabled: true},
		{Name: "AdGuard Annoyances Filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_48.txt", Enabled: true},
		// --- Steven Black ---
		{Name: "Steven Black Unified", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Enabled: true},
		{Name: "Steven Black (Porn/Gambling/FakeNews)", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn/hosts", Enabled: true},
		// --- 1Hosts ---
		{Name: "1Hosts (Lite)", URL: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.txt", Enabled: true},
		{Name: "1Hosts (Pro)", URL: "https://raw.githubusercontent.com/badmojr/1Hosts/master/Pro/hosts.txt", Enabled: true},
		{Name: "uBlock Origin Filter List", URL: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt", Enabled: true},
		// --- Specialized ---
		{Name: "Phishing.Database (Phishing Domains)", URL: "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-active.txt", Enabled: true},
		{Name: "Dandelion Sprout's Game Console List", URL: "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/GameConsoleAdblockList.txt", Enabled: true},
		{Name: "Lightswitch05 (Ads & Tracking Extended)", URL: "https://raw.githubusercontent.com/lightswitch05/hosts/master/ads-and-tracking-extended.txt", Enabled: true},
		{Name: "The Big List of Hacked Sites", URL: "https://raw.githubusercontent.com/mitchellkrogza/The-Big-List-of-Hacked-Malware-Web-Sites/master/hacked-domains.txt", Enabled: true},
		{Name: "KADhost (German Blocklist)", URL: "https://raw.githubusercontent.com/KADhost/KADhost/master/KADhost.txt", Enabled: true},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(presets)
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current  string `json:"current"`
		New      string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	if err := bcrypt.CompareHashAndPassword([]byte(config.AdminPasswordHashed), []byte(req.Current)); err != nil { // Changed from PasswordHash to AdminPasswordHashed
		http.Error(w, "Current password incorrect", http.StatusUnauthorized)
		return
	}

	if len(req.New) < 12 {
		http.Error(w, "New password too short", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error secure hashing", http.StatusInternalServerError)
		return
	}
	config.AdminPasswordHashed = string(hash) // Changed from PasswordHash to AdminPasswordHashed
	saveConfigNoLock()

	// Clear all sessions on pwd change
	sessionLock.Lock()
	sessionToken = ""
	sessionLock.Unlock()

	w.WriteHeader(http.StatusOK)
}

func loadConfig() {
	configLock.Lock()
	defer configLock.Unlock()

	file, err := os.ReadFile(ConfigPath)
	if err != nil {
		log.Printf("Creating default config")
		config = Config{
			Upstreams:       []string{"86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"},
			UpstreamDoT:     []string{"unfiltered.joindns4.eu", "dns.quad9.net", "one.one.one.one", "dns.google"},
			PreferEncrypted: true,
			Lists: []List{
				{Name: "ShieldDNS Official Blocklist", URL: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/blocklists/default.txt", Enabled: true},
				{Name: "HaGeZi Multi Pro", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt", Enabled: true},
				{Name: "AdGuard DNS Filter", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Enabled: true},
				{Name: "Steven Black Unified", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Enabled: false},
				{Name: "AdAway Default", URL: "https://adaway.org/hosts.txt", Enabled: false},
				{Name: "OISD Pro", URL: "https://big.oisd.nl", Enabled: false},
			},
			Whitelists: []List{
				{Name: "ShieldDNS Official Whitelist", URL: "https://raw.githubusercontent.com/FaserF/ShieldDNS/main/official/whitelists/default.txt", Enabled: true},
			},
		}
		saveConfigNoLock()
		return
	}
	json.Unmarshal(file, &config)

	// Ensure defaults if fields are empty
	if len(config.Upstreams) == 0 {
		config.Upstreams = []string{"86.54.11.100", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.0.0.1"}
	}
	// Limit to max 5
	if len(config.Upstreams) > 5 { config.Upstreams = config.Upstreams[:5] }
	if len(config.UpstreamDoT) > 5 { config.UpstreamDoT = config.UpstreamDoT[:5] }
}

func saveConfigNoLock() {
	data, _ := json.MarshalIndent(config, "", "  ")
	os.MkdirAll(filepath.Dir(ConfigPath), 0755)
	os.WriteFile(ConfigPath, data, 0644)
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	statsLock.RLock()
	s := stats
	statsLock.RUnlock()

	s.Version = Version
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		configLock.Lock()
		// Preserve password hash if not provided in POST (usual case)
		if newConfig.AdminPasswordHashed == "" { // Changed from PasswordHash to AdminPasswordHashed
			newConfig.AdminPasswordHashed = config.AdminPasswordHashed // Changed from PasswordHash to AdminPasswordHashed
		}
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

func startBackgroundUpdater() {
	updateBlocklist() // Initial update
	ticker := time.NewTicker(6 * time.Hour)
	for range ticker.C {
		updateBlocklist()
	}
}

func updateBlocklist() {
	log.Println("Updating blocklists...")
	configLock.RLock()
	blocklists := config.Lists
	whitelists := config.Whitelists
	customBlocked := config.CustomBlocked
	customAllowed := config.CustomAllowed
	configLock.RUnlock()

	blockDomains := make(map[string]struct{})
	whiteDomains := make(map[string]struct{})

	for _, list := range blocklists {
		if !list.Enabled { continue }
		processList(list, blockDomains, whiteDomains)
	}

	for _, list := range whitelists {
		if !list.Enabled { continue }
		processList(list, blockDomains, whiteDomains) // Whitelists can also have block rules technically, but usually they just have white
	}

	// Add Custom Rules
	for _, d := range customBlocked {
		blockDomains[d] = struct{}{}
	}
	for _, d := range customAllowed {
		whiteDomains[d] = struct{}{}
	}

	// Remove whitelisted domains from blocklist
	for d := range whiteDomains {
		delete(blockDomains, d)
	}

	// Write Blocklist
	var combined strings.Builder
	for domain := range blockDomains {
		combined.WriteString(fmt.Sprintf("0.0.0.0 %s\n", domain))
	}
	os.MkdirAll(filepath.Dir(BlocklistPath), 0755)
	os.WriteFile(BlocklistPath, []byte(combined.String()), 0644)
	log.Printf("Blocklist updated with %d domains", len(blockDomains))

	// Write Whitelist for CoreDNS explicitly (optional but good for tracking)
	var whiteBuilder strings.Builder
	for domain := range whiteDomains {
		whiteBuilder.WriteString(fmt.Sprintf("127.0.0.1 %s\n", domain)) // Or just track it
	}
	os.WriteFile(WhitelistPath, []byte(whiteBuilder.String()), 0644)
}

func processList(list List, blockMap map[string]struct{}, whiteMap map[string]struct{}) {
	var body []byte
	var err error

	if strings.HasPrefix(list.URL, "file://") {
		path := strings.TrimPrefix(list.URL, "file://")
		body, err = os.ReadFile(path)
	} else {
		resp, err := http.Get(list.URL)
		if err != nil {
			log.Printf("⚠️  WARNING: Could not fetch %s (%s): %v. Skipping...", list.Name, list.URL, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Printf("⚠️  WARNING: %s returned status %d. Skipping...", list.Name, resp.StatusCode)
			return
		}
		body, err = io.ReadAll(resp.Body)
	}

	if err != nil {
		log.Printf("⚠️  WARNING: Error reading %s: %v. Skipping...", list.Name, err)
		return
	}

	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		isWhitelist := false
		if strings.HasPrefix(line, "@@") {
			isWhitelist = true
			line = line[2:]
		}

		domain := ""
		// AdGuard / AdBlock: ||domain^
		if strings.HasPrefix(line, "||") {
			domain = strings.Split(strings.TrimPrefix(line, "||"), "^")[0]
		} else if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") || strings.HasPrefix(line, "::1 ") {
			// Hosts: 0.0.0.0 domain
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain = parts[1]
			}
		} else if strings.HasPrefix(line, "address=/") {
			// Dnsmasq: address=/domain/0.0.0.0
			parts := strings.Split(line, "/")
			if len(parts) >= 3 {
				domain = parts[1]
			}
		} else if !strings.Contains(line, "/") && !strings.Contains(line, " ") && strings.Contains(line, ".") {
			// Raw domain
			domain = line
		}

		if domain != "" {
			domain = strings.Trim(domain, ".") // Some lists have trailing dots
			if isWhitelist {
				whiteMap[domain] = struct{}{}
			} else {
				blockMap[domain] = struct{}{}
			}
		}
	}
}

func startHealthChecker() {
	checkAll() // Initial check
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		checkAll()
	}
}

func checkAll() {
	configLock.RLock()
	upstreams := config.Upstreams
	dots := config.UpstreamDoT
	smart := config.UseFastestUpstream
	configLock.RUnlock()

	var newHealthyUpstreams []string
	for _, u := range upstreams {
		start := time.Now()
		if checkDNS(u) {
			lat := time.Since(start)
			latencyLock.Lock()
			latencyMap[u] = lat
			latencyLock.Unlock()
			newHealthyUpstreams = append(newHealthyUpstreams, u)
		}
	}

	var newHealthyDoT []string
	for _, u := range dots {
		start := time.Now()
		if checkDoT(u) {
			lat := time.Since(start)
			latencyLock.Lock()
			latencyMap[u] = lat
			latencyLock.Unlock()
			newHealthyDoT = append(newHealthyDoT, u)
		}
	}

	healthLock.Lock()
	healthyUpstreams = newHealthyUpstreams
	healthyDoT = newHealthyDoT
	healthLock.Unlock()

	if smart {
		updateCorefile()
	}
}

func checkDNS(addr string) bool {
	if !strings.Contains(addr, ":") { addr += ":53" }
	conn, err := net.DialTimeout("udp", addr, 2*time.Second)
	if err != nil { return false }
	conn.Close()
	return true
}

func checkDoT(addr string) bool {
	host := addr
	if !strings.Contains(host, ":") { host += ":853" }
	conf := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", host, conf)
	if err != nil { return false }
	conn.Close()
	return true
}

func equal(a, b []string) bool {
	if len(a) != len(b) { return false }
	for i := range a {
		if a[i] != b[i] { return false }
	}
	return true
}

func updateCorefile() {
	configLock.RLock()
	preferEncrypted := config.PreferEncrypted
	smart := config.UseFastestUpstream
	configLock.RUnlock()

	healthLock.RLock()
	hDNS := make([]string, len(healthyUpstreams))
	copy(hDNS, healthyUpstreams)
	hDoT := make([]string, len(healthyDoT))
	copy(hDoT, healthyDoT)
	healthLock.RUnlock()

	if smart {
		latencyLock.RLock()
		sort.Slice(hDNS, func(i, j int) bool {
			return latencyMap[hDNS[i]] < latencyMap[hDNS[j]]
		})
		sort.Slice(hDoT, func(i, j int) bool {
			return latencyMap[hDoT[i]] < latencyMap[hDoT[j]]
		})
		latencyLock.RUnlock()
	}

	var upstreams []string
	if preferEncrypted {
		for _, u := range hDoT {
			if !strings.Contains(u, ":") { u += ":853" }
			upstreams = append(upstreams, "tls://"+u)
		}
	}
	// Fallback to normal DNS
	upstreams = append(upstreams, hDNS...)

	// If everything is down, use defaults as last resort to avoid total failure
	if len(upstreams) == 0 {
		upstreams = []string{"8.8.8.8", "1.1.1.1"}
	}

	upstreamStr := strings.Join(upstreams, " ")

	// Get cert paths from environment (provided by run.sh)
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	if certFile == "" { certFile = "/ssl/fullchain.pem" }
	if keyFile == "" { keyFile = "/ssl/privkey.pem" }

	corefile := fmt.Sprintf(`.:53 {
    bind 0.0.0.0
    dnssec
    health :8082
    serve_stale
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
    }
    hosts %s {
        reload 5s
        fallthrough
    }
    log
    errors
}

tls://.:853 {
    tls %s %s {
        protocols tls1.2 tls1.3
        ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305
    }
    dnssec
    health :8082
    serve_stale
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
    }
    log
    errors
}

https://.:5553 {
    tls %s %s {
        protocols tls1.2 tls1.3
        ciphers ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305
    }
    dnssec
    health :8082
    serve_stale
    cache 3600 {
        success 10000
        denial 2500
        prefetch 10 10m 10%%
    }
    forward . %s {
        health_check 10s
    }
    log
    errors
}
`, upstreamStr, BlocklistPath, certFile, keyFile, upstreamStr, certFile, keyFile, upstreamStr)

	os.WriteFile(CorefilePath, []byte(corefile), 0644)
}

func startCoreDNS() {
	for {
		log.Println("Starting CoreDNS...")
		dnsCmd = exec.Command("/usr/bin/coredns", "-conf", CorefilePath)

		stdout, err := dnsCmd.StdoutPipe()
		if err != nil {
			log.Printf("Error creating stdout pipe: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		dnsCmd.Stderr = os.Stderr

		if err := dnsCmd.Start(); err != nil {
			log.Printf("Error starting CoreDNS: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		go func(reader io.Reader) {
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				line := scanner.Text()
				fmt.Println(line)
				parseLogLine(line)
			}
		}(stdout)

		dnsCmd.Wait()
		log.Println("CoreDNS exited. Restarting...")
		time.Sleep(1 * time.Second)
	}
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

	var queries []Query
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
	// Get last 24 hours of stats grouped by hour
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
	// Fill results conservatively, mapping hour strings to indices
	for rows.Next() {
		var hr int
		var total, blocked int64
		rows.Scan(&hr, &total, &blocked)
		if hr >= 0 && hr < 24 {
			result[hr] = HourStats{Total: total, Blocked: blocked}
		}
	}

	// Rotate result so current hour is last
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

	searchStr := fmt.Sprintf(" %s", query)
	file, err := os.Open(BlocklistPath)
	if err != nil {
		http.Error(w, "Blocklist not found", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	found := false
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), searchStr) {
			found = true
			break
		}
	}

	json.NewEncoder(w).Encode(map[string]bool{"blocked": found})
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

	var result []map[string]interface{}
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

	var result []map[string]interface{}
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

func parseLogLine(line string) {
	if !strings.Contains(line, " \"") {
		return
	}

	// Extract Client IP (IPv4/IPv6 safe)
	fields := strings.Fields(line)
	clientIP := ""
	if len(fields) > 1 {
		host, _, err := net.SplitHostPort(fields[1])
		if err == nil {
			clientIP = host
		} else {
			clientIP = fields[1] // Fallback if no port
		}
	}

	parts := strings.Split(line, "\"")
	if len(parts) < 2 {
		return
	}
	queryPart := parts[1]
	queryFields := strings.Fields(queryPart)
	if len(queryFields) < 3 {
		return
	}

	qType := queryFields[0]
	qDomain := strings.TrimSuffix(queryFields[2], ".")
	isBlocked := strings.Contains(line, "qr,aa")
	isCacheHit := strings.Contains(line, "qr,aa") && !isBlocked // Simple heuristic for CoreDNS with cache plugin

	// Update memory stats for real-time dashboard
	statsLock.Lock()
	stats.TotalQueries++
	if isBlocked {
		stats.BlockedQueries++
	}
	if isCacheHit {
		stats.CacheHits++
	}
	stats.QueryTypes[qType]++
	statsLock.Unlock()

	status := "Allowed"
	if isBlocked {
		status = "Blocked"
	}

	// Buffer for batch SQLite insert
	q := Query{
		Time:     time.Now(),
		Domain:   qDomain,
		Type:     qType,
		Status:   status,
		ClientIP: clientIP,
	}

	// Broadcast to SSE clients
	go func(query Query) {
		sseLock.Lock()
		defer sseLock.Unlock()
		for ch := range sseClients {
			select {
			case ch <- query:
			default:
			}
		}
	}(q)

	bufferLock.Lock()
	logBuffer = append(logBuffer, q)
	bufferLock.Unlock()
}
