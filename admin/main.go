package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Upstreams    []string `json:"upstreams"`
	Lists        []List   `json:"lists"`
	PasswordHash string   `json:"password_hash"`
}

type List struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

type Stats struct {
	TotalQueries   int64  `json:"total_queries"`
	BlockedQueries int64  `json:"blocked_queries"`
	Version        string `json:"version"`
}

type Query struct {
	Time   time.Time `json:"time"`
	Domain string    `json:"domain"`
	Type   string    `json:"type"`
	Status string    `json:"status"` // "Allowed" or "Blocked"
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
)

const (
	ConfigPath    = "/etc/shielddns/config.json"
	BlocklistPath = "/etc/shielddns/blocklist.hosts"
	CorefilePath  = "/etc/Corefile"
	CookieName    = "shielddns_session"
)

func main() {
	loadConfig()

	// Start background updater
	go startBackgroundUpdater()

	// Start history cleaner
	go func() {
		for {
			now := time.Now()
			next := now.Truncate(time.Hour).Add(time.Hour)
			time.Sleep(time.Until(next))
			historyLock.Lock()
			history[time.Now().Hour()] = HourStats{}
			historyLock.Unlock()
		}
	}()

	// Start CoreDNS management
	go startCoreDNS()

	// Auth API
	http.HandleFunc("/api/auth-status", handleAuthStatus)
	http.HandleFunc("/api/setup", handleSetup)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/presets", handlePresets)

	// Protected API
	http.Handle("/api/stats", authMiddleware(http.HandlerFunc(handleStats)))
	http.Handle("/api/config", authMiddleware(http.HandlerFunc(handleConfig)))
	http.Handle("/api/refresh", authMiddleware(http.HandlerFunc(handleRefresh)))
	http.Handle("/api/queries", authMiddleware(http.HandlerFunc(handleQueries)))
	http.Handle("/api/history", authMiddleware(http.HandlerFunc(handleHistory)))
	http.Handle("/api/search", authMiddleware(http.HandlerFunc(handleSearch)))
	http.Handle("/api/change-password", authMiddleware(http.HandlerFunc(handleChangePassword)))

	// Static Files
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Serve index for all but check auth status in JS
		http.FileServer(http.Dir("/var/www/admin")).ServeHTTP(w, r)
	})

	port := os.Getenv("ADMIN_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("ShieldDNS Admin starting on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configLock.RLock()
		hasPwd := config.PasswordHash != ""
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
	hasPwd := config.PasswordHash != ""
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

	if config.PasswordHash != "" {
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
	config.PasswordHash = string(hash)
	saveConfigNoLock()
	w.WriteHeader(http.StatusOK)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	configLock.RLock()
	err := bcrypt.CompareHashAndPassword([]byte(config.PasswordHash), []byte(req.Password))
	configLock.RUnlock()

	if err != nil {
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

	if err := bcrypt.CompareHashAndPassword([]byte(config.PasswordHash), []byte(req.Current)); err != nil {
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
	config.PasswordHash = string(hash)
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
			Upstreams: []string{"1.1.1.1", "8.8.8.8"},
			Lists: []List{
				{Name: "AdGuard DNS Filter", URL: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", Enabled: true},
				{Name: "AdAway Default", URL: "https://adaway.org/hosts.txt", Enabled: true},
				{Name: "Peter Lowe's List", URL: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext", Enabled: true},
				{Name: "OISD Basic", URL: "https://big.oisd.nl", Enabled: false},
			},
		}
		saveConfigNoLock()
		return
	}
	json.Unmarshal(file, &config)
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
		if newConfig.PasswordHash == "" {
			newConfig.PasswordHash = config.PasswordHash
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
	lists := config.Lists
	configLock.RUnlock()

	uniqueDomains := make(map[string]struct{})
	for _, list := range lists {
		if !list.Enabled {
			continue
		}
		resp, err := http.Get(list.URL)
		if err != nil {
			log.Printf("⚠️  WARNING: Could not fetch %s (%s): %v. Skipping...", list.Name, list.URL, err)
			continue
		}
		
		if resp.StatusCode != http.StatusOK {
			log.Printf("⚠️  WARNING: %s returned status %d. Skipping...", list.Name, resp.StatusCode)
			resp.Body.Close()
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close() // Close immediately to avoid leaks
		if err != nil {
			log.Printf("⚠️  WARNING: Error reading body of %s: %v. Skipping...", list.Name, err)
			continue
		}

		lines := strings.Split(string(body), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}

			domain := ""
			if strings.HasPrefix(line, "||") && strings.Contains(line, "^") {
				parts := strings.Split(line[2:], "^")
				domain = parts[0]
			} else if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					domain = parts[1]
				}
			} else if !strings.Contains(line, "/") && !strings.Contains(line, " ") && strings.Contains(line, ".") {
				domain = line
			}

			if domain != "" {
				uniqueDomains[domain] = struct{}{}
			}
		}
	}

	var combined strings.Builder
	for domain := range uniqueDomains {
		combined.WriteString(fmt.Sprintf("0.0.0.0 %s\n", domain))
	}

	os.MkdirAll(filepath.Dir(BlocklistPath), 0755)
	os.WriteFile(BlocklistPath, []byte(combined.String()), 0644)
	log.Printf("Blocklist updated with %d domains", len(uniqueDomains))
}

func updateCorefile() {
	configLock.RLock()
	upstreams := strings.Join(config.Upstreams, " ")
	configLock.RUnlock()

	// Get cert paths from environment (provided by run.sh)
	certFile := os.Getenv("CERT_FILE")
	keyFile := os.Getenv("KEY_FILE")
	if certFile == "" { certFile = "/ssl/fullchain.pem" }
	if keyFile == "" { keyFile = "/ssl/privkey.pem" }

	corefile := fmt.Sprintf(`.:53 {
    bind 0.0.0.0
    forward . %s
    hosts %s {
        reload 5s
        fallthrough
    }
    log
    errors
}

https://.:5553 {
    tls %s %s
    forward . %s
    log
    errors
}
`, upstreams, BlocklistPath, certFile, keyFile, upstreams)

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
	queryLock.RLock()
	defer queryLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(recentQueries)
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	historyLock.RLock()
	defer historyLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	
	// Shift history so current hour is last
	hour := time.Now().Hour()
	var result [24]HourStats
	for i := 0; i < 24; i++ {
		result[i] = history[(hour+1+i)%24]
	}
	json.NewEncoder(w).Encode(result)
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

func parseLogLine(line string) {
	// ... (no changes to start)
	if !strings.Contains(line, " \"") {
		return
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

	statsLock.Lock()
	stats.TotalQueries++
	if isBlocked {
		stats.BlockedQueries++
	}
	statsLock.Unlock()

	// Update History
	hour := time.Now().Hour()
	historyLock.Lock()
	history[hour].Total++
	if isBlocked {
		history[hour].Blocked++
	}
	historyLock.Unlock()

	status := "Allowed"
	if isBlocked {
		status = "Blocked"
	}

	queryLock.Lock()
	recentQueries = append([]Query{{
		Time:   time.Now(),
		Domain: qDomain,
		Type:   qType,
		Status: status,
	}}, recentQueries...)
	if len(recentQueries) > 100 {
		recentQueries = recentQueries[:100]
	}
	queryLock.Unlock()
}
