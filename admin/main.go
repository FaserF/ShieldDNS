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
	TotalQueries   int64 `json:"total_queries"`
	BlockedQueries int64 `json:"blocked_queries"`
}

var (
	config       Config
	configLock   sync.RWMutex
	stats        Stats
	statsLock    sync.RWMutex
	dnsCmd       *exec.Cmd
	sessionToken string
	sessionLock  sync.RWMutex
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
	json.NewDecoder(r.Body).Decode(&req)

	if len(req.Password) < 12 {
		http.Error(w, "Password too short", http.StatusBadRequest)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	config.PasswordHash = string(hash)
	saveConfigNoLock()
	w.WriteHeader(http.StatusOK)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	json.NewDecoder(r.Body).Decode(&req)

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
		{Name: "OISD Basic", URL: "https://big.oisd.nl", Enabled: true},
		{Name: "Hagezi Multi Light", URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt", Enabled: true},
		{Name: "Steven Black Basic", URL: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", Enabled: true},
		{Name: "AdGuard Tracking Filter", URL: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt", Enabled: true},
		{Name: "uBlock Origin List", URL: "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt", Enabled: true},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(presets)
}

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current  string `json:"current"`
		New      string `json:"new"`
	}
	json.NewDecoder(r.Body).Decode(&req)

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

	hash, _ := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
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
	defer statsLock.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
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
			log.Printf("Error fetching %s: %v", list.Name, err)
			continue
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
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
`, upstreams, BlocklistPath)

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

func parseLogLine(line string) {
	// Example: [INFO] [::1]:53 - 1 "A IN google.com. udp 45 false 512" NOERROR qr,rd,ra 68 0.000188613s
	if !strings.Contains(line, " \"") {
		return
	}

	parts := strings.Split(line, "\"")
	if len(parts) < 2 {
		return
	}
	queryPart := parts[1] // "A IN google.com. udp 45 false 512"
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
