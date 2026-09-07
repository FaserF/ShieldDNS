package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
		if newConfig.RoutingRules == nil && config.RoutingRules != nil {
			newConfig.RoutingRules = config.RoutingRules
		}
		if newConfig.WireGuardGateway == "" && config.WireGuardGateway != "" {
			newConfig.WireGuardGateway = config.WireGuardGateway
		}
		if newConfig.LocalPTRUpstreams == nil && config.LocalPTRUpstreams != nil {
			newConfig.LocalPTRUpstreams = config.LocalPTRUpstreams
		}
		if newConfig.ClientRules == nil && config.ClientRules != nil {
			newConfig.ClientRules = config.ClientRules
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
