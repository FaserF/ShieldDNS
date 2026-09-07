package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var configKeyCategories = map[string]string{
	"upstreams":                     "dns",
	"upstream_dot":                  "dns",
	"prefer_encrypted":              "dns",
	"use_fastest_upstream":          "dns",
	"smart_selection_policy":        "dns",
	"dnssec_enabled":                "dns",
	"serve_stale":                   "dns",
	"filtering_enabled":             "filtering",
	"custom_blocked":                "filtering",
	"custom_allowed":                "filtering",
	"custom_mappings":               "filtering",
	"lists":                         "lists",
	"allowlists":                    "lists",
	"blocked_countries":             "lists",
	"blocked_clients":               "clients",
	"blocked_clients_info":          "clients",
	"client_aliases":                "clients",
	"autoblock_whitelist":           "clients",
	"abuse_detection_enabled":       "abuse",
	"abuse_dga_threshold":           "abuse",
	"abuse_dga_min_len":             "abuse",
	"malicious_ip_blocking_enabled": "abuse",
	"malicious_ip_interval":         "abuse",
	"retention_days":                "system",
	"admin_domain":                  "system",
	"block_page_ip":                 "system",
	"latency_test_interval":         "system",
	"diagnostics_refresh_interval":  "system",
	"sign_mobileconfig":             "system",
	"verify_upstream_tls":           "system",
	"doh_rate_limit":                "system",
	"debug_mode":                    "system",
	"server_country":                "system",
	"admin_password_hashed":         "auth",
	"mfa_enabled":                   "auth",
	"totp_configs":                  "auth",
	"webauthn_credentials":          "auth",
	"api_keys":                      "auth",
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

