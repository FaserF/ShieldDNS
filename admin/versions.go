package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type VersionInfo struct {
	ShieldDNS string
	CoreDNS   string
	Alpine    string
	LastCheck time.Time
}

var (
	latestVersions VersionInfo
	versionLock    sync.RWMutex
	coreDNSVersion string
	coreDNSLock    sync.RWMutex
	alpineVersion  string
	alpineLock     sync.RWMutex
)

func getCoreDNSVersion() string {
	coreDNSLock.RLock()
	if coreDNSVersion != "" {
		defer coreDNSLock.RUnlock()
		return coreDNSVersion
	}
	coreDNSLock.RUnlock()

	coreDNSLock.Lock()
	defer coreDNSLock.Unlock()

	// Re-check after lock
	if coreDNSVersion != "" {
		return coreDNSVersion
	}

	// Try to get version from binary (both Stdout and Stderr)
	out, err := exec.Command("coredns", "-version").CombinedOutput()
	if err != nil {
		// Try absolute path as fallback
		out, err = exec.Command("/usr/bin/coredns", "-version").CombinedOutput()
	}

	if err != nil {
		// Fallback to current target version if not found (e.g. in dev environment)
		slog.Debug("Could not execute coredns -version, using fallback", "error", err)
		coreDNSVersion = "v1.14.3"
		return coreDNSVersion
	}

	// Output format is usually: "CoreDNS-1.14.2" or "v1.14.2 ..."
	s := strings.TrimSpace(string(out))
	fields := strings.Fields(s)

	if len(fields) > 0 {
		// Output can be: "CoreDNS-1.14.2", "v1.14.2", "1.14.2", etc.
		for _, f := range fields {
			fClean := strings.Trim(f, ",()")
			fLower := strings.ToLower(fClean)

			// Look for something that looks like a version (starts with v or a digit or coredns)
			// and contains at least one dot (to avoid architecture names like arm64)
			if (strings.HasPrefix(fLower, "v") || strings.HasPrefix(fLower, "coredns-") || (len(fLower) > 0 && fLower[0] >= '0' && fLower[0] <= '9')) &&
				strings.Contains(fLower, ".") {

				v := fClean
				if strings.HasPrefix(fLower, "coredns-") {
					v = v[8:]
				}
				if !strings.HasPrefix(strings.ToLower(v), "v") {
					v = "v" + v
				}
				coreDNSVersion = v
				break
			}
		}
	}

	if coreDNSVersion == "" {
		coreDNSVersion = s
	}

	// Final cleanup (remove any trailing metadata after a space or hyphen if not part of version)
	coreDNSVersion = strings.Split(coreDNSVersion, " ")[0]
	coreDNSVersion = strings.Split(coreDNSVersion, "-")[0]
	coreDNSVersion = strings.TrimRight(coreDNSVersion, ",()")
	coreDNSVersion = strings.ToLower(coreDNSVersion)

	return coreDNSVersion
}

func getOSVersion() string {
	alpineLock.RLock()
	if alpineVersion != "" {
		defer alpineLock.RUnlock()
		return alpineVersion
	}
	alpineLock.RUnlock()

	alpineLock.Lock()
	defer alpineLock.Unlock()

	if alpineVersion != "" {
		return alpineVersion
	}

	// Try to read Alpine version
	ver := "3.23" // Fallback
	if b, err := os.ReadFile("/etc/alpine-release"); err == nil {
		ver = strings.TrimSpace(string(b))
	}
	alpineVersion = ver
	return alpineVersion
}

func getLatestVersions() VersionInfo {
	versionLock.RLock()
	lastCheck := latestVersions.LastCheck
	shieldV := latestVersions.ShieldDNS
	versionLock.RUnlock()

	// If never checked or checked >1h ago, trigger update in background
	if time.Since(lastCheck) > 1*time.Hour || shieldV == "" {
		go updateVersions()
	}

	versionLock.RLock()
	defer versionLock.RUnlock()
	return latestVersions
}

func updateVersions() {
	// Mark as checking immediately to prevent rapid re-entry on failure
	versionLock.Lock()
	latestVersions.LastCheck = time.Now()
	versionLock.Unlock()

	if testMode {
		slog.Info("Mocking updateVersions in testMode")
		return
	}

	slog.Debug("Checking for component updates (GitHub/Alpine)")

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		configLock.RLock()
		channel := config.UpdateChannel
		configLock.RUnlock()

		v := fetchShieldDNSVersion(channel)
		if v != "" {
			versionLock.Lock()
			latestVersions.ShieldDNS = v
			versionLock.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		v := fetchGitHubLatestTag("coredns/coredns")
		if v != "" {
			versionLock.Lock()
			latestVersions.CoreDNS = v
			versionLock.Unlock()
		}
	}()

	go func() {
		defer wg.Done()
		v := fetchAlpineLatest()
		if v != "" {
			versionLock.Lock()
			latestVersions.Alpine = v
			versionLock.Unlock()
		}
	}()

	wg.Wait()

	versionLock.RLock()
	defer versionLock.RUnlock()
	slog.Debug("Update check complete",
		"ShieldDNS", latestVersions.ShieldDNS,
		"CoreDNS", latestVersions.CoreDNS,
		"Alpine", latestVersions.Alpine)
}

func fetchShieldDNSVersion(channel string) string {
	client := &http.Client{Timeout: 5 * time.Second}

	if channel == "beta" {
		req, err := http.NewRequest("GET", "https://api.github.com/repos/FaserF/ShieldDNS/releases", nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", "ShieldDNS-Updater")
		resp, err := client.Do(req)
		if err != nil {
			slog.Error("Error fetching beta version info", "error", err)
			return ""
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return ""
		}
		var releases []struct {
			TagName string `json:"tag_name"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil || len(releases) == 0 {
			return ""
		}
		return releases[0].TagName
	}

	if channel == "dev" {
		req, err := http.NewRequest("GET", "https://api.github.com/repos/FaserF/ShieldDNS/commits?sha=main", nil)
		if err != nil {
			return ""
		}
		req.Header.Set("User-Agent", "ShieldDNS-Updater")
		resp, err := client.Do(req)
		if err != nil {
			slog.Error("Error fetching dev version info", "error", err)
			return ""
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return ""
		}
		var commits []struct {
			SHA string `json:"sha"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&commits); err != nil || len(commits) == 0 {
			return ""
		}
		sha := commits[0].SHA
		if len(sha) > 7 {
			sha = sha[:7]
		}
		return "dev-" + sha
	}

	// Default to stable
	req, err := http.NewRequest("GET", "https://api.github.com/repos/FaserF/ShieldDNS/releases/latest", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "ShieldDNS-Updater")
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error fetching latest stable version", "error", err)
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	return data.TagName
}

func fetchGitHubLatestTag(repo string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "ShieldDNS-Updater")
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("Error fetching latest version", "repo", repo, "error", err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var data struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	return data.TagName
}

func fetchAlpineLatest() string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/latest-releases.yaml")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, 1*1024*1024)
	b, _ := io.ReadAll(lr)
	content := string(b)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "version:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

func checkVersionsNow() VersionInfo {
	updateVersions()
	versionLock.RLock()
	defer versionLock.RUnlock()
	return latestVersions
}

func createAutoBackup() error {
	slog.Info("Creating pre-update backup...")
	backupBytes, err := GenerateBackupZIP(true)
	if err != nil {
		return fmt.Errorf("failed to generate backup ZIP: %w", err)
	}

	backupFile := filepath.Join(DataDir, "backup_before_update.zip")
	err = os.WriteFile(backupFile, backupBytes, 0600)
	if err != nil {
		return fmt.Errorf("failed to write backup file: %w", err)
	}

	slog.Info("Backup created successfully before update", "path", backupFile)
	return nil
}

func triggerUpdate(channel string) error {
	if testMode {
		slog.Info("Mocking self-update trigger in testMode")
		return nil
	}
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		return triggerDockerComposeUpdate(channel)
	}
	return fmt.Errorf("self-update is only supported when running via Docker with /var/run/docker.sock mounted")
}

func triggerDockerComposeUpdate(channel string) error {
	socketPath := "/var/run/docker.sock"
	tag := "latest"
	if channel == "beta" {
		tag = "beta"
	} else if channel == "dev" {
		tag = "dev"
	}

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to get hostname: %w", err)
	}

	resp, err := client.Get("http://localhost/containers/" + hostname + "/json")
	if err != nil {
		return fmt.Errorf("failed to inspect container via Docker API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Docker API returned status %d on inspect", resp.StatusCode)
	}

	var inspectData struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inspectData); err != nil {
		return fmt.Errorf("failed to decode container inspect data: %w", err)
	}

	composeDir := inspectData.Config.Labels["com.docker.compose.project.working_dir"]
	if composeDir == "" {
		return fmt.Errorf("container is not running via Docker Compose (missing com.docker.compose.project.working_dir label)")
	}

	helperName := "shielddns-update-helper"
	cmdStr := fmt.Sprintf("sleep 3 && docker compose -f %s/docker-compose.yml pull && docker compose -f %s/docker-compose.yml up -d --remove-orphans", composeDir, composeDir)

	createPayload := map[string]interface{}{
		"Image": "docker:cli",
		"Cmd":   []string{"sh", "-c", cmdStr},
		"HostConfig": map[string]interface{}{
			"Binds": []string{
				"/var/run/docker.sock:/var/run/docker.sock",
				composeDir + ":" + composeDir,
			},
			"AutoRemove": true,
		},
	}

	payloadBytes, err := json.Marshal(createPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal helper container config: %w", err)
	}

	reqDelete, _ := http.NewRequest("DELETE", "http://localhost/containers/"+helperName+"?force=true", nil)
	client.Do(reqDelete)

	reqCreate, err := http.NewRequest("POST", "http://localhost/containers/create?name="+helperName, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("failed to build create request for helper container: %w", err)
	}
	reqCreate.Header.Set("Content-Type", "application/json")

	respCreate, err := client.Do(reqCreate)
	if err != nil {
		return fmt.Errorf("failed to create helper container: %w", err)
	}
	defer respCreate.Body.Close()

	if respCreate.StatusCode != http.StatusCreated && respCreate.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(respCreate.Body)
		return fmt.Errorf("failed to create helper container, status: %d, body: %s", respCreate.StatusCode, string(bodyBytes))
	}

	var createResult struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(respCreate.Body).Decode(&createResult); err != nil {
		return fmt.Errorf("failed to decode create helper result: %w", err)
	}

	reqStart, err := http.NewRequest("POST", "http://localhost/containers/"+createResult.ID+"/start", nil)
	if err != nil {
		return fmt.Errorf("failed to build start request for helper: %w", err)
	}
	respStart, err := client.Do(reqStart)
	if err != nil {
		return fmt.Errorf("failed to start helper container: %w", err)
	}
	defer respStart.Body.Close()

	if respStart.StatusCode != http.StatusNoContent && respStart.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to start helper container, status: %d", respStart.StatusCode)
	}

	slog.Info("Successfully launched helper container to pull and recreate ShieldDNS", "helper_id", createResult.ID[:12], "tag", tag)
	return nil
}

func startAutoUpdateWorker(ctx context.Context) {
	slog.Info("Auto-update worker started")
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	lastAutoUpdateDay := -1

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			configLock.RLock()
			enabled := config.AutoUpdateEnabled
			hour := config.AutoUpdateHour
			channel := config.UpdateChannel
			configLock.RUnlock()

			if !enabled {
				continue
			}

			now := time.Now()
			if now.Hour() == hour && now.Day() != lastAutoUpdateDay {
				lastAutoUpdateDay = now.Day()
				slog.Info("Auto-update hour reached. Checking for updates...", "hour", hour, "channel", channel)

				currentVer := Version
				latestVer := fetchShieldDNSVersion(channel)

				if latestVer != "" && latestVer != currentVer {
					slog.Info("New version found for auto-update", "current", currentVer, "latest", latestVer)
					err := createAutoBackup()
					if err != nil {
						slog.Error("Auto-update failed: could not create pre-update backup", "error", err)
						continue
					}

					slog.Info("Initiating auto-update...")
					err = triggerUpdate(channel)
					if err != nil {
						slog.Error("Auto-update trigger failed", "error", err)
					}
				}
			}
		}
	}
}
