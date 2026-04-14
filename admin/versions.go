package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os/exec"
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

	// Try to get version from binary
	out, err := exec.Command("coredns", "-version").Output()
	if err != nil {
		// Fallback to a sensible default if not found (e.g. in dev environment)
		coreDNSVersion = "v1.14.2"
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

	slog.Debug("Checking for component updates (GitHub/Alpine)")

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		v := fetchGitHubLatestTag("FaserF/ShieldDNS")
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

func fetchGitHubLatestTag(repo string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/" + repo + "/releases/latest")
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
	// Alpine Linux stable releases: https://alpinelinux.org/releases.json
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64/latest-releases.yaml")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// The file is YAML, but we can just look for the version string as a simple heuristic
	// Example content:
	// - branch: v3.21
	//   arch: x86_64
	//   version: 3.21.3

	// Actually, let's just use the branch part or the first version we find.
	// Since it's a small file, we can read it.
	lr := io.LimitReader(resp.Body, 1*1024*1024) // 1MB limit for YAML
	b, _ := io.ReadAll(lr)
	content := string(b)

	// Simple parsing for "version: X.Y.Z"
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
