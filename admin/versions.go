package main

import (
	"encoding/json"
	"io"
	"log"
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
	latestVersions  VersionInfo
	versionLock     sync.RWMutex
	coreDNSVersion  string
	coreDNSLock     sync.RWMutex
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

	// Output format is usually: "CoreDNS-1.14.2"
	s := strings.TrimSpace(string(out))
	if strings.Contains(s, "CoreDNS-") {
		coreDNSVersion = "v" + strings.TrimPrefix(s, "CoreDNS-")
	} else if strings.Contains(s, " ") {
		coreDNSVersion = strings.Fields(s)[1]
	} else {
		coreDNSVersion = s
	}

	return coreDNSVersion
}

func getLatestVersions() VersionInfo {
	versionLock.RLock()
	if time.Since(latestVersions.LastCheck) < 1*time.Hour && latestVersions.ShieldDNS != "" {
		defer versionLock.RUnlock()
		return latestVersions
	}
	versionLock.RUnlock()

	// Update in background or blocking? User wants reliability.
	// We'll update synchronously if cache is old, but use a timeout.
	updateVersions()
	
	versionLock.RLock()
	defer versionLock.RUnlock()
	return latestVersions
}

func updateVersions() {
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		v := fetchGitHubLatestTag("FaserF/ShieldDNS")
		versionLock.Lock()
		if v != "" { latestVersions.ShieldDNS = v }
		versionLock.Unlock()
	}()

	go func() {
		defer wg.Done()
		v := fetchGitHubLatestTag("coredns/coredns")
		versionLock.Lock()
		if v != "" { latestVersions.CoreDNS = v }
		versionLock.Unlock()
	}()

	go func() {
		defer wg.Done()
		// Alpine latest stable is a bit harder, we can check their releases page or a specific tag
		// For simplicity, we check the latest tag on their github mirror or similar.
		// Actually, let's use a reliable way for Alpine.
		v := fetchAlpineLatest()
		versionLock.Lock()
		if v != "" { latestVersions.Alpine = v }
		versionLock.Unlock()
	}()

	wg.Wait()
	versionLock.Lock()
	latestVersions.LastCheck = time.Now()
	versionLock.Unlock()
}

func fetchGitHubLatestTag(repo string) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/" + repo + "/releases/latest")
	if err != nil {
		log.Printf("Error fetching latest version for %s: %v", repo, err)
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
	b, _ := io.ReadAll(resp.Body)
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
