package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	maliciousIPList []string
	maliciousIPMap  = &sync.Map{} // *sync.Map
	maliciousMu     sync.RWMutex
	maliciousPath   = filepath.Join(DataDir, "malicious.hosts")
)

func initMalicious() {
	loadMaliciousFromDisk()
}

func loadMaliciousFromDisk() {
	file, err := os.Open(maliciousPath)
	if err != nil {
		return
	}
	defer file.Close()

	var ips []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" && !strings.HasPrefix(ip, "#") {
			ips = append(ips, ip)
		}
	}

	updateMaliciousMemory(ips)
	slog.Info("Loaded malicious IPs from disk", "count", len(ips))
}

func syncMaliciousIPs() error {
	configLock.RLock()
	enabled := config.MaliciousIPBlockingEnabled
	configLock.RUnlock()

	if !enabled {
		return nil
	}

	slog.Info("Syncing malicious IP list from blocklist.de")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://lists.blocklist.de/lists/all.txt", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download malicious list: status %d", resp.StatusCode)
	}

	tmpPath := maliciousPath + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer out.Close()

	var ips []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if ip != "" {
			// Basic validation to ensure it's a valid IP
			if net.ParseIP(ip) != nil {
				ips = append(ips, ip)
				fmt.Fprintln(out, ip)
			}
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return err
	}

	out.Close()
	os.Remove(maliciousPath)
	os.Rename(tmpPath, maliciousPath)

	updateMaliciousMemory(ips)
	slog.Info("Malicious IP list updated", "count", len(ips))

	// Re-generate Corefile to apply changes
	updateCorefile()
	restartCoreDNS()
	
	return nil
}

func updateMaliciousMemory(ips []string) {
	maliciousMu.Lock()
	maliciousIPList = ips
	maliciousMu.Unlock()

	// Rebuild and swap pointer
	newMap := &sync.Map{}
	for _, ip := range ips {
		newMap.Store(ip, struct{}{})
	}
	maliciousIPMap = newMap
}

func IsMaliciousIP(ip string) bool {
	configLock.RLock()
	enabled := config.MaliciousIPBlockingEnabled
	configLock.RUnlock()

	if !enabled {
		return false
	}

	_, found := maliciousIPMap.Load(ip)
	return found
}

func getMaliciousIPRules() []string {
	configLock.RLock()
	enabled := config.MaliciousIPBlockingEnabled
	configLock.RUnlock()

	if !enabled {
		return nil
	}

	maliciousMu.RLock()
	defer maliciousMu.RUnlock()
	return maliciousIPList
}

func startMaliciousUpdater(ctx context.Context) {
	configLock.RLock()
	interval := config.MaliciousIPInterval
	enabled := config.MaliciousIPBlockingEnabled
	configLock.RUnlock()

	if !enabled {
		return
	}

	if interval < 8 {
		interval = 8
	}

	slog.Info("Starting malicious IP updater", "interval_hours", interval)
	ticker := time.NewTicker(time.Duration(interval) * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncMaliciousIPs()
		}
	}
}

// Note: restartMaliciousUpdater is no longer needed with the global context pattern
// but kept for compatibility if called elsewhere, now a no-op as main manages workers.
func restartMaliciousUpdater() {
	// In the new architecture, we'd ideally trigger a re-run or just wait for the next tick.
	// For now, we'll keep it simple.
}
