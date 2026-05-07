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
	"sync/atomic"
	"time"
)

var (
	maliciousIPList []string
	maliciousIPMap  atomic.Value // holds *sync.Map
	maliciousMu     sync.RWMutex
	maliciousPath   = filepath.Join(DataDir, "malicious.hosts")
	maliciousSignal = make(chan struct{}, 1)
)

func init() {
	maliciousIPMap.Store(&sync.Map{})
}

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

func syncMaliciousIPs(restartCore bool) error {
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
	if restartCore {
		restartCoreDNS()
	}

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
	maliciousIPMap.Store(newMap)
}

func IsMaliciousIP(ip string) bool {
	if !config.MaliciousIPBlockingEnabled {
		return false
	}

	m := maliciousIPMap.Load().(*sync.Map)
	_, found := m.Load(ip)
	return found
}

func getMaliciousIPRules() []string {
	if !config.MaliciousIPBlockingEnabled {
		return nil
	}

	maliciousMu.RLock()
	defer maliciousMu.RUnlock()
	return maliciousIPList
}

func startMaliciousUpdater(ctx context.Context) {
	for {
		configLock.RLock()
		interval := config.MaliciousIPInterval
		enabled := config.MaliciousIPBlockingEnabled
		configLock.RUnlock()

		if !enabled {
			// If disabled, wait for a signal to potentially re-enable or context to end
			select {
			case <-ctx.Done():
				return
			case <-maliciousSignal:
				continue
			}
		}

		if interval < 8 {
			interval = 8
		}

		slog.Info("Starting malicious IP updater", "interval_hours", interval)
		ticker := time.NewTicker(time.Duration(interval) * time.Hour)

		stopTicker := false
		for !stopTicker {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-maliciousSignal:
				slog.Info("Malicious IP updater received restart signal")
				ticker.Stop()
				stopTicker = true
			case <-ticker.C:
				syncMaliciousIPs(true)
			}
		}
	}
}

func restartMaliciousUpdater() {
	select {
	case maliciousSignal <- struct{}{}:
	default:
	}
}
