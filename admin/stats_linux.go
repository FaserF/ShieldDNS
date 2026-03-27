//go:build linux

package main

import (
	"math"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func fillCPUStats(stats map[string]interface{}) {
	// CPU Load
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			stats["cpu_load"] = []string{fields[0], fields[1], fields[2]}
		}
	}

	// CPU Info
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "model name") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					stats["cpu_model"] = strings.TrimSpace(parts[1])
					break
				}
			}
		}
		// Count cores
		cores := 0
		for _, line := range lines {
			if strings.HasPrefix(line, "processor") {
				cores++
			}
		}
		stats["cpu_cores"] = cores
	}
}

func fillRAMStats(stats map[string]interface{}) {
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(data), "\n")
		var total, available int64
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseInt(fields[1], 10, 64)
			if fields[0] == "MemTotal:" {
				total = val
			} else if fields[0] == "MemAvailable:" {
				available = val
			}
		}
		if total > 0 {
			used := total - available
			percent := float64(used) / float64(total) * 100
			stats["ram_total_mb"] = total / 1024
			stats["ram_used_mb"] = used / 1024
			stats["ram_percent"] = math.Round(percent*10) / 10
		}
	}
}

func fillUptimeStats(stats map[string]interface{}) {
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			uptimeSeconds, _ := strconv.ParseFloat(fields[0], 64)
			stats["uptime_seconds"] = int64(uptimeSeconds)
		}
	}
}

func fillDiskStats(stats map[string]interface{}) {
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err == nil {
		total := fs.Blocks * uint64(fs.Bsize)
		free := fs.Bfree * uint64(fs.Bsize)
		used := total - free
		percent := float64(used) / float64(total) * 100
		stats["disk_total_gb"] = math.Round(float64(total)/1024/1024/1024*10) / 10
		stats["disk_used_gb"] = math.Round(float64(used)/1024/1024/1024*10) / 10
		stats["disk_percent"] = math.Round(percent*10) / 10
	}
}
