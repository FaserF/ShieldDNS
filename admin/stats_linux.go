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
			l1, _ := strconv.ParseFloat(fields[0], 64)
			l5, _ := strconv.ParseFloat(fields[1], 64)
			l15, _ := strconv.ParseFloat(fields[2], 64)
			stats["cpu_load"] = []float64{l1, l5, l15}
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
			stats["ram"] = map[string]interface{}{
				"total": total, // in KB
				"used":  used,  // in KB
			}
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
		stats["disk"] = map[string]interface{}{
			"total": total, // in Bytes
			"used":  used,  // in Bytes
		}
	}
}
